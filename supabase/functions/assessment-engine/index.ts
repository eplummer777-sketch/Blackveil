import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { requireEnv } from "../_lib/env.ts";
import { runHttpChecks, normalizeTarget, HttpFinding, CheckResult } from "./http.ts";
import { runCloudflareChecks, applyCloudflareFix, verifyCloudflareFix, CfFinding } from "./cfbridge.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ASSESSMENT_RATE_LIMIT = 10; // per hour

async function verifyCfToken(token: string): Promise<boolean> {
  try {
    const resp = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
      headers: { "Authorization": `Bearer ${token}`, "User-Agent": "Blackveil-Remediation-Engine/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return resp.ok && data?.success === true;
  } catch {
    return false;
  }
}

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

interface Ctx {
  svc: SupabaseClient;
  userId: string;
  isAdmin: boolean;
}

async function logAudit(ctx: Ctx, action: string, ids: { assessment_id?: string; finding_id?: string }, detail: Record<string, unknown> = {}) {
  await ctx.svc.from("remediation_audit").insert({
    user_id: ctx.userId,
    action,
    assessment_id: ids.assessment_id ?? null,
    finding_id: ids.finding_id ?? null,
    detail,
  });
  await ctx.svc.from("audit_logs").insert({
    user_id: ctx.userId,
    action: `remediation_${action}`,
    detail: { ...ids, ...detail },
  });
}

// --- Load Cloudflare integration + decrypt token ---
async function loadCfIntegration(ctx: Ctx, integrationId: string) {
  const { data: integration } = await ctx.svc.from("architect_integrations")
    .select("*").eq("id", integrationId).maybeSingle();
  if (!integration || (integration.user_id !== ctx.userId && !ctx.isAdmin)) {
    throw new HttpError(404, "Cloudflare integration not found.");
  }
  if (integration.status !== "connected") throw new HttpError(400, "This Cloudflare integration is disconnected.");
  const { data: secret } = await ctx.svc.from("architect_integration_secrets")
    .select("encrypted_token, iv").eq("integration_id", integrationId).maybeSingle();
  if (!secret) throw new HttpError(404, "No stored credentials for this integration.");
  return { integration, secret };
}

async function decryptCfToken(secret: { encrypted_token: string; iv: string }): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(requireEnv("CF_ENCRYPTION_KEY")), { name: "PBKDF2" }, false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("blackveil-cf-salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const ivBytes = Uint8Array.from(atob(secret.iv), (c) => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(secret.encrypted_token), (c) => c.charCodeAt(0));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, ciphertext);
  return new TextDecoder().decode(dec);
}

// --- Compute summary ---
function computeSummary(findings: { severity: string }[]): { status: string; summary: Record<string, number> } {
  const summary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  let status = "Good";
  if (summary.critical > 0) status = "Critical";
  else if (summary.high > 0) status = "Needs attention";
  else if (summary.medium > 0) status = "Fair";
  return { status, summary };
}

// --- Handlers ---

async function runAssessment(ctx: Ctx, body: Record<string, unknown>) {
  const target = typeof body.target === "string" ? body.target.trim() : "";
  const authorized = body.authorization_confirmed === true;
  if (!target) throw new HttpError(400, "A target domain is required.");
  if (!authorized) throw new HttpError(400, "You must confirm you own or have permission to assess this target.");

  const parsed = normalizeTarget(target);
  if (!parsed) throw new HttpError(400, "Invalid or blocked target. Use a public domain you own. Private, loopback, and metadata destinations are blocked.");

  // Rate limit
  const since = new Date(Date.now() - 3_600_000).toISOString();
  const { count } = await ctx.svc.from("remediation_assessments")
    .select("id", { count: "exact", head: true })
    .eq("user_id", ctx.userId).gte("created_at", since);
  if ((count ?? 0) >= ASSESSMENT_RATE_LIMIT) {
    throw new HttpError(429, `Assessment rate limit reached (${ASSESSMENT_RATE_LIMIT}/hour). Try again later.`);
  }

  // Determine sources
  const sources: string[] = ["http"];
  let integrationId: string | null = null;
  let cfToken: string | null = null;
  let zoneId: string | null = null;

  if (typeof body.integration_id === "string" && UUID.test(body.integration_id)) {
    const { integration, secret } = await loadCfIntegration(ctx, body.integration_id);
    integrationId = integration.id;
    zoneId = integration.zone_id;
    cfToken = await decryptCfToken(secret);
    // Verify the token still works
    const verify = await verifyCfToken(cfToken);
    if (!verify) {
      await ctx.svc.from("architect_integrations").update({ status: "error", last_error: "Token invalid during assessment." }).eq("id", integrationId);
      throw new HttpError(401, "Your Cloudflare token is no longer valid. Please reconnect in the Architect tab.");
    }
    sources.push("cloudflare");
  }

  // Create assessment record
  const { data: assessment, error: aErr } = await ctx.svc.from("remediation_assessments").insert({
    user_id: ctx.userId,
    target: parsed.host,
    integration_id: integrationId,
    sources,
    status: "running",
  }).select("id").maybeSingle();
  if (aErr || !assessment) throw new HttpError(500, "Could not start the assessment.");

  const assessmentId = assessment.id;

  try {
    const allFindings: (HttpFinding | CfFinding)[] = [];
    const allChecks: CheckResult[] = [];

    // Run HTTP checks
    try {
      const httpResult = await runHttpChecks(parsed.host);
      allFindings.push(...httpResult.findings);
      allChecks.push(...httpResult.checks);
    } catch (e) {
      allChecks.push({ check_id: "http_checks", status: "failed", note: (e as Error).message });
    }

    // Run Cloudflare checks if connected
    if (cfToken && zoneId) {
      try {
        const cfResult = await runCloudflareChecks(cfToken, zoneId);
        allFindings.push(...cfResult.findings);
        allChecks.push(...cfResult.checks);
      } catch (e) {
        allChecks.push({ check_id: "cf_checks", status: "failed", note: (e as Error).message });
      }
    }

    const { status: overall, summary } = computeSummary(allFindings);

    // Save findings
    const findingRows = allFindings.map((f) => {
      const isCf = f.source === "cloudflare";
      const cf = isCf ? (f as CfFinding) : null;
      return {
        assessment_id: assessmentId,
        user_id: ctx.userId,
        check_id: f.check_id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        source: f.source,
        description: f.description,
        evidence: f.evidence,
        impact: f.impact,
        remediation: f.remediation,
        verified: f.verified,
        fixable: cf?.fixable ?? false,
        cf_setting_key: cf?.cf_setting_key ?? null,
        cf_api_path: cf?.cf_api_path ?? null,
        current_value: cf?.current_value ?? null,
        proposed_value: cf?.proposed_value ?? null,
        recommended_value: cf?.recommended_value ?? null,
        rollback_value: cf?.rollback_value ?? null,
        rollback_supported: cf?.rollback_supported ?? false,
        rollback_instructions: cf?.rollback_instructions ?? "",
        risks: cf?.risks ?? [],
        risk_level: cf?.risk_level ?? "medium",
        fix_status: cf?.fixable ? "proposed" : "none",
      };
    });

    if (findingRows.length > 0) {
      await ctx.svc.from("remediation_findings").insert(findingRows);
    }

    await ctx.svc.from("remediation_assessments").update({
      status: "completed",
      overall_status: overall,
      summary: { ...summary, total: allFindings.length, checks: allChecks },
      check_results: allChecks,
      completed_at: new Date().toISOString(),
    }).eq("id", assessmentId);

    await logAudit(ctx, "assessment_completed", { assessment_id: assessmentId }, {
      target: parsed.host, sources, findings: allFindings.length, overall,
    });

    // Return full assessment
    const { data: fullAssessment } = await ctx.svc.from("remediation_assessments").select("*").eq("id", assessmentId).maybeSingle();
    const { data: fullFindings } = await ctx.svc.from("remediation_findings").select("*").eq("assessment_id", assessmentId).order("created_at", { ascending: true });
    return { assessment: fullAssessment, findings: fullFindings ?? [] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    await ctx.svc.from("remediation_assessments").update({
      status: "failed", error: msg, completed_at: new Date().toISOString(),
    }).eq("id", assessmentId);
    await logAudit(ctx, "assessment_failed", { assessment_id: assessmentId }, { error: msg });
    throw new HttpError(500, "The assessment encountered an error. Please try again.");
  }
}

async function loadFinding(ctx: Ctx, findingId: string) {
  if (!UUID.test(findingId)) throw new HttpError(400, "Invalid finding id.");
  const { data: finding } = await ctx.svc.from("remediation_findings").select("*").eq("id", findingId).maybeSingle();
  if (!finding || (finding.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Finding not found.");
  return finding;
}

async function approveFix(ctx: Ctx, body: Record<string, unknown>) {
  const finding = await loadFinding(ctx, body.finding_id as string);
  if (finding.fix_status !== "proposed") throw new HttpError(409, "Only proposed fixes can be approved.");
  if (!finding.fixable) throw new HttpError(400, "This finding does not have an applicable fix.");

  const ack = body.acknowledged_risks === true;
  if (!ack) throw new HttpError(400, "Please confirm you have read the risks before approving.");
  if (finding.risk_level === "high") {
    const note = typeof body.note === "string" ? body.note.trim() : "";
    if (note.length < 10) throw new HttpError(400, "High-risk changes need a written reason (at least 10 characters).");
  }

  // Verify the integration is in write mode
  const { data: assessment } = await ctx.svc.from("remediation_assessments")
    .select("integration_id").eq("id", finding.assessment_id).maybeSingle();
  if (assessment?.integration_id) {
    const { data: integration } = await ctx.svc.from("architect_integrations")
      .select("mode").eq("id", assessment.integration_id).maybeSingle();
    if (integration?.mode !== "write") {
      throw new HttpError(403, "This Cloudflare integration is in read-only mode. Enable write mode in the Architect tab first.");
    }
  } else if (finding.source === "cloudflare") {
    throw new HttpError(400, "No Cloudflare integration is linked to this finding.");
  }

  const now = new Date().toISOString();
  await ctx.svc.from("remediation_findings").update({
    fix_status: "approved",
    approved_by: ctx.userId,
    approved_at: now,
  }).eq("id", finding.id).eq("fix_status", "proposed");

  await logAudit(ctx, "fix_approved", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
    setting: finding.cf_setting_key, risk_level: finding.risk_level,
  });
  return { message: `Approved: ${finding.title}. Nothing has been applied yet.` };
}

async function rejectFix(ctx: Ctx, body: Record<string, unknown>) {
  const finding = await loadFinding(ctx, body.finding_id as string);
  if (!["proposed", "approved"].includes(finding.fix_status)) {
    throw new HttpError(409, "This fix can only be rejected before it is applied.");
  }
  await ctx.svc.from("remediation_findings").update({
    fix_status: "rejected",
    rejected_at: new Date().toISOString(),
  }).eq("id", finding.id).in("fix_status", ["proposed", "approved"]);

  await logAudit(ctx, "fix_rejected", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
    setting: finding.cf_setting_key,
  });
  return { message: `Rejected: ${finding.title}.` };
}

async function applyFix(ctx: Ctx, body: Record<string, unknown>) {
  const finding = await loadFinding(ctx, body.finding_id as string);
  if (finding.fix_status !== "approved") throw new HttpError(409, "Only approved fixes can be applied.");
  if (!finding.fixable) throw new HttpError(400, "This finding does not have an applicable fix.");
  if (finding.source !== "cloudflare") throw new HttpError(400, "Only Cloudflare findings can be applied automatically.");
  const confirmed = body.confirmed === true;
  if (!confirmed) throw new HttpError(400, "Please confirm you want to apply this change to your live Cloudflare zone.");

  // Load integration
  const { data: assessment } = await ctx.svc.from("remediation_assessments")
    .select("integration_id, target").eq("id", finding.assessment_id).maybeSingle();
  if (!assessment?.integration_id) throw new HttpError(400, "No Cloudflare integration is linked to this finding.");

  const { data: integration } = await ctx.svc.from("architect_integrations")
    .select("*").eq("id", assessment.integration_id).maybeSingle();
  if (!integration || integration.status !== "connected") throw new HttpError(400, "The Cloudflare integration is disconnected.");
  if (integration.mode !== "write") throw new HttpError(403, "This integration is in read-only mode. Enable write mode first.");

  const { data: secret } = await ctx.svc.from("architect_integration_secrets")
    .select("encrypted_token, iv").eq("integration_id", integration.id).maybeSingle();
  if (!secret) throw new HttpError(404, "No stored credentials for this integration.");

  const token = await decryptCfToken(secret as { encrypted_token: string; iv: string });

  const result = await applyCloudflareFix(token, integration.zone_id, finding.cf_setting_key, finding.proposed_value);
  const now = new Date().toISOString();

  if (!result.ok) {
    await ctx.svc.from("remediation_findings").update({
      fix_status: "failed",
      apply_error: result.error ?? "Unknown error",
      updated_at: now,
    }).eq("id", finding.id).eq("fix_status", "approved");

    await logAudit(ctx, "fix_apply_failed", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
      setting: finding.cf_setting_key, error: result.error,
    });
    throw new HttpError(502, `Cloudflare rejected the change: ${result.error}`);
  }

  await ctx.svc.from("remediation_findings").update({
    fix_status: "applied",
    applied_at: now,
    apply_error: null,
  }).eq("id", finding.id).eq("fix_status", "approved");

  await logAudit(ctx, "fix_applied", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
    setting: finding.cf_setting_key,
  });
  return { message: `Applied: ${finding.title}. Re-reading the setting to verify it took effect.` };
}

async function verifyFix(ctx: Ctx, body: Record<string, unknown>) {
  const finding = await loadFinding(ctx, body.finding_id as string);
  if (!["applied", "verified", "failed"].includes(finding.fix_status)) {
    throw new HttpError(409, "Only applied changes can be verified.");
  }
  if (finding.source !== "cloudflare") throw new HttpError(400, "Only Cloudflare findings can be verified automatically.");

  const { data: assessment } = await ctx.svc.from("remediation_assessments")
    .select("integration_id").eq("id", finding.assessment_id).maybeSingle();
  if (!assessment?.integration_id) throw new HttpError(400, "No Cloudflare integration linked.");

  const { data: integration } = await ctx.svc.from("architect_integrations")
    .select("zone_id").eq("id", assessment.integration_id).maybeSingle();
  if (!integration) throw new HttpError(400, "Integration not found.");

  const { data: secret } = await ctx.svc.from("architect_integration_secrets")
    .select("encrypted_token, iv").eq("integration_id", assessment.integration_id).maybeSingle();
  if (!secret) throw new HttpError(404, "No stored credentials.");

  const token = await decryptCfToken(secret as { encrypted_token: string; iv: string });

  const result = await verifyCloudflareFix(token, integration.zone_id, finding.cf_setting_key);
  const now = new Date().toISOString();

  const verificationResult = {
    ok: result.ok,
    expected: finding.proposed_value,
    actual: result.value,
    checked_at: now,
    error: result.error ?? null,
  };

  if (result.ok && JSON.stringify(result.value) === JSON.stringify(finding.proposed_value)) {
    await ctx.svc.from("remediation_findings").update({
      fix_status: "verified",
      verified_at: now,
      verification_result: verificationResult,
    }).eq("id", finding.id);
    await logAudit(ctx, "fix_verified", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
      setting: finding.cf_setting_key, actual: result.value,
    });
    return { message: `Verified: ${finding.title} now matches the recommended value.`, passed: true, verification_result: verificationResult };
  } else {
    await ctx.svc.from("remediation_findings").update({
      verification_result: verificationResult,
      verified_at: now,
    }).eq("id", finding.id);
    await logAudit(ctx, "fix_verify_mismatch", { assessment_id: finding.assessment_id, finding_id: finding.id }, {
      setting: finding.cf_setting_key, expected: finding.proposed_value, actual: result.value,
    });
    return { message: `Not verified: the actual value (${JSON.stringify(result.value)}) does not match the expected value (${JSON.stringify(finding.proposed_value)}).`, passed: false, verification_result: verificationResult };
  }
}

async function getAssessment(ctx: Ctx, assessmentId: string) {
  if (!UUID.test(assessmentId)) throw new HttpError(400, "Invalid assessment id.");
  const { data: assessment } = await ctx.svc.from("remediation_assessments").select("*").eq("id", assessmentId).maybeSingle();
  if (!assessment || (assessment.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Assessment not found.");
  const { data: findings } = await ctx.svc.from("remediation_findings").select("*").eq("assessment_id", assessmentId).order("created_at", { ascending: true });
  const { data: audit } = await ctx.svc.from("remediation_audit").select("*").eq("assessment_id", assessmentId).order("created_at", { ascending: false }).limit(50);
  return { assessment, findings: findings ?? [], audit: audit ?? [] };
}

// --- Router ---
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user, error: authError } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(authError ?? "Unauthorized", 401);

    const svc = getServiceClient();
    const isAdmin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const ctx: Ctx = { svc, userId: user.id, isAdmin };

    let body: Record<string, unknown>;
    try { body = await req.json(); } catch { return errorResponse("Invalid request body.", 400); }

    switch (body.action) {
      case "run_assessment": return json(await runAssessment(ctx, body));
      case "approve_fix": return json(await approveFix(ctx, body));
      case "reject_fix": return json(await rejectFix(ctx, body));
      case "apply_fix": return json(await applyFix(ctx, body));
      case "verify_fix": return json(await verifyFix(ctx, body));
      case "get_assessment": {
        if (typeof body.assessment_id !== "string") return errorResponse("Assessment id is required.", 400);
        return json(await getAssessment(ctx, body.assessment_id));
      }
      default: return errorResponse("Unknown action.", 400);
    }
  } catch (e) {
    if (e instanceof HttpError) return errorResponse(e.message, e.status);
    console.error("assessment-engine error", e);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
