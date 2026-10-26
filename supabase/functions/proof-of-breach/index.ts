import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { normalizeHostname, resolvePublic, Scope, ScopeError, safeFetch, SafeResponse } from "../_lib/net.ts";
import { CHECKS, computeScore, errorOutcome, Outcome, TOOL, TOOL_VERSION } from "./checks.ts";
import { analyzeCheck } from "../_lib/ai-analyst.ts";

type Svc = ReturnType<typeof getServiceClient>;

const QUICK_LIMIT_MS = 60_000;
const SCANS_PER_HOUR = 10;
const MAX_TARGETS = 15;
const VERIFY_DAYS = 90;

const TOOLS = [
  { name: TOOL, version: TOOL_VERSION, status: "connected", detail: "Powers the Web Scanner: read-only HTTP/TLS/DNS checks on verified targets, with SSRF guards." },
  { name: "Blackveil Discovery", version: "1.0", status: "connected", detail: "Powers Network Scan: host, open-port and service discovery on verified domains and admin-approved ranges, analyzed by Proof-of-Breach AI." },
  { name: "Blackveil Pentest Engine", version: "1.0", status: "connected", detail: "Native non-destructive penetration testing: baseline reconnaissance on any public domain, active checks only on verified targets or recorded authorizations. Findings are explained by Proof-of-Breach AI." },
  { name: "Blackveil Engine", version: "1.0", status: "connected", detail: "Built-in web crawler with passive security checks and content discovery on verified targets. Installed on the server; no screen launches it yet." },
];

async function audit(svc: Svc, userId: string, action: string, detail: Record<string, unknown>, ids: { target_id?: string; scan_id?: string } = {}) {
  await svc.from("pob_audit").insert({ user_id: userId, action, detail, ...ids });
}

async function hasElite(svc: Svc, userId: string, admin: boolean): Promise<boolean> {
  if (admin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && data.plan === "elite" && (data.status === "active" || data.status === "trialing");
}

async function isPaused(svc: Svc): Promise<boolean> {
  const { data } = await svc.from("pob_control").select("paused").eq("id", 1).maybeSingle();
  return !!data?.paused;
}

async function loadVerifiedTarget(svc: Svc, userId: string, targetId: string) {
  const { data: t } = await svc.from("pob_targets").select("*").eq("id", targetId).eq("user_id", userId).maybeSingle();
  if (!t) return { error: "Target not found" };
  if (t.status !== "verified") return { error: "This target has not passed ownership verification" };
  if (t.expires_at && new Date(t.expires_at) < new Date()) {
    await svc.from("pob_targets").update({ status: "expired" }).eq("id", t.id);
    return { error: "Authorization expired. Re-verify ownership to continue testing." };
  }
  return { target: t };
}

function makeScope(t: { hostname: string; allowed_paths: string[]; max_requests_per_scan: number }, signal: AbortSignal, budget?: number): Scope {
  return { host: t.hostname, allowedPaths: t.allowed_paths, budget: { remaining: budget ?? t.max_requests_per_scan }, signal, violations: [] };
}

function homeLoader(scope: Scope) {
  let p: Promise<SafeResponse> | null = null;
  return () => (p ??= safeFetch(`https://${scope.host}/`, scope));
}

function checkRow(outcome: Outcome, def: (typeof CHECKS)[number], extra: Record<string, unknown>) {
  return {
    ...extra,
    check_key: def.key,
    title: def.title,
    category: def.category,
    result: outcome.result,
    severity: outcome.result === "passed" ? "info" : outcome.severity,
    confidence: outcome.confidence,
    validation: outcome.validation,
    affected_asset: outcome.affected_asset,
    summary: outcome.summary,
    evidence: { ...outcome.evidence, remediation: def.fix },
    tool: TOOL,
    tool_version: TOOL_VERSION,
    operation: outcome.operation,
    finished_at: new Date().toISOString(),
  };
}

async function runQuick(svc: Svc, userId: string, targetId: string) {
  const { target, error } = await loadVerifiedTarget(svc, userId, targetId);
  if (!target) return errorResponse(error!, 403);

  await svc.from("pob_scans").update({ status: "failed", error: "Worker stopped responding", finished_at: new Date().toISOString() })
    .eq("user_id", userId).eq("status", "running").lt("started_at", new Date(Date.now() - 3 * 60_000).toISOString());

  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("pob_audit").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("action", "scan_started").gte("created_at", since);
  if ((count ?? 0) >= SCANS_PER_HOUR) return errorResponse(`Limit reached: ${SCANS_PER_HOUR} assessments per hour.`, 429);

  const started = Date.now();
  const { data: scan, error: insErr } = await svc.from("pob_scans").insert({
    user_id: userId, target_id: target.id, hostname: target.hostname, kind: "quick",
    phase: "authorization", deadline_at: new Date(started + QUICK_LIMIT_MS).toISOString(),
  }).select("*").single();
  if (insErr || !scan) return errorResponse("An assessment is already running. Wait for it to finish or stop it.", 409);
  await audit(svc, userId, "scan_started", { hostname: target.hostname, kind: "quick" }, { target_id: target.id, scan_id: scan.id });

  const ctrl = new AbortController();
  const deadline = setTimeout(() => ctrl.abort(), QUICK_LIMIT_MS - 3000);
  const stopPoll = setInterval(async () => {
    const { data } = await svc.from("pob_scans").select("stop_requested").eq("id", scan.id).maybeSingle();
    if (data?.stop_requested || (await isPaused(svc))) ctrl.abort();
  }, 2000);

  const scope = makeScope(target, ctrl.signal);
  const rows: Outcome[] = [];
  const base = { scan_id: scan.id, user_id: userId };
  try {
    await svc.from("pob_scans").update({ phase: "reconnaissance" }).eq("id", scan.id);
    let reconOk = true;
    try {
      await resolvePublic(target.hostname);
    } catch (err) {
      reconOk = false;
      if (err instanceof ScopeError) await audit(svc, userId, "scope_violation", { reason: err.message }, { scan_id: scan.id });
    }
    await svc.from("pob_scans").update({ phase: "checks" }).eq("id", scan.id);
    const ctx = { scope, home: homeLoader(scope) };
    const allowed = CHECKS.filter((c) => target.allowed_categories.includes(c.category));
    for (const def of CHECKS) {
      let out: Outcome;
      if (!allowed.includes(def)) {
        out = { ...errorOutcome(new ScopeError("category not permitted for this target"), "skipped", target.hostname) };
      } else if (!reconOk) {
        out = { ...errorOutcome(new ScopeError("target failed DNS safety validation"), "skipped", target.hostname) };
      } else if (ctrl.signal.aborted) {
        out = { ...errorOutcome(new DOMException("aborted", "AbortError"), "not started", target.hostname), summary: "Not started before the time limit or stop request." };
      } else {
        out = await def.run(ctx).catch((e) => errorOutcome(e, "internal", target.hostname));
      }
      rows.push(out);
      await svc.from("pob_checks").insert(checkRow(out, def, base));
    }
    if (scope.violations.length) await audit(svc, userId, "scope_violation", { blocked: scope.violations.slice(0, 10) }, { scan_id: scan.id });
    const { score, counts } = computeScore(rows);
    const { data: fresh } = await svc.from("pob_scans").select("stop_requested").eq("id", scan.id).maybeSingle();
    const status = fresh?.stop_requested ? "stopped" : counts.incomplete + counts.not_performed > 0 ? "partial" : "completed";
    await svc.from("pob_scans").update({ status, phase: "done", score, counts, finished_at: new Date().toISOString() }).eq("id", scan.id);
    await audit(svc, userId, "scan_finished", { status, score, duration_ms: Date.now() - started, requests_used: target.max_requests_per_scan - scope.budget.remaining }, { scan_id: scan.id });
    return json({ scan_id: scan.id, status, score, counts });
  } catch (err) {
    console.error("pob scan failed", err);
    await svc.from("pob_scans").update({ status: "failed", phase: "done", error: "The assessment stopped unexpectedly.", finished_at: new Date().toISOString() }).eq("id", scan.id);
    return errorResponse("The assessment stopped unexpectedly. Completed checks were saved.", 500);
  } finally {
    clearTimeout(deadline);
    clearInterval(stopPoll);
  }
}

async function retest(svc: Svc, userId: string, checkId: string) {
  const { data: c } = await svc.from("pob_checks").select("*, pob_scans!inner(target_id)").eq("id", checkId).eq("user_id", userId).maybeSingle();
  if (!c) return errorResponse("Finding not found", 404);
  const def = CHECKS.find((d) => d.key === c.check_key);
  if (!def) return errorResponse("This check can no longer be re-run", 400);
  const { target, error } = await loadVerifiedTarget(svc, userId, c.pob_scans.target_id);
  if (!target) return errorResponse(error!, 403);
  if (!target.allowed_categories.includes(def.category)) return errorResponse("This test category is no longer in scope", 403);

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  const scope = makeScope(target, ctrl.signal, 8);
  const out = await def.run({ scope, home: homeLoader(scope) }).catch((e) => errorOutcome(e, "internal", target.hostname));
  clearTimeout(t);

  let status: string;
  if (out.result === "passed") status = "fixed_verified";
  else if (out.result === "partial" && c.result === "failed") status = "partially_fixed";
  else if (out.result === "failed" || out.result === "partial") status = "still_vulnerable";
  else if (out.result === "incomplete") status = "inconclusive";
  else status = "retest_failed";

  const retest_evidence = { result: out.result, summary: out.summary, evidence: out.evidence, operation: out.operation, tool: `${TOOL} ${TOOL_VERSION}`, at: new Date().toISOString() };
  await svc.from("pob_checks").update({ retest_status: status, retest_evidence, retested_at: retest_evidence.at }).eq("id", c.id);
  await audit(svc, userId, "retest", { check: c.check_key, outcome: status }, { target_id: target.id, scan_id: c.scan_id });
  return json({ retest_status: status, retest_evidence });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "POST") return errorResponse("Method not allowed", 405);
    const { user } = await getAuthenticatedUser(req);
    if (!user) return errorResponse("Unauthorized", 401);
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const svc = getServiceClient();
    const body = await req.json().catch(() => ({}));
    const action = String(body.action ?? "");

    if (action === "status") {
      return json({ elite: await hasElite(svc, user.id, admin), paused: await isPaused(svc), admin, tools: TOOLS, quick_limit_seconds: QUICK_LIMIT_MS / 1000 });
    }
    if (action === "set_pause") {
      if (!admin) return errorResponse("Forbidden", 403);
      const paused = body.paused === true;
      await svc.from("pob_control").update({ paused, updated_at: new Date().toISOString() }).eq("id", 1);
      if (paused) {
        await svc.from("pob_scans").update({ stop_requested: true }).eq("status", "running");
        await svc.from("zap_scans").update({ cancel_requested: true }).in("status", ["queued", "running"]);
      }
      await audit(svc, user.id, paused ? "emergency_stop_on" : "emergency_stop_off", {});
      return json({ paused });
    }

    if (!(await hasElite(svc, user.id, admin))) return errorResponse("Proof-of-Breach AI is included with the Elite plan.", 402);

    switch (action) {
      case "add_target": {
        const hostname = normalizeHostname(body.hostname);
        if (!hostname) return errorResponse("Enter a public domain name like example.com (no IP addresses or internal names).", 400);
        const environment = ["production", "staging", "development"].includes(body.environment) ? body.environment : "production";
        const { count } = await svc.from("pob_targets").select("id", { count: "exact", head: true }).eq("user_id", user.id);
        if ((count ?? 0) >= MAX_TARGETS) return errorResponse(`You can register up to ${MAX_TARGETS} targets.`, 400);
        const token = crypto.randomUUID().replace(/-/g, "");
        const { data, error } = await svc.from("pob_targets").insert({ user_id: user.id, hostname, label: String(body.label ?? "").slice(0, 80), environment, verify_token: token }).select("*").single();
        if (error) return errorResponse(error.code === "23505" ? "That domain is already registered." : "Could not add target.", 400);
        await audit(svc, user.id, "target_added", { hostname, environment }, { target_id: data.id });
        return json({ target: data });
      }
      case "verify_target": {
        const { data: t } = await svc.from("pob_targets").select("*").eq("id", body.target_id).eq("user_id", user.id).maybeSingle();
        if (!t) return errorResponse("Target not found", 404);
        let records: string[] = [];
        try {
          records = (await Deno.resolveDns(`_blackveil-verify.${t.hostname}`, "TXT")).map((r) => r.join(""));
        } catch { /* no record yet */ }
        const ok = records.some((r) => r.trim() === `blackveil-verify=${t.verify_token}`);
        if (!ok) {
          await audit(svc, user.id, "verification_failed", { hostname: t.hostname, records_found: records.length }, { target_id: t.id });
          return errorResponse("Verification record not found yet. DNS changes can take a few minutes to appear.", 400);
        }
        try {
          await resolvePublic(t.hostname);
        } catch (err) {
          return errorResponse(err instanceof Error ? err.message : "Target failed network safety checks", 400);
        }
        const expires = new Date(Date.now() + VERIFY_DAYS * 86400_000).toISOString();
        const { data } = await svc.from("pob_targets").update({ status: "verified", verification_method: "dns_txt", verified_at: new Date().toISOString(), expires_at: expires }).eq("id", t.id).select("*").single();
        await audit(svc, user.id, "target_verified", { hostname: t.hostname, method: "dns_txt", expires_at: expires }, { target_id: t.id });
        return json({ target: data });
      }
      case "remove_target": {
        const { data: t } = await svc.from("pob_targets").select("id, hostname").eq("id", body.target_id).eq("user_id", user.id).maybeSingle();
        if (!t) return errorResponse("Target not found", 404);
        await audit(svc, user.id, "target_removed", { hostname: t.hostname });
        await svc.from("pob_targets").delete().eq("id", t.id);
        return json({ ok: true });
      }
      case "run_quick": {
        if (await isPaused(svc)) return errorResponse("Testing is paused by an administrator (emergency stop).", 503);
        return await runQuick(svc, user.id, String(body.target_id ?? ""));
      }
      case "stop_scan": {
        await svc.from("pob_scans").update({ stop_requested: true }).eq("id", body.scan_id).eq("user_id", user.id).eq("status", "running");
        await audit(svc, user.id, "scan_stop_requested", {}, { scan_id: body.scan_id });
        return json({ ok: true });
      }
      case "analyze": {
        const { data: c } = await svc.from("pob_checks").select("*").eq("id", body.check_id).eq("user_id", user.id).maybeSingle();
        if (!c) return errorResponse("Finding not found", 404);
        if (c.ai_status === "pending") return errorResponse("Analysis already in progress", 409);
        await svc.from("pob_checks").update({ ai_status: "pending", ai_error: null }).eq("id", c.id);
        try {
          const { analysis, model } = await analyzeCheck(c);
          const payload = { ...analysis, model, based_on: { finding_id: c.id, operation: c.operation }, generated_at: new Date().toISOString() };
          await svc.from("pob_checks").update({ ai_status: "ready", ai_analysis: payload }).eq("id", c.id);
          await svc.from("ai_usage").insert({ user_id: user.id, feature: "proof_of_breach", model }).then(() => {}, () => {});
          return json({ ai_status: "ready", ai_analysis: payload });
        } catch (err) {
          console.error("pob ai failed", err);
          await svc.from("pob_checks").update({ ai_status: "failed", ai_error: "The AI analyst is unavailable right now." }).eq("id", c.id);
          return errorResponse("The AI analyst is unavailable right now. Your findings are safe; try again shortly.", 503);
        }
      }
      case "remediation": {
        const step = body.step === "applied" ? "fix_applied_by_user" : body.step === "approve" ? "fix_approved" : null;
        if (!step) return errorResponse("Unknown step", 400);
        const { data: c } = await svc.from("pob_checks").select("id, scan_id, check_key").eq("id", body.check_id).eq("user_id", user.id).maybeSingle();
        if (!c) return errorResponse("Finding not found", 404);
        await svc.from("pob_checks").update({ remediation_status: step }).eq("id", c.id);
        await audit(svc, user.id, step === "fix_approved" ? "fix_plan_approved" : "fix_marked_applied", { check: c.check_key }, { scan_id: c.scan_id });
        return json({ remediation_status: step });
      }
      case "retest":
        return await retest(svc, user.id, String(body.check_id ?? ""));
      case "log_export": {
        const { data: s } = await svc.from("pob_scans").select("id").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!s) return errorResponse("Report not found", 404);
        await audit(svc, user.id, "report_exported", {}, { scan_id: s.id });
        return json({ ok: true });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("proof-of-breach error", err);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
