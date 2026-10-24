import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { quotaMessage, resolveQuota } from "../_lib/ai-quota.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RETURN_COLS = "id, message_id, kind, summary, status, result, created_at, expires_at";

type Svc = ReturnType<typeof getServiceClient>;

async function callFn(req: Request, name: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const resp = await fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/${name}`, {
    method: "POST",
    headers: {
      Authorization: req.headers.get("Authorization") ?? "",
      apikey: Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({})) as Record<string, unknown>;
  if (!resp.ok) {
    const msg = typeof data.error === "string" ? data.error : typeof data.message === "string" ? data.message : "";
    throw new Error(msg || `The request could not be completed (${resp.status}).`);
  }
  return data;
}

async function execute(
  req: Request, svc: Svc, userId: string, kind: string, p: Record<string, unknown>,
): Promise<{ message: string; detail?: Record<string, unknown> }> {
  switch (kind) {
    case "scan_device":
      await callFn(req, "endpoint-control", { action: "scan", deviceId: p.device_id, scanType: p.scan_type });
      return { message: "Scan started. Results will appear on the Devices page as soon as the device reports back." };
    case "remove_threats":
      await callFn(req, "endpoint-control", {
        action: "approve_remediation", deviceId: p.device_id, threatIds: p.threat_ids, acknowledged: true,
      });
      return { message: "Removal approved. The device will quarantine the threats and you can restore them from the Devices page if needed." };
    case "verify_device":
      await callFn(req, "endpoint-control", { action: "verify", deviceId: p.device_id });
      return { message: "Verification started. The device's status will update on the Devices page shortly." };
    case "set_scan_schedule": {
      const { data: dev } = await svc.from("endpoint_devices").select("allowed_scopes, allowed_paths")
        .eq("id", p.device_id as string).eq("user_id", userId).is("revoked_at", null).maybeSingle();
      if (!dev) throw new Error("That device is no longer available.");
      await callFn(req, "endpoint-control", {
        action: "update_scope", deviceId: p.device_id, scopes: dev.allowed_scopes, paths: dev.allowed_paths, schedule: p.schedule,
      });
      return { message: p.schedule === "off" ? "Automatic scans turned off." : `Automatic ${p.schedule} scans are now on.` };
    }
    case "scan_link": {
      const r = await callFn(req, "link-scanner", { input: p.url, scan_type: "url" });
      const verdict = String(r.verdict ?? "unknown").replace(/_/g, " ");
      return { message: `Verdict: ${verdict} (risk score ${Number(r.risk_score ?? 0)}/100). Full details are in your scan history.`, detail: { verdict: r.verdict, risk_score: r.risk_score } };
    }
    case "assess_website": {
      const r = await callFn(req, "website-assessment", { target: p.domain, authorization_confirmed: true });
      if (r.status === "failed") throw new Error("The assessment could not finish. Please try again later.");
      const findings = Array.isArray(r.findings) ? r.findings.length : 0;
      const overall = typeof r.overall_status === "string" ? r.overall_status.replace(/_/g, " ") : "complete";
      return { message: `Assessment finished: ${overall}, ${findings} finding${findings === 1 ? "" : "s"}. See the full report on the Assessments page.`, detail: { assessmentId: r.assessmentId } };
    }
    case "apply_cloudflare_fix": {
      const { data: prop } = await svc.from("architect_cf_proposals").select("status, risk_level")
        .eq("id", p.proposal_id as string).eq("user_id", userId).maybeSingle();
      if (!prop || prop.risk_level === "high" || !["proposed", "approved"].includes(prop.status)) {
        throw new Error("This Cloudflare change is no longer available to apply.");
      }
      if (prop.status === "proposed") {
        await callFn(req, "cloudflare-architect", { action: "approve", proposal_id: p.proposal_id, acknowledged_risks: true });
      }
      await callFn(req, "cloudflare-architect", { action: "apply", proposal_id: p.proposal_id, confirmed: true });
      return { message: "Protection applied to your live Cloudflare zone. You can verify or roll it back from the Architect page." };
    }
    case "pob_quick_scan":
    case "pentest_scan":
    case "network_scan": {
      const { data: t } = await svc.from("pob_targets").select("id, hostname")
        .eq("id", p.target_id as string).eq("user_id", userId).eq("status", "verified").maybeSingle();
      if (!t) throw new Error("That target is no longer verified. Re-verify it on the Proof-of-Breach AI page.");
      if (kind === "pob_quick_scan") {
        await callFn(req, "proof-of-breach", { action: "run_quick", target_id: t.id });
        return { message: `Proof-of-Breach test started on ${t.hostname}. Follow progress on the Proof-of-Breach AI page.`, detail: { page: "proof-of-breach" } };
      }
      if (kind === "pentest_scan") {
        await callFn(req, "pentest-engine", { action: "start", target_id: t.id, target_url: `https://${t.hostname}`, mode: p.mode, authorized: true });
        return { message: `Penetration test started on ${t.hostname}. Follow progress on the Penetration Test page.`, detail: { page: "pentest" } };
      }
      await callFn(req, "network-scanner", { action: "start", target: t.hostname, profile: p.profile, authorized: true });
      return { message: `Network scan started on ${t.hostname}. Follow progress on the Network Scan page.`, detail: { page: "network-scan" } };
    }
    case "send_report_now":
      await callFn(req, "monitoring", { action: "report_now" });
      return { message: "Your security report is on its way to your email." };
    case "open_page":
      return { message: "Opening the page.", detail: { page: p.page } };
    default:
      throw new Error("Unsupported action.");
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user, error } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(error ?? "Unauthorized", 401);

    const body = await req.json().catch(() => null) as { actionId?: unknown; decision?: unknown; confirmed?: unknown } | null;
    if (!body || typeof body.actionId !== "string" || !UUID.test(body.actionId)) return errorResponse("Invalid action", 400);
    if (body.decision !== "confirm" && body.decision !== "reject") return errorResponse("Invalid decision", 400);

    const svc = getServiceClient();
    const { data: action } = await svc.from("assistant_actions").select("id, kind, params, status, expires_at")
      .eq("id", body.actionId).eq("user_id", user.id).maybeSingle();
    if (!action) return errorResponse("Action not found", 404);
    if (action.status !== "pending") return errorResponse("This action was already handled.", 409);

    const now = new Date().toISOString();
    if (new Date(action.expires_at).getTime() < Date.now()) {
      await svc.from("assistant_actions").update({ status: "expired", decided_at: now }).eq("id", action.id).eq("status", "pending");
      return errorResponse("This action expired. Ask the assistant again to get a fresh one.", 410);
    }

    if (body.decision === "reject") {
      const { data } = await svc.from("assistant_actions").update({ status: "rejected", decided_at: now })
        .eq("id", action.id).eq("status", "pending").select(RETURN_COLS).maybeSingle();
      return json({ action: data });
    }

    if (body.confirmed !== true) return errorResponse("Please confirm this action before it runs.", 400);

    const q = await resolveQuota(svc, user);
    const free = action.kind === "open_page";
    if (!free && q.limit > 0 && q.remaining <= 0) return json({ error: "quota_reached", message: quotaMessage(q) }, 429);

    const { data: claimed } = await svc.from("assistant_actions").update({ status: "running", decided_at: now })
      .eq("id", action.id).eq("status", "pending").gt("expires_at", now).select("id").maybeSingle();
    if (!claimed) return errorResponse("This action was already handled.", 409);

    let status: "succeeded" | "failed";
    let result: Record<string, unknown>;
    try {
      const out = await execute(req, svc, user.id, action.kind, action.params as Record<string, unknown>);
      status = "succeeded";
      result = { message: out.message, ...(out.detail ?? {}) };
    } catch (err) {
      status = "failed";
      result = { message: err instanceof Error ? err.message : "The action failed." };
    }

    const { data: updated } = await svc.from("assistant_actions").update({ status, result })
      .eq("id", action.id).select(RETURN_COLS).single();

    const charged = status === "succeeded" && !free;
    if (charged) {
      await svc.from("ai_usage").insert({
        user_id: user.id, feature: "assistant", model: "action", input_tokens: 0, output_tokens: 0, cost_usd: 0,
      });
    }
    await svc.from("audit_logs").insert({
      user_id: user.id,
      action: "ai_assistant_action",
      detail: { action_id: action.id, kind: action.kind, status },
    });

    const remaining = q.remaining === -1 ? -1 : Math.max(0, q.remaining - (charged ? 1 : 0));
    return json({ action: updated, remaining, limit: q.limit, plan: q.plan, window: q.window });
  } catch (err) {
    return errorResponse(err instanceof Error ? err.message : "Unexpected error", 500);
  }
});
