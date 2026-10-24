import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { resolvePublic, safeFetch } from "../_lib/net.ts";
import { hasElite } from "../_lib/elite.ts";
import { createZap, type ZapApi, ZapError } from "../_lib/zapclient.ts";
import { BASELINE_STATEMENT, buildConfig, INTRUSIVE_STATEMENT, isIntrusive, parseScanMode, parseTargetUrl, type ScanConfig, scopeFor, urlInTargetScope, validateSpec } from "./scope.ts";
import { advanceNative, type EngineDeps, ENGINE_VERSION, launchNative } from "./engine.ts";
import { advance, type Deps, launch, type Patch, type ScanRow } from "./lifecycle.ts";
import type { AlertRow } from "./parse.ts";
import { analyzeAlert } from "./ai.ts";
import { runDiagnostics } from "./diagnostics.ts";

type Svc = ReturnType<typeof getServiceClient>;

const SCANS_PER_HOUR = 6;
const MAX_CONCURRENT = 1;
const STALE_GRACE_MS = 2 * 60_000;
const ZAP_URL = "https://blackveil.blitz.cloud";

const SETUP_STEPS = [
  "Run ZAP in daemon mode on a separate server (Docker: ghcr.io/zaproxy/zaproxy:stable, command zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=<long random key>). Permit only the address of the proxy in front of ZAP, never .*, plus the host name zap, e.g. -config api.addrs.addr(0).name=10\\\\.244\\\\.241\\\\.185 -config api.addrs.addr(0).regex=true -config api.addrs.addr(1).name=zap -config api.addrs.addr(1).regex=false.",
  "Put it behind HTTPS (for example a Cloudflare Tunnel or reverse proxy) and firewall it so only this app can reach the API.",
  "Block the ZAP server from reaching private networks and cloud metadata (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).",
  `Make sure ZAP answers at ${ZAP_URL} and add the secret ZAP_API_KEY (the same key) to this project's server secrets.`,
];

function zapClient(): ZapApi {
  return createZap(ZAP_URL, Deno.env.get("ZAP_API_KEY"));
}

function friendly(err: unknown): string {
  if (err instanceof ZapError) {
    if (err.kind === "unconfigured") return "The ZAP scanning server is not set up yet. An administrator needs to connect it.";
    if (err.kind === "unreachable") return "The ZAP scanning server is offline or unreachable right now.";
    if (err.kind === "auth") return "The ZAP scanning server rejected the app's API key. An administrator needs to update it.";
    return err.message;
  }
  return "The scan engine hit an unexpected error.";
}

async function audit(svc: Svc, userId: string, action: string, detail: Record<string, unknown>, targetId?: string) {
  await svc.from("pob_audit").insert({ user_id: userId, action, detail, target_id: targetId ?? null });
}

async function isPaused(svc: Svc) {
  const { data } = await svc.from("pob_control").select("paused").eq("id", 1).maybeSingle();
  return !!data?.paused;
}

async function loadVerifiedTarget(svc: Svc, userId: string, targetId: string) {
  const { data: t } = await svc.from("pob_targets").select("*").eq("id", targetId).eq("user_id", userId).maybeSingle();
  if (!t) return { error: "Target not found" };
  if (t.status !== "verified") return { error: "This website has not passed ownership verification yet." };
  if (t.expires_at && new Date(t.expires_at) < new Date()) return { error: "Authorization expired. Re-verify ownership to continue testing." };
  return { target: t };
}

async function expireStale(svc: Svc) {
  await svc.from("zap_scans").update({ status: "failed", phase: "done", error: "The scan stopped receiving updates and passed its time limit.", finished_at: new Date().toISOString() })
    .in("status", ["queued", "running"]).lt("deadline_at", new Date(Date.now() - STALE_GRACE_MS).toISOString());
}

async function hasCapacity(svc: Svc) {
  const { count } = await svc.from("zap_scans").select("id", { count: "exact", head: true }).eq("status", "running");
  return (count ?? 0) < MAX_CONCURRENT;
}

function alertSaver(svc: Svc, scan: { id: string; user_id: string }) {
  return async (rows: AlertRow[]) => {
    if (!rows.length) return;
    const { error } = await svc.from("zap_alerts").upsert(rows.map((r) => ({ ...r, scan_id: scan.id, user_id: scan.user_id })), { onConflict: "scan_id,plugin_id" });
    if (error) throw new Error("could not save alerts");
  };
}

const checkDns = async (h: string) => { await resolvePublic(h); };

function deps(svc: Svc, zap: ZapApi, scan: { id: string; user_id: string }, target: Deps["target"], spec?: string): Deps {
  return { zap, target, spec, now: () => Date.now(), checkDns, saveAlerts: alertSaver(svc, scan) };
}

function nativeDeps(svc: Svc, scan: { id: string; user_id: string }, target: Deps["target"], spec?: string): EngineDeps {
  const scope = scopeFor(target);
  return {
    target, spec, now: () => Date.now(), checkDns, saveAlerts: alertSaver(svc, scan),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    fetchPage: (url) => safeFetch(url, scope, { maxBody: 262144 }),
  };
}

const isNative = (scan: { config?: ScanConfig }) => scan.config?.engine === "native";

async function zapReachable(): Promise<boolean> {
  try {
    await zapClient().call("core", "view", "version");
    return true;
  } catch {
    return false;
  }
}

async function save(svc: Svc, scan: ScanRow & { user_id: string; target_id: string; hostname: string }, patch: Patch) {
  if (!Object.keys(patch).length) return scan;
  const { data } = await svc.from("zap_scans").update(patch).eq("id", scan.id).select("*").single();
  if (patch.status && patch.status !== scan.status && ["completed", "failed", "cancelled"].includes(patch.status)) {
    await audit(svc, scan.user_id, `zap_scan_${patch.status}`, { hostname: scan.hostname, mode: scan.mode, counts: patch.counts ?? null, error: patch.error ?? null }, scan.target_id);
  }
  return data ?? { ...scan, ...patch };
}

// deno-lint-ignore no-explicit-any
async function tryLaunch(svc: Svc, scan: any, target: any, spec?: string) {
  try {
    const patch = isNative(scan) ? await launchNative(scan, nativeDeps(svc, scan, target, spec)) : await launch(scan, deps(svc, zapClient(), scan, target, spec));
    return save(svc, scan, patch);
  } catch (err) {
    console.error("zap launch failed", err);
    return save(svc, scan, { status: "failed", phase: "done", error: friendly(err), finished_at: new Date().toISOString() });
  }
}

// deno-lint-ignore no-explicit-any
async function step(svc: Svc, scan: any) {
  const { data: target } = await svc.from("pob_targets").select("*").eq("id", scan.target_id).maybeSingle();
  if (!target) return save(svc, scan, { status: "failed", phase: "done", error: "The target was removed.", finished_at: new Date().toISOString() });
  if (scan.status === "queued") {
    if (scan.cancel_requested || (await isPaused(svc))) return save(svc, scan, { status: "cancelled", phase: "done", finished_at: new Date().toISOString() });
    await expireStale(svc);
    const { data: oldest } = await svc.from("zap_scans").select("id").eq("status", "queued").order("started_at").limit(1).maybeSingle();
    if (oldest?.id !== scan.id || !(await hasCapacity(svc))) return scan;
    return tryLaunch(svc, scan, target);
  }
  if (scan.status !== "running") return scan;
  if (!scan.cancel_requested && (await isPaused(svc))) scan.cancel_requested = true;
  try {
    if (isNative(scan)) return save(svc, scan, await advanceNative(scan, nativeDeps(svc, scan, target)));
    return save(svc, scan, await advance(scan, deps(svc, zapClient(), scan, target)));
  } catch (err) {
    console.error("zap advance failed", err);
    return save(svc, scan, { error: `${friendly(err)} Retrying automatically until the time limit.` });
  }
}

async function startScan(svc: Svc, userId: string, body: Record<string, unknown>) {
  if (await isPaused(svc)) return errorResponse("Testing is paused by an administrator (emergency stop).", 503);
  const mode = parseScanMode(body.mode);
  if (!mode) return errorResponse("Choose a scan mode.", 400);
  const { target, error } = await loadVerifiedTarget(svc, userId, String(body.target_id ?? ""));
  if (!target) return errorResponse(error!, 403);
  const parsed = parseTargetUrl(body.target_url, target);
  if ("error" in parsed) return errorResponse(parsed.error, 400);
  if (body.authorized !== true) return errorResponse("Confirm that you are authorized to test this website.", 400);
  const intrusive = isIntrusive(mode);
  if (intrusive && body.intrusive_ack !== true) return errorResponse("Intrusive scans need explicit confirmation.", 400);
  if (intrusive && target.environment === "production" && String(body.confirm_hostname ?? "").trim().toLowerCase() !== target.hostname) {
    return errorResponse(`This is a production website. Type ${target.hostname} to confirm the intrusive scan.`, 400);
  }

  let openapi: ScanConfig["openapi"] = null;
  let spec: string | undefined;
  if (mode === "api") {
    if (typeof body.openapi_url === "string" && body.openapi_url.trim()) {
      const u = body.openapi_url.trim();
      if (!urlInTargetScope(u, target)) return errorResponse(`The OpenAPI address must be on ${target.hostname} inside the allowed paths.`, 400);
      openapi = { source: "url", url: u };
    } else {
      const v = validateSpec(body.openapi_spec);
      if ("error" in v) return errorResponse(v.error, 400);
      spec = v.spec;
      openapi = { source: "upload", bytes: spec.length };
    }
  }

  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("zap_scans").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("started_at", since);
  if ((count ?? 0) >= SCANS_PER_HOUR) return errorResponse(`Limit reached: ${SCANS_PER_HOUR} ZAP scans per hour.`, 429);

  const engine = (await zapReachable()) ? "zap" : "native";
  await expireStale(svc);
  const free = await hasCapacity(svc);
  if (!free && spec) return errorResponse("The scanner is busy. Uploaded API files can only start when it is free; try again in a few minutes, or use a hosted OpenAPI address.", 409);

  const config = { ...buildConfig(mode, openapi), engine } as ScanConfig;
  const { data: scan, error: insErr } = await svc.from("zap_scans").insert({
    user_id: userId, target_id: target.id, hostname: target.hostname, target_url: parsed.url, mode, config,
    authorization_statement: intrusive ? INTRUSIVE_STATEMENT : BASELINE_STATEMENT,
    deadline_at: new Date(Date.now() + config.max_minutes * 60_000).toISOString(),
  }).select("*").single();
  if (insErr || !scan) return errorResponse(insErr?.code === "23505" ? "You already have a ZAP scan queued or running. Wait for it to finish or cancel it." : "Could not create the scan.", 409);
  await audit(svc, userId, "zap_scan_requested", { hostname: target.hostname, mode, url: parsed.url, statement: scan.authorization_statement }, target.id);

  const result = free ? await tryLaunch(svc, scan, target, spec) : scan;
  return json({ scan: result });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "POST") return errorResponse("Method not allowed", 405);
    const { user } = await getAuthenticatedUser(req);
    if (!user) return errorResponse("Unauthorized", 401);
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const svc = getServiceClient();
    if (!(await hasElite(svc, user.id, admin))) return errorResponse("ZAP scanning is included with the Elite plan.", 402);
    const body = await req.json().catch(() => ({}));

    switch (String(body.action ?? "")) {
      case "diagnostics": {
        if (!admin) return errorResponse("Administrators only.", 403);
        return json(await runDiagnostics(ZAP_URL, Deno.env.get("ZAP_API_KEY")));
      }
      case "health": {
        try {
          const v = await zapClient().call("core", "view", "version");
          return json({ configured: true, reachable: true, engine: "zap", version: String(v.version ?? "unknown") });
        } catch (err) {
          const kind = err instanceof ZapError ? err.kind : "api";
          return json({ configured: kind !== "unconfigured", reachable: true, engine: "native", version: ENGINE_VERSION, kind, message: friendly(err), setup: SETUP_STEPS });
        }
      }
      case "start":
        return await startScan(svc, user.id, body);
      case "poll": {
        const { data: scan } = await svc.from("zap_scans").select("*").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!scan) return errorResponse("Scan not found", 404);
        return json({ scan: await step(svc, scan) });
      }
      case "cancel": {
        const { data: scan } = await svc.from("zap_scans").update({ cancel_requested: true }).eq("id", body.scan_id).eq("user_id", user.id)
          .in("status", ["queued", "running"]).select("*").maybeSingle();
        if (!scan) return errorResponse("No active scan to cancel", 404);
        await audit(svc, user.id, "zap_scan_cancel_requested", { hostname: scan.hostname }, scan.target_id);
        return json({ scan: await step(svc, scan) });
      }
      case "analyze": {
        const { data: a } = await svc.from("zap_alerts").select("*").eq("id", body.alert_id).eq("user_id", user.id).maybeSingle();
        if (!a) return errorResponse("Finding not found", 404);
        if (a.ai_status === "pending") return errorResponse("Analysis already in progress", 409);
        await svc.from("zap_alerts").update({ ai_status: "pending", ai_error: null }).eq("id", a.id);
        try {
          const { analysis, model } = await analyzeAlert(a);
          const payload = { ...analysis, model, generated_at: new Date().toISOString() };
          await svc.from("zap_alerts").update({ ai_status: "ready", ai_analysis: payload }).eq("id", a.id);
          await svc.from("ai_usage").insert({ user_id: user.id, feature: "zap_analyst", model }).then(() => {}, () => {});
          return json({ ai_status: "ready", ai_analysis: payload });
        } catch (err) {
          console.error("zap ai failed", err);
          await svc.from("zap_alerts").update({ ai_status: "failed", ai_error: "The AI analyst is unavailable right now." }).eq("id", a.id);
          return errorResponse("The AI analyst is unavailable right now. Your findings are safe; try again shortly.", 503);
        }
      }
      case "log_export": {
        const { data: s } = await svc.from("zap_scans").select("id, hostname, target_id").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!s) return errorResponse("Report not found", 404);
        await audit(svc, user.id, "zap_report_exported", { hostname: s.hostname }, s.target_id);
        return json({ ok: true });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("zap-scanner error", err);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
