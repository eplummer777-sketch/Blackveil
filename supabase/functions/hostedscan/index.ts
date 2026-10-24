import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { isBlockedIp } from "../_lib/net.ts";
import { authorizeTarget, parseTarget } from "../_lib/nmap.ts";
import { hs, HsError, HsRisk, HsScan, isConfigured } from "./client.ts";

type Svc = ReturnType<typeof getServiceClient>;

const SCANS_PER_HOUR = 5;
const SCANS_PER_DAY = 20;
const MAX_RISKS = 60;
const MIN_REFRESH_MS = 5_000;
const TYPES = ["NMAP", "NMAP_UDP"] as const;
const ACTIVE = ["queued", "running", "stopping"];
const STATEMENT = "I confirm I own or am explicitly authorized in writing to scan this target, and I accept responsibility for this cloud scan run by HostedScan.";

const mapState = (s: string) => {
  const v = String(s ?? "").toLowerCase();
  return ["queued", "running", "stopping", "succeeded", "failed", "stopped", "over_limit"].includes(v) ? v : "running";
};

const clip = (v: unknown, n: number) => (typeof v === "string" ? v.slice(0, n) : "");

async function audit(svc: Svc, userId: string, actor: string, action: string, detail: Record<string, unknown>) {
  await svc.from("nmap_audit").insert({ user_id: userId, actor, action, detail: { source: "hostedscan", ...detail } });
}

async function hasElite(svc: Svc, userId: string, admin: boolean) {
  if (admin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && data.plan === "elite" && (data.status === "active" || data.status === "trialing");
}

async function isPaused(svc: Svc) {
  const { data } = await svc.from("pob_control").select("paused").eq("id", 1).maybeSingle();
  return !!data?.paused;
}

async function resolveA(host: string): Promise<string[]> {
  try {
    return await Deno.resolveDns(host, "A");
  } catch {
    return [];
  }
}

function sanitizeRisk(r: HsRisk) {
  const d = r.risk_definition ?? {};
  const info: Record<string, string> = {};
  for (const [k, v] of Object.entries(d.additional_info ?? {}).slice(0, 12)) {
    if (["string", "number", "boolean"].includes(typeof v)) info[k.slice(0, 40)] = String(v).slice(0, 300);
  }
  return {
    id: clip(r.id, 64), title: clip(d.title, 200) || "Untitled finding", threat_level: clip(d.threat_level, 12) || "LOW",
    cvss: typeof d.cvss === "string" ? d.cvss.slice(0, 8) : null, status: clip(r.status, 12), target: clip(r.target, 253),
    description: clip(d.description, 2000), solution: clip(d.solution, 2000),
    references: (Array.isArray(d.references) ? d.references : []).filter((x) => typeof x === "string" && /^https?:\/\//.test(x)).slice(0, 5).map((x) => x.slice(0, 300)),
    details: info,
  };
}

async function fetchRisks(scan: HsScan) {
  const ids = [...(scan.risks?.new_open ?? []), ...(scan.risks?.still_open ?? [])]
    .map((r) => r.risk_id).filter((x): x is string => typeof x === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(x));
  const unique = [...new Set(ids)].slice(0, MAX_RISKS);
  const out = [];
  for (let i = 0; i < unique.length; i += 6) {
    const batch = await Promise.all(unique.slice(i, i + 6).map((id) => hs<{ data: HsRisk }>(`/risks/${encodeURIComponent(id)}`).then((r) => r.data, () => null)));
    for (const r of batch) if (r?.id) out.push(sanitizeRisk(r));
  }
  return { risks: out, truncated: ids.length > MAX_RISKS };
}

async function startScan(svc: Svc, userId: string, body: Record<string, unknown>) {
  if (!isConfigured()) return errorResponse("HostedScan is not connected yet. An administrator needs to add the API key.", 503);
  if (await isPaused(svc)) return errorResponse("Testing is paused by an administrator (emergency stop).", 503);
  const type = TYPES.find((t) => t === body.scan_type);
  if (!type) return errorResponse("Choose a scan type.", 400);
  if (body.authorized !== true) return errorResponse("Confirm that you are authorized to scan this target.", 400);

  const parsed = parseTarget(body.target);
  if ("error" in parsed) return errorResponse(parsed.error, 400);
  if (parsed.kind === "cidr") return errorResponse("HostedScan accepts a single public IPv4 address or hostname, not a range.", 400);

  const [{ data: verified }, { data: scopes }] = await Promise.all([
    svc.from("pob_targets").select("id, hostname, expires_at").eq("user_id", userId).eq("status", "verified"),
    svc.from("nmap_scopes").select("id, cidr").eq("user_id", userId).is("revoked_at", null),
  ]);
  const verifiedHosts = (verified ?? []).filter((t) => !t.expires_at || new Date(t.expires_at) > new Date());
  const resolved = parsed.kind === "hostname" ? await resolveA(parsed.value) : [];
  const auth = authorizeTarget(parsed, { resolved, verifiedHosts, scopes: scopes ?? [] });
  if ("error" in auth) {
    await audit(svc, userId, "user", "cloud_scan_rejected", { target: parsed.value, reason: auth.error });
    return errorResponse(auth.error, 403);
  }
  if (auth.targets.some((ip) => isBlockedIp(ip))) {
    return errorResponse("HostedScan scans from the internet, so it can only reach public addresses. Use the on-premise scanner for private or lab ranges.", 400);
  }

  const now = Date.now();
  const [{ count: hour }, { count: day }] = await Promise.all([
    svc.from("hostedscan_scans").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("created_at", new Date(now - 3600_000).toISOString()),
    svc.from("hostedscan_scans").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("created_at", new Date(now - 86400_000).toISOString()),
  ]);
  if ((hour ?? 0) >= SCANS_PER_HOUR) return errorResponse(`Limit reached: ${SCANS_PER_HOUR} cloud scans per hour.`, 429);
  if ((day ?? 0) >= SCANS_PER_DAY) return errorResponse(`Limit reached: ${SCANS_PER_DAY} cloud scans per day.`, 429);

  const { data: row, error } = await svc.from("hostedscan_scans").insert({
    user_id: userId, scan_type: type, target: parsed.value, auth_basis: auth.basis,
    pob_target_id: auth.pob_target_id, scope_id: auth.scope_id, authorization_statement: STATEMENT,
  }).select("*").single();
  if (error || !row) return errorResponse(error?.code === "23505" ? "You already have a cloud scan in progress." : "Could not create the scan.", 409);

  try {
    const { data } = await hs<{ data: HsScan }>("/scans", { method: "POST", body: { type, targets: [parsed.value] } });
    if (!data?.id) throw new HsError(502, "HostedScan did not return a scan id.");
    const { data: scan } = await svc.from("hostedscan_scans").update({
      hs_scan_id: data.id, status: mapState(data.state), progress: Number(data.progress) || 0, updated_at: new Date().toISOString(),
    }).eq("id", row.id).select("*").single();
    await audit(svc, userId, "user", "cloud_scan_started", { target: parsed.value, type, basis: auth.basis, hs_scan_id: data.id, row_id: row.id });
    return json({ scan });
  } catch (err) {
    const msg = err instanceof HsError ? err.message : "Could not start the scan on HostedScan.";
    await svc.from("hostedscan_scans").update({ status: "failed", error: msg, finished_at: new Date().toISOString() }).eq("id", row.id);
    await audit(svc, userId, "system", "cloud_scan_start_failed", { target: parsed.value, type, error: msg, row_id: row.id });
    return errorResponse(msg, err instanceof HsError && err.status < 500 ? 400 : 502);
  }
}

async function refresh(svc: Svc, row: Record<string, unknown>) {
  if (!ACTIVE.includes(String(row.status))) return row;
  if (!row.hs_scan_id) {
    if (Date.now() - new Date(String(row.created_at)).getTime() < 120_000) return row;
    const { data } = await svc.from("hostedscan_scans").update({ status: "failed", error: "The scan never started on HostedScan.", finished_at: new Date().toISOString() }).eq("id", row.id).select("*").maybeSingle();
    return data ?? row;
  }
  if (Date.now() - new Date(String(row.updated_at)).getTime() < MIN_REFRESH_MS) return row;
  const { data } = await hs<{ data: HsScan }>(`/scans/${encodeURIComponent(String(row.hs_scan_id))}`);
  const status = mapState(data.state);
  const patch: Record<string, unknown> = {
    status, progress: Math.min(100, Math.max(0, Number(data.progress) || 0)), updated_at: new Date().toISOString(),
    skipped: (data.skipped_targets ?? []).slice(0, 10).map((s) => ({ reason: clip(s.skipped_reason, 300) })),
  };
  if (!ACTIVE.includes(status)) {
    patch.finished_at = new Date().toISOString();
    if (status === "succeeded") {
      const { risks, truncated } = await fetchRisks(data);
      patch.risks = risks;
      if (truncated) patch.error = `Showing the first ${MAX_RISKS} findings. View the rest in your HostedScan dashboard.`;
    }
    if (status === "failed") patch.error = "HostedScan could not complete this scan (for example, the target could not be resolved or reached).";
    if (status === "over_limit") patch.error = "The connected HostedScan account has reached its plan limits, so this scan did not run.";
  }
  const { data: updated } = await svc.from("hostedscan_scans").update(patch).eq("id", row.id).in("status", ACTIVE).select("*").maybeSingle();
  return updated ?? row;
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

    if (action === "status") return json({ elite: await hasElite(svc, user.id, admin), admin, configured: isConfigured() });

    if (action === "test") {
      if (!admin) return errorResponse("Administrators only.", 403);
      if (!isConfigured()) return json({ ok: false, configured: false, message: "The HOSTEDSCAN_API_KEY secret has not been added yet." });
      const t0 = Date.now();
      try {
        const r = await hs<{ data: unknown[] }>("/scans?page_size=1");
        if (!Array.isArray(r.data)) throw new HsError(502, "HostedScan returned an unexpected response.");
        await audit(svc, user.id, "admin", "cloud_connection_test", { ok: true });
        return json({ ok: true, configured: true, latency_ms: Date.now() - t0, message: "Connected to HostedScan. The API key was accepted." });
      } catch (err) {
        const message = err instanceof HsError ? err.message : "Connection test failed.";
        await audit(svc, user.id, "admin", "cloud_connection_test", { ok: false, error: message });
        return json({ ok: false, configured: true, message });
      }
    }

    if (!(await hasElite(svc, user.id, admin))) return errorResponse("Cloud scanning is included with the Elite plan.", 402);

    switch (action) {
      case "start":
        return await startScan(svc, user.id, body);
      case "poll": {
        const { data: row } = await svc.from("hostedscan_scans").select("*").eq("id", String(body.scan_id ?? "")).eq("user_id", user.id).maybeSingle();
        if (!row) return errorResponse("Scan not found", 404);
        try {
          return json({ scan: await refresh(svc, row) });
        } catch (err) {
          if (err instanceof HsError) return json({ scan: row, warning: err.message });
          throw err;
        }
      }
      case "cancel": {
        const { data: row } = await svc.from("hostedscan_scans").select("*").eq("id", String(body.scan_id ?? "")).eq("user_id", user.id).in("status", ["queued", "running"]).maybeSingle();
        if (!row) return errorResponse("No active scan to stop", 404);
        if (row.hs_scan_id) {
          try {
            const { data } = await hs<{ data: HsScan }>(`/scans/${encodeURIComponent(row.hs_scan_id)}/stop`, { method: "POST" });
            const status = mapState(data?.state ?? "STOPPING");
            const { data: scan } = await svc.from("hostedscan_scans").update({ status, updated_at: new Date().toISOString(), ...(ACTIVE.includes(status) ? {} : { finished_at: new Date().toISOString() }) }).eq("id", row.id).select("*").single();
            await audit(svc, user.id, "user", "cloud_scan_stop_requested", { hs_scan_id: row.hs_scan_id, row_id: row.id });
            return json({ scan });
          } catch (err) {
            if (err instanceof HsError) return errorResponse(err.message, 502);
            throw err;
          }
        }
        const { data: scan } = await svc.from("hostedscan_scans").update({ status: "stopped", finished_at: new Date().toISOString() }).eq("id", row.id).select("*").single();
        return json({ scan });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("hostedscan function error", err instanceof Error ? err.name : "unknown");
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
