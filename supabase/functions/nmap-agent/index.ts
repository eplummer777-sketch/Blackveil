import { getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { addressInTargets, cidrRange, hitsAlwaysBlocked, MAX_XML_BYTES, parseNmapXml, PROFILES, summarize } from "../_lib/nmap.ts";

type Svc = ReturnType<typeof getServiceClient>;
type Agent = { id: string; name: string };
type ScanRow = { id: string; user_id: string; started_at: string; targets: string[]; cancel_requested: boolean };

async function sha256(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function authAgent(svc: Svc, req: Request): Promise<Agent | null> {
  const token = req.headers.get("x-agent-token") ?? "";
  if (!/^bvna_[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const { data } = await svc.from("nmap_agents").select("id, name").eq("token_hash", await sha256(token)).eq("revoked", false).maybeSingle();
  return data;
}

// eslint-disable-next-line no-control-regex
const clip = (v: unknown, n: number) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);

async function audit(svc: Svc, userId: string, action: string, detail: Record<string, unknown>, scanId: string) {
  await svc.from("nmap_audit").insert({ user_id: userId, actor: "agent", action, detail, scan_id: scanId });
}

async function ownScan(svc: Svc, agent: Agent, id: unknown) {
  const { data } = await svc.from("nmap_scans").select("*").eq("id", String(id ?? "")).eq("agent_id", agent.id).eq("status", "running").maybeSingle();
  return data as ScanRow | null;
}

async function finish(svc: Svc, scan: ScanRow, agent: Agent, patch: Record<string, unknown>) {
  const finished = new Date();
  const full = { ...patch, finished_at: finished.toISOString(), duration_ms: finished.getTime() - new Date(scan.started_at).getTime() };
  await svc.from("nmap_scans").update(full).eq("id", scan.id).eq("status", "running");
  await audit(svc, scan.user_id, `scan_${patch.status}`, { agent: agent.name, error: patch.error ?? null, summary: patch.summary ?? null }, scan.id);
}

async function complete(svc: Svc, agent: Agent, scan: ScanRow, body: Record<string, unknown>) {
  if (typeof body.xml !== "string" || body.xml.length > MAX_XML_BYTES) {
    return finish(svc, scan, agent, { status: "failed", error: "The scanner agent returned no usable Nmap output." });
  }
  let run;
  try {
    run = parseNmapXml(body.xml);
  } catch (err) {
    return finish(svc, scan, agent, { status: "failed", error: `Could not read Nmap results: ${err instanceof Error ? err.message : "parse error"}` });
  }
  const inScope = run.hosts.filter((h) => addressInTargets(h.address, scan.targets));
  const dropped = run.hosts.length - inScope.length;
  if (inScope.length) {
    const { error } = await svc.from("nmap_hosts").upsert(inScope.map((h) => ({
      scan_id: scan.id, user_id: scan.user_id, address: h.address, hostnames: h.hostnames, state: h.state, reason: h.reason, ports: h.ports, extraports: h.extraports,
    })), { onConflict: "scan_id,address" });
    if (error) return finish(svc, scan, agent, { status: "failed", error: "Could not save the scan results." });
  }
  const summary = { ...summarize(inScope, run), out_of_scope_dropped: dropped };
  const exitCode = Number(body.exit_code);
  const nmapError = run.exit === "error" || exitCode !== 0;
  const { data: fresh } = await svc.from("nmap_scans").select("cancel_requested").eq("id", scan.id).maybeSingle();
  const status = fresh?.cancel_requested ? "cancelled" : nmapError ? "failed" : "completed";
  const error = nmapError ? clip(run.errormsg || body.stderr || `Nmap exited with code ${exitCode}.`, 400) : null;
  return finish(svc, scan, agent, { status, summary, error, nmap_version: clip(run.version, 32) || null });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "POST") return errorResponse("Method not allowed", 405);
    const svc = getServiceClient();
    const agent = await authAgent(svc, req);
    if (!agent) return errorResponse("Unauthorized", 401);
    const body = await req.json().catch(() => ({}));

    switch (String(body.action ?? "")) {
      case "heartbeat": {
        const h = body.health ?? {};
        await svc.from("nmap_agents").update({
          last_seen_at: new Date().toISOString(),
          nmap_available: h.nmap_available === true,
          nmap_version: h.nmap_version ? clip(h.nmap_version, 32) : null,
          privileged: h.privileged === true,
          raw_capable: h.raw_capable === true,
          health: { message: clip(h.message, 300), agent_version: clip(h.agent_version, 16), platform: clip(h.platform, 40), checked_at: new Date().toISOString() },
        }).eq("id", agent.id);
        return json({ ok: true });
      }
      case "claim": {
        const { data: ag } = await svc.from("nmap_agents").select("raw_capable, nmap_available").eq("id", agent.id).single();
        if (!ag?.nmap_available) return json({ scan: null });
        const { data, error } = await svc.rpc("nmap_claim_scan", { p_agent: agent.id, p_raw_ok: ag.raw_capable });
        if (error) throw error;
        const scan = Array.isArray(data) ? data[0] : null;
        if (!scan) return json({ scan: null });
        const profile = PROFILES[scan.profile as keyof typeof PROFILES];
        const unsafe = !profile || scan.targets.some((t: string) => { const r = cidrRange(t); return !r || hitsAlwaysBlocked(r); });
        if (unsafe) {
          await finish(svc, scan, agent, { status: "failed", error: "The scan failed a safety re-check and was not run." });
          return json({ scan: null });
        }
        await audit(svc, scan.user_id, "scan_started", { agent: agent.name }, scan.id);
        return json({ scan: { id: scan.id, profile: scan.profile, args: profile.args, targets: scan.targets, timeout_seconds: scan.timeout_seconds } });
      }
      case "progress": {
        const scan = await ownScan(svc, agent, body.scan_id);
        if (!scan) return json({ cancel: true });
        await svc.from("nmap_scans").update({ heartbeat_at: new Date().toISOString() }).eq("id", scan.id);
        return json({ cancel: scan.cancel_requested });
      }
      case "complete": {
        const scan = await ownScan(svc, agent, body.scan_id);
        if (!scan) return errorResponse("Scan not found", 404);
        await complete(svc, agent, scan, body);
        return json({ ok: true });
      }
      case "fail": {
        const scan = await ownScan(svc, agent, body.scan_id);
        if (!scan) return errorResponse("Scan not found", 404);
        const cancelled = body.cancelled === true && scan.cancel_requested;
        await finish(svc, scan, agent, cancelled
          ? { status: "cancelled" }
          : { status: "failed", error: clip(body.error || "The scanner agent reported a failure.", 400) });
        return json({ ok: true });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("nmap-agent error", err);
    return errorResponse("Something went wrong.", 500);
  }
});
