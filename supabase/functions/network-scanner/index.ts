import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { authorizeTarget, hitsAlwaysBlocked, cidrRange, normalizeCidr, parseProfile, parseTarget, PROFILES } from "../_lib/nmap.ts";
import { analyzeScan } from "./ai.ts";
import { audit, driveNative, expireNative, finalize, inBackground, stepNative, type Svc } from "./jobs.ts";
import { expandTargets, initialState, isNativeProfile, NATIVE_PROFILES, NATIVE_VERSION, type NativeProfile } from "./native.ts";

const NATIVE_GLOBAL_CONCURRENCY = 6;

const SCANS_PER_HOUR = 10;
const ONLINE_MS = 90_000;
const HEARTBEAT_GRACE_MS = 3 * 60_000;
const QUEUE_LIMIT_MS = 30 * 60_000;
const STATEMENT = "I confirm I own or am explicitly authorized in writing to scan this network target, and I accept responsibility for this scan.";

async function hasElite(svc: Svc, userId: string, admin: boolean) {
  if (admin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && data.plan === "elite" && (data.status === "active" || data.status === "trialing");
}

async function isPaused(svc: Svc) {
  const { data } = await svc.from("pob_control").select("paused").eq("id", 1).maybeSingle();
  return !!data?.paused;
}

const isOnline = (a: { last_seen_at: string | null; revoked: boolean }) =>
  !a.revoked && !!a.last_seen_at && Date.now() - new Date(a.last_seen_at).getTime() < ONLINE_MS;

async function loadAgents(svc: Svc) {
  const { data } = await svc.from("nmap_agents").select("id, name, revoked, last_seen_at, nmap_version, nmap_available, privileged, raw_capable, health, created_at").order("created_at");
  return (data ?? []).map((a) => ({ ...a, online: isOnline(a) }));
}

async function expireStale(svc: Svc) {
  const { data } = await svc.from("nmap_scans").select("id, user_id, status, created_at, started_at, heartbeat_at, timeout_seconds").neq("engine", "native").in("status", ["queued", "running"]);
  const now = Date.now();
  for (const s of data ?? []) {
    let error = "";
    if (s.status === "queued" && now - new Date(s.created_at).getTime() > QUEUE_LIMIT_MS) error = "No scanner agent picked up this scan within 30 minutes.";
    if (s.status === "running") {
      const hb = new Date(s.heartbeat_at ?? s.started_at).getTime();
      const deadline = new Date(s.started_at).getTime() + (s.timeout_seconds + 120) * 1000;
      if (now - hb > HEARTBEAT_GRACE_MS) error = "The scanner agent stopped reporting progress.";
      else if (now > deadline) error = "The scan passed its time limit.";
    }
    if (!error) continue;
    const { data: upd } = await svc.from("nmap_scans").update({ status: "failed", error, finished_at: new Date().toISOString() })
      .eq("id", s.id).in("status", ["queued", "running"]).select("id").maybeSingle();
    if (upd) await audit(svc, s.user_id, "system", "scan_expired", { error }, s.id);
  }
  await expireNative(svc);
}

async function resolveA(host: string): Promise<string[]> {
  try {
    return await Deno.resolveDns(host, "A");
  } catch {
    return [];
  }
}

async function startScan(svc: Svc, userId: string, body: Record<string, unknown>) {
  if (await isPaused(svc)) return errorResponse("Testing is paused by an administrator (emergency stop).", 503);
  if (!isNativeProfile(body.profile)) return errorResponse("Choose Quick or Standard discovery. Nmap scanning has been replaced by the Blackveil Discovery Engine.", 400);
  const native = true;
  const profile = native ? body.profile as NativeProfile : parseProfile(body.profile);
  if (!profile) return errorResponse("Choose a scan profile.", 400);
  if (body.authorized !== true) return errorResponse("Confirm that you are authorized to scan this target.", 400);
  const parsed = parseTarget(body.target);
  if ("error" in parsed) {
    await audit(svc, userId, "user", "scan_rejected", { target: String(body.target ?? "").slice(0, 100), reason: parsed.error });
    return errorResponse(parsed.error, 400);
  }

  const [{ data: verified }, { data: scopes }] = await Promise.all([
    svc.from("pob_targets").select("id, hostname, expires_at").eq("user_id", userId).eq("status", "verified"),
    svc.from("nmap_scopes").select("id, cidr").eq("user_id", userId).is("revoked_at", null),
  ]);
  const verifiedHosts = (verified ?? []).filter((t) => !t.expires_at || new Date(t.expires_at) > new Date());
  const resolved = parsed.kind === "hostname" ? await resolveA(parsed.value) : [];
  const auth = authorizeTarget(parsed, { resolved, verifiedHosts, scopes: scopes ?? [] });
  if ("error" in auth) {
    await audit(svc, userId, "user", "scan_rejected", { target: parsed.value, reason: auth.error });
    return errorResponse(auth.error, 403);
  }

  let nativeTargets: string[] = [];
  if (native) {
    const exp = expandTargets(auth.targets, NATIVE_PROFILES[profile as NativeProfile].maxTargets);
    if ("error" in exp) return errorResponse(exp.error, 400);
    nativeTargets = exp;
    const { count: running } = await svc.from("nmap_scans").select("id", { count: "exact", head: true }).eq("engine", "native").eq("status", "running");
    if ((running ?? 0) >= NATIVE_GLOBAL_CONCURRENCY) return errorResponse("The discovery engine is busy with other scans. Try again in a minute.", 503);
  } else {
    const agents = (await loadAgents(svc)).filter((a) => a.online && a.nmap_available);
    if (!agents.length) return errorResponse("No scanner agent with Nmap is online. An administrator needs to start one.", 503);
    if (PROFILES[profile as keyof typeof PROFILES].raw && !agents.some((a) => a.raw_capable)) {
      return errorResponse("Raw SYN scanning is not supported by any online scanner agent (it needs root or raw-socket privileges). Use the basic TCP scan instead.", 409);
    }
  }

  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("nmap_scans").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("created_at", since);
  if ((count ?? 0) >= SCANS_PER_HOUR) return errorResponse(`Limit reached: ${SCANS_PER_HOUR} network scans per hour.`, 429);

  await expireStale(svc);
  const common = {
    user_id: userId, target_input: parsed.value, target_kind: parsed.kind, auth_basis: auth.basis,
    scope_id: auth.scope_id, pob_target_id: auth.pob_target_id, profile, authorization_statement: STATEMENT,
  };
  const now = Date.now();
  const row = native
    ? {
      ...common, engine: "native", targets: nativeTargets, args: [], status: "running", nmap_version: NATIVE_VERSION,
      timeout_seconds: NATIVE_PROFILES[profile as NativeProfile].deadlineSec, started_at: new Date(now).toISOString(),
      heartbeat_at: new Date(now).toISOString(), progress: 0,
      deadline_at: new Date(now + NATIVE_PROFILES[profile as NativeProfile].deadlineSec * 1000).toISOString(),
      engine_state: initialState(nativeTargets, profile as NativeProfile),
    }
    : { ...common, targets: auth.targets, args: PROFILES[profile as keyof typeof PROFILES].args, timeout_seconds: PROFILES[profile as keyof typeof PROFILES].timeout };
  const { data: scan, error } = await svc.from("nmap_scans").insert(row).select("*").single();
  if (error || !scan) return errorResponse(error?.code === "23505" ? "You already have a network scan queued or running." : "Could not create the scan.", 409);
  await audit(svc, userId, "user", "scan_requested", { target: parsed.value, targets: auth.targets, profile, basis: auth.basis, engine: native ? "native" : "nmap_agent" }, scan.id);
  if (native) inBackground(driveNative(svc, scan.id, userId));
  return json({ scan });
}

async function adminAction(svc: Svc, adminId: string, action: string, body: Record<string, unknown>) {
  switch (action) {
    case "admin_overview": {
      const [agents, scopes, auditRows] = await Promise.all([
        loadAgents(svc),
        svc.from("nmap_scopes").select("id, cidr, label, user_id, created_at, revoked_at").is("revoked_at", null).order("created_at", { ascending: false }),
        svc.from("nmap_audit").select("id, actor, action, detail, scan_id, created_at, user_id").order("created_at", { ascending: false }).limit(60),
      ]);
      const ids = [...new Set((scopes.data ?? []).map((s) => s.user_id))];
      const { data: profiles } = ids.length ? await svc.from("profiles").select("id, email").in("id", ids) : { data: [] };
      const email = new Map((profiles ?? []).map((p) => [p.id, p.email]));
      return json({
        agents,
        scopes: (scopes.data ?? []).map((s) => ({ ...s, email: email.get(s.user_id) ?? "unknown" })),
        audit: auditRows.data ?? [],
      });
    }
    case "agent_create": {
      const name = String(body.name ?? "").trim().slice(0, 60);
      if (!name) return errorResponse("Give the scanner a name.", 400);
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const token = "bvna_" + btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, (c) => (c === "+" ? "-" : c === "/" ? "_" : ""));
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)))).map((b) => b.toString(16).padStart(2, "0")).join("");
      const { data, error } = await svc.from("nmap_agents").insert({ name, token_hash: hash, created_by: adminId }).select("id, name").single();
      if (error || !data) return errorResponse("Could not register the scanner.", 500);
      await audit(svc, adminId, "admin", "agent_registered", { agent: name, agent_id: data.id });
      return json({ agent: data, token });
    }
    case "agent_revoke": {
      const { data } = await svc.from("nmap_agents").update({ revoked: true }).eq("id", String(body.agent_id ?? "")).select("id, name").maybeSingle();
      if (!data) return errorResponse("Scanner not found", 404);
      await audit(svc, adminId, "admin", "agent_revoked", { agent: data.name, agent_id: data.id });
      return json({ ok: true });
    }
    case "scope_add": {
      const cidr = normalizeCidr(body.cidr);
      const bits = cidr ? Number(cidr.split("/")[1]) : 0;
      if (!cidr || bits < 16) return errorResponse("Enter a valid IPv4 range no larger than /16 (e.g. 10.20.0.0/24 or 127.0.0.1/32).", 400);
      if (hitsAlwaysBlocked(cidrRange(cidr)!)) return errorResponse("That range includes cloud metadata, link-local, multicast or reserved addresses, which can never be approved.", 400);
      const email = String(body.email ?? "").trim().toLowerCase();
      const { data: prof } = await svc.from("profiles").select("id, email").ilike("email", email).maybeSingle();
      if (!prof) return errorResponse("No user with that email address.", 404);
      const label = String(body.label ?? "").trim().slice(0, 80);
      const { data, error } = await svc.from("nmap_scopes").insert({ user_id: prof.id, cidr, label, created_by: adminId }).select("id").single();
      if (error || !data) return errorResponse("Could not save the approved range.", 500);
      await audit(svc, adminId, "admin", "scope_approved", { cidr, label, for: prof.email, scope_id: data.id });
      await audit(svc, prof.id, "admin", "scope_approved", { cidr, label, scope_id: data.id });
      return json({ ok: true });
    }
    case "scope_revoke": {
      const { data } = await svc.from("nmap_scopes").update({ revoked_at: new Date().toISOString() }).eq("id", String(body.scope_id ?? "")).is("revoked_at", null).select("id, cidr, user_id").maybeSingle();
      if (!data) return errorResponse("Range not found", 404);
      await audit(svc, adminId, "admin", "scope_revoked", { cidr: data.cidr, scope_id: data.id });
      await audit(svc, data.user_id, "admin", "scope_revoked", { cidr: data.cidr, scope_id: data.id });
      return json({ ok: true });
    }
  }
  return null;
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
      const elite = await hasElite(svc, user.id, admin);
      if (!elite) return json({ elite, admin });
      await expireStale(svc);
      const nativeProfiles = Object.fromEntries(Object.entries(NATIVE_PROFILES).map(([k, p]) => [k, { label: p.label, ports: p.ports.length, deadline: p.deadlineSec, max_targets: p.maxTargets }]));
      return json({ elite, admin, paused: await isPaused(svc), native: { version: NATIVE_VERSION, profiles: nativeProfiles } });
    }
    if (action.startsWith("admin_") || action.startsWith("agent_") || action.startsWith("scope_")) {
      if (!admin) return errorResponse("Administrators only.", 403);
      return (await adminAction(svc, user.id, action, body)) ?? errorResponse("Unknown action", 400);
    }
    if (!(await hasElite(svc, user.id, admin))) return errorResponse("Network scanning is included with the Elite plan.", 402);

    switch (action) {
      case "start":
        return await startScan(svc, user.id, body);
      case "poll": {
        await expireStale(svc);
        const { data: scan } = await svc.from("nmap_scans").select("*").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!scan) return errorResponse("Scan not found", 404);
        if (scan.engine === "native" && scan.status === "running") {
          const leaseFree = !scan.lease_until || new Date(scan.lease_until).getTime() < Date.now();
          if (leaseFree) inBackground(stepNative(svc, scan.id, user.id));
        }
        return json({ scan });
      }
      case "retry": {
        const { data: prev } = await svc.from("nmap_scans").select("target_input, profile, status").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!prev) return errorResponse("Scan not found", 404);
        if (prev.status === "queued" || prev.status === "running") return errorResponse("That scan is still running.", 409);
        return await startScan(svc, user.id, { target: prev.target_input, profile: isNativeProfile(prev.profile) ? prev.profile : "native_quick", authorized: body.authorized });
      }
      case "cancel": {
        const { data: s } = await svc.from("nmap_scans").select("*").eq("id", body.scan_id).eq("user_id", user.id).in("status", ["queued", "running"]).maybeSingle();
        if (!s) return errorResponse("No active scan to cancel", 404);
        if (s.engine === "native") {
          await svc.from("nmap_scans").update({ cancel_requested: true }).eq("id", s.id);
          await finalize(svc, s, s.engine_state ?? initialState([], s.profile), "cancelled", { ai: false, actor: "user" });
          await audit(svc, user.id, "user", "scan_cancel_requested", { was: s.status }, s.id);
          const { data: scan } = await svc.from("nmap_scans").select("*").eq("id", s.id).maybeSingle();
          return json({ scan });
        }
        const patch = s.status === "queued"
          ? { cancel_requested: true, status: "cancelled", finished_at: new Date().toISOString() }
          : { cancel_requested: true };
        const { data: scan } = await svc.from("nmap_scans").update(patch).eq("id", s.id).eq("status", s.status).select("*").maybeSingle();
        await audit(svc, user.id, "user", "scan_cancel_requested", { was: s.status }, s.id);
        return json({ scan });
      }
      case "analyze": {
        const { data: scan } = await svc.from("nmap_scans").select("*").eq("id", body.scan_id).eq("user_id", user.id).maybeSingle();
        if (!scan) return errorResponse("Scan not found", 404);
        if (scan.status !== "completed" && scan.status !== "partial") return errorResponse("Only finished scans can be analyzed.", 409);
        if (scan.ai_status === "pending") return errorResponse("Analysis already in progress", 409);
        const { data: hosts } = await svc.from("nmap_hosts").select("address, hostnames, state, ports").eq("scan_id", scan.id);
        await svc.from("nmap_scans").update({ ai_status: "pending", ai_error: null }).eq("id", scan.id);
        try {
          const { analysis, model } = await analyzeScan(scan, hosts ?? []);
          const payload = { ...analysis, model, generated_at: new Date().toISOString() };
          await svc.from("nmap_scans").update({ ai_status: "ready", ai_analysis: payload }).eq("id", scan.id);
          await svc.from("ai_usage").insert({ user_id: user.id, feature: "network_analyst", model }).then(() => {}, () => {});
          return json({ ai_status: "ready", ai_analysis: payload });
        } catch (err) {
          console.error("network ai failed", err);
          await svc.from("nmap_scans").update({ ai_status: "failed", ai_error: "The AI analyst is unavailable right now." }).eq("id", scan.id);
          return errorResponse("The AI analyst is unavailable right now. Your results are safe; try again shortly.", 503);
        }
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("network-scanner error", err);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
