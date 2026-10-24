import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { SCAN_TYPES, isScopeAllowed, newDeviceToken, sha256Hex, validatePaths } from "../_lib/endpoint.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_DEVICES = 5;
const JOBS_PER_HOUR = 30;
const AGENT_ONLINE_MS = 2 * 60_000;
const PAID_PLANS = ["malware_removal", "pro", "elite"];

interface Ctx { svc: SupabaseClient; userId: string }

async function hasAccess(svc: SupabaseClient, userId: string, isAdmin: boolean): Promise<boolean> {
  if (isAdmin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && PAID_PLANS.includes(data.plan) && ["active", "trialing"].includes(data.status);
}

async function audit(ctx: Ctx, deviceId: string | null, jobId: string | null, action: string, outcome: string, detail: Record<string, unknown> = {}) {
  await ctx.svc.from("endpoint_audit").insert({ user_id: ctx.userId, device_id: deviceId, job_id: jobId, actor: "user", action, outcome, detail });
}

function parseScopes(raw: unknown): string[] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const set = [...new Set(raw)];
  return set.every((s) => SCAN_TYPES.includes(s as never)) ? (set as string[]) : null;
}

async function ownDevice(ctx: Ctx, deviceId: unknown) {
  if (typeof deviceId !== "string" || !UUID.test(deviceId)) return null;
  const { data } = await ctx.svc.from("endpoint_devices")
    .select("id, name, allowed_scopes, allowed_paths, last_seen_at, revoked_at")
    .eq("id", deviceId).eq("user_id", ctx.userId).maybeSingle();
  return data && !data.revoked_at ? data : null;
}

async function underRateLimit(ctx: Ctx): Promise<boolean> {
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await ctx.svc.from("endpoint_jobs").select("id", { count: "exact", head: true })
    .eq("user_id", ctx.userId).gte("created_at", since);
  return (count ?? 0) < JOBS_PER_HOUR;
}

const isOnline = (lastSeen: string | null) => !!lastSeen && Date.now() - new Date(lastSeen).getTime() < AGENT_ONLINE_MS;

async function createJob(ctx: Ctx, deviceId: string, kind: string, params: Record<string, unknown>, approved: boolean) {
  const now = new Date().toISOString();
  const { data, error } = await ctx.svc.from("endpoint_jobs").insert({
    device_id: deviceId, user_id: ctx.userId, kind, params, status: "queued", requested_by: ctx.userId,
    approved_by: approved ? ctx.userId : null, approved_at: approved ? now : null,
    expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
  }).select("id").single();
  if (error || !data) throw new Error("job_insert_failed");
  return data.id as string;
}

async function enroll(ctx: Ctx, body: Record<string, unknown>) {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (name.length < 1 || name.length > 60) return errorResponse("Device name must be 1-60 characters", 400);
  const scopes = parseScopes(body.scopes);
  const paths = validatePaths(body.paths ?? []);
  if (!scopes || !paths) return errorResponse("Invalid scan scope", 400);
  if (scopes.includes("custom") && paths.length === 0) return errorResponse("Add at least one folder for custom scans", 400);
  const { count } = await ctx.svc.from("endpoint_devices").select("id", { count: "exact", head: true })
    .eq("user_id", ctx.userId).is("revoked_at", null);
  if ((count ?? 0) >= MAX_DEVICES) return errorResponse(`You can enroll up to ${MAX_DEVICES} devices`, 409);
  const token = newDeviceToken();
  const { data, error } = await ctx.svc.from("endpoint_devices").insert({
    user_id: ctx.userId, name, os: "windows", token_hash: await sha256Hex(token), allowed_scopes: scopes, allowed_paths: paths,
  }).select("id").single();
  if (error || !data) return errorResponse("Could not enroll device", 500);
  await audit(ctx, data.id, null, "device_enrolled", "succeeded", { name, scopes, paths });
  return json({ deviceId: data.id, token });
}

async function updateScope(ctx: Ctx, body: Record<string, unknown>) {
  const device = await ownDevice(ctx, body.deviceId);
  if (!device) return errorResponse("Device not found", 404);
  const scopes = parseScopes(body.scopes);
  const paths = validatePaths(body.paths ?? []);
  if (!scopes || !paths) return errorResponse("Invalid scan scope", 400);
  const schedule = body.schedule ?? "off";
  if (!SCHEDULES.includes(schedule as string)) return errorResponse("Invalid scan schedule", 400);
  if (schedule !== "off" && !scopes.includes("quick") && !scopes.includes("full")) {
    return errorResponse("Scheduled scans need Quick or Full scans to be allowed", 400);
  }
  await ctx.svc.from("endpoint_devices").update({
    allowed_scopes: scopes, allowed_paths: paths, scan_schedule: schedule,
    next_scan_at: schedule === "off" ? null : new Date(Date.now() + 5 * 60_000).toISOString(),
  }).eq("id", device.id);
  await audit(ctx, device.id, null, "scope_updated", "succeeded", { scopes, paths, schedule });
  return json({ ok: true });
}

async function revoke(ctx: Ctx, body: Record<string, unknown>) {
  const device = await ownDevice(ctx, body.deviceId);
  if (!device) return errorResponse("Device not found", 404);
  await ctx.svc.from("endpoint_devices").update({ revoked_at: new Date().toISOString() }).eq("id", device.id);
  await ctx.svc.from("endpoint_jobs").update({ status: "cancelled", completed_at: new Date().toISOString() })
    .eq("device_id", device.id).in("status", ["queued", "pending_approval"]);
  await audit(ctx, device.id, null, "device_revoked", "succeeded");
  return json({ ok: true });
}

async function requestScan(ctx: Ctx, body: Record<string, unknown>) {
  const device = await ownDevice(ctx, body.deviceId);
  if (!device) return errorResponse("Device not found", 404);
  const scanType = String(body.scanType ?? "");
  const path = typeof body.path === "string" ? body.path : undefined;
  if (!isScopeAllowed(device, scanType, path)) return errorResponse("That scan is outside the scope you authorized for this device", 403);
  if (!isOnline(device.last_seen_at)) return errorResponse("The Blackveil agent on this device is not connected", 409);
  const { data: running } = await ctx.svc.from("endpoint_jobs").select("id").eq("device_id", device.id)
    .in("kind", ["scan", "remediate", "verify", "restore"]).in("status", ["queued", "dispatched"]).limit(1).maybeSingle();
  if (running) return errorResponse("Another action is already running on this device", 409);
  if (!(await underRateLimit(ctx))) return errorResponse("Too many requests. Try again later.", 429);
  const jobId = await createJob(ctx, device.id, "scan", { scanType, ...(path ? { path } : {}) }, true);
  await audit(ctx, device.id, jobId, "scan_requested", "queued", { scanType, path: path ?? null });
  return json({ jobId });
}

async function approveRemediation(ctx: Ctx, body: Record<string, unknown>) {
  const device = await ownDevice(ctx, body.deviceId);
  if (!device) return errorResponse("Device not found", 404);
  if (body.acknowledged !== true) return errorResponse("Remediation requires explicit approval", 400);
  const ids = Array.isArray(body.threatIds) ? body.threatIds.filter((x): x is string => typeof x === "string" && UUID.test(x)) : [];
  const { data: pending } = await ctx.svc.from("endpoint_threats").select("id, engine_threat_id, name")
    .eq("device_id", device.id).eq("user_id", ctx.userId).eq("status", "awaiting_approval");
  const pendingIds = (pending ?? []).map((t) => t.id as string);
  // Defender's remediation applies to every active detection at once, so approval must cover all of them.
  if (!pendingIds.length) return errorResponse("No active detections are awaiting approval", 409);
  if (ids.length !== pendingIds.length || !pendingIds.every((id) => ids.includes(id))) {
    return errorResponse("The list of active detections changed. Review the findings again before approving.", 409);
  }
  if (!isOnline(device.last_seen_at)) return errorResponse("The Blackveil agent on this device is not connected", 409);
  if (!(await underRateLimit(ctx))) return errorResponse("Too many requests. Try again later.", 429);
  const engineThreatIds = (pending ?? []).map((t) => t.engine_threat_id as string);
  const jobId = await createJob(ctx, device.id, "remediate", { engineThreatIds }, true);
  await audit(ctx, device.id, jobId, "remediation_approved", "queued", { threats: (pending ?? []).map((t) => t.name) });
  return json({ jobId });
}

async function requestVerify(ctx: Ctx, body: Record<string, unknown>) {
  const device = await ownDevice(ctx, body.deviceId);
  if (!device) return errorResponse("Device not found", 404);
  if (!isOnline(device.last_seen_at)) return errorResponse("The Blackveil agent on this device is not connected", 409);
  const { data: threats } = await ctx.svc.from("endpoint_threats").select("engine_threat_id, resources")
    .eq("device_id", device.id).eq("user_id", ctx.userId).in("status", ["quarantined", "removed", "failed"]);
  if (!threats?.length) return errorResponse("Nothing to verify yet", 409);
  if (!(await underRateLimit(ctx))) return errorResponse("Too many requests. Try again later.", 429);
  const jobId = await createJob(ctx, device.id, "verify", {
    engineThreatIds: threats.map((t) => t.engine_threat_id),
    resources: threats.map((t) => ({ threatId: t.engine_threat_id, resources: t.resources })),
  }, true);
  await audit(ctx, device.id, jobId, "verification_requested", "queued", { count: threats.length });
  return json({ jobId });
}

async function restore(ctx: Ctx, body: Record<string, unknown>) {
  const threatId = typeof body.threatId === "string" && UUID.test(body.threatId) ? body.threatId : "";
  const { data: threat } = await ctx.svc.from("endpoint_threats").select("id, device_id, engine_threat_id, name, status, resources")
    .eq("id", threatId).eq("user_id", ctx.userId).maybeSingle();
  if (!threat) return errorResponse("Threat not found", 404);
  if (threat.status !== "quarantined") return errorResponse("Only quarantined items can be restored", 409);
  if (body.confirmName !== threat.name) return errorResponse("Type the exact threat name to confirm the restore", 400);
  const device = await ownDevice(ctx, threat.device_id);
  if (!device) return errorResponse("Device not found", 404);
  if (!isOnline(device.last_seen_at)) return errorResponse("The Blackveil agent on this device is not connected", 409);
  if (!(await underRateLimit(ctx))) return errorResponse("Too many requests. Try again later.", 429);
  const jobId = await createJob(ctx, device.id, "restore", { engineThreatId: threat.engine_threat_id, name: threat.name, resources: threat.resources }, true);
  await audit(ctx, device.id, jobId, "restore_approved", "queued", { threat: threat.name, reason: "user_reported_false_positive" });
  return json({ jobId });
}

async function cancelJob(ctx: Ctx, body: Record<string, unknown>) {
  const jobId = typeof body.jobId === "string" && UUID.test(body.jobId) ? body.jobId : "";
  const { data } = await ctx.svc.from("endpoint_jobs").update({ status: "cancelled", completed_at: new Date().toISOString() })
    .eq("id", jobId).eq("user_id", ctx.userId).eq("status", "queued").select("id, device_id").maybeSingle();
  if (!data) return errorResponse("Only jobs that have not started can be cancelled", 409);
  await audit(ctx, data.device_id, data.id, "job_cancelled", "succeeded");
  return json({ ok: true });
}

const SCHEDULES = ["off", "daily", "weekly"];
const MANUAL_INCIDENT_STATUSES = ["investigating", "resolved", "unresolved"];

async function setIncidentStatus(ctx: Ctx, body: Record<string, unknown>) {
  const id = typeof body.incidentId === "string" && UUID.test(body.incidentId) ? body.incidentId : "";
  const status = String(body.status ?? "");
  if (!MANUAL_INCIDENT_STATUSES.includes(status)) return errorResponse("Invalid incident status", 400);
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 300) : "";
  const { data: current } = await ctx.svc.from("endpoint_incidents").select("id, device_id, status")
    .eq("id", id).eq("user_id", ctx.userId).maybeSingle();
  if (!current) return errorResponse("Incident not found", 404);
  if (current.status === status) return json({ ok: true });
  const now = new Date().toISOString();
  const { error } = await ctx.svc.from("endpoint_incidents").update({
    status, updated_at: now, auto_managed: false,
    resolved_at: status === "resolved" ? now : null,
    resolution: status === "resolved" ? (note || "Closed by user") : null,
  }).eq("id", id).eq("user_id", ctx.userId);
  if (error) return errorResponse("Could not update incident", 500);
  await audit(ctx, current.device_id, null, "incident_status_changed", status, { incident: id, from: current.status, note: note || null });
  return json({ ok: true });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);
  try {
    const { user, error } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(error ?? "Unauthorized", 401);
    const svc = getServiceClient();
    const isAdmin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    if (!(await hasAccess(svc, user.id, isAdmin))) return errorResponse("Device remediation requires a paid plan", 403);
    let body: Record<string, unknown>;
    try { body = await req.json(); } catch { return errorResponse("Invalid request body", 400); }
    const ctx: Ctx = { svc, userId: user.id };
    switch (body.action) {
      case "enroll": return await enroll(ctx, body);
      case "update_scope": return await updateScope(ctx, body);
      case "revoke": return await revoke(ctx, body);
      case "scan": return await requestScan(ctx, body);
      case "approve_remediation": return await approveRemediation(ctx, body);
      case "verify": return await requestVerify(ctx, body);
      case "restore": return await restore(ctx, body);
      case "cancel_job": return await cancelJob(ctx, body);
      case "incident_status": return await setIncidentStatus(ctx, body);
      default: return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("endpoint-control error", err instanceof Error ? err.message : "unknown");
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
