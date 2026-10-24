import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import {
  jobTimeoutMinutes, mapEngineStatus, sha256Hex, statusAfterScan, validateEngineStatus,
  validateThreats, validateVerifyItems, verifyOutcome, type ThreatStatus,
} from "../_lib/endpoint.ts";

const MAX_BODY_BYTES = 512 * 1024;

interface Device {
  id: string;
  user_id: string;
  allowed_scopes: string[];
  allowed_paths: string[];
}

interface Job {
  id: string;
  kind: string;
  params: Record<string, unknown>;
  status: string;
  attempts: number;
  dispatched_at: string | null;
}

async function audit(svc: SupabaseClient, device: Device, jobId: string | null, action: string, outcome: string, detail: Record<string, unknown> = {}) {
  await svc.from("endpoint_audit").insert({ user_id: device.user_id, device_id: device.id, job_id: jobId, actor: "agent", action, outcome, detail });
}

async function recoverStaleJobs(svc: SupabaseClient, device: Device) {
  const now = new Date();
  await svc.from("endpoint_jobs").update({ status: "expired", completed_at: now.toISOString(), error: "Agent did not pick up the job in time" })
    .eq("device_id", device.id).eq("status", "queued").lt("expires_at", now.toISOString());

  const { data: running } = await svc.from("endpoint_jobs").select("id, kind, params, attempts, dispatched_at")
    .eq("device_id", device.id).eq("status", "dispatched");
  for (const j of (running ?? []) as Job[]) {
    const limit = jobTimeoutMinutes(j.kind, String(j.params?.scanType ?? ""));
    if (!j.dispatched_at || now.getTime() - new Date(j.dispatched_at).getTime() < limit * 60_000) continue;
    if (j.attempts < 2 && j.kind !== "remediate") {
      await svc.from("endpoint_jobs").update({ status: "queued", expires_at: new Date(now.getTime() + 30 * 60_000).toISOString() }).eq("id", j.id).eq("status", "dispatched");
      await audit(svc, device, j.id, `${j.kind}_retry`, "requeued", { reason: "interrupted_or_timed_out" });
    } else {
      await svc.from("endpoint_jobs").update({ status: "failed", completed_at: now.toISOString(), error: "Interrupted: the agent stopped responding before reporting a result" }).eq("id", j.id).eq("status", "dispatched");
      await audit(svc, device, j.id, j.kind, "failed", { reason: "interrupted" });
    }
  }
}

async function poll(svc: SupabaseClient, device: Device) {
  await recoverStaleJobs(svc, device);
  const { data: next } = await svc.from("endpoint_jobs").select("id").eq("device_id", device.id).eq("status", "queued")
    .order("created_at", { ascending: true }).limit(1).maybeSingle();
  if (!next) return json({ job: null });
  const { data: claimed } = await svc.from("endpoint_jobs")
    .update({ status: "dispatched", dispatched_at: new Date().toISOString() })
    .eq("id", next.id).eq("status", "queued").select("id, kind, params, attempts").maybeSingle();
  if (!claimed) return json({ job: null });
  await svc.from("endpoint_jobs").update({ attempts: (claimed.attempts ?? 0) + 1 }).eq("id", claimed.id);
  await audit(svc, device, claimed.id, `${claimed.kind}_dispatched`, "sent_to_agent");
  return json({ job: { id: claimed.id, kind: claimed.kind, params: claimed.params }, allowedPaths: device.allowed_paths });
}

async function finishJob(svc: SupabaseClient, device: Device, job: Job, ok: boolean, result: Record<string, unknown>, error?: string) {
  await svc.from("endpoint_jobs").update({
    status: ok ? "succeeded" : "failed", completed_at: new Date().toISOString(), result, error: error ?? null,
  }).eq("id", job.id).eq("status", "dispatched");
  await audit(svc, device, job.id, job.kind, ok ? "succeeded" : "failed", { ...result, ...(error ? { error } : {}) });
}

async function handleScan(svc: SupabaseClient, device: Device, job: Job, data: Record<string, unknown>) {
  const engine = validateEngineStatus(data.engineStatus);
  const threats = validateThreats(data.threats);
  if (!engine || !threats) return finishJob(svc, device, job, false, {}, "Agent sent an invalid scan report");

  const ids = threats.map((t) => t.threatId);
  const { data: existing } = ids.length
    ? await svc.from("endpoint_threats").select("id, engine_threat_id, status, times_seen").eq("device_id", device.id).in("engine_threat_id", ids)
    : { data: [] };
  const byId = new Map((existing ?? []).map((e) => [e.engine_threat_id as string, e]));
  const now = new Date().toISOString();
  let active = 0;
  let repeats = 0;

  for (const t of threats) {
    const prev = byId.get(t.threatId);
    const status = statusAfterScan((prev?.status as ThreatStatus) ?? null, t);
    if (t.active) active++;
    const engineAction = t.engineStatusId !== null ? mapEngineStatus(t.engineStatusId).action : null;
    if (prev) {
      const repeat = t.active && ["quarantined", "removed", "verified_clean", "restored"].includes(prev.status as string);
      if (repeat) repeats++;
      await svc.from("endpoint_threats").update({
        status, severity: t.severity, category: t.category, resources: t.resources, sha256: t.sha256 ?? undefined,
        engine_action: engineAction, last_seen_at: now, times_seen: (prev.times_seen as number) + (t.active ? 1 : 0),
      }).eq("id", prev.id);
    } else {
      await svc.from("endpoint_threats").insert({
        device_id: device.id, user_id: device.user_id, engine_threat_id: t.threatId, name: t.name, severity: t.severity,
        category: t.category, resources: t.resources, sha256: t.sha256, status, engine_action: engineAction,
      });
    }
  }

  await svc.from("endpoint_devices").update({
    engine_status: engine, last_scan_at: now, last_scan_status: active ? "threats_found" : "no_active_detections",
  }).eq("id", device.id);
  return finishJob(svc, device, job, true, { scanType: job.params.scanType, reported: threats.length, active, repeats, engine });
}

async function handleRemediate(svc: SupabaseClient, device: Device, job: Job, data: Record<string, unknown>) {
  const approved = Array.isArray(job.params.engineThreatIds) ? (job.params.engineThreatIds as string[]) : [];
  const results = Array.isArray(data.results) ? data.results.slice(0, 200) : null;
  if (!results) return finishJob(svc, device, job, false, {}, "Agent sent an invalid remediation report");

  const summary: Record<string, string> = {};
  for (const id of approved) {
    const r = results.find((x) => x && String((x as Record<string, unknown>).threatId) === id) as Record<string, unknown> | undefined;
    let status: ThreatStatus = "failed";
    let action = "no_result_reported";
    if (r) {
      const mapped = mapEngineStatus(r.statusId);
      const stillThere = Array.isArray(r.existingResources) && r.existingResources.length > 0;
      status = mapped.status === "detected" ? "failed" : mapped.status;
      action = mapped.action;
      if (stillThere && status === "removed") { status = "failed"; action = "file_still_present"; }
    }
    summary[id] = status;
    await svc.from("endpoint_threats").update({ status, engine_action: action }).eq("device_id", device.id).eq("engine_threat_id", id);
  }
  const failed = Object.values(summary).filter((s) => s === "failed").length;
  const rebootRequired = data.rebootRequired === true;
  return finishJob(svc, device, job, failed === 0, { summary, rebootRequired }, failed ? `${failed} threat(s) could not be remediated` : undefined);
}

async function handleVerify(svc: SupabaseClient, device: Device, job: Job, data: Record<string, unknown>) {
  const items = validateVerifyItems(data.items);
  if (!items) return finishJob(svc, device, job, false, {}, "Agent sent an invalid verification report");
  const expected = Array.isArray(job.params.engineThreatIds) ? (job.params.engineThreatIds as string[]) : [];
  const now = new Date().toISOString();
  const summary: Record<string, string> = {};
  for (const id of expected) {
    const item = items.find((i) => i.threatId === id);
    const outcome = item ? verifyOutcome(item) : { status: "failed" as ThreatStatus, reasons: ["The agent did not report a verification result for this threat."] };
    summary[id] = outcome.status;
    await svc.from("endpoint_threats").update({
      status: outcome.status,
      verification: { checked_at: now, reasons: outcome.reasons, existing_resources: item?.existingResources ?? [], persistence_hits: item?.persistenceHits ?? [] },
    }).eq("device_id", device.id).eq("engine_threat_id", id);
  }
  const engine = validateEngineStatus(data.engineStatus);
  if (engine) await svc.from("endpoint_devices").update({ engine_status: engine, last_scan_at: now }).eq("id", device.id);
  const failed = Object.values(summary).filter((s) => s !== "verified_clean").length;
  return finishJob(svc, device, job, failed === 0, { summary }, failed ? `${failed} threat(s) did not pass verification` : undefined);
}

async function handleRestore(svc: SupabaseClient, device: Device, job: Job, data: Record<string, unknown>) {
  const id = String(job.params.engineThreatId ?? "");
  if (data.restored !== true) return finishJob(svc, device, job, false, { fileExists: data.fileExists === true }, "Defender did not restore the item");
  await svc.from("endpoint_threats").update({ status: "restored", engine_action: "restored_by_user" }).eq("device_id", device.id).eq("engine_threat_id", id);
  return finishJob(svc, device, job, true, { fileExists: data.fileExists === true });
}

async function report(svc: SupabaseClient, device: Device, body: Record<string, unknown>) {
  const jobId = typeof body.jobId === "string" ? body.jobId : "";
  const { data: job } = await svc.from("endpoint_jobs").select("id, kind, params, status, attempts, dispatched_at")
    .eq("id", jobId).eq("device_id", device.id).maybeSingle();
  if (!job || job.status !== "dispatched") return errorResponse("Job is not awaiting a result", 409);
  const data = body.data && typeof body.data === "object" ? (body.data as Record<string, unknown>) : {};

  if (body.ok !== true) {
    const err = typeof body.error === "string" ? body.error.slice(0, 300) : "Agent reported a failure";
    if (job.kind === "scan") await svc.from("endpoint_devices").update({ last_scan_status: "failed" }).eq("id", device.id);
    await finishJob(svc, device, job as Job, false, { code: typeof data.code === "string" ? data.code.slice(0, 60) : null }, err);
    return json({ accepted: true });
  }
  if (job.kind === "scan") await handleScan(svc, device, job as Job, data);
  else if (job.kind === "remediate") await handleRemediate(svc, device, job as Job, data);
  else if (job.kind === "verify") await handleVerify(svc, device, job as Job, data);
  else if (job.kind === "restore") await handleRestore(svc, device, job as Job, data);
  return json({ accepted: true });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);
  try {
    const token = req.headers.get("x-device-token") ?? "";
    if (!/^bvd_[A-Za-z0-9_-]{40,60}$/.test(token)) return errorResponse("Unauthorized", 401);
    const raw = await req.text();
    if (raw.length > MAX_BODY_BYTES) return errorResponse("Payload too large", 413);
    let body: Record<string, unknown>;
    try { body = JSON.parse(raw); } catch { return errorResponse("Invalid JSON", 400); }

    const svc = getServiceClient();
    const { data: device } = await svc.from("endpoint_devices").select("id, user_id, allowed_scopes, allowed_paths")
      .eq("token_hash", await sha256Hex(token)).is("revoked_at", null).maybeSingle();
    if (!device) return errorResponse("Unauthorized", 401);

    const engine = validateEngineStatus(body.engineStatus);
    await svc.from("endpoint_devices").update({
      last_seen_at: new Date().toISOString(),
      ...(typeof body.osVersion === "string" ? { os_version: body.osVersion.slice(0, 80) } : {}),
      ...(typeof body.agentVersion === "string" ? { agent_version: body.agentVersion.slice(0, 20) } : {}),
      ...(engine ? { engine_status: engine } : {}),
    }).eq("id", device.id);

    if (body.action === "poll") return await poll(svc, device as Device);
    if (body.action === "report") return await report(svc, device as Device, body);
    if (body.action === "heartbeat") return json({ ok: true });
    return errorResponse("Unknown action", 400);
  } catch (err) {
    console.error("endpoint-agent error", err instanceof Error ? err.message : "unknown");
    return errorResponse("Internal error", 500);
  }
});
