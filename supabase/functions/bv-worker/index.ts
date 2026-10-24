import { getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { cleanOutput, MAX_COMMAND_LEN, TOKEN_RE, tokenPrefix, workerHealth } from "../_lib/bvos.ts";

type Svc = ReturnType<typeof getServiceClient>;
type Worker = { id: string; name: string; revoked: boolean; last_seen_at: string | null; caps: unknown };
type JobRow = { id: string; command: string; status: string; cancel_requested: boolean };

const clip = (v: unknown, n: number) => cleanOutput(v, n).replace(/[\r\n\t]/g, " ");

async function sha256(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function authWorker(svc: Svc, req: Request): Promise<Worker | null> {
  const token = req.headers.get("x-worker-token") ?? "";
  if (!TOKEN_RE.test(token)) return null;
  const { data } = await svc.from("bv_workers").select("id, name, revoked, last_seen_at, caps")
    .eq("token_hash", await sha256(token)).maybeSingle();
  const w = data as Worker | null;
  if (w && !w.revoked) return w;
  // Attribute the rejection to a registered worker (by its non-secret prefix) so admins see "unauthorized".
  const reason = w ? "Token revoked by an administrator." : "Worker presented a wrong or outdated token.";
  await svc.from("bv_workers").update({ last_auth_fail_at: new Date().toISOString(), last_auth_fail_reason: reason })
    .eq(w ? "id" : "token_prefix", w ? w.id : tokenPrefix(token));
  return null;
}

async function ownJob(svc: Svc, worker: Worker, id: unknown): Promise<JobRow | null> {
  const { data } = await svc.from("bv_jobs").select("id, command, status, cancel_requested")
    .eq("id", String(id ?? "")).eq("worker_id", worker.id).eq("status", "running").maybeSingle();
  return data as JobRow | null;
}

function sanitizeCaps(raw: unknown) {
  const c = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  return {
    docker: c.docker === true,
    docker_version: clip(c.docker_version, 40) || null,
    image: clip(c.image, 80) || null,
    platform: clip(c.platform, 40) || null,
    node: clip(c.node, 20) || null,
    sandbox_ok: c.sandbox_ok === true,
    sandbox_error: clip(c.sandbox_error, 300) || null,
    selftest_uid: clip(c.selftest_uid, 20) || null,
    network_isolated: c.network_isolated === true,
    checked_at: new Date().toISOString(),
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const svc = getServiceClient();
    const worker = await authWorker(svc, req);
    if (!worker) return errorResponse("Unauthorized", 401);
    const body = await req.json().catch(() => ({}));

    switch (String(body.action ?? "")) {
      case "heartbeat": {
        const caps = sanitizeCaps(body.caps);
        const now = new Date().toISOString();
        await svc.from("bv_workers").update({ last_seen_at: now, version: clip(body.version, 24) || null, caps })
          .eq("id", worker.id);
        const health = workerHealth({ ...worker, last_seen_at: now, caps, last_auth_fail_at: null });
        return json({ ok: true, worker: worker.name, state: health.state, reason: health.reason });
      }
      case "claim": {
        const health = workerHealth({ ...worker, last_auth_fail_at: null });
        if (health.state !== "online") return json({ job: null, state: health.state, reason: health.reason });
        const { data, error } = await svc.rpc("bv_claim_job", { p_worker: worker.id });
        if (error) throw error;
        const job = Array.isArray(data) ? data[0] : null;
        if (!job) return json({ job: null, state: "online" });
        return json({ job: { id: job.id, command: String(job.command).slice(0, MAX_COMMAND_LEN) } });
      }
      case "progress": {
        const job = await ownJob(svc, worker, body.job_id);
        return json({ cancel: !job || job.cancel_requested });
      }
      case "complete": {
        const job = await ownJob(svc, worker, body.job_id);
        if (!job) return errorResponse("Job not found", 404);
        const exitCode = Number(body.exit_code);
        const duration = Number(body.duration_ms);
        await svc.from("bv_jobs").update({
          status: job.cancel_requested ? "cancelled" : "completed",
          stdout: cleanOutput(body.stdout),
          stderr: cleanOutput(body.stderr),
          exit_code: Number.isInteger(exitCode) ? exitCode : null,
          duration_ms: Number.isFinite(duration) && duration >= 0 ? Math.round(duration) : null,
          finished_at: new Date().toISOString(),
        }).eq("id", job.id).eq("status", "running");
        return json({ ok: true });
      }
      case "fail": {
        const job = await ownJob(svc, worker, body.job_id);
        if (!job) return errorResponse("Job not found", 404);
        const cancelled = body.cancelled === true && job.cancel_requested;
        await svc.from("bv_jobs").update({
          status: cancelled ? "cancelled" : "failed",
          error: cancelled ? null : clip(body.error || "The sandbox reported a failure.", 400),
          stdout: cleanOutput(body.stdout) || null,
          stderr: cleanOutput(body.stderr) || null,
          duration_ms: Number.isFinite(Number(body.duration_ms)) ? Math.round(Number(body.duration_ms)) : null,
          finished_at: new Date().toISOString(),
        }).eq("id", job.id).eq("status", "running");
        return json({ ok: true });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("bv-worker error", err);
    return errorResponse("Something went wrong.", 500);
  }
});
