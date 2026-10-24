import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { sanitizeCommand, tokenPrefix, workerHealth, type WorkerRow } from "../_lib/bvos.ts";

type Svc = ReturnType<typeof getServiceClient>;
type User = { id: string };

const JOBS_PER_HOUR = 60;
const STALE_QUEUE_MS = 2 * 60_000;
const STUCK_RUNNING_MS = 3 * 60_000;

const SANDBOX = {
  version: "Blackveil OS 1.0",
  isolation: "Docker container (one fresh container per command)",
  network: "none (egress and ingress disabled)",
  fs: "read-only root, ephemeral /tmp only",
  user: "unprivileged (nobody)",
};

async function expireStale(svc: Svc) {
  const now = new Date().toISOString();
  await svc.from("bv_jobs").update({ status: "failed", error: "No execution worker picked up this command in time.", finished_at: now })
    .eq("status", "queued").lt("deadline_at", now);
  await svc.from("bv_jobs").update({ status: "failed", error: "The execution worker stopped responding while running this command.", finished_at: now })
    .eq("status", "running").lt("started_at", new Date(Date.now() - STUCK_RUNNING_MS).toISOString());
}

async function ensureSession(svc: Svc, user: User, sessionId: unknown) {
  if (sessionId) {
    const { data } = await svc.from("bv_sessions").select("*").eq("id", String(sessionId)).eq("user_id", user.id).maybeSingle();
    if (data) {
      await svc.from("bv_sessions").update({ last_used_at: new Date().toISOString() }).eq("id", data.id);
      return data;
    }
  }
  const { data } = await svc.from("bv_sessions").insert({ user_id: user.id, label: "Terminal" }).select("*").single();
  return data;
}

async function listWorkers(svc: Svc) {
  const { data } = await svc.from("bv_workers")
    .select("id, name, version, caps, last_seen_at, revoked, created_at, token_prefix, last_auth_fail_at, last_auth_fail_reason")
    .order("created_at");
  return (data ?? []).map((w) => {
    const h = workerHealth(w as WorkerRow);
    return { ...w, online: h.state === "online", state: h.state, reason: h.reason };
  });
}

async function statusAction(svc: Svc, user: User, admin: boolean) {
  await expireStale(svc);
  const [all, sessions, jobs] = await Promise.all([
    listWorkers(svc),
    svc.from("bv_sessions").select("*").eq("user_id", user.id).order("created_at", { ascending: false }).limit(5),
    svc.from("bv_jobs").select("*").eq("user_id", user.id).order("created_at", { ascending: false }).limit(30),
  ]);
  const live = all.filter((w) => !w.revoked);
  return {
    sandbox: SANDBOX,
    workers: admin ? all : [],
    workersOnline: live.filter((w) => w.online).length,
    workersTotal: live.length,
    sessions: sessions.data ?? [],
    jobs: jobs.data ?? [],
    admin,
  };
}

async function execAction(svc: Svc, user: User, body: Record<string, unknown>) {
  const clean = sanitizeCommand(body.command);
  if (!clean.ok) return errorResponse(clean.error, 400);

  const since = new Date(Date.now() - 3600_000).toISOString();
  const [{ count }, { data: active }, session] = await Promise.all([
    svc.from("bv_jobs").select("id", { count: "exact", head: true }).eq("user_id", user.id).gte("created_at", since),
    svc.from("bv_jobs").select("id").eq("user_id", user.id).in("status", ["queued", "running"]),
    ensureSession(svc, user, body.session_id),
  ]);
  if ((count ?? 0) >= JOBS_PER_HOUR) return errorResponse(`Limit reached: ${JOBS_PER_HOUR} commands per hour.`, 429);
  if ((active ?? []).length > 0) return errorResponse("A command is already running. Wait for it to finish.", 429);
  const workers = await listWorkers(svc);
  if (!workers.some((w) => w.online)) {
    return errorResponse("The Linux execution worker is offline, so this command was not run. An administrator must start a healthy worker.", 503);
  }

  const { data: job, error } = await svc.from("bv_jobs").insert({
    user_id: user.id,
    session_id: session?.id ?? null,
    kind: "shell",
    command: clean.command,
    status: "queued",
    deadline_at: new Date(Date.now() + STALE_QUEUE_MS).toISOString(),
  }).select("*").single();

  if (error || !job) {
    return errorResponse(error?.code === "23505" ? "A command is already running for your session." : "Could not queue the command.", 409);
  }
  await svc.from("bv_audit").insert({ user_id: user.id, action: "os_command", detail: { command: clean.command, job_id: job.id } });
  return { job };
}

async function adminAction(svc: Svc, adminId: string, action: string, body: Record<string, unknown>) {
  switch (action) {
    case "admin_workers": {
      await expireStale(svc);
      return { workers: await listWorkers(svc), endpoint: `${Deno.env.get("SUPABASE_URL")}/functions/v1/bv-worker` };
    }
    case "admin_worker_create": {
      const name = String(body.name ?? "").trim().slice(0, 60);
      if (!name) return errorResponse("Give the worker a name.", 400);
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const token = "bvos_" + btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, (c) => (c === "+" ? "-" : c === "/" ? "_" : ""));
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)))).map((b) => b.toString(16).padStart(2, "0")).join("");
      const { data, error } = await svc.from("bv_workers").insert({ name, token_hash: hash, token_prefix: tokenPrefix(token), created_by: adminId }).select("id, name").single();
      if (error || !data) return errorResponse("Could not register the worker.", 500);
      await svc.from("bv_audit").insert({ user_id: adminId, action: "os_worker_created", detail: { name, worker_id: data.id } });
      return { worker: data, token, endpoint: `${Deno.env.get("SUPABASE_URL")}/functions/v1/bv-worker` };
    }
    case "admin_worker_revoke": {
      const { data } = await svc.from("bv_workers").update({ revoked: true }).eq("id", String(body.worker_id ?? "")).select("id, name").maybeSingle();
      if (!data) return errorResponse("Worker not found.", 404);
      await svc.from("bv_audit").insert({ user_id: adminId, action: "os_worker_revoked", detail: { name: data.name, worker_id: data.id } });
      return { ok: true };
    }
  }
  return null;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user } = await getAuthenticatedUser(req);
    if (!user) return errorResponse("Unauthorized", 401);
    const svc = getServiceClient();
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const body = await req.json().catch(() => ({}));
    const action = String(body.action ?? "");

    if (action.startsWith("admin_")) {
      if (!admin) return errorResponse("Administrators only.", 403);
      return json((await adminAction(svc, user.id, action, body)) ?? { error: "Unknown action" });
    }

    switch (action) {
      case "status":
        return json(await statusAction(svc, { id: user.id }, admin));
      case "exec":
        return json(await execAction(svc, { id: user.id }, body));
      case "poll": {
        await expireStale(svc);
        const { data } = await svc.from("bv_jobs").select("*").eq("id", String(body.job_id ?? "")).eq("user_id", user.id).maybeSingle();
        if (!data) return errorResponse("Command not found.", 404);
        return json({ job: data });
      }
      case "cancel": {
        const { data } = await svc.from("bv_jobs").select("*").eq("id", String(body.job_id ?? "")).eq("user_id", user.id).in("status", ["queued", "running"]).maybeSingle();
        if (!data) return errorResponse("No active command to cancel.", 404);
        const patch = data.status === "queued"
          ? { status: "cancelled", finished_at: new Date().toISOString() }
          : { cancel_requested: true };
        await svc.from("bv_jobs").update(patch).eq("id", data.id);
        await svc.from("bv_audit").insert({ user_id: user.id, action: "os_command_cancelled", detail: { job_id: data.id } });
        return json({ ok: true });
      }
      case "jobs": {
        const { data } = await svc.from("bv_jobs").select("*").eq("user_id", user.id).order("created_at", { ascending: false }).limit(50);
        return json({ jobs: data ?? [] });
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("bv-terminal error", err);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
