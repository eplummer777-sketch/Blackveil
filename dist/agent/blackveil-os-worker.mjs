#!/usr/bin/env node
// Blackveil OS - isolated Linux execution worker.
// Runs every terminal command in its own fresh, throwaway Docker container with
// no network, a read-only root filesystem, a non-root user, dropped capabilities
// and strict CPU / memory / process / time limits. No secrets or host paths are
// passed into the container.
//
// Requirements: Linux, Node.js 18+, Docker Engine usable by the current user.
// Env:
//   BLACKVEIL_ENDPOINT      https://<project>.supabase.co/functions/v1/bv-worker
//   BLACKVEIL_WORKER_TOKEN  bvos_... token shown once when the worker is registered
//   BVOS_IMAGE              optional, container image (default busybox:1.36)
import { spawn, spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const WORKER_VERSION = "1.1.0";
export const EXEC_TIMEOUT_MS = 30_000;
export const MAX_OUTPUT = 60_000;
const MAX_CMD_LEN = 400;
const SELFTEST_EVERY_MS = 10 * 60_000;

export function validateCommand(cmd) {
  if (typeof cmd !== "string" || !cmd.trim()) return "empty command";
  if (cmd.length > MAX_CMD_LEN) return "command too long";
  if (/[\x00-\x1f\x7f]/.test(cmd)) return "invalid characters";
  if (/[;&|<>`]|\$\(/.test(cmd)) return "shell operators are not allowed";
  return null;
}

export function sandboxArgs(image, name, cmd) {
  return [
    "run", "--rm", "--name", name, "--pull", "never",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--user", "65534:65534",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "64",
    "--memory", "64m", "--memory-swap", "64m",
    "--cpus", "0.5",
    "--ulimit", "nofile=256:256",
    "--hostname", "blackveil-os",
    "--workdir", "/tmp",
    image, "sh", "-c", cmd,
  ];
}

function dockerVersion() {
  const r = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8", timeout: 15_000 });
  return r.status === 0 ? (r.stdout || "unknown").trim() : null;
}

function ensureImage(image) {
  if (spawnSync("docker", ["image", "inspect", image], { stdio: "ignore", timeout: 15_000 }).status === 0) return true;
  console.log(`[bv-os] pulling ${image} ...`);
  return spawnSync("docker", ["pull", image], { stdio: "inherit", timeout: 300_000 }).status === 0;
}

export function runInSandbox(image, cmd, { name, timeoutMs = EXEC_TIMEOUT_MS, onTick } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const out = { stdout: "", stderr: "" };
    let timedOut = false;
    let cancelled = false;
    let spawnError = null;
    const child = spawn("docker", sandboxArgs(image, name, cmd), { stdio: ["ignore", "pipe", "pipe"] });
    const take = (key) => (chunk) => {
      if (out[key].length < MAX_OUTPUT) out[key] += chunk.toString("utf8").slice(0, MAX_OUTPUT - out[key].length);
    };
    child.stdout.on("data", take("stdout"));
    child.stderr.on("data", take("stderr"));
    const stop = () => {
      spawnSync("docker", ["kill", name], { stdio: "ignore", timeout: 15_000 });
      child.kill("SIGKILL");
    };
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    const tick = onTick ? setInterval(async () => {
      if (await onTick().catch(() => false)) { cancelled = true; stop(); }
    }, 3000) : null;
    child.on("error", (e) => { spawnError = e.message; });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (tick) clearInterval(tick);
      resolve({
        ...out,
        exitCode: code,
        durationMs: Date.now() - started,
        timedOut,
        cancelled,
        // 125 = docker itself failed (daemon, image, flags), not the user's command
        dockerError: spawnError ?? (code === 125 && !timedOut && !cancelled ? out.stderr.trim().slice(0, 300) || "docker run failed" : null),
      });
    });
  });
}

export function parseSelfTest(stdout) {
  const lines = stdout.trim().split(/\s+/).filter(Boolean);
  const uid = lines[0] ?? "";
  const nets = lines.slice(1);
  return { uid, networkIsolated: nets.length === 1 && nets[0] === "lo" };
}

async function selfTest(image) {
  const caps = {
    docker: false, docker_version: null, image, platform: `${process.platform}-${process.arch}`,
    node: process.version, sandbox_ok: false, sandbox_error: null, selftest_uid: null, network_isolated: false,
  };
  const dv = dockerVersion();
  if (!dv) { caps.sandbox_error = "Docker is not running or this user cannot access it."; return caps; }
  caps.docker = true;
  caps.docker_version = dv;
  if (!ensureImage(image)) { caps.sandbox_error = `Could not pull the image ${image}.`; return caps; }
  const r = await runInSandbox(image, "id -u; ls /sys/class/net", { name: `bvos-selftest-${process.pid}`, timeoutMs: 60_000 });
  if (r.dockerError || r.exitCode !== 0) {
    caps.sandbox_error = `Sandbox self-test failed: ${(r.dockerError || r.stderr || `exit ${r.exitCode}`).slice(0, 200)}`;
    return caps;
  }
  const t = parseSelfTest(r.stdout);
  caps.selftest_uid = t.uid;
  caps.network_isolated = t.networkIsolated;
  if (t.uid !== "65534") caps.sandbox_error = `Sandbox is not running as the unprivileged user (uid ${t.uid}).`;
  else if (!t.networkIsolated) caps.sandbox_error = "Sandbox still has a network interface; refusing to run commands.";
  else caps.sandbox_ok = true;
  return caps;
}

async function main() {
  const endpoint = process.env.BLACKVEIL_ENDPOINT ?? "";
  const token = process.env.BLACKVEIL_WORKER_TOKEN ?? "";
  const image = process.env.BVOS_IMAGE || "busybox:1.36";
  if (!/^https:\/\/.+\/functions\/v1\/bv-worker$/.test(endpoint) || !/^bvos_[A-Za-z0-9_-]{40,60}$/.test(token)) {
    console.error("[bv-os] Set BLACKVEIL_ENDPOINT (https://<project>.supabase.co/functions/v1/bv-worker) and BLACKVEIL_WORKER_TOKEN (bvos_...).");
    process.exit(1);
  }

  const api = async (body) => {
    const r = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-worker-token": token },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (r.status === 401) {
      console.error("[bv-os] UNAUTHORIZED: the token was rejected (revoked or mistyped). Register a new worker and update the token.");
      process.exit(2);
    }
    if (!r.ok) throw new Error(`server responded ${r.status}`);
    return r.json();
  };

  let caps = await selfTest(image);
  let lastTest = Date.now();
  console.log(`[bv-os] worker ${WORKER_VERSION} docker=${caps.docker_version ?? "MISSING"} image=${image} sandbox=${caps.sandbox_ok ? "OK" : caps.sandbox_error}`);

  const beat = async () => {
    const r = await api({ action: "heartbeat", version: WORKER_VERSION, caps });
    console.log(`[bv-os] heartbeat: ${r.state} - ${r.reason}`);
  };
  await beat().catch((e) => console.error("[bv-os] heartbeat failed:", e.message));
  setInterval(() => beat().catch((e) => console.error("[bv-os] heartbeat failed:", e.message)), 30_000);

  let lastState = "";
  for (;;) {
    try {
      if (Date.now() - lastTest > (caps.sandbox_ok ? SELFTEST_EVERY_MS : 60_000)) {
        caps = await selfTest(image);
        lastTest = Date.now();
        await beat();
      }
      const res = await api({ action: "claim" });
      const state = res.state ?? "online";
      if (state !== lastState) { console.log(`[bv-os] ${state}${res.reason ? `: ${res.reason}` : ""}`); lastState = state; }
      const job = res.job;
      if (job) {
        const bad = validateCommand(job.command);
        if (bad) {
          await api({ action: "fail", job_id: job.id, error: `Worker refused: ${bad}` });
          continue;
        }
        console.log(`[bv-os] run ${job.id}: ${job.command}`);
        const run = await runInSandbox(image, job.command, {
          name: `bvos-${job.id}`,
          onTick: async () => (await api({ action: "progress", job_id: job.id })).cancel === true,
        });
        const base = { job_id: job.id, stdout: run.stdout, stderr: run.stderr, duration_ms: run.durationMs };
        if (run.cancelled) await api({ ...base, action: "fail", cancelled: true });
        else if (run.timedOut) await api({ ...base, action: "fail", error: `Stopped after ${EXEC_TIMEOUT_MS / 1000}s time limit.` });
        else if (run.dockerError) {
          await api({ ...base, action: "fail", error: `Sandbox error: ${run.dockerError}` });
          caps.sandbox_ok = false;
          caps.sandbox_error = `Last run failed inside Docker: ${run.dockerError}`.slice(0, 300);
          await beat();
        } else await api({ ...base, action: "complete", exit_code: run.exitCode });
        console.log(`[bv-os] done ${job.id}: exit=${run.exitCode} ${run.durationMs}ms`);
        continue;
      }
    } catch (e) {
      console.error("[bv-os] loop error:", e.message);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
