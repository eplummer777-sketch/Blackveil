#!/usr/bin/env node
// Blackveil Security AI - Nmap scanner agent. Requires Node.js 18+ and the official Nmap binary.
// Env: BLACKVEIL_ENDPOINT (nmap-agent function URL), BLACKVEIL_AGENT_TOKEN, optional NMAP_PATH.
import { spawn } from 'node:child_process';
import { setPriority } from 'node:os';
import { pathToFileURL } from 'node:url';

export const AGENT_VERSION = '1.0.0';

// Must match the server's fixed profiles exactly; any other argument list is refused.
export const PROFILE_ARGS = {
  discovery: ['-sn', '-n'],
  tcp_basic: ['-sT', '-Pn', '-n', '--top-ports', '100'],
  service: ['-sT', '-Pn', '-n', '-sV', '--version-intensity', '5', '--top-ports', '100'],
  syn: ['-sS', '-Pn', '-n', '--top-ports', '1000'],
};

const TARGET_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(\/(2[4-9]|3[0-2]))?$/;
const MAX_OUTPUT = 5_000_000;

export function validateJob(job) {
  if (!job || typeof job !== 'object') return 'missing job';
  const allowed = PROFILE_ARGS[job.profile];
  if (!Object.hasOwn(PROFILE_ARGS, job.profile) || !allowed) return 'unknown profile';
  if (!Array.isArray(job.args) || job.args.length !== allowed.length || job.args.some((a, i) => a !== allowed[i])) return 'arguments do not match the allowlisted profile';
  if (!Array.isArray(job.targets) || !job.targets.length || job.targets.length > 16) return 'invalid target list';
  if (job.targets.some((t) => typeof t !== 'string' || !TARGET_RE.test(t))) return 'invalid target';
  const t = Number(job.timeout_seconds);
  if (!Number.isInteger(t) || t < 30 || t > 3600) return 'invalid timeout';
  return null;
}

export function buildArgv(job) {
  const hostTimeout = Math.min(job.timeout_seconds, 900);
  return [...PROFILE_ARGS[job.profile], '-oX', '-', '--max-retries', '2', '--host-timeout', `${hostTimeout}s`, '--max-rate', '300', '-T3', ...job.targets];
}

export function runNmap({ nmapPath, argv, timeoutMs, shouldCancel, pollMs = 5000, maxBytes = MAX_OUTPUT }) {
  return new Promise((resolve) => {
    let out = '', err = '', settled = false, timedOut = false, cancelled = false, oversized = false;
    const child = spawn(nmapPath, argv, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    try { setPriority(child.pid, 10); } catch { /* lowering priority is best-effort */ }
    const kill = () => {
      child.kill('SIGTERM');
      setTimeout(() => { if (!settled) child.kill('SIGKILL'); }, 5000).unref();
    };
    child.stdout.on('data', (d) => {
      out += d;
      if (out.length > maxBytes) { oversized = true; kill(); }
    });
    child.stderr.on('data', (d) => { if (err.length < 4000) err += d; });
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
    const poll = shouldCancel ? setInterval(async () => {
      try { if (await shouldCancel()) { cancelled = true; kill(); } } catch { /* transient network errors: keep scanning */ }
    }, pollMs) : null;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (poll) clearInterval(poll);
      resolve({ xml: out, stderr: err.slice(0, 2000), timedOut, cancelled, oversized, ...r });
    };
    child.on('error', (e) => done({ exitCode: -1, error: e.code === 'ENOENT' ? 'Nmap executable not found' : e.message }));
    child.on('close', (code, signal) => done({ exitCode: code ?? -1, signal }));
  });
}

export async function detectCapabilities(nmapPath) {
  const v = await runNmap({ nmapPath, argv: ['--version'], timeoutMs: 15000 });
  if (v.error || v.exitCode !== 0) {
    return { nmap_available: false, nmap_version: null, privileged: false, raw_capable: false, message: v.error || `nmap --version failed: ${v.stderr.trim().slice(0, 200)}` };
  }
  const version = /Nmap version ([\w.+-]+)/.exec(v.xml)?.[1] ?? 'unknown';
  const probe = await runNmap({ nmapPath, argv: ['-sS', '-p', '1', '-Pn', '-n', '--max-retries', '0', '-oX', '-', '127.0.0.1'], timeoutMs: 30000 });
  const text = probe.xml + probe.stderr;
  const raw = probe.exitCode === 0 && !/requires root privileges|Operation not permitted|QUITTING/i.test(text) && /<runstats>/.test(probe.xml);
  const root = typeof process.getuid === 'function' && process.getuid() === 0;
  return {
    nmap_available: true,
    nmap_version: version,
    privileged: root || raw,
    raw_capable: raw,
    message: raw ? 'Raw packet scanning available.' : 'Raw SYN scanning unavailable: Nmap lacks root or raw-socket privileges. TCP connect scans still work.',
  };
}

async function main() {
  const endpoint = process.env.BLACKVEIL_ENDPOINT;
  const token = process.env.BLACKVEIL_AGENT_TOKEN;
  const nmapPath = process.env.NMAP_PATH || 'nmap';
  if (!endpoint?.startsWith('https://') || !token) {
    console.error('Set BLACKVEIL_ENDPOINT (https URL of the nmap-agent function) and BLACKVEIL_AGENT_TOKEN.');
    process.exit(1);
  }
  const api = async (body) => {
    const r = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-agent-token': token }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
    if (r.status === 401) { console.error('Agent token rejected (revoked or wrong). Exiting.'); process.exit(2); }
    if (!r.ok) throw new Error(`server ${r.status}`);
    return r.json();
  };
  let health = await detectCapabilities(nmapPath);
  let healthAt = Date.now();
  const beat = () => api({ action: 'heartbeat', health: { ...health, agent_version: AGENT_VERSION, platform: `${process.platform}-${process.arch}` } });
  console.log(`[agent] ${health.message} nmap=${health.nmap_version ?? 'missing'}`);
  setInterval(() => beat().catch((e) => console.error('[agent] heartbeat failed', e.message)), 30000);
  await beat().catch((e) => console.error('[agent] heartbeat failed', e.message));

  for (;;) {
    try {
      if (Date.now() - healthAt > 600000) { health = await detectCapabilities(nmapPath); healthAt = Date.now(); await beat(); }
      const { scan } = await api({ action: 'claim' });
      if (scan) {
        const bad = validateJob(scan);
        if (bad) {
          await api({ action: 'fail', scan_id: scan.id, error: `Agent refused the job: ${bad}` });
        } else {
          console.log(`[agent] scan ${scan.id} profile=${scan.profile} targets=${scan.targets.join(',')}`);
          const r = await runNmap({
            nmapPath, argv: buildArgv(scan), timeoutMs: scan.timeout_seconds * 1000,
            shouldCancel: async () => (await api({ action: 'progress', scan_id: scan.id })).cancel === true,
          });
          if (r.cancelled) await api({ action: 'fail', scan_id: scan.id, cancelled: true });
          else if (r.error) await api({ action: 'fail', scan_id: scan.id, error: r.error });
          else if (r.timedOut) await api({ action: 'fail', scan_id: scan.id, error: `The scan exceeded its ${scan.timeout_seconds}s time limit and was stopped.` });
          else if (r.oversized) await api({ action: 'fail', scan_id: scan.id, error: 'Nmap output exceeded the size limit and the scan was stopped.' });
          else await api({ action: 'complete', scan_id: scan.id, xml: r.xml, exit_code: r.exitCode, stderr: r.stderr });
          continue;
        }
      }
    } catch (e) {
      console.error('[agent] loop error', e.message);
    }
    await new Promise((res) => setTimeout(res, 10000));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
