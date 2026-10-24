import type { getServiceClient } from "../_lib/auth.ts";
import { analyzeScan } from "./ai.ts";
import { denoDialer } from "./dialer.ts";
import {
  buildHosts, type FinalStatus, finalStatus, NATIVE_PROFILES, type NativeScan, type NativeState, progressOf,
  runSlice, scanBudgetEnd, summarizeNative,
} from "./native.ts";

export type Svc = ReturnType<typeof getServiceClient>;

export const SLICE_MS = 35_000;
const LEASE_MS = SLICE_MS + 25_000;
const STALE_GRACE_MS = 60_000;

export async function audit(svc: Svc, userId: string | null, actor: string, action: string, detail: Record<string, unknown>, scanId?: string) {
  await svc.from("nmap_audit").insert({ user_id: userId, actor, action, detail, scan_id: scanId ?? null });
}

type ScanRow = NativeScan & { id: string; user_id: string; target_input: string; target_kind: string; summary: unknown };

async function runAi(svc: Svc, scan: ScanRow, hosts: ReturnType<typeof buildHosts>) {
  const left = new Date(scan.deadline_at).getTime() - Date.now();
  if (left < 8000) {
    await svc.from("nmap_scans").update({ ai_status: "none" }).eq("id", scan.id);
    return;
  }
  await svc.from("nmap_scans").update({ ai_status: "pending", ai_error: null }).eq("id", scan.id);
  try {
    const { analysis, model } = await analyzeScan(scan, hosts, Math.min(40_000, left - 3000));
    await svc.from("nmap_scans").update({ ai_status: "ready", ai_analysis: { ...analysis, model, generated_at: new Date().toISOString() } }).eq("id", scan.id);
    await svc.from("ai_usage").insert({ user_id: scan.user_id, feature: "network_analyst", model }).then(() => {}, () => {});
  } catch (err) {
    console.error("native ai failed", err);
    await svc.from("nmap_scans").update({ ai_status: "failed", ai_error: "The AI analyst did not finish in time. Your results are saved; you can run the analysis again." }).eq("id", scan.id);
  }
}

export async function finalize(svc: Svc, scan: ScanRow, state: NativeState, status: FinalStatus, opts: { error?: string; ai: boolean; actor?: string }) {
  const hostnames = scan.target_kind === "hostname" ? Object.fromEntries(scan.targets.map((ip) => [ip, [scan.target_input]])) : {};
  const hosts = buildHosts(state, scan.targets, hostnames);
  const elapsed = Date.now() - new Date(scan.started_at).getTime();
  const summary = summarizeNative(state, scan.targets, status, elapsed);
  const { data: won } = await svc.from("nmap_scans").update({
    status, summary, engine_state: state, progress: progressOf(state), finished_at: new Date().toISOString(),
    duration_ms: elapsed, lease_until: null, error: opts.error ?? null,
  }).eq("id", scan.id).eq("status", "running").select("id").maybeSingle();
  if (!won) return null;
  if (hosts.length) await svc.from("nmap_hosts").insert(hosts.map((h) => ({ ...h, scan_id: scan.id, user_id: scan.user_id })));
  await audit(svc, scan.user_id, opts.actor ?? "system", "scan_finished", { status, open: summary.open, checked: summary.checked, planned: summary.planned, rejected: summary.rejected }, scan.id);
  if (opts.ai && status !== "cancelled") await runAi(svc, { ...scan, summary }, hosts);
  return summary;
}

export async function stepNative(svc: Svc, scanId: string, userId: string) {
  const nowIso = new Date().toISOString();
  const { data: scan } = await svc.from("nmap_scans").update({ lease_until: new Date(Date.now() + LEASE_MS).toISOString(), heartbeat_at: nowIso })
    .eq("id", scanId).eq("user_id", userId).eq("engine", "native").eq("status", "running")
    .or(`lease_until.is.null,lease_until.lt.${nowIso}`).select("*").maybeSingle();
  if (!scan) return;
  const row = scan as ScanRow & { cancel_requested: boolean };
  if (row.cancel_requested) {
    await finalize(svc, row, row.engine_state ?? { next: 0, total: 0, results: {}, rejected: [] }, "cancelled", { ai: false, actor: "user" });
    return;
  }
  let cancelled = false;
  const state = await runSlice(row, denoDialer, {
    sliceEndMs: Date.now() + SLICE_MS,
    isCancelled: async () => {
      const { data } = await svc.from("nmap_scans").select("cancel_requested, status").eq("id", scanId).maybeSingle();
      cancelled = !data || !!data.cancel_requested || data.status !== "running";
      return cancelled;
    },
  });
  const outOfTime = Date.now() >= scanBudgetEnd(row) - 1000;
  if (cancelled || state.next >= state.total || outOfTime) {
    const status = finalStatus(state, cancelled);
    const error = status === "partial" ? `Time limit reached (${NATIVE_PROFILES[row.profile].deadlineSec}s). Results are partial.` : undefined;
    await finalize(svc, row, state, status, { error, ai: true, actor: cancelled ? "user" : "system" });
    return;
  }
  await svc.from("nmap_scans").update({ engine_state: state, progress: progressOf(state), heartbeat_at: new Date().toISOString(), lease_until: null })
    .eq("id", scanId).eq("status", "running");
}

const DRIVE_BUDGET_MS = 110_000;

export async function driveNative(svc: Svc, scanId: string, userId: string) {
  const until = Date.now() + DRIVE_BUDGET_MS;
  while (Date.now() + SLICE_MS + 10_000 < until) {
    await stepNative(svc, scanId, userId);
    const { data } = await svc.from("nmap_scans").select("status").eq("id", scanId).maybeSingle();
    if (data?.status !== "running") return;
  }
}

export function inBackground(p: Promise<unknown>) {
  const rt = (globalThis as { EdgeRuntime?: { waitUntil(p: Promise<unknown>): void } }).EdgeRuntime;
  const guarded = p.catch((e) => console.error("native background step failed", e));
  if (rt) rt.waitUntil(guarded);
}

export async function expireNative(svc: Svc) {
  const { data } = await svc.from("nmap_scans").select("*").eq("engine", "native").eq("status", "running");
  const now = Date.now();
  for (const s of (data ?? []) as (ScanRow & { lease_until: string | null })[]) {
    const leaseActive = s.lease_until && new Date(s.lease_until).getTime() > now;
    if (leaseActive || now < new Date(s.deadline_at).getTime() + STALE_GRACE_MS) continue;
    const state = s.engine_state ?? { next: 0, total: 0, results: {}, rejected: [] };
    await finalize(svc, s, state, state.total && state.next >= state.total ? "completed" : "partial",
      { error: "The scan stopped receiving work before finishing (the page was closed). Results are partial.", ai: false });
  }
}
