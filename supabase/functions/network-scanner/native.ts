import { addressInTargets, cidrRange, hitsAlwaysBlocked } from "../_lib/nmap.ts";
import { QUICK_PORTS, STANDARD_PORTS } from "./fingerprints.ts";
import { DialError, type Dialer, type PortResult, probePort } from "./probe.ts";

export const NATIVE_VERSION = "Blackveil Discovery 1.0";

export type NativeProfile = "native_quick" | "native_standard";

export interface NativeProfileDef {
  label: string;
  ports: number[];
  deadlineSec: number;
  reserveSec: number;
  concurrency: number;
  connectTimeoutMs: number;
  bannerTimeoutMs: number;
  maxTargets: number;
}

export const EGRESS_BLOCKED_PORTS = [25, 587];
const allowed = (ports: number[]) => ports.filter((p) => !EGRESS_BLOCKED_PORTS.includes(p));

export const NATIVE_PROFILES: Record<NativeProfile, NativeProfileDef> = {
  native_quick: { label: "Quick discovery", ports: allowed(QUICK_PORTS), deadlineSec: 90, reserveSec: 25, concurrency: 24, connectTimeoutMs: 2000, bannerTimeoutMs: 1500, maxTargets: 4 },
  native_standard: { label: "Standard discovery", ports: allowed(STANDARD_PORTS), deadlineSec: 600, reserveSec: 40, concurrency: 32, connectTimeoutMs: 2500, bannerTimeoutMs: 2000, maxTargets: 16 },
};

export const isNativeProfile = (p: unknown): p is NativeProfile => p === "native_quick" || p === "native_standard";

export interface NativeState {
  next: number;
  total: number;
  results: Record<string, PortResult[]>;
  rejected: string[];
}

export interface NativeScan {
  profile: NativeProfile;
  targets: string[];
  started_at: string;
  deadline_at: string;
  engine_state: NativeState | null;
}

export interface HostRow {
  address: string;
  hostnames: string[];
  state: "up" | "unknown";
  reason: string;
  ports: PortResult[];
  extraports: { state: string; count: number }[];
}

const intToIp = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

export function expandTargets(targets: string[], max: number): string[] | { error: string } {
  const out = new Set<string>();
  for (const t of targets) {
    const r = cidrRange(t);
    if (!r) return { error: "A target could not be read." };
    const size = r.end - r.start + 1;
    const [start, end] = size > 2 ? [r.start + 1, r.end - 1] : [r.start, r.end];
    if (out.size + (end - start + 1) > max) return { error: `This profile scans at most ${max} addresses. Use a smaller range (for example a /28).` };
    for (let n = start; n <= end; n++) out.add(intToIp(n >>> 0));
  }
  return [...out];
}

export function initialState(targets: string[], profile: NativeProfile): NativeState {
  return { next: 0, total: targets.length * NATIVE_PROFILES[profile].ports.length, results: {}, rejected: [] };
}

export const scanBudgetEnd = (s: Pick<NativeScan, "deadline_at" | "profile">) =>
  new Date(s.deadline_at).getTime() - NATIVE_PROFILES[s.profile].reserveSec * 1000;

export const maxProbeMs = (p: NativeProfileDef) => 2 * (p.connectTimeoutMs + p.bannerTimeoutMs) + 500;

export function guardDialer(inner: Dialer, targets: string[]): Dialer {
  const check = (ip: string) => {
    const r = cidrRange(`${ip}/32`);
    if (!r || hitsAlwaysBlocked(r) || !addressInTargets(ip, targets)) throw new DialError("blocked", `Address ${ip} is outside the authorized scope`);
  };
  return {
    tcp: async (ip, port, t) => { check(ip); return await inner.tcp(ip, port, t); },
    tls: inner.tls ? async (ip, port, sn, t) => { check(ip); return await inner.tls!(ip, port, sn, t); } : undefined,
  };
}

export interface SliceOptions {
  sliceEndMs: number;
  isCancelled: () => Promise<boolean> | boolean;
  now?: () => number;
  serverName?: string;
}

export async function runSlice(scan: NativeScan, dialer: Dialer, o: SliceOptions): Promise<NativeState> {
  const p = NATIVE_PROFILES[scan.profile];
  const now = o.now ?? Date.now;
  const state: NativeState = structuredClone(scan.engine_state ?? initialState(scan.targets, scan.profile));
  const stopAt = Math.min(o.sliceEndMs, scanBudgetEnd(scan)) - maxProbeMs(p);
  const guarded = guardDialer(dialer, scan.targets);
  let cancelled = false;
  let lastCancelCheck = now();

  const worker = async () => {
    while (!cancelled && state.next < state.total && now() < stopAt) {
      if (now() - lastCancelCheck > 3000) {
        lastCancelCheck = now();
        if (await o.isCancelled()) { cancelled = true; break; }
      }
      const i = state.next++;
      const ip = scan.targets[Math.floor(i / p.ports.length)];
      const port = p.ports[i % p.ports.length];
      try {
        const r = await probePort(guarded, ip, port, {
          connectTimeoutMs: p.connectTimeoutMs, bannerTimeoutMs: p.bannerTimeoutMs, identify: true, serverName: o.serverName,
        });
        (state.results[ip] ??= []).push(r);
      } catch (e) {
        if (e instanceof DialError && e.kind === "blocked" && !state.rejected.includes(ip)) state.rejected.push(ip);
      }
    }
  };
  await Promise.all(Array.from({ length: p.concurrency }, worker));
  return state;
}

export function buildHosts(state: NativeState, targets: string[], hostnames: Record<string, string[]> = {}): HostRow[] {
  return targets.filter((ip) => state.results[ip]?.length).map((ip) => {
    const ports = [...state.results[ip]].sort((a, b) => a.port - b.port);
    const responded = ports.some((r) => r.state !== "filtered");
    const visible = ports.filter((r) => r.state === "open");
    const closed = ports.filter((r) => r.state === "closed").length;
    const filtered = ports.filter((r) => r.state === "filtered").length;
    const extraports = [
      ...(closed ? [{ state: "closed", count: closed }] : []),
      ...(filtered ? [{ state: "filtered", count: filtered }] : []),
    ];
    return {
      address: ip,
      hostnames: hostnames[ip] ?? [],
      state: responded ? "up" : "unknown",
      reason: responded ? "tcp-response" : "no-response",
      ports: visible,
      extraports,
    };
  });
}

export type FinalStatus = "completed" | "partial" | "cancelled";

export function finalStatus(state: NativeState, cancelled: boolean): FinalStatus {
  if (cancelled) return "cancelled";
  return state.next >= state.total ? "completed" : "partial";
}

export function summarizeNative(state: NativeState, targets: string[], status: FinalStatus, elapsedMs: number) {
  let open = 0, closed = 0, filtered = 0, services = 0, up = 0;
  for (const ip of targets) {
    const rs = state.results[ip] ?? [];
    if (rs.some((r) => r.state !== "filtered")) up++;
    for (const r of rs) {
      if (r.state === "open") { open++; if (r.service && r.confidence !== "low") services++; }
      else if (r.state === "closed") closed++;
      else filtered++;
    }
  }
  const checked = open + closed + filtered;
  const complete = status === "completed";
  let note: string;
  if (!complete) note = `Coverage incomplete: ${checked} of ${state.total} port checks finished. Unchecked ports are unknown, not safe.`;
  else if (open === 0) note = "No open ports were observed on the ports checked. This is not proof the target is secure: other ports, UDP, and filtered services were not covered.";
  else note = "Open ports show reachable services only. An open port is not a breach or a confirmed vulnerability.";
  return {
    engine: NATIVE_VERSION, hosts_up: up, hosts_down: 0, hosts_total: targets.length, hosts_unknown: targets.length - up,
    open, closed, filtered, services, checked, planned: state.total, complete, rejected: state.rejected,
    elapsed: Math.round(elapsedMs / 100) / 10, coverage_note: note,
  };
}

export const progressOf = (s: NativeState) => (s.total ? Math.min(100, Math.floor((s.next / s.total) * 100)) : 100);
