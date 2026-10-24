import { type ScanConfig, type TargetLike, urlInTargetScope } from "./scope.ts";
import { type AlertRow, countByRisk, groupAlerts } from "./parse.ts";
import { DISCOVERY_PATHS, discoveryCheck, extractLinks, openApiPaths, type PageResponse, passiveChecks, type RawAlert } from "./rules.ts";
import type { Patch, ScanRow } from "./lifecycle.ts";

export const ENGINE_VERSION = "Blackveil Engine 1.0";

export interface EngineState {
  queue: string[];
  visited: string[];
  alerts: RawAlert[];
}

export interface EngineDeps {
  target: TargetLike;
  fetchPage: (url: string) => Promise<PageResponse>;
  checkDns: (host: string) => Promise<void>;
  saveAlerts: (rows: AlertRow[]) => Promise<void>;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  spec?: string;
}

export type EngineScan = ScanRow & { engine_state: EngineState | null };

const STEP_BUDGET_MS = 15_000;
const PAGES_PER_STEP = 8;
const MAX_RAW_ALERTS = 3000;

function normalize(u: string): string {
  const x = new URL(u);
  x.hash = "";
  return x.toString();
}

function addAlerts(state: EngineState, list: RawAlert[]) {
  const seen = new Set(state.alerts.map((a) => `${a.pluginId}|${a.url}|${a.param}`));
  for (const a of list) {
    const key = `${a.pluginId}|${a.url}|${a.param}`;
    if (seen.has(key) || state.alerts.length >= MAX_RAW_ALERTS) continue;
    seen.add(key);
    state.alerts.push(a);
  }
}

function enqueue(state: EngineState, urls: string[], target: TargetLike, limit: number) {
  const known = new Set([...state.visited, ...state.queue]);
  for (const raw of urls) {
    if (known.size >= limit) return;
    let u: string;
    try { u = normalize(raw); } catch { continue; }
    if (known.has(u) || !urlInTargetScope(u, target)) continue;
    known.add(u);
    state.queue.push(u);
  }
}

function pageLimit(c: ScanConfig) {
  return Math.max(10, c.spider_children);
}

async function seedFromOpenApi(scan: ScanRow, deps: EngineDeps): Promise<string[]> {
  const c = scan.config.openapi;
  if (!c) return [];
  const base = new URL(scan.target_url).origin;
  if (c.source === "upload") return deps.spec ? openApiPaths(JSON.parse(deps.spec), base) : [];
  try {
    const r = await deps.fetchPage(c.url);
    return openApiPaths(JSON.parse(r.body), base);
  } catch {
    return [];
  }
}

export async function launchNative(scan: ScanRow, deps: EngineDeps): Promise<Patch & { engine_state: EngineState }> {
  await deps.checkDns(deps.target.hostname);
  const state: EngineState = { queue: [], visited: [], alerts: [] };
  enqueue(state, [scan.target_url, ...(await seedFromOpenApi(scan, deps))], deps.target, pageLimit(scan.config));
  return {
    status: "running", phase: "spider", progress: 2, phase_started_at: new Date(deps.now()).toISOString(),
    zap_version: ENGINE_VERSION, engine_state: state,
  };
}

async function finishNative(scan: EngineScan, state: EngineState, deps: EngineDeps, status: "completed" | "failed" | "cancelled", error: string | null): Promise<Patch & { engine_state: null }> {
  const { rows, dropped } = groupAlerts(state.alerts, deps.target);
  let counts: Record<string, number> | undefined;
  try {
    await deps.saveAlerts(rows);
    counts = { ...countByRisk(rows), out_of_scope_dropped: dropped, pages_scanned: state.visited.length };
  } catch {
    error = [error, "Results could not be saved."].filter(Boolean).join(" ");
    if (status === "completed") status = "failed";
  }
  return {
    status, phase: "done", progress: status === "completed" ? 100 : scan.progress, error, engine_state: null,
    finished_at: new Date(deps.now()).toISOString(), ...(counts ? { counts } : {}),
  };
}

export async function advanceNative(scan: EngineScan, deps: EngineDeps): Promise<Patch & { engine_state?: EngineState | null }> {
  if (scan.status !== "running") return {};
  const state: EngineState = scan.engine_state ?? { queue: [], visited: [], alerts: [] };
  if (scan.cancel_requested) return finishNative(scan, state, deps, "cancelled", null);
  if (deps.now() > new Date(scan.deadline_at).getTime()) {
    return finishNative(scan, state, deps, "failed", `Time limit of ${scan.config.max_minutes} minutes reached. Results found so far were saved.`);
  }
  try {
    await deps.checkDns(deps.target.hostname);
  } catch {
    return finishNative(scan, state, deps, "failed", "The target now resolves to a private or reserved address, so scanning was stopped.");
  }

  const started = deps.now();
  const limit = pageLimit(scan.config);

  if (scan.phase === "spider") {
    let n = 0;
    while (state.queue.length && n < PAGES_PER_STEP && deps.now() - started < STEP_BUDGET_MS) {
      const url = state.queue.shift()!;
      state.visited.push(url);
      n++;
      try {
        const r = await deps.fetchPage(url);
        if (!urlInTargetScope(r.url, deps.target)) continue;
        addAlerts(state, passiveChecks(r));
        enqueue(state, extractLinks(r), deps.target, limit);
      } catch { /* unreachable or out-of-scope page; keep crawling */ }
      if (scan.config.delay_ms) await deps.sleep(scan.config.delay_ms);
    }
    const total = state.visited.length + state.queue.length;
    const pct = Math.round((state.visited.length / Math.max(1, total)) * (scan.config.run_active ? 60 : 85));
    if (state.queue.length) return { progress: Math.max(2, pct), engine_state: state };
    if (!scan.config.run_active) return { phase: "collecting", progress: 90, phase_started_at: new Date(deps.now()).toISOString(), engine_state: state };
    return { phase: "active", progress: 65, phase_started_at: new Date(deps.now()).toISOString(), engine_state: state };
  }

  if (scan.phase === "active") {
    const origin = new URL(scan.target_url).origin;
    for (const path of DISCOVERY_PATHS) {
      const url = `${origin}${path}`;
      if (!urlInTargetScope(url, deps.target)) continue;
      try {
        const found = discoveryCheck(path, await deps.fetchPage(url));
        if (found) addAlerts(state, [found]);
      } catch { /* not reachable */ }
      if (scan.config.delay_ms) await deps.sleep(scan.config.delay_ms);
    }
    return { phase: "collecting", progress: 90, phase_started_at: new Date(deps.now()).toISOString(), engine_state: state };
  }

  if (scan.phase === "collecting") return finishNative(scan, state, deps, "completed", null);
  return {};
}
