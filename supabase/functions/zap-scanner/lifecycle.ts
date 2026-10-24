import { type ZapApi, ZapError } from "../_lib/zapclient.ts";
import { contextIncludeRegex, type ScanConfig, type ScanMode, type TargetLike } from "./scope.ts";
import { type AlertRow, countByRisk, groupAlerts } from "./parse.ts";

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface ScanRow {
  id: string;
  mode: ScanMode;
  status: ScanStatus;
  phase: string;
  progress: number;
  target_url: string;
  config: ScanConfig;
  zap_context: string | null;
  spider_id: string | null;
  ascan_id: string | null;
  cancel_requested: boolean;
  deadline_at: string;
  phase_started_at: string;
}

export interface Deps {
  zap: ZapApi;
  target: TargetLike;
  checkDns: (host: string) => Promise<void>;
  saveAlerts: (rows: AlertRow[]) => Promise<void>;
  now: () => number;
  spec?: string;
}

export type Patch = Partial<ScanRow> & { zap_version?: string; error?: string | null; counts?: Record<string, number>; finished_at?: string };

const ALERT_PAGE = 500;
const MAX_ALERTS = 5000;

function phase(name: string, deps: Deps, extra: Patch = {}): Patch {
  return { phase: name, phase_started_at: new Date(deps.now()).toISOString(), ...extra };
}

function percent(v: unknown): number {
  const n = Number.parseInt(String(v ?? "0"), 10);
  return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
}

export async function launch(scan: ScanRow, deps: Deps): Promise<Patch> {
  const { zap, target } = deps;
  const c = scan.config;
  await deps.checkDns(target.hostname);
  const ver = await zap.call("core", "view", "version");
  await zap.call("core", "action", "newSession", { name: `blackveil-${scan.id}`, overwrite: true });
  const ctxName = `bv-${scan.id}`;
  const ctx = await zap.call("context", "action", "newContext", { contextName: ctxName });
  const contextId = String(ctx.contextId ?? "");
  await zap.call("context", "action", "includeInContext", { contextName: ctxName, regex: contextIncludeRegex(target) });
  await zap.call("context", "action", "setContextInScope", { contextName: ctxName, booleanInScope: true });
  await zap.call("spider", "action", "setOptionMaxDuration", { Integer: c.spider_minutes });
  await zap.call("spider", "action", "setOptionMaxDepth", { Integer: c.spider_depth });
  await zap.call("spider", "action", "setOptionMaxChildren", { Integer: c.spider_children });
  await zap.call("spider", "action", "setOptionThreadCount", { Integer: c.threads_per_host });
  await zap.call("ascan", "action", "setOptionThreadPerHost", { Integer: c.threads_per_host });
  await zap.call("ascan", "action", "setOptionDelayInMs", { Integer: c.delay_ms });
  await zap.call("ascan", "action", "setOptionMaxScanDurationInMins", { Integer: c.ascan_minutes });
  await zap.call("ascan", "action", "setOptionMaxRuleDurationInMins", { Integer: c.ascan_rule_minutes });

  const origin = new URL(scan.target_url).origin;
  if (c.openapi?.source === "url") {
    await zap.call("openapi", "action", "importUrl", { url: c.openapi.url, hostOverride: new URL(origin).host, contextId });
  } else if (c.openapi?.source === "upload") {
    if (!deps.spec) throw new ZapError("The uploaded OpenAPI file is no longer available. Start the scan again.", "api");
    const path = await zap.upload(`openapi-${scan.id}.json`, deps.spec);
    await zap.call("openapi", "action", "importFile", { file: path, target: origin, contextId });
  }

  const sp = await zap.call("spider", "action", "scan", { url: scan.target_url, maxChildren: c.spider_children, recurse: true, contextName: ctxName, subtreeOnly: true });
  return phase("spider", deps, {
    status: "running", progress: 2, zap_context: contextId || ctxName, spider_id: String(sp.scan ?? ""),
    zap_version: String(ver.version ?? "unknown"),
  });
}

async function stopJobs(scan: ScanRow, zap: ZapApi) {
  if (scan.spider_id) await zap.call("spider", "action", "stop", { scanId: scan.spider_id }).catch(() => {});
  if (scan.ascan_id) await zap.call("ascan", "action", "stop", { scanId: scan.ascan_id }).catch(() => {});
}

async function collect(scan: ScanRow, deps: Deps): Promise<{ counts: Record<string, number> }> {
  const raw: unknown[] = [];
  const baseurl = new URL(scan.target_url).origin;
  for (let start = 0; start < MAX_ALERTS; start += ALERT_PAGE) {
    const page = await deps.zap.call("core", "view", "alerts", { baseurl, start, count: ALERT_PAGE });
    const list = Array.isArray(page.alerts) ? page.alerts : [];
    raw.push(...list);
    if (list.length < ALERT_PAGE) break;
  }
  const { rows, dropped } = groupAlerts(raw, deps.target);
  await deps.saveAlerts(rows);
  return { counts: { ...countByRisk(rows), out_of_scope_dropped: dropped } };
}

async function finish(scan: ScanRow, deps: Deps, status: ScanStatus, error: string | null): Promise<Patch> {
  let counts: Record<string, number> | undefined;
  try {
    counts = (await collect(scan, deps)).counts;
  } catch (e) {
    error = [error, `Results could not be collected: ${e instanceof Error ? e.message : "unknown error"}`].filter(Boolean).join(" ");
    if (status === "completed") status = "failed";
  }
  return { status, phase: "done", progress: status === "completed" ? 100 : scan.progress, error, finished_at: new Date(deps.now()).toISOString(), ...(counts ? { counts } : {}) };
}

export async function advance(scan: ScanRow, deps: Deps): Promise<Patch> {
  if (scan.status !== "running") return {};
  const { zap } = deps;

  if (scan.cancel_requested) {
    await stopJobs(scan, zap);
    return finish(scan, deps, "cancelled", null);
  }
  if (deps.now() > new Date(scan.deadline_at).getTime()) {
    await stopJobs(scan, zap);
    return finish(scan, deps, "failed", `Time limit of ${scan.config.max_minutes} minutes reached. Results found so far were saved.`);
  }
  try {
    await deps.checkDns(deps.target.hostname);
  } catch {
    await stopJobs(scan, zap);
    return finish(scan, deps, "failed", "The target now resolves to a private or reserved address, so scanning was stopped.");
  }

  if (scan.phase === "spider") {
    const st = percent((await zap.call("spider", "view", "status", { scanId: scan.spider_id ?? "" })).status);
    if (st < 100) return { progress: Math.max(2, Math.round(st * 0.3)) };
    return phase("passive", deps, { progress: 30 });
  }
  if (scan.phase === "passive") {
    const left = percent((await zap.call("pscan", "view", "recordsToScan")).recordsToScan);
    const waited = deps.now() - new Date(scan.phase_started_at).getTime();
    if (left > 0 && waited < scan.config.passive_wait_seconds * 1000) return { progress: 35 };
    if (!scan.config.run_active) return phase("collecting", deps, { progress: 90 });
    const as = await zap.call("ascan", "action", "scan", { url: scan.target_url, recurse: true, inScopeOnly: true, contextId: scan.zap_context ?? "" });
    return phase("active", deps, { progress: 40, ascan_id: String(as.scan ?? "") });
  }
  if (scan.phase === "active") {
    const st = percent((await zap.call("ascan", "view", "status", { scanId: scan.ascan_id ?? "" })).status);
    if (st < 100) return { progress: 40 + Math.round(st * 0.5) };
    return phase("collecting", deps, { progress: 90 });
  }
  if (scan.phase === "collecting") return finish(scan, deps, "completed", null);
  return {};
}
