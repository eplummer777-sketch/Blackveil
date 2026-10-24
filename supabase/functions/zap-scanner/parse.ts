import { type TargetLike, urlInTargetScope } from "./scope.ts";

export type Risk = "high" | "medium" | "low" | "info";

export interface AlertInstance {
  url: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
}

export interface AlertRow {
  plugin_id: string;
  name: string;
  risk: Risk;
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  other_info: string;
  cwe_id: number | null;
  wasc_id: number | null;
  source: string;
  instance_count: number;
  instances: AlertInstance[];
}

const MAX_INSTANCES = 25;

export function riskFromZap(v: unknown): Risk {
  const s = String(v ?? "").toLowerCase();
  if (s === "high" || s === "3") return "high";
  if (s === "medium" || s === "2") return "medium";
  if (s === "low" || s === "1") return "low";
  return "info";
}

const str = (v: unknown, max: number) => (typeof v === "string" ? v : v == null ? "" : String(v)).slice(0, max);

export function redact(s: string): string {
  return s
    .replace(/((?:set-)?cookie\s*:\s*[^=;\s]+=)[^;\s]+/gi, "$1[redacted]")
    .replace(/(authorization\s*:\s*\w+\s+)\S+/gi, "$1[redacted]")
    .replace(/((?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?)[^"'&\s]{4,}/gi, "$1[redacted]");
}

function toInt(v: unknown): number | null {
  const n = Number.parseInt(String(v ?? ""), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function groupAlerts(raw: unknown[], target: TargetLike): { rows: AlertRow[]; dropped: number } {
  const byPlugin = new Map<string, AlertRow>();
  let dropped = 0;
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const a = item as Record<string, unknown>;
    const url = str(a.url, 2048);
    if (!urlInTargetScope(url, target)) {
      dropped++;
      continue;
    }
    const pluginId = str(a.pluginId, 20) || "unknown";
    let row = byPlugin.get(pluginId);
    if (!row) {
      row = {
        plugin_id: pluginId,
        name: str(a.alert ?? a.name, 200) || "Unnamed alert",
        risk: riskFromZap(a.risk),
        confidence: str(a.confidence, 20).toLowerCase() || "medium",
        description: str(a.description, 4000),
        solution: str(a.solution, 4000),
        reference: str(a.reference, 2000),
        other_info: redact(str(a.other, 2000)),
        cwe_id: toInt(a.cweid),
        wasc_id: toInt(a.wascid),
        source: String(a.sourceid ?? "") === "1" ? "active" : "passive",
        instance_count: 0,
        instances: [],
      };
      byPlugin.set(pluginId, row);
    }
    row.instance_count++;
    if (row.instances.length < MAX_INSTANCES) {
      row.instances.push({
        url,
        method: str(a.method, 10),
        param: str(a.param, 200),
        attack: redact(str(a.attack, 300)),
        evidence: redact(str(a.evidence, 500)),
      });
    }
  }
  const order: Record<Risk, number> = { high: 0, medium: 1, low: 2, info: 3 };
  const rows = [...byPlugin.values()].sort((x, y) => order[x.risk] - order[y.risk]);
  return { rows, dropped };
}

export function countByRisk(rows: AlertRow[]): Record<Risk | "total", number> {
  const c = { high: 0, medium: 0, low: 0, info: 0, total: rows.length };
  for (const r of rows) c[r.risk]++;
  return c;
}
