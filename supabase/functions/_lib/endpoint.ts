export type ScanType = "quick" | "full" | "custom";
export type ThreatStatus =
  | "detected" | "awaiting_approval" | "quarantined" | "removed" | "failed" | "restored" | "verified_clean";

export const SCAN_TYPES: ScanType[] = ["quick", "full", "custom"];
export const MAX_THREATS_PER_REPORT = 200;
export const MAX_RESOURCES_PER_THREAT = 25;

// Minutes a dispatched job may run before it is treated as interrupted.
export function jobTimeoutMinutes(kind: string, scanType?: string): number {
  if (kind === "scan") return scanType === "full" ? 480 : scanType === "custom" ? 90 : 45;
  if (kind === "verify") return 60;
  if (kind === "remediate") return 20;
  return 10;
}

export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function newDeviceToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return "bvd_" + btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function normalizeWindowsPath(p: string): string {
  return p.trim().replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
}

export function validatePaths(raw: unknown): string[] | null {
  if (!Array.isArray(raw) || raw.length > 10) return null;
  const out: string[] = [];
  for (const p of raw) {
    if (typeof p !== "string") return null;
    const t = p.trim();
    if (!/^[a-zA-Z]:\\[^<>"|?*\x00-\x1f]{0,255}$/.test(t) || t.includes("..")) return null;
    out.push(t);
  }
  return out;
}

export function isScopeAllowed(
  device: { allowed_scopes: string[]; allowed_paths: string[] },
  scanType: string,
  path?: string,
): boolean {
  if (!SCAN_TYPES.includes(scanType as ScanType) || !device.allowed_scopes.includes(scanType)) return false;
  if (scanType !== "custom") return true;
  if (!path) return false;
  const target = normalizeWindowsPath(path);
  return device.allowed_paths.some((a) => {
    const base = normalizeWindowsPath(a);
    return target === base || target.startsWith(base + "\\");
  });
}

// Microsoft Defender SeverityID values.
export function mapSeverity(id: unknown): string {
  switch (Number(id)) {
    case 5: return "critical";
    case 4: return "high";
    case 2: return "medium";
    case 1: return "low";
    default: return "unknown";
  }
}

// Microsoft Defender ThreatStatusID values (MSFT_MpThreatDetection).
export function mapEngineStatus(id: unknown): { status: ThreatStatus; action: string } {
  switch (Number(id)) {
    case 2: return { status: "removed", action: "cleaned" };
    case 3: return { status: "quarantined", action: "quarantined" };
    case 4: return { status: "removed", action: "removed" };
    case 6: return { status: "quarantined", action: "blocked" };
    case 102: return { status: "failed", action: "quarantine_failed" };
    case 103: return { status: "failed", action: "remove_failed" };
    case 107: return { status: "failed", action: "block_failed" };
    case 5: return { status: "detected", action: "allowed_by_user" };
    default: return { status: "detected", action: "detected" };
  }
}

export function isTestSignature(name: string): boolean {
  return /eicar/i.test(name);
}

const str = (v: unknown, max: number): string | null =>
  typeof v === "string" && v.length > 0 ? v.slice(0, max) : null;

export interface ReportedThreat {
  threatId: string;
  name: string;
  severity: string;
  category: string | null;
  resources: string[];
  sha256: string | null;
  active: boolean;
  engineStatusId: number | null;
}

export function validateThreats(raw: unknown): ReportedThreat[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_THREATS_PER_REPORT) return null;
  const out: ReportedThreat[] = [];
  for (const t of raw) {
    if (!t || typeof t !== "object") return null;
    const r = t as Record<string, unknown>;
    const threatId = typeof r.threatId === "number" || typeof r.threatId === "string" ? String(r.threatId).slice(0, 40) : null;
    const name = str(r.name, 300);
    if (!threatId || !/^\d+$/.test(threatId) || !name) return null;
    const resources = Array.isArray(r.resources)
      ? r.resources.filter((x): x is string => typeof x === "string").slice(0, MAX_RESOURCES_PER_THREAT).map((x) => x.slice(0, 600))
      : [];
    const sha = typeof r.sha256 === "string" && /^[a-fA-F0-9]{64}$/.test(r.sha256) ? r.sha256.toLowerCase() : null;
    out.push({
      threatId,
      name,
      severity: mapSeverity(r.severityId),
      category: str(r.category, 80),
      resources,
      sha256: sha,
      active: r.active === true,
      engineStatusId: Number.isFinite(Number(r.statusId)) && r.statusId !== null ? Number(r.statusId) : null,
    });
  }
  return out;
}

export interface EngineStatus {
  antivirusEnabled: boolean;
  realTimeProtection: boolean;
  runningMode: string | null;
  signatureVersion: string | null;
  signatureUpdated: string | null;
}

export function validateEngineStatus(raw: unknown): EngineStatus | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  return {
    antivirusEnabled: r.antivirusEnabled === true,
    realTimeProtection: r.realTimeProtection === true,
    runningMode: str(r.runningMode, 40),
    signatureVersion: str(r.signatureVersion, 40),
    signatureUpdated: str(r.signatureUpdated, 40),
  };
}

// Status for a threat seen in a fresh scan, given what we already knew.
export function statusAfterScan(prev: ThreatStatus | null, t: ReportedThreat): ThreatStatus {
  if (t.active) return "awaiting_approval";
  // Defender keeps historical detections; an inactive old record must not undo a later verified outcome.
  if (prev === "verified_clean" || prev === "restored") return prev;
  if (t.engineStatusId !== null) {
    const mapped = mapEngineStatus(t.engineStatusId).status;
    if (mapped !== "detected") return mapped;
  }
  return prev ?? "detected";
}

export interface VerifyItem {
  threatId: string;
  activeDetection: boolean;
  existingResources: string[];
  persistenceHits: string[];
}

export function validateVerifyItems(raw: unknown): VerifyItem[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_THREATS_PER_REPORT) return null;
  const out: VerifyItem[] = [];
  for (const v of raw) {
    if (!v || typeof v !== "object") return null;
    const r = v as Record<string, unknown>;
    const threatId = r.threatId != null ? String(r.threatId) : "";
    if (!/^\d+$/.test(threatId) || typeof r.activeDetection !== "boolean") return null;
    const list = (x: unknown) => (Array.isArray(x) ? x.filter((s): s is string => typeof s === "string").slice(0, 25).map((s) => s.slice(0, 600)) : []);
    out.push({ threatId, activeDetection: r.activeDetection, existingResources: list(r.existingResources), persistenceHits: list(r.persistenceHits) });
  }
  return out;
}

export function verifyOutcome(v: VerifyItem): { status: ThreatStatus; reasons: string[] } {
  const reasons: string[] = [];
  if (v.activeDetection) reasons.push("Defender still reports this threat as active after a fresh scan.");
  if (v.existingResources.length) reasons.push(`${v.existingResources.length} original file location(s) still exist.`);
  if (v.persistenceHits.length) reasons.push(`${v.persistenceHits.length} startup/persistence entr(ies) still reference the threat.`);
  return { status: reasons.length ? "failed" : "verified_clean", reasons };
}
