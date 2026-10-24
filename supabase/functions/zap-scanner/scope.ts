import { inScope, type Scope } from "../_lib/net.ts";

export type ScanMode = "baseline" | "active" | "api";

export interface TargetLike {
  hostname: string;
  allowed_paths: string[];
  environment: string;
}

export interface ScanConfig {
  max_minutes: number;
  spider_minutes: number;
  spider_depth: number;
  spider_children: number;
  passive_wait_seconds: number;
  ascan_minutes: number;
  ascan_rule_minutes: number;
  threads_per_host: number;
  delay_ms: number;
  run_active: boolean;
  openapi: { source: "url"; url: string } | { source: "upload"; bytes: number } | null;
  engine?: "zap" | "native";
}

export const BASELINE_STATEMENT = "I own this website or have written permission to run a passive security scan against it.";
export const INTRUSIVE_STATEMENT =
  "I own this website or have written permission to run intrusive security tests that send attack payloads and may change data.";

export const MAX_SPEC_BYTES = 1_000_000;

export function parseScanMode(v: unknown): ScanMode | null {
  return v === "baseline" || v === "active" || v === "api" ? v : null;
}

export function isIntrusive(mode: ScanMode): boolean {
  return mode !== "baseline";
}

export function buildConfig(mode: ScanMode, openapi: ScanConfig["openapi"]): ScanConfig {
  const intrusive = isIntrusive(mode);
  return {
    max_minutes: intrusive ? 45 : 15,
    spider_minutes: mode === "api" ? 2 : 5,
    spider_depth: 5,
    spider_children: 50,
    passive_wait_seconds: 90,
    ascan_minutes: 30,
    ascan_rule_minutes: 5,
    threads_per_host: 2,
    delay_ms: 250,
    run_active: intrusive,
    openapi,
  };
}

export function scopeFor(t: TargetLike): Scope {
  return { host: t.hostname, allowedPaths: t.allowed_paths, budget: { remaining: Infinity }, signal: new AbortController().signal, violations: [] };
}

export function urlInTargetScope(raw: string, t: TargetLike): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.username || u.password) return false;
  return inScope(u, scopeFor(t));
}

export function parseTargetUrl(input: unknown, t: TargetLike): { url: string } | { error: string } {
  const s = String(input ?? "").trim();
  if (!s || s.length > 2048) return { error: "Enter the full address to scan, like https://example.com/" };
  let u: URL;
  try {
    u = new URL(/^[a-z]+:\/\//i.test(s) ? s : `https://${s}`);
  } catch {
    return { error: "That is not a valid web address." };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { error: "Only http and https addresses can be scanned." };
  if (u.username || u.password) return { error: "Addresses with embedded usernames or passwords are not allowed." };
  u.hash = "";
  if (!urlInTargetScope(u.toString(), t)) {
    return { error: `The address must be on ${t.hostname} (standard ports only) and inside the allowed paths: ${t.allowed_paths.join(", ")}` };
  }
  return { url: u.toString() };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function contextIncludeRegex(t: TargetLike): string {
  const host = escapeRe(t.hostname.replace(/^www\./, ""));
  const paths = t.allowed_paths.map((p) => escapeRe(p.startsWith("/") ? p : `/${p}`)).join("|");
  return `^https?://(www\\.)?${host}(:(80|443))?(${paths}).*$`;
}

export function validateSpec(raw: unknown): { spec: string } | { error: string } {
  if (typeof raw !== "string" || !raw.trim()) return { error: "Upload an OpenAPI file." };
  if (raw.length > MAX_SPEC_BYTES) return { error: "The OpenAPI file is larger than 1 MB." };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { error: "The OpenAPI file must be JSON (YAML is not supported for uploads)." };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { error: "The OpenAPI file has the wrong structure." };
  const o = parsed as Record<string, unknown>;
  const ver = typeof o.openapi === "string" ? o.openapi : typeof o.swagger === "string" ? o.swagger : "";
  if (!/^(2|3)\./.test(ver)) return { error: "This does not look like an OpenAPI 2 or 3 document." };
  if (!o.paths || typeof o.paths !== "object") return { error: "The OpenAPI document has no paths to test." };
  return { spec: JSON.stringify(parsed) };
}
