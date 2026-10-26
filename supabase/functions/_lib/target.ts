// Strict parsing of a user-supplied scan target. Everything here runs on the server:
// a malformed host, an embedded credential, a non-standard port, a private address or
// a cloud metadata endpoint is rejected before any request is made.

import { isBlockedIp, normalizeHostname } from "./net.ts";

export class TargetError extends Error {}

export interface ParsedTarget {
  host: string;
  url: string;
}

// Hostnames that resolve to cloud metadata services or are otherwise never a website.
const BLOCKED_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
  "kubernetes.default",
  "kubernetes.default.svc",
];

function isBlockedHostname(host: string): boolean {
  return BLOCKED_HOSTNAMES.some((b) => host === b || host.endsWith(`.${b}`) || host.startsWith(`${b}.`));
}

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const ALLOWED_PORTS: Record<string, string[]> = { "http:": ["", "80"], "https:": ["", "443"] };

/**
 * Accepts a plain hostname ("example.com") or a supported HTTP/HTTPS URL and returns
 * the canonical host and URL to store on the scan. Query string and fragment are
 * dropped; credentials, unsupported schemes and non-standard ports are refused.
 */
export function parseTargetInput(input: unknown): ParsedTarget | { error: string } {
  const raw = String(input ?? "").trim();
  if (!raw) return { error: "Enter a public website address like https://example.com/." };
  if (raw.length > 2048) return { error: "That address is too long." };
  if (/[\s\u0000-\u001f]/.test(raw)) return { error: "That address contains characters a web address cannot use." };

  const withScheme = SCHEME_RE.test(raw) ? raw : `https://${raw}`;
  let u: URL;
  try {
    u = new URL(withScheme);
  } catch {
    return { error: "That is not a valid web address." };
  }

  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { error: "Only http:// and https:// addresses can be tested." };
  }
  if (u.username || u.password) {
    return { error: "Addresses with a username or password are not allowed." };
  }
  if (!ALLOWED_PORTS[u.protocol].includes(u.port)) {
    return { error: "Only the standard web ports (80 and 443) can be tested." };
  }

  const host = normalizeHostname(u.hostname);
  if (!host) {
    return { error: "Enter a public domain name like example.com. IP addresses, localhost and internal names are not allowed." };
  }
  if (isBlockedHostname(host)) {
    return { error: "That host is a cloud metadata or cluster-internal endpoint and can never be tested." };
  }

  const path = u.pathname && u.pathname.startsWith("/") ? u.pathname : "/";
  return { host, url: `${u.protocol}//${host}${path}` };
}

/**
 * A URL a user recorded as the source of their permission (bug bounty page, signed
 * authorization). It is stored and shown, never fetched, so only its shape is checked.
 */
export function parseHttpsUrl(input: unknown): string | null {
  const raw = String(input ?? "").trim();
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password) return null;
  const host = normalizeHostname(u.hostname);
  if (!host) return null;
  return `${u.protocol}//${host}${u.pathname}`.slice(0, 500);
}

/** Resolve A and AAAA records and refuse anything that is not a public unicast address. */
export async function resolveRecords(host: string): Promise<{ a: string[]; aaaa: string[] }> {
  if (isBlockedHostname(host)) throw new TargetError("That host is a cloud metadata or cluster-internal endpoint.");
  const a: string[] = [];
  const aaaa: string[] = [];
  for (const type of ["A", "AAAA"] as const) {
    try {
      const found = await Deno.resolveDns(host, type);
      (type === "A" ? a : aaaa).push(...found);
    } catch { /* no records of this type */ }
  }
  if (a.length === 0 && aaaa.length === 0) throw new TargetError(`${host} does not resolve to a public address.`);
  const bad = [...a, ...aaaa].find(isBlockedIp);
  if (bad) throw new TargetError(`${host} resolves to a private, loopback or reserved address (${bad}).`);
  return { a, aaaa };
}

/** Resolve and validate before the first request, and again on every scan step. */
export async function assertPublicHost(host: string): Promise<string[]> {
  const { a, aaaa } = await resolveRecords(host);
  return [...a, ...aaaa];
}

/** True when two hostnames are the same site, allowing the "www." prefix either way. */
export function sameHost(a: string, b: string): boolean {
  const x = a.toLowerCase().replace(/\.$/, "");
  const y = b.toLowerCase().replace(/\.$/, "");
  return x === y || x === `www.${y}` || `www.${x}` === y;
}
