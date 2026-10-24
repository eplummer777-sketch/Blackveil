export class ScopeError extends Error {}

const HOST_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;

export function normalizeHostname(input: string): string | null {
  let s = String(input ?? "").trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").split(/[/?#]/)[0];
  if (s.includes("@") || s.includes(":")) return null;
  s = s.replace(/\.$/, "");
  if (!HOST_RE.test(s)) return null;
  if (/\.(local|localhost|internal|lan|home|corp|arpa|test|invalid|example)$/.test(s)) return null;
  return s;
}

function v4ToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    n = n * 256 + Number(x);
  }
  return n;
}

const V4_BLOCKS: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

export function isBlockedIp(ip: string): boolean {
  const s = ip.trim().toLowerCase();
  const n = v4ToInt(s);
  if (n !== null) {
    return V4_BLOCKS.some(([base, bits]) => {
      const b = v4ToInt(base)!;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return ((n & mask) >>> 0) === ((b & mask) >>> 0);
    });
  }
  if (!s.includes(":")) return true;
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIp(mapped[1]);
  if (s === "::" || s === "::1") return true;
  if (/^::ffff:/.test(s) || /^64:ff9b:/.test(s) || /^2001:db8:/.test(s) || /^2002:/.test(s)) return true;
  if (/^f[cd][0-9a-f]{2}:/.test(s)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(s)) return true;
  if (/^ff[0-9a-f]{2}:/.test(s)) return true;
  return false;
}

export async function resolvePublic(host: string): Promise<string[]> {
  const ips: string[] = [];
  for (const type of ["A", "AAAA"] as const) {
    try {
      ips.push(...(await Deno.resolveDns(host, type)));
    } catch { /* no records of this type */ }
  }
  if (ips.length === 0) throw new ScopeError(`${host} does not resolve`);
  const bad = ips.find(isBlockedIp);
  if (bad) throw new ScopeError(`${host} resolves to a private or reserved address`);
  return ips;
}

export interface Scope {
  host: string;
  allowedPaths: string[];
  budget: { remaining: number };
  signal: AbortSignal;
  violations: string[];
}

export function inScope(url: URL, scope: Scope): boolean {
  const h = url.hostname.toLowerCase();
  const hostOk = h === scope.host || h === "www." + scope.host || "www." + h === scope.host;
  const portOk = url.port === "" || url.port === "80" || url.port === "443";
  const protoOk = url.protocol === "https:" || url.protocol === "http:";
  const pathOk = scope.allowedPaths.some((p) => url.pathname.startsWith(p));
  return hostOk && portOk && protoOk && pathOk;
}

export interface SafeResponse {
  url: string;
  status: number;
  headers: Headers;
  setCookies: string[];
  body: string;
  hops: { url: string; status: number }[];
}

async function readLimited(resp: Response, max: number): Promise<string> {
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, max));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.length, all.length - off);
    all.set(c.subarray(0, take), off);
    off += take;
  }
  return new TextDecoder().decode(all);
}

export async function safeFetch(
  rawUrl: string,
  scope: Scope,
  opts: { method?: string; headers?: Record<string, string>; followRedirects?: boolean; maxBody?: number } = {},
): Promise<SafeResponse> {
  let url = new URL(rawUrl);
  const hops: { url: string; status: number }[] = [];
  for (let hop = 0; hop < 4; hop++) {
    if (!inScope(url, scope)) {
      scope.violations.push(url.toString());
      throw new ScopeError(`Out of scope: ${url.hostname}${url.pathname}`);
    }
    if (scope.budget.remaining <= 0) throw new ScopeError("Request budget for this scan exhausted");
    scope.budget.remaining--;
    await resolvePublic(url.hostname);
    const resp = await fetch(url, {
      method: opts.method ?? "GET",
      redirect: "manual",
      headers: { "User-Agent": "Blackveil-ProofOfBreach/1.0 (+authorized assessment)", ...(opts.headers ?? {}) },
      signal: AbortSignal.any([scope.signal, AbortSignal.timeout(8000)]),
    });
    hops.push({ url: url.toString(), status: resp.status });
    const loc = resp.headers.get("location");
    if (opts.followRedirects !== false && resp.status >= 300 && resp.status < 400 && loc) {
      await resp.body?.cancel();
      url = new URL(loc, url);
      continue;
    }
    const setCookies = typeof resp.headers.getSetCookie === "function" ? resp.headers.getSetCookie() : [];
    const body = opts.method === "HEAD" ? "" : await readLimited(resp, opts.maxBody ?? 65536);
    return { url: url.toString(), status: resp.status, headers: resp.headers, setCookies, body, hops };
  }
  throw new ScopeError("Too many redirects");
}
