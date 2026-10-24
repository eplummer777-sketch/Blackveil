import { isBlockedIp, normalizeHostname } from "./net.ts";

export type Profile = "discovery" | "tcp_basic" | "service" | "syn";

export const PROFILES: Record<Profile, { args: string[]; timeout: number; raw: boolean }> = {
  discovery: { args: ["-sn", "-n"], timeout: 300, raw: false },
  tcp_basic: { args: ["-sT", "-Pn", "-n", "--top-ports", "100"], timeout: 600, raw: false },
  service: { args: ["-sT", "-Pn", "-n", "-sV", "--version-intensity", "5", "--top-ports", "100"], timeout: 1200, raw: false },
  syn: { args: ["-sS", "-Pn", "-n", "--top-ports", "1000"], timeout: 900, raw: true },
};

export function parseProfile(v: unknown): Profile | null {
  return typeof v === "string" && Object.hasOwn(PROFILES, v) ? (v as Profile) : null;
}

export const MIN_PREFIX = 24;
export const MAX_RESOLVED = 16;

// Never scannable, even inside an approved range: cloud metadata, link-local, multicast, reserved.
const ALWAYS_BLOCKED = ["0.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "168.63.129.16/32", "192.0.0.192/32", "224.0.0.0/4", "240.0.0.0/4"];

export function ipToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^(0|[1-9]\d{0,2})$/.test(x) || Number(x) > 255) return null;
    n = n * 256 + Number(x);
  }
  return n;
}

const intToIp = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");

export interface Range { start: number; end: number }

export function cidrRange(cidr: string): Range | null {
  const m = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(cidr.trim());
  if (!m) return null;
  const base = ipToInt(m[1]);
  const bits = m[2] === undefined ? 32 : Number(m[2]);
  if (base === null || bits > 32) return null;
  const size = 2 ** (32 - bits);
  const start = Math.floor(base / size) * size;
  return { start, end: start + size - 1 };
}

export function normalizeCidr(input: unknown): string | null {
  const s = String(input ?? "").trim();
  const r = cidrRange(s);
  if (!r) return null;
  const bits = s.includes("/") ? Number(s.split("/")[1]) : 32;
  return `${intToIp(r.start)}/${bits}`;
}

const contains = (outer: Range, inner: Range) => inner.start >= outer.start && inner.end <= outer.end;
const overlaps = (a: Range, b: Range) => a.start <= b.end && b.start <= a.end;

export function hitsAlwaysBlocked(r: Range): boolean {
  return ALWAYS_BLOCKED.some((c) => overlaps(cidrRange(c)!, r));
}

export type ParsedTarget =
  | { kind: "ip"; value: string }
  | { kind: "cidr"; value: string }
  | { kind: "hostname"; value: string };

export function parseTarget(input: unknown): ParsedTarget | { error: string } {
  const s = String(input ?? "").trim().toLowerCase();
  if (!s || s.length > 253) return { error: "Enter an IP address, hostname or CIDR range." };
  if (s.includes(":")) return { error: "IPv6 targets and ports are not supported. Enter an IPv4 address, IPv4 range or hostname." };
  if (/^[\d.]+\/\d{1,2}$/.test(s)) {
    const bits = Number(s.split("/")[1]);
    const c = normalizeCidr(s);
    if (!c || bits > 32) return { error: "That network range is not valid." };
    if (bits < MIN_PREFIX) return { error: `Ranges larger than /${MIN_PREFIX} (256 addresses) are not allowed.` };
    return bits === 32 ? { kind: "ip", value: c.split("/")[0] } : { kind: "cidr", value: c };
  }
  if (/^[\d.]+$/.test(s)) {
    return ipToInt(s) === null ? { error: "That IP address is not valid." } : { kind: "ip", value: s };
  }
  const h = normalizeHostname(s);
  if (!h || h !== s) return { error: "That hostname is not valid. Use a plain public hostname like server.example.com." };
  return { kind: "hostname", value: h };
}

export interface AuthContext {
  resolved: string[];
  verifiedHosts: { id: string; hostname: string }[];
  scopes: { id: string; cidr: string }[];
}

export type Authorized = { targets: string[]; basis: "verified_domain" | "approved_scope"; scope_id: string | null; pob_target_id: string | null };

function scopeFor(r: Range, scopes: AuthContext["scopes"]) {
  return scopes.find((s) => {
    const sr = cidrRange(s.cidr);
    return !!sr && contains(sr, r);
  });
}

const BLOCKED_MSG = "That target includes cloud metadata, link-local, multicast or reserved addresses, which can never be scanned.";

export function authorizeTarget(t: ParsedTarget, ctx: AuthContext): Authorized | { error: string } {
  if (t.kind !== "hostname") {
    const r = cidrRange(t.value)!;
    if (hitsAlwaysBlocked(r)) return { error: BLOCKED_MSG };
    const scope = scopeFor(r, ctx.scopes);
    if (scope) return { targets: [t.value], basis: "approved_scope", scope_id: scope.id, pob_target_id: null };
    const internal = isBlockedIp(intToIp(r.start)) || isBlockedIp(intToIp(r.end));
    return { error: internal
      ? "Private, loopback and internal addresses can only be scanned inside a lab range an administrator has approved for your account."
      : "Public IP addresses and ranges can only be scanned after an administrator approves them for your account. For websites you own, scan the verified hostname instead." };
  }
  const ips = [...new Set(ctx.resolved.filter((ip) => ipToInt(ip) !== null))].slice(0, MAX_RESOLVED);
  if (!ips.length) return { error: "That hostname does not resolve to an IPv4 address." };
  const ranges = ips.map((ip) => cidrRange(ip)!);
  if (ranges.some(hitsAlwaysBlocked)) return { error: BLOCKED_MSG };
  const scopes = ranges.map((r) => scopeFor(r, ctx.scopes));
  if (scopes.every(Boolean)) return { targets: ips, basis: "approved_scope", scope_id: scopes[0]!.id, pob_target_id: null };
  if (ips.some((ip) => isBlockedIp(ip))) {
    return { error: "This hostname points to a private or internal address that is not in an approved lab range." };
  }
  const verified = ctx.verifiedHosts.find((h) => h.hostname === t.value);
  if (!verified) return { error: "Only hostnames you have verified ownership of (Proof-of-Breach > Authorized Targets) or approved lab ranges can be scanned." };
  return { targets: ips, basis: "verified_domain", scope_id: null, pob_target_id: verified.id };
}

export function addressInTargets(addr: string, targets: string[]): boolean {
  const a = cidrRange(addr);
  if (!a || a.start !== a.end) return false;
  return targets.some((t) => {
    const r = cidrRange(t);
    return !!r && contains(r, a);
  });
}

export interface NmapPort { port: number; protocol: string; state: string; reason: string; service: string; product: string; version: string; extrainfo: string; tunnel: string }
export interface NmapHost { address: string; hostnames: string[]; state: string; reason: string; ports: NmapPort[]; extraports: { state: string; count: number }[] }
export interface NmapRun { version: string; args: string; hosts: NmapHost[]; exit: string; errormsg: string; elapsed: number; up: number; down: number; total: number }

export const MAX_XML_BYTES = 5_000_000;
const MAX_HOSTS = 512;
const MAX_PORTS = 1100;

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function decode(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 31 && n < 0x110000 ? String.fromCodePoint(n) : "";
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

// eslint-disable-next-line no-control-regex
const clip = (s: string | undefined, n = 160) => decode(s ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);

function attrs(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of raw.matchAll(/([a-zA-Z_:-]+)="([^"]*)"/g)) out[m[1]] = m[2];
  return out;
}

export function parseNmapXml(xml: string): NmapRun {
  if (typeof xml !== "string" || !xml.trim()) throw new Error("Nmap returned no XML output.");
  if (xml.length > MAX_XML_BYTES) throw new Error("Nmap output was too large.");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml.replace(/<!DOCTYPE nmaprun>/, ""))) throw new Error("Nmap output contained a forbidden document type declaration.");
  if (!/<nmaprun[\s>]/.test(xml)) throw new Error("Output was not Nmap XML.");

  const run: NmapRun = { version: "", args: "", hosts: [], exit: "", errormsg: "", elapsed: 0, up: 0, down: 0, total: 0 };
  let host: NmapHost | null = null;
  let port: NmapPort | null = null;
  const tag = /<(\/?)([a-zA-Z]+)((?:\s+[a-zA-Z_:-]+="[^"]*")*)\s*(\/?)>/g;
  for (const m of xml.matchAll(tag)) {
    const [, close, name, rawAttrs] = m;
    if (close) {
      if (name === "port" && host && port) {
        if (host.ports.length < MAX_PORTS) host.ports.push(port);
        port = null;
      } else if (name === "host" && host) {
        if (host.address && run.hosts.length < MAX_HOSTS) run.hosts.push(host);
        host = null;
      }
      continue;
    }
    const a = attrs(rawAttrs);
    switch (name) {
      case "nmaprun": run.version = clip(a.version, 32); run.args = clip(a.args, 500); break;
      case "host": host = { address: "", hostnames: [], state: "unknown", reason: "", ports: [], extraports: [] }; break;
      case "status": if (host) { host.state = clip(a.state, 16); host.reason = clip(a.reason, 40); } break;
      case "address": if (host && a.addrtype === "ipv4" && ipToInt(a.addr ?? "") !== null) host.address = a.addr; break;
      case "hostname": if (host && a.name && host.hostnames.length < 8) host.hostnames.push(clip(a.name, 253)); break;
      case "extraports": if (host) host.extraports.push({ state: clip(a.state, 24), count: Math.max(0, Number(a.count) || 0) }); break;
      case "port": {
        const n = Number(a.portid);
        port = Number.isInteger(n) && n > 0 && n < 65536
          ? { port: n, protocol: clip(a.protocol, 8), state: "", reason: "", service: "", product: "", version: "", extrainfo: "", tunnel: "" }
          : null;
        break;
      }
      case "state": if (port) { port.state = clip(a.state, 24); port.reason = clip(a.reason, 40); } break;
      case "service": if (port) {
        port.service = clip(a.name, 40); port.product = clip(a.product, 120); port.version = clip(a.version, 80);
        port.extrainfo = clip(a.extrainfo, 160); port.tunnel = clip(a.tunnel, 16);
      } break;
      case "finished": run.exit = clip(a.exit, 16); run.errormsg = clip(a.errormsg, 300); run.elapsed = Number(a.elapsed) || 0; break;
      case "hosts": if (!host) { run.up = Number(a.up) || 0; run.down = Number(a.down) || 0; run.total = Number(a.total) || 0; } break;
    }
  }
  return run;
}

export function summarize(hosts: NmapHost[], run: Pick<NmapRun, "up" | "down" | "total" | "elapsed">) {
  let open = 0, closed = 0, filtered = 0, services = 0;
  for (const h of hosts) {
    for (const p of h.ports) {
      if (p.state === "open") { open++; if (p.product || p.version) services++; }
      else if (p.state === "closed") closed++;
      else filtered++;
    }
    for (const e of h.extraports) {
      if (e.state === "closed") closed += e.count; else filtered += e.count;
    }
  }
  return { hosts_up: run.up, hosts_down: run.down, hosts_total: run.total, open, closed, filtered, services, elapsed: run.elapsed };
}
