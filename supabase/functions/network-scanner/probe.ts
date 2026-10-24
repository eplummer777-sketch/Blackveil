import { type Confidence, fromBanner, fromHttp, HTTP_PORTS, portGuess, type ServiceGuess, TLS_PORTS } from "./fingerprints.ts";

export interface Conn {
  write(data: Uint8Array): Promise<void>;
  read(timeoutMs: number): Promise<Uint8Array>;
  close(): void;
}

export type DialErrorKind = "refused" | "timeout" | "unreachable" | "blocked";

export class DialError extends Error {
  kind: DialErrorKind;
  constructor(kind: DialErrorKind, msg: string = kind) {
    super(msg);
    this.kind = kind;
  }
}

export interface Dialer {
  tcp(ip: string, port: number, timeoutMs: number): Promise<Conn>;
  tls?(ip: string, port: number, serverName: string, timeoutMs: number): Promise<Conn>;
}

export type PortState = "open" | "closed" | "filtered";

export interface PortResult {
  port: number;
  protocol: "tcp";
  state: PortState;
  reason: string;
  service: string;
  product: string;
  version: string;
  extrainfo: string;
  tunnel: string;
  confidence: Confidence;
  method: string;
}

export interface ProbeOptions {
  connectTimeoutMs: number;
  bannerTimeoutMs: number;
  identify: boolean;
  serverName?: string;
}

const enc = new TextEncoder();

function httpHead(host: string) {
  return enc.encode(`HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: Blackveil-Discovery/1.0 (authorized scan)\r\nConnection: close\r\n\r\n`);
}

async function readSafe(conn: Conn, ms: number): Promise<Uint8Array> {
  try {
    return await conn.read(ms);
  } catch {
    return new Uint8Array();
  }
}

async function identify(conn: Conn, ip: string, port: number, d: Dialer, o: ProbeOptions): Promise<ServiceGuess> {
  const host = o.serverName ?? ip;
  if (HTTP_PORTS.has(port)) {
    await conn.write(httpHead(host)).catch(() => {});
    const r = await readSafe(conn, o.bannerTimeoutMs);
    if (r.length) return fromBanner(port, r) ?? portGuess(port);
    return portGuess(port);
  }
  if (!TLS_PORTS.has(port)) {
    const greeting = await readSafe(conn, o.bannerTimeoutMs);
    return greeting.length ? fromBanner(port, greeting) ?? portGuess(port) : portGuess(port);
  }
  if (d.tls) {
    let tls: Conn | null = null;
    try {
      tls = await d.tls(ip, port, host, o.connectTimeoutMs);
      if (port === 443 || port === 8443) {
        await tls.write(httpHead(host));
        const r = await readSafe(tls, o.bannerTimeoutMs);
        if (/^HTTP\/\d/.test(new TextDecoder().decode(r.subarray(0, 8)))) return fromHttp(new TextDecoder().decode(r.subarray(0, 2048)), true);
      }
      return { ...portGuess(port), tunnel: "ssl", confidence: "medium", method: "probe", extrainfo: "TLS handshake succeeded" };
    } catch {
      return portGuess(port);
    } finally {
      tls?.close();
    }
  }
  return portGuess(port);
}

export async function probePort(d: Dialer, ip: string, port: number, o: ProbeOptions): Promise<PortResult> {
  let conn: Conn;
  try {
    conn = await d.tcp(ip, port, o.connectTimeoutMs);
  } catch (e) {
    const kind = e instanceof DialError ? e.kind : "unreachable";
    if (kind === "blocked") throw e;
    const state: PortState = kind === "refused" ? "closed" : "filtered";
    const reason = kind === "refused" ? "conn-refused" : kind === "timeout" ? "no-response" : "unreachable";
    return { port, protocol: "tcp", state, reason, ...portGuess(port), confidence: "low", method: "port" };
  }
  try {
    const g = o.identify ? await identify(conn, ip, port, d, o) : portGuess(port);
    return { port, protocol: "tcp", state: "open", reason: "syn-ack", ...g };
  } finally {
    conn.close();
  }
}