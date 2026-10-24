// Native TLS client: a minimal, read-only TLS 1.2 handshake implemented on top of
// the platform's TCP socket. It extracts the server's certificate chain, negotiated
// handshake version and cipher suite — the raw facts a TLS auditor needs — without
// performing any destructive or authentication-bypassing behavior.

import { parseCertificate, daysRemaining, type X509Cert } from "./x509.ts";

export interface TlsEvidence {
  reachable: boolean;
  handshakeError: string | null;
  protocolVersion: string | null;
  cipherSuite: number | null;
  cipherSuiteName: string;
  alpn: string | null;
  certificateChain: X509Cert[];
  serverCert: X509Cert | null;
  error: string | null;
}

/** Structural socket interface shared by Deno.Conn and Node net.Socket adapters. */
export interface TlsConn {
  read(buf: Uint8Array): Promise<number | null>;
  write(data: Uint8Array): Promise<number>;
  close(): void;
}

export type ConnFactory = (host: string, port: number) => Promise<TlsConn>;

const denoConnFactory: ConnFactory = (host, port) =>
  Deno.connect({ hostname: host, port, transport: "tcp" }) as unknown as Promise<TlsConn>;

function connectTcp(host: string, port: number, timeoutMs: number): Promise<TlsConn> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("connect timeout")), timeoutMs);
    denoConnFactory(host, port)
      .then((c) => { clearTimeout(t); resolve(c); }, (e) => { clearTimeout(t); reject(e); });
  });
}

const TLS_CONTENT_TYPES = { changeCipherSpec: 20, alert: 21, handshake: 22, applicationData: 23 } as const;
const HANDSHAKE_TYPES = { clientHello: 1, serverHello: 2, certificate: 11, serverHelloDone: 14 } as const;
const ALERT_LEVELS = { warning: 1, fatal: 2 } as const;

const CIPHER_SUITES: Record<number, string> = {
  0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  0x1301: "TLS_AES_128_GCM_SHA256 (TLS 1.3)",
  0x1302: "TLS_AES_256_GCM_SHA384 (TLS 1.3)",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)",
  0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
  0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
  0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
  0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
};

export function cipherName(suite: number): string {
  return CIPHER_SUITES[suite] ?? `0x${suite.toString(16).padStart(4, "0")}`;
}

interface RecvOpts { timeoutMs?: number }

async function readExact(conn: TlsConn, n: number, timeoutMs: number): Promise<Uint8Array> {
  const out = new Uint8Array(n);
  let off = 0;
  while (off < n) {
    const buf = new Uint8Array(Math.min(4096, n - off));
    let read: number | null;
    try {
      read = await Promise.race([
        conn.read(buf),
        new Promise<null>((r) => setTimeout(() => r(null), timeoutMs)),
      ]);
    } catch {
      read = null;
    }
    if (read === null || read === 0) throw new Error("connection closed by peer");
    out.set(buf.subarray(0, read), off);
    off += read;
  }
  return out;
}

function readRecordHeader(conn: TlsConn, timeoutMs: number): Promise<{ contentType: number; length: number; body: Uint8Array }> {
  return readExact(conn, 5, timeoutMs).then((hdr) => {
    const contentType = hdr[0];
    const length = (hdr[3] << 8) | hdr[4];
    return { contentType, length, body: new Uint8Array(0) };
  });
}

async function recvRecord(conn: TlsConn, timeoutMs: number): Promise<{ contentType: number; body: Uint8Array }> {
  const hdr = await readExact(conn, 5, timeoutMs);
  const contentType = hdr[0];
  const length = (hdr[3] << 8) | hdr[4];
  const body = await readExact(conn, length, timeoutMs);
  return { contentType, body };
}

function buildClientHello(serverName: string, ciphers: number[], tls13: boolean): Uint8Array {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const legacyVersion = new Uint8Array([0x03, 0x03]);

  const extSNI = buildExt(0x0000, buildServerNameList(serverName));
  const extGroups = buildExt(0x000a, Uint8Array.from([0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19])); // x25519, secp256r1, secp384r1, secp521r1
  const extAlpn = buildExt(0x0010, Uint8Array.from([0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31])); // h2, http/1.1
  const extSigAlgs = buildExt(0x000d, Uint8Array.from([0x00, 0x08, 0x04, 0x03, 0x04, 0x01, 0x05, 0x03, 0x05, 0x01]));

  let supportedVersions = new Uint8Array(0);
  if (tls13) {
    supportedVersions = buildExt(0x002b, Uint8Array.from([0x02, 0x03, 0x04]));
  }

  const cipherBytes = new Uint8Array(ciphers.length * 2);
  ciphers.forEach((c, i) => { cipherBytes[i * 2] = c >> 8; cipherBytes[i * 2 + 1] = c & 0xff; });
  const cipherLen = new Uint8Array([(cipherBytes.length >> 8) & 0xff, cipherBytes.length & 0xff]);
  const compLen = new Uint8Array([0x01, 0x00]);

  const extensions = concatBytes(extSNI, extGroups, extAlpn, extSigAlgs, supportedVersions);
  const extLen = new Uint8Array([(extensions.length >> 8) & 0xff, extensions.length & 0xff]);

  const body = concatBytes(
    legacyVersion,
    random,
    new Uint8Array([0x00]), // session id length 0
    cipherLen, cipherBytes, compLen,
    extLen, extensions,
  );

  const header = new Uint8Array([0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]);
  return handshakeRecord(header.length + body.length, header, body);
}

function buildExt(type: number, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.length);
  out[0] = type >> 8; out[1] = type & 0xff;
  out[2] = data.length >> 8; out[3] = data.length & 0xff;
  out.set(data, 4);
  return out;
}

function buildServerNameList(host: string): Uint8Array {
  // ServerNameList ::= <2-byte length><ServerName>
  // ServerName ::= name_type(1)=0 | name length(2) | name bytes
  const name = new TextEncoder().encode(host);
  const entry = concatBytes(
    new Uint8Array([0x00]),
    new Uint8Array([name.length >> 8, name.length & 0xff]),
    name,
  );
  return concatBytes(new Uint8Array([entry.length >> 8, entry.length & 0xff]), entry);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function handshakeRecord(bodyLen: number, ...parts: Uint8Array[]): Uint8Array {
  const body = concatBytes(...parts);
  const out = new Uint8Array(5 + bodyLen);
  out[0] = TLS_CONTENT_TYPES.handshake;
  out[1] = 0x03; out[2] = 0x01;
  out[3] = (bodyLen >> 8) & 0xff; out[4] = bodyLen & 0xff;
  out.set(body, 5);
  return out;
}

async function writeAll(conn: TlsConn, data: Uint8Array): Promise<void> {
  await conn.write(data);
}

interface HandshakeResult {
  protocolVersion: string;
  cipherSuite: number;
  alpn: string | null;
  certificates: Uint8Array[];
}

async function handshake(conn: TlsConn, serverName: string, timeoutMs: number, signal?: AbortSignal): Promise<HandshakeResult> {
  // Offer only TLS 1.2. TLS 1.3 encrypts the Certificate message, so a read-only
  // certificate inspection must force 1.2 to receive the chain in cleartext.
  const ciphers = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009c, 0x009d, 0xc013, 0xc014, 0x002f, 0x0035];
  const hello = buildClientHello(serverName, ciphers, false);
  await writeAll(conn, hello);

  let protocolVersion = "TLS 1.2";
  let cipherSuite = 0;
  let alpn: string | null = null;
  const certificates: Uint8Array[] = [];
  let handshakeBuf = new Uint8Array(0);
  const deadline = Date.now() + timeoutMs;

  const parseServerHello = (msg: Uint8Array): void => {
    const legacy = (msg[0] << 8) | msg[1];
    const sidLen = msg[34];
    let q = 35 + sidLen;
    if (q + 2 > msg.length) return;
    cipherSuite = (msg[q] << 8) | msg[q + 1];
    q += 2;
    if (q >= msg.length) return;
    const compLen = msg[q];
    q += 1 + compLen;
    if (q + 2 <= msg.length) {
      const extLen = (msg[q] << 8) | msg[q + 1];
      q += 2;
      const extEnd = Math.min(msg.length, q + extLen);
      while (q + 4 <= extEnd) {
        const extType = (msg[q] << 8) | msg[q + 1];
        const elen = (msg[q + 2] << 8) | msg[q + 3];
        q += 4;
        const ev = msg.subarray(q, q + elen);
        q += elen;
        if (extType === 0x0010 && ev.length >= 3) {
          const alpnLen = ev[1];
          alpn = new TextDecoder().decode(ev.subarray(2, 2 + alpnLen)) || null;
        }
      }
    }
    if (legacy === 0x0303) protocolVersion = "TLS 1.2";
    else if (legacy === 0x0301) protocolVersion = "TLS 1.0";
    else if (legacy === 0x0302) protocolVersion = "TLS 1.1";
  };

  const parseCertificate = (msg: Uint8Array): void => {
    if (msg.length < 3) return;
    const totalLen = (msg[0] << 16) | (msg[1] << 8) | msg[2];
    let r = 3;
    const end = Math.min(msg.length, r + totalLen);
    while (r + 3 <= end) {
      const certLen = (msg[r] << 16) | (msg[r + 1] << 8) | msg[r + 2];
      r += 3;
      if (r + certLen > msg.length) break;
      certificates.push(msg.subarray(r, r + certLen));
      r += certLen;
    }
  };

  // Reassemble handshake messages that span multiple TLS records, then process
  // every complete message in the buffer.
  const drain = (): boolean => {
    while (handshakeBuf.length >= 4) {
      const msgType = handshakeBuf[0];
      const len = (handshakeBuf[1] << 16) | (handshakeBuf[2] << 8) | handshakeBuf[3];
      if (handshakeBuf.length < 4 + len) return false;
      const msg = handshakeBuf.subarray(4, 4 + len);
      handshakeBuf = handshakeBuf.subarray(4 + len);
      if (msgType === HANDSHAKE_TYPES.serverHello) parseServerHello(msg);
      else if (msgType === HANDSHAKE_TYPES.certificate) parseCertificate(msg);
      else if (msgType === HANDSHAKE_TYPES.serverHelloDone) return true;
    }
    return false;
  };

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("aborted");
    const rec = await recvRecord(conn, Math.max(500, deadline - Date.now()));
    if (rec.contentType === TLS_CONTENT_TYPES.alert) {
      const desc = rec.body[1];
      if (rec.body[0] === ALERT_LEVELS.fatal) {
        throw new Error(`TLS handshake alert ${desc} (${alertDescription(desc)})`);
      }
      continue;
    }
    if (rec.contentType === TLS_CONTENT_TYPES.changeCipherSpec) continue;
    if (rec.contentType !== TLS_CONTENT_TYPES.handshake) continue;
    const next = new Uint8Array(handshakeBuf.length + rec.body.length);
    next.set(handshakeBuf, 0);
    next.set(rec.body, handshakeBuf.length);
    handshakeBuf = next;
    if (drain() && certificates.length > 0) {
      return { protocolVersion, cipherSuite, alpn, certificates };
    }
  }
  throw new Error("TLS handshake timed out");
}

function alertDescription(code: number): string {
  const map: Record<number, string> = {
    40: "handshake_failure", 42: "bad_certificate", 47: "illegal_parameter", 48: "unknown_ca",
    70: "protocol_version", 71: "insufficient_security", 112: "unrecognized_name",
  };
  return map[code] ?? `unknown`;
}

export async function probeTls(
  host: string,
  port: number,
  opts: { serverName?: string; timeoutMs?: number; signal?: AbortSignal; connFactory?: ConnFactory } = {},
): Promise<TlsEvidence> {
  const serverName = opts.serverName ?? host;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const signal = opts.signal;
  const connect = opts.connFactory ?? connectTcp;
  const base: TlsEvidence = {
    reachable: false, handshakeError: null, protocolVersion: null, cipherSuite: null,
    cipherSuiteName: "", alpn: null, certificateChain: [], serverCert: null, error: null,
  };
  let conn: TlsConn | null = null;
  try {
    if (signal?.aborted) throw new Error("aborted");
    conn = await Promise.race([
      connect(host, port),
      new Promise<TlsConn>((_, reject) => setTimeout(() => reject(new Error("connect timeout")), timeoutMs)),
    ]);
  } catch (e) {
    const msg = errMsg(e);
    if (msg === "aborted") return { ...base, error: "Stopped before finishing (time limit or stop requested)." };
    return { ...base, error: `TCP connect failed: ${msg}` };
  }
  try {
    const result = await handshake(conn, serverName, timeoutMs, signal);
    let chainParsed: X509Cert[] = [];
    let parseErrors: string[] = [];
    for (const raw of result.certificates) {
      try {
        chainParsed.push(parseCertificate(raw));
      } catch (e) {
        parseErrors.push(errMsg(e));
      }
    }
    if (chainParsed.length === 0 && parseErrors.length) {
      return { ...base, reachable: false, error: `Certificate chain could not be parsed (${parseErrors[0]})` };
    }
    return {
      ...base,
      reachable: true,
      protocolVersion: result.protocolVersion,
      cipherSuite: result.cipherSuite,
      cipherSuiteName: cipherName(result.cipherSuite),
      alpn: result.alpn,
      certificateChain: chainParsed,
      serverCert: chainParsed[0] ?? null,
    };
  } catch (e) {
    return { ...base, reachable: false, handshakeError: errMsg(e), error: errMsg(e) };
  } finally {
    try { conn.close(); } catch { /* already closed */ }
  }
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// Re-export helpers used by tests and auditors.
export { daysRemaining };
