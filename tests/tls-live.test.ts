import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import type { Socket } from 'node:net';
import { probeTls, type TlsConn } from '../supabase/functions/_lib/tls.ts';

// A public, non-malicious host used only as a real-world fixture to prove the
// raw TLS handshake and certificate parser actually work end-to-end.
const HOST = 'example.com';
const PORT = 443;

function nodeConnFactory(host: string, port: number): Promise<TlsConn> {
  return new Promise((resolve, reject) => {
    const s: Socket = connect({ host, port, timeout: 4000 });
    let buf = Buffer.alloc(0);
    let ended = false;
    const waiters: Array<{ buf: Uint8Array; resolve: (n: number | null) => void; reject: (e: unknown) => void }> = [];

    const flush = (): void => {
      while (waiters.length) {
        const w = waiters[0];
        if (buf.length === 0) {
          if (ended) { w.resolve(null); waiters.shift(); continue; }
          break;
        }
        const n = Math.min(w.buf.length, buf.length);
        w.buf.set(buf.subarray(0, n), 0);
        buf = buf.subarray(n);
        w.resolve(n);
        waiters.shift();
      }
    };

    s.on('data', (c: Buffer) => { buf = buf.length === 0 ? c : Buffer.concat([buf, c]); flush(); });
    s.on('end', () => { ended = true; flush(); });
    s.on('error', (e) => { ended = true; for (const w of waiters) w.reject(e); waiters.length = 0; });

    const conn: TlsConn = {
      read: (b) => new Promise((res, rej) => { waiters.push({ buf: b, resolve: res, reject: rej }); flush(); }),
      write: (data) => new Promise((res, rej) => { s.write(data, (e) => e ? rej(e) : res(data.length)); }),
      close: () => s.destroy(),
    };
    s.once('connect', () => resolve(conn));
    s.once('error', reject);
  });
}

async function canConnect(): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host: HOST, port: PORT, timeout: 4000 });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
    s.once('timeout', () => { s.destroy(); resolve(false); });
  });
}

describe('native TLS auditor live handshake (network)', () => {
  it('completes a TLS 1.2 handshake and parses the real certificate', async () => {
    const online = await canConnect();
    if (!online) {
      console.log('WARN: no egress to example.com:443 — skipping live handshake test');
      return;
    }
    const ev = await probeTls(HOST, PORT, { timeoutMs: 8000, connFactory: nodeConnFactory });
    assert.equal(ev.reachable, true, `handshake failed: ${ev.error ?? ev.handshakeError}`);
    assert.ok(ev.serverCert, 'server certificate should be parsed');
    assert.match(ev.serverCert!.subject, /example/i);
    assert.equal(ev.protocolVersion, 'TLS 1.2');
    assert.ok(ev.cipherSuiteName, 'cipher suite should be named');
    assert.ok(ev.certificateChain.length >= 1, 'at least the leaf certificate');
  });
});
