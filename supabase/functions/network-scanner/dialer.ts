import { type Conn, DialError, type Dialer } from "./probe.ts";

function wrap(c: Deno.Conn): Conn {
  return {
    write: async (d) => { await c.write(d); },
    read: (ms) => new Promise<Uint8Array>((resolve, reject) => {
      const buf = new Uint8Array(4096);
      const t = setTimeout(() => reject(new DialError("timeout")), ms);
      c.read(buf).then((n) => { clearTimeout(t); resolve(n ? buf.subarray(0, n) : new Uint8Array()); }, (e) => { clearTimeout(t); reject(e); });
    }),
    close: () => { try { c.close(); } catch { /* already closed */ } },
  };
}

function classify(e: unknown): DialError {
  if (e instanceof DialError) return e;
  if (e instanceof Deno.errors.ConnectionRefused || e instanceof Deno.errors.ConnectionReset) return new DialError("refused");
  if (e instanceof Deno.errors.TimedOut) return new DialError("timeout");
  return new DialError("unreachable", e instanceof Error ? e.message : String(e));
}

function withTimeout(p: Promise<Deno.Conn>, ms: number): Promise<Conn> {
  return new Promise((resolve, reject) => {
    let done = false;
    const t = setTimeout(() => { done = true; reject(new DialError("timeout")); }, ms);
    p.then((c) => {
      clearTimeout(t);
      if (done) { try { c.close(); } catch { /* ignore */ } return; }
      resolve(wrap(c));
    }, (e) => { clearTimeout(t); if (!done) reject(classify(e)); });
  });
}

export const denoDialer: Dialer = {
  tcp: (ip, port, ms) => withTimeout(Deno.connect({ hostname: ip, port, transport: "tcp" }), ms),
  tls: (ip, port, _serverName, ms) => withTimeout(Deno.connectTls({ hostname: ip, port }), ms),
};
