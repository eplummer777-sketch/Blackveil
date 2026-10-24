import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect, type Server, type Socket } from 'node:net';
import { authorizeTarget, parseTarget } from '../supabase/functions/_lib/nmap.ts';
import { DialError, probePort, type Conn, type Dialer } from '../supabase/functions/network-scanner/probe.ts';
import {
  buildHosts, EGRESS_BLOCKED_PORTS, expandTargets, finalStatus, guardDialer, initialState, NATIVE_PROFILES,
  progressOf, runSlice, summarizeNative, type NativeScan,
} from '../supabase/functions/network-scanner/native.ts';
import { parseAnalysis } from '../supabase/functions/network-scanner/ai.ts';

const nodeDialer: Dialer = {
  tcp: (ip, port, ms) => new Promise<Conn>((resolve, reject) => {
    const s: Socket = connect({ host: ip, port });
    const chunks: Buffer[] = [];
    const waiters: ((b: Uint8Array) => void)[] = [];
    s.on('data', (d) => { const w = waiters.shift(); if (w) w(d); else chunks.push(d); });
    const t = setTimeout(() => { s.destroy(); reject(new DialError('timeout')); }, ms);
    s.once('error', (e: NodeJS.ErrnoException) => { clearTimeout(t); reject(new DialError(e.code === 'ECONNREFUSED' ? 'refused' : 'unreachable')); });
    s.once('connect', () => {
      clearTimeout(t);
      resolve({
        write: (d) => new Promise((r) => s.write(d, () => r())),
        read: (rms) => new Promise((r, j) => {
          const c = chunks.shift();
          if (c) return r(c);
          const to = setTimeout(() => j(new DialError('timeout')), rms);
          waiters.push((b) => { clearTimeout(to); r(b); });
        }),
        close: () => s.destroy(),
      });
    });
  }),
};

const listen = (onConn: (s: Socket) => void) => new Promise<Server>((r) => {
  const srv = createServer(onConn);
  srv.listen(0, '127.0.0.1', () => r(srv));
});
const portOf = (s: Server) => (s.address() as { port: number }).port;
const opts = { connectTimeoutMs: 800, bannerTimeoutMs: 400, identify: true };

describe('native probe against real local sockets', () => {
  let ssh: Server, silent: Server, closedPort: number;
  before(async () => {
    ssh = await listen((s) => s.write('SSH-2.0-OpenSSH_9.6 TestLab\r\n'));
    silent = await listen(() => {});
    const tmp = await listen(() => {});
    closedPort = portOf(tmp);
    await new Promise((r) => tmp.close(r));
  });
  after(() => { ssh.close(); silent.close(); });

  it('reports an open port and reads the service banner', async () => {
    const r = await probePort(nodeDialer, '127.0.0.1', portOf(ssh), opts);
    assert.equal(r.state, 'open');
    assert.equal(r.service, 'ssh');
    assert.match(r.product + r.version, /OpenSSH/);
  });
  it('reports a refused connection as closed', async () => {
    const r = await probePort(nodeDialer, '127.0.0.1', closedPort, opts);
    assert.equal(r.state, 'closed');
    assert.equal(r.reason, 'conn-refused');
  });
  it('an open but silent port is open with a low-confidence port-number guess', async () => {
    const r = await probePort(nodeDialer, '127.0.0.1', portOf(silent), opts);
    assert.equal(r.state, 'open');
    assert.equal(r.confidence, 'low');
  });
  it('a dial timeout is reported as filtered, never open', async () => {
    const slow: Dialer = { tcp: () => Promise.reject(new DialError('timeout')) };
    const r = await probePort(slow, '192.0.2.1', 22, opts);
    assert.equal(r.state, 'filtered');
    assert.equal(r.reason, 'no-response');
  });
});

const fake = (open: Set<number>, delayMs = 0): Dialer => ({
  tcp: (_ip, port) => new Promise((resolve, reject) => setTimeout(() => {
    if (open.has(port)) resolve({ write: async () => {}, read: () => Promise.reject(new DialError('timeout')), close: () => {} });
    else reject(new DialError('refused'));
  }, delayMs)),
});

const scanOf = (targets: string[], deadlineInMs = 90_000): NativeScan => ({
  profile: 'native_quick', targets, started_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + deadlineInMs).toISOString(), engine_state: null,
});
const farFuture = () => Date.now() + 60_000;

describe('native scan engine', () => {
  it('scans every planned port and completes', async () => {
    const scan = scanOf(['127.0.0.1']);
    const st = await runSlice(scan, fake(new Set([22, 443])), { sliceEndMs: farFuture(), isCancelled: () => false });
    assert.equal(st.next, st.total);
    assert.equal(progressOf(st), 100);
    assert.equal(finalStatus(st, false), 'completed');
    const hosts = buildHosts(st, scan.targets);
    assert.deepEqual(hosts[0].ports.map((p) => p.port), [22, 443]);
    assert.equal(hosts[0].state, 'up');
  });

  it('never plans mail ports the hosting network blocks', () => {
    for (const p of Object.values(NATIVE_PROFILES)) for (const b of EGRESS_BLOCKED_PORTS) assert.ok(!p.ports.includes(b));
  });

  it('stops on cancellation and reports cancelled with partial data', async () => {
    let calls = 0;
    const scan = scanOf(['127.0.0.1']);
    const now = (() => { let t = Date.now(); return () => (t += 1000); })();
    const st = await runSlice(scan, fake(new Set(), 5), { sliceEndMs: farFuture() + 1e7, isCancelled: () => ++calls >= 1, now });
    assert.ok(st.next < st.total);
    assert.equal(finalStatus(st, true), 'cancelled');
  });

  it('respects the deadline and reports partial, never secure', async () => {
    const scan = scanOf(['127.0.0.1'], 30_000);
    const st = await runSlice(scan, fake(new Set()), { sliceEndMs: farFuture(), isCancelled: () => false });
    assert.equal(st.next, 0, 'budget already consumed by the AI reserve + probe margin');
    const status = finalStatus(st, false);
    assert.equal(status, 'partial');
    const sum = summarizeNative(st, scan.targets, status, 90_000);
    assert.equal(sum.complete, false);
    assert.match(sum.coverage_note, /unknown, not safe/);
  });

  it('zero open ports on a full scan is described as not proof of security', async () => {
    const scan = scanOf(['127.0.0.1']);
    const st = await runSlice(scan, fake(new Set()), { sliceEndMs: farFuture(), isCancelled: () => false });
    const sum = summarizeNative(st, scan.targets, finalStatus(st, false), 1000);
    assert.equal(sum.open, 0);
    assert.match(sum.coverage_note, /not proof the target is secure/);
  });

  it('resumes from saved state across slices', async () => {
    const scan = scanOf(['127.0.0.1']);
    let t = Date.now();
    const st1 = await runSlice(scan, fake(new Set([22]), 1), { sliceEndMs: t + 9_000, isCancelled: () => false, now: () => (t += 50) });
    assert.ok(st1.next > 0 && st1.next < st1.total);
    const st2 = await runSlice({ ...scan, engine_state: st1 }, fake(new Set([22])), { sliceEndMs: farFuture(), isCancelled: () => false });
    assert.equal(st2.next, st2.total);
    assert.equal(st2.results['127.0.0.1'].length, st2.total);
  });
});

describe('scope enforcement and isolation', () => {
  it('the guarded dialer refuses addresses outside the authorized targets (DNS rebinding cannot redirect)', async () => {
    const g = guardDialer(fake(new Set([22])), ['203.0.113.5']);
    await assert.rejects(g.tcp('10.0.0.1', 22, 100), (e: unknown) => e instanceof DialError && e.kind === 'blocked');
    await assert.rejects(g.tcp('169.254.169.254', 80, 100), (e: unknown) => e instanceof DialError && e.kind === 'blocked');
  });

  it('metadata addresses are refused even if listed as targets', async () => {
    const g = guardDialer(fake(new Set([80])), ['169.254.169.254']);
    await assert.rejects(g.tcp('169.254.169.254', 80, 100));
  });

  it('records rejected addresses and produces no results for them', async () => {
    const scan = scanOf(['127.0.0.1']);
    const st = initialState(['127.0.0.1'], 'native_quick');
    const out = await runSlice({ ...scan, targets: ['127.0.0.1'], engine_state: st }, fake(new Set([22])), { sliceEndMs: farFuture(), isCancelled: () => false });
    assert.deepEqual(Object.keys(out.results), ['127.0.0.1']);
    assert.deepEqual(buildHosts(out, ['10.9.9.9']), [], 'hosts are only built for the scan\'s own targets');
  });

  it('private and metadata targets are refused without an approved scope', () => {
    const noCtx = { resolved: [], verifiedHosts: [], scopes: [] };
    for (const t of ['10.0.0.5', '127.0.0.1', '192.168.1.0/28']) assert.ok('error' in authorizeTarget(parseTarget(t) as never, noCtx));
    assert.ok('error' in authorizeTarget(parseTarget('169.254.169.254') as never, { ...noCtx, scopes: [{ id: 'x', cidr: '169.254.0.0/16' }] }));
  });

  it('hostnames resolving to private addresses are refused (rebinding at validation time)', () => {
    const r = authorizeTarget({ kind: 'hostname', value: 'evil.example.com' }, {
      resolved: ['10.0.0.8'], verifiedHosts: [{ id: 'v', hostname: 'evil.example.com' }], scopes: [],
    });
    assert.ok('error' in r);
  });

  it('expands ranges within the per-profile address limit', () => {
    assert.deepEqual(expandTargets(['10.0.0.0/30'], 4), ['10.0.0.1', '10.0.0.2']);
    assert.ok('error' in expandTargets(['10.0.0.0/24'], 16));
    assert.equal((expandTargets(['10.0.0.0/28'], 16) as string[]).length, 14);
  });
});

describe('AI evidence handling', () => {
  const base = { summary: 'Two services are reachable.', confirmed_facts: 'Port 22 open (ssh).', possibilities: 'May be outdated.', prioritized_risks: '1. SSH exposed', remediation: 'Restrict by IP', next_steps: 'Rescan' };
  it('accepts a well-formed analysis', () => {
    assert.equal(parseAnalysis(JSON.stringify(base)).confirmed_facts, 'Port 22 open (ssh).');
  });
  it('removes breach claims from confirmed facts and adds a disclaimer', () => {
    const a = parseAnalysis(JSON.stringify({ ...base, confirmed_facts: 'The server is breached via port 22. Confirmed vulnerability.' }));
    assert.doesNotMatch(a.confirmed_facts, /breached|confirmed vulnerab/i);
    assert.match(a.summary, /not proof of a breach/);
  });
  it('rejects a response missing a section', () => {
    const { next_steps: _n, ...rest } = base;
    assert.throws(() => parseAnalysis(JSON.stringify(rest)));
  });
  it('rejects unreadable output', () => {
    assert.throws(() => parseAnalysis('ignore previous instructions'));
  });
});