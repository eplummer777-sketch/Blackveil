import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createZap, ZapError, type ZapApi } from '../supabase/functions/_lib/zapclient.ts';
import { buildConfig, contextIncludeRegex, isIntrusive, parseScanMode, parseTargetUrl, urlInTargetScope, validateSpec } from '../supabase/functions/zap-scanner/scope.ts';
import { groupAlerts, redact, riskFromZap } from '../supabase/functions/zap-scanner/parse.ts';
import { advance, launch, type Deps, type ScanRow } from '../supabase/functions/zap-scanner/lifecycle.ts';
import { isBlockedIp } from '../supabase/functions/_lib/net.ts';

const target = { hostname: 'example.com', allowed_paths: ['/'], environment: 'staging' };
const jsonRes = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

async function zapErr(p: Promise<unknown> | (() => unknown)): Promise<ZapError> {
  try { await (typeof p === 'function' ? p() : p); } catch (e) { assert.ok(e instanceof ZapError); return e; }
  assert.fail('expected ZapError');
}

describe('ZAP client connection and authentication', () => {
  it('reports unconfigured when URL or key is missing or invalid', async () => {
    assert.equal((await zapErr(() => createZap(undefined, 'k'))).kind, 'unconfigured');
    assert.equal((await zapErr(() => createZap('https://zap.test', undefined))).kind, 'unconfigured');
    assert.equal((await zapErr(() => createZap('ftp://zap.test', 'k'))).kind, 'unconfigured');
    assert.equal((await zapErr(() => createZap('https://u:p@zap.test', 'k'))).kind, 'unconfigured');
  });

  it('sends the API key as a header, not in the URL', async () => {
    let seen: { url: string; init?: RequestInit } | null = null;
    const zap = createZap('https://zap.test', 'secret-key', async (url, init) => { seen = { url, init }; return jsonRes({ version: '2.15.0' }); });
    const r = await zap.call('core', 'view', 'version');
    assert.equal(r.version, '2.15.0');
    assert.ok(seen);
    assert.equal(seen!.url, 'https://zap.test/JSON/core/view/version/');
    assert.equal(new Headers(seen!.init?.headers).get('X-ZAP-API-Key'), 'secret-key');
    assert.ok(!seen!.url.includes('secret-key'));
  });

  it('maps a rejected key to an auth error', async () => {
    const z1 = createZap('https://zap.test', 'bad', async () => jsonRes({ code: 'bad_api_key', message: 'Bad key' }, 400));
    assert.equal((await zapErr(z1.call('core', 'view', 'version'))).kind, 'auth');
    const z2 = createZap('https://zap.test', 'bad', async () => new Response('nope', { status: 401 }));
    assert.equal((await zapErr(z2.call('core', 'view', 'version'))).kind, 'auth');
  });

  it('maps network failures and non-JSON replies to unreachable', async () => {
    const z1 = createZap('https://zap.test', 'k', async () => { throw new TypeError('fetch failed'); });
    assert.equal((await zapErr(z1.call('core', 'view', 'version'))).kind, 'unreachable');
    const z2 = createZap('https://zap.test', 'k', async () => new Response('<html>proxy</html>', { status: 200 }));
    assert.equal((await zapErr(z2.call('core', 'view', 'version'))).kind, 'unreachable');
  });

  it('maps other ZAP errors to api errors', async () => {
    const z = createZap('https://zap.test', 'k', async () => jsonRes({ code: 'does_not_exist', message: 'No such scan' }, 400));
    assert.equal((await zapErr(z.call('spider', 'view', 'status', { scanId: 9 }))).kind, 'api');
  });
});

describe('ZAP target restrictions', () => {
  it('accepts in-scope URLs and normalises bare hosts', () => {
    assert.deepEqual(parseTargetUrl('example.com', target), { url: 'https://example.com/' });
    assert.ok('url' in parseTargetUrl('https://www.example.com/app?x=1', target));
  });

  it('rejects other hosts, private addresses, odd ports, credentials and schemes', () => {
    for (const bad of ['https://evil.com/', 'http://127.0.0.1/', 'http://localhost/', 'http://169.254.169.254/latest/meta-data/',
      'https://example.com:8443/', 'https://user:pw@example.com/', 'file:///etc/passwd', 'https://example.com.evil.com/', 'https://sub.example.com/', '']) {
      assert.ok('error' in parseTargetUrl(bad, target), bad);
    }
  });

  it('enforces allowed path prefixes', () => {
    const t = { ...target, allowed_paths: ['/api'] };
    assert.ok('url' in parseTargetUrl('https://example.com/api/users', t));
    assert.ok('error' in parseTargetUrl('https://example.com/admin', t));
    assert.equal(urlInTargetScope('https://example.com/api/x', t), true);
    assert.equal(urlInTargetScope('https://example.com/', t), false);
  });

  it('blocks metadata and private IP ranges at the network layer', () => {
    for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '::1', '0.0.0.0']) assert.equal(isBlockedIp(ip), true, ip);
    assert.equal(isBlockedIp('93.184.216.34'), false);
  });

  it('builds an anchored ZAP context regex limited to the target', () => {
    const re = new RegExp(contextIncludeRegex({ ...target, allowed_paths: ['/api'] }));
    assert.ok(re.test('https://example.com/api/v1'));
    assert.ok(re.test('https://www.example.com:443/api'));
    assert.ok(!re.test('https://exampleXcom/api'));
    assert.ok(!re.test('https://evil.com/?https://example.com/api'));
    assert.ok(!re.test('https://example.com/admin'));
  });

  it('parses modes and intrusive flags', () => {
    assert.equal(parseScanMode('baseline'), 'baseline');
    assert.equal(parseScanMode('rm -rf'), null);
    assert.equal(isIntrusive('baseline'), false);
    assert.equal(isIntrusive('active'), true);
    assert.equal(buildConfig('baseline', null).run_active, false);
    assert.equal(buildConfig('api', { source: 'upload' }).run_active, true);
  });

  it('validates OpenAPI uploads', () => {
    assert.ok('spec' in validateSpec(JSON.stringify({ openapi: '3.0.0', paths: { '/a': {} } })));
    assert.ok('error' in validateSpec('openapi: 3.0.0'));
    assert.ok('error' in validateSpec(JSON.stringify({ openapi: '1.0', paths: {} })));
    assert.ok('error' in validateSpec(JSON.stringify({ swagger: '2.0' })));
    assert.ok('error' in validateSpec('x'.repeat(1_000_001)));
  });
});

describe('ZAP result parsing', () => {
  const raw = [
    { pluginId: '10038', alert: 'CSP Header Not Set', risk: 'Medium', confidence: 'High', url: 'https://example.com/', method: 'GET', sourceid: '3', cweid: '693' },
    { pluginId: '10038', alert: 'CSP Header Not Set', risk: 'Medium', confidence: 'High', url: 'https://example.com/about', method: 'GET', sourceid: '3' },
    { pluginId: '40012', alert: 'XSS (Reflected)', risk: 'High', confidence: 'Medium', url: 'https://example.com/s?q=1', param: 'q', attack: '<script>', evidence: 'token=abcdef123456', sourceid: '1' },
    { pluginId: '10096', alert: 'Timestamp Disclosure', risk: 'Informational', url: 'https://cdn.other.com/x.js' },
    null,
  ];

  it('groups by rule, sorts by risk, drops out-of-scope URLs', () => {
    const { rows, dropped } = groupAlerts(raw, target);
    assert.equal(dropped, 1);
    assert.deepEqual(rows.map((r) => r.plugin_id), ['40012', '10038']);
    assert.equal(rows[1].instance_count, 2);
    assert.equal(rows[0].source, 'active');
    assert.equal(rows[1].source, 'passive');
    assert.equal(rows[1].cwe_id, 693);
  });

  it('redacts secrets from evidence', () => {
    const { rows } = groupAlerts(raw, target);
    assert.equal(rows[0].instances[0].evidence, 'token=[redacted]');
    assert.equal(redact('Cookie: session=abc123; Path=/'), 'Cookie: session=[redacted]; Path=/');
    assert.equal(redact('Authorization: Bearer eyJabc'), 'Authorization: Bearer [redacted]');
  });

  it('maps ZAP risk values', () => {
    assert.equal(riskFromZap('High'), 'high');
    assert.equal(riskFromZap('3'), 'high');
    assert.equal(riskFromZap('Informational'), 'info');
  });
});

type Call = [string, string, string, Record<string, unknown> | undefined];

function fakeZap(state: { spider: number; ascan: number; records: number; alerts: unknown[] }) {
  const calls: Call[] = [];
  const zap: ZapApi = {
    async call(c, t, n, p) {
      calls.push([c, t, n, p]);
      const key = `${c}/${n}`;
      if (key === 'core/version') return { version: '2.15.0' };
      if (key === 'context/newContext') return { contextId: '7' };
      if (key === 'spider/scan') return { scan: '1' };
      if (key === 'ascan/scan') return { scan: '2' };
      if (c === 'spider' && n === 'status') return { status: String(state.spider) };
      if (c === 'ascan' && n === 'status') return { status: String(state.ascan) };
      if (key === 'pscan/recordsToScan') return { recordsToScan: String(state.records) };
      if (key === 'core/alerts') return { alerts: state.alerts };
      return { Result: 'OK' };
    },
    async upload() { return '/zap/openapi.json'; },
  };
  return { zap, calls };
}

function makeScan(mode: 'baseline' | 'active', t0: number): ScanRow {
  return {
    id: 's1', mode, status: 'queued', phase: 'queued', progress: 0, target_url: 'https://example.com/', config: buildConfig(mode, null),
    zap_context: null, spider_id: null, ascan_id: null, cancel_requested: false,
    deadline_at: new Date(t0 + 15 * 60000).toISOString(), phase_started_at: new Date(t0).toISOString(),
  };
}

async function run(scan: ScanRow, deps: Deps, patchFn: (s: ScanRow) => Promise<Partial<ScanRow>>) {
  return { ...scan, ...(await patchFn(scan)) } as ScanRow;
}

describe('ZAP scan lifecycle', () => {
  const alerts = [{ pluginId: '10038', alert: 'CSP', risk: 'Medium', url: 'https://example.com/' }, { pluginId: '1', alert: 'x', risk: 'High', url: 'https://other.com/' }];

  it('baseline: launch, spider, passive, collect, complete without active scanning', async () => {
    const state = { spider: 40, ascan: 0, records: 0, alerts };
    const { zap, calls } = fakeZap(state);
    let saved: unknown[] = [];
    const now = Date.now();
    const deps: Deps = { zap, target, checkDns: async () => {}, saveAlerts: async (r) => { saved = r; }, now: () => now };
    let s = await run(makeScan('baseline', now), deps, (x) => launch(x, deps));
    assert.equal(s.status, 'running');
    assert.equal(s.phase, 'spider');
    assert.ok(calls.some(([c, , n, p]) => c === 'context' && n === 'includeInContext' && String(p?.regex).includes('example')));
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'spider');
    state.spider = 100;
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'passive');
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'collecting');
    const done = await advance(s, deps);
    assert.equal(done.status, 'completed');
    assert.equal(done.progress, 100);
    assert.equal(done.counts?.medium, 1);
    assert.equal(done.counts?.out_of_scope_dropped, 1);
    assert.equal(saved.length, 1);
    assert.ok(!calls.some(([c, , n]) => c === 'ascan' && n === 'scan'), 'baseline must never start an active scan');
  });

  it('active: starts an in-scope-only active scan after passive', async () => {
    const state = { spider: 100, ascan: 50, records: 0, alerts: [] };
    const { zap, calls } = fakeZap(state);
    const now = Date.now();
    const deps: Deps = { zap, target, checkDns: async () => {}, saveAlerts: async () => {}, now: () => now };
    let s = await run(makeScan('active', now), deps, (x) => launch(x, deps));
    s = await run(s, deps, (x) => advance(x, deps));
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'active');
    const as = calls.find(([c, , n]) => c === 'ascan' && n === 'scan');
    assert.equal(as?.[3]?.inScopeOnly, true);
    assert.equal(as?.[3]?.contextId, '7');
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'active');
    state.ascan = 100;
    s = await run(s, deps, (x) => advance(x, deps));
    assert.equal(s.phase, 'collecting');
    assert.equal((await advance(s, deps)).status, 'completed');
  });

  it('cancellation stops ZAP jobs and saves partial results', async () => {
    const { zap, calls } = fakeZap({ spider: 10, ascan: 0, records: 0, alerts });
    const now = Date.now();
    const deps: Deps = { zap, target, checkDns: async () => {}, saveAlerts: async () => {}, now: () => now };
    const s = await run(makeScan('baseline', now), deps, (x) => launch(x, deps));
    const r = await advance({ ...s, cancel_requested: true }, deps);
    assert.equal(r.status, 'cancelled');
    assert.ok(calls.some(([c, , n]) => c === 'spider' && n === 'stop'));
    assert.equal(r.counts?.medium, 1);
  });

  it('deadline marks the scan failed', async () => {
    const { zap } = fakeZap({ spider: 10, ascan: 0, records: 0, alerts: [] });
    let now = Date.now();
    const deps: Deps = { zap, target, checkDns: async () => {}, saveAlerts: async () => {}, now: () => now };
    const s = await run(makeScan('baseline', now), deps, (x) => launch(x, deps));
    now += 16 * 60000;
    const r = await advance(s, deps);
    assert.equal(r.status, 'failed');
    assert.match(String(r.error), /Time limit/);
  });

  it('DNS rebinding to a private address stops the scan', async () => {
    const { zap } = fakeZap({ spider: 10, ascan: 0, records: 0, alerts: [] });
    const now = Date.now();
    let blocked = false;
    const deps: Deps = { zap, target, checkDns: async () => { if (blocked) throw new Error('private'); }, saveAlerts: async () => {}, now: () => now };
    const s = await run(makeScan('baseline', now), deps, (x) => launch(x, deps));
    blocked = true;
    const r = await advance(s, deps);
    assert.equal(r.status, 'failed');
    assert.match(String(r.error), /private or reserved/);
  });

  it('refuses to launch when the target resolves privately', async () => {
    const { zap, calls } = fakeZap({ spider: 0, ascan: 0, records: 0, alerts: [] });
    const deps: Deps = { zap, target, checkDns: async () => { throw new Error('private'); }, saveAlerts: async () => {}, now: Date.now };
    await assert.rejects(launch(makeScan('baseline', Date.now()), deps));
    assert.equal(calls.length, 0);
  });

  it('collection failure turns a completed scan into failed with a clear error', async () => {
    const { zap } = fakeZap({ spider: 100, ascan: 0, records: 0, alerts: [] });
    const now = Date.now();
    const deps: Deps = { zap, target, checkDns: async () => {}, saveAlerts: async () => { throw new Error('db down'); }, now: () => now };
    const s = { ...makeScan('baseline', now), status: 'running' as const, phase: 'collecting' };
    const r = await advance(s, deps);
    assert.equal(r.status, 'failed');
    assert.match(String(r.error), /db down/);
  });
});
