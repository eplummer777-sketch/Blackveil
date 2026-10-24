import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { keyHint, validateApiKey, validateInstanceName, validateInstanceUrl } from '../supabase/functions/zap-instances/validate.ts';
import { decryptSecret, encryptSecret } from '../supabase/functions/zap-instances/secrets.ts';
import { checkInstance } from '../supabase/functions/zap-instances/health.ts';
import { getProvider, validateLimits } from '../supabase/functions/zap-instances/provider.ts';

const KEY = 'k'.repeat(32);
const MASTER = 'm'.repeat(48);
const BASE = 'https://zap.example.com';
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const okDns = async () => ['93.184.216.34'];
const noSleep = async () => {};

function keyFromInit(init?: RequestInit): string | null {
  return new Headers(init?.headers).get('X-ZAP-API-Key');
}

function zapServer(opts: { requireKey?: boolean; validKey?: string; version?: string } = {}) {
  const { requireKey = true, validKey = KEY, version = '2.17.0' } = opts;
  return async (url: string | URL | Request, init?: RequestInit) => {
    assert.equal(init?.redirect, 'manual');
    assert.ok(String(url).startsWith(BASE));
    const k = keyFromInit(init);
    if (!requireKey) return json({ version });
    if (k === null) return json({ code: 'bad_api_key', message: 'Missing key' }, 400);
    if (k !== validKey) return json({ code: 'bad_api_key', message: 'Wrong key' }, 400);
    return json({ version });
  };
}

describe('scanner URL validation (SSRF)', () => {
  it('accepts public https hosts and normalizes them', () => {
    assert.deepEqual(validateInstanceUrl('https://Zap.Example.com/'), { value: 'https://zap.example.com' });
    assert.deepEqual(validateInstanceUrl('https://zap.example.com:8443'), { value: 'https://zap.example.com:8443' });
  });

  for (const bad of [
    'http://zap.example.com',
    'https://127.0.0.1', 'https://10.0.0.5', 'https://[::1]', 'https://169.254.169.254', 'https://0x7f000001',
    'https://localhost', 'https://metadata.google.internal', 'https://app.svc.cluster.local', 'https://printer.local',
    'https://zap.example.com:22', 'https://zap.example.com:6379',
    'https://zap.example.com/JSON/core', 'https://zap.example.com/?x=1', 'https://user:pw@zap.example.com',
    'ftp://zap.example.com', 'javascript:alert(1)', '', 'not a url',
  ]) {
    it(`rejects ${bad || '(empty)'}`, () => assert.ok('error' in validateInstanceUrl(bad)));
  }

  it('rejects non-string input', () => {
    assert.ok('error' in validateInstanceUrl(42));
    assert.ok('error' in validateInstanceUrl(null));
  });
});

describe('name and API key validation', () => {
  it('validates names', () => {
    assert.deepEqual(validateInstanceName('  Prod  '), { value: 'Prod' });
    assert.ok('error' in validateInstanceName(''));
    assert.ok('error' in validateInstanceName('x'.repeat(61)));
  });
  it('validates keys and only exposes a 4-character hint', () => {
    assert.ok('error' in validateApiKey('short'));
    assert.ok('error' in validateApiKey('has space in the key value'));
    assert.ok('error' in validateApiKey('x'.repeat(201)));
    assert.deepEqual(validateApiKey(KEY), { value: KEY });
    assert.equal(keyHint('abcdefghijklmnopWXYZ'), 'WXYZ');
  });
});

describe('API key encryption', () => {
  it('round-trips and never contains the plaintext', async () => {
    const blob = await encryptSecret(KEY, MASTER, 'user-1');
    assert.ok(blob.startsWith('v1.'));
    assert.ok(!blob.includes(KEY));
    assert.equal(await decryptSecret(blob, MASTER, 'user-1'), KEY);
  });
  it('uses a fresh IV each time', async () => {
    assert.notEqual(await encryptSecret(KEY, MASTER, 'u'), await encryptSecret(KEY, MASTER, 'u'));
  });
  it("cannot be decrypted as another user's key", async () => {
    const blob = await encryptSecret(KEY, MASTER, 'user-1');
    await assert.rejects(decryptSecret(blob, MASTER, 'user-2'));
  });
  it('rejects a wrong master secret or tampered data', async () => {
    const blob = await encryptSecret(KEY, MASTER, 'u');
    await assert.rejects(decryptSecret(blob, 'z'.repeat(48), 'u'));
    const parts = blob.split('.');
    const ct = Buffer.from(parts[2], 'base64');
    ct[0] ^= 1;
    await assert.rejects(decryptSecret(`${parts[0]}.${parts[1]}.${ct.toString('base64')}`, MASTER, 'u'));
  });
  it('refuses a weak master secret', async () => {
    await assert.rejects(encryptSecret(KEY, 'short', 'u'));
  });
});

describe('connection test', () => {
  it('reports connected with the ZAP version', async () => {
    const r = await checkInstance(BASE, KEY, { resolvePublic: okDns, fetchImpl: zapServer(), sleep: noSleep });
    assert.equal(r.status, 'connected');
    assert.equal(r.version, '2.17.0');
    assert.ok(r.checks.every((c) => c.ok));
    assert.ok(!JSON.stringify(r).includes(KEY));
  });

  it('refuses hosts that resolve to private addresses without calling them', async () => {
    let called = false;
    const r = await checkInstance(BASE, KEY, {
      resolvePublic: async () => { throw new Error('private'); },
      fetchImpl: async () => { called = true; return json({}); },
    });
    assert.equal(r.status, 'unhealthy');
    assert.equal(called, false);
  });

  it('reports disconnected on timeout after retrying', async () => {
    let calls = 0;
    const r = await checkInstance(BASE, KEY, {
      resolvePublic: okDns, sleep: noSleep, retries: 2,
      fetchImpl: async () => { calls++; throw new DOMException('timeout', 'TimeoutError'); },
    });
    assert.equal(r.status, 'disconnected');
    assert.equal(calls, 3);
  });

  it('recovers when a retry succeeds', async () => {
    let calls = 0;
    const real = zapServer();
    const r = await checkInstance(BASE, KEY, {
      resolvePublic: okDns, sleep: noSleep,
      fetchImpl: async (u, i) => { if (calls++ === 0) throw new TypeError('reset'); return real(u, i); },
    });
    assert.equal(r.status, 'connected');
  });

  it('does not follow redirects', async () => {
    const r = await checkInstance(BASE, KEY, {
      resolvePublic: okDns, sleep: noSleep,
      fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } }),
    });
    assert.equal(r.status, 'unhealthy');
  });

  it('does not trust any server that merely answers HTTP', async () => {
    const r = await checkInstance(BASE, KEY, {
      resolvePublic: okDns, sleep: noSleep, fetchImpl: async () => new Response('<html>hello</html>', { status: 200 }),
    });
    assert.equal(r.status, 'unhealthy');
  });

  it('flags a ZAP that runs without an API key', async () => {
    const r = await checkInstance(BASE, KEY, { resolvePublic: okDns, sleep: noSleep, fetchImpl: zapServer({ requireKey: false }) });
    assert.equal(r.status, 'unhealthy');
    assert.match(r.error ?? '', /without an API key/);
  });

  it('reports a wrong key as unhealthy', async () => {
    const r = await checkInstance(BASE, 'w'.repeat(32), { resolvePublic: okDns, sleep: noSleep, fetchImpl: zapServer() });
    assert.equal(r.status, 'unhealthy');
    assert.equal(r.version, null);
  });

  it('rejects an invalid version value', async () => {
    const r = await checkInstance(BASE, KEY, { resolvePublic: okDns, sleep: noSleep, fetchImpl: zapServer({ version: '<script>' }) });
    assert.equal(r.status, 'unhealthy');
  });
});

describe('scanner provisioning', () => {
  it('is honestly unconfigured and never pretends to create servers', async () => {
    const p = getProvider();
    assert.equal(p.configured, false);
    const c = await p.create('user-1', { cpu: 1, memoryMb: 1024 });
    assert.equal(c.ok, false);
    for (const op of [p.restart, p.shutdown, p.destroy]) assert.equal((await op('x')).ok, false);
  });
  it('enforces resource limits', () => {
    assert.deepEqual(validateLimits(undefined), { value: { cpu: 1, memoryMb: 1024 } });
    assert.ok('error' in validateLimits({ cpu: 16 }));
    assert.ok('error' in validateLimits({ memoryMb: 100000 }));
    assert.ok('error' in validateLimits({ cpu: Number.NaN }));
  });
});
