import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoveryCheck, extractLinks, openApiPaths, type PageResponse, passiveChecks } from '../supabase/functions/zap-scanner/rules.ts';
import { advanceNative, type EngineDeps, type EngineScan, launchNative } from '../supabase/functions/zap-scanner/engine.ts';
import { buildConfig } from '../supabase/functions/zap-scanner/scope.ts';
import type { AlertRow } from '../supabase/functions/zap-scanner/parse.ts';

const target = { hostname: 'example.com', allowed_paths: ['/'], environment: 'staging' };

function page(url: string, body: string, headers: Record<string, string> = {}, setCookies: string[] = [], status = 200): PageResponse {
  return { url, status, body, setCookies, headers: new Headers({ 'content-type': 'text/html', ...headers }) };
}

const ids = (list: { pluginId: string }[]) => new Set(list.map((a) => a.pluginId));

test('passive checks flag missing headers, weak cookies and risky markup', () => {
  const body = `<form method="post" action="/login"><input name="user"></form>
    <script src="https://cdn.other.com/x.js"></script><img src="http://insecure.com/a.png">
    <a href="/reset?token=abcdef">x</a>`;
  const found = ids(passiveChecks(page('https://example.com/', body, { server: 'nginx/1.18.0', 'x-powered-by': 'Express', 'access-control-allow-origin': '*' }, ['sid=1; Path=/'])));
  for (const id of ['10038', '10020', '10021', '10035', '10010', '10011', '10054', '10036', '10037', '10098', '10202', '90003', '10040', '10024', '10063']) {
    assert.ok(found.has(id), `expected ${id}`);
  }
});

test('hardened page produces no header findings', () => {
  const headers = {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000', 'permissions-policy': 'camera=()', server: 'cloudflare',
  };
  const body = '<form method="post"><input type="hidden" name="csrf_token" value="x"></form>';
  assert.equal(passiveChecks(page('https://example.com/', body, headers, ['sid=1; Secure; HttpOnly; SameSite=Lax'])).length, 0);
});

test('discovery only reports real exposures', () => {
  assert.equal(discoveryCheck('/.env', page('https://example.com/.env', 'DB_PASSWORD=abc', { 'content-type': 'text/plain' }))?.risk, 'High');
  assert.equal(discoveryCheck('/.env', page('https://example.com/.env', '<html>FOO=bar</html>')), null);
  assert.equal(discoveryCheck('/.git/HEAD', page('https://example.com/.git/HEAD', 'ref: refs/heads/main', { 'content-type': 'text/plain' }))?.pluginId, '41');
  assert.equal(discoveryCheck('/.git/HEAD', page('https://example.com/.git/HEAD', 'nope', {}, [], 404)), null);
});

test('link extraction skips assets and non-http schemes', () => {
  const links = extractLinks(page('https://example.com/a/', '<a href="b">b</a><a href="mailto:x@y">m</a><link href="/s.css"><a href="https://evil.com/">e</a>'));
  assert.deepEqual(links, ['https://example.com/a/b', 'https://evil.com/']);
  assert.deepEqual(openApiPaths({ paths: { '/users': { get: {} }, '/users/{id}': { get: {} }, '/login': { post: {} } } }, 'https://example.com'), ['https://example.com/users']);
});

test('native engine crawls in scope, saves grouped findings and completes', async () => {
  const site: Record<string, PageResponse> = {
    'https://example.com/': page('https://example.com/', '<a href="/about">a</a><a href="https://evil.com/">e</a>'),
    'https://example.com/about': page('https://example.com/about', 'about'),
  };
  const fetched: string[] = [];
  let saved: AlertRow[] = [];
  const deps: EngineDeps = {
    target, now: () => Date.now(), sleep: async () => {}, checkDns: async () => {},
    saveAlerts: async (r) => { saved = r; },
    fetchPage: async (u) => { fetched.push(u); if (!site[u]) throw new Error('404'); return site[u]; },
  };
  const config = { ...buildConfig('baseline', null), delay_ms: 0, engine: 'native' as const };
  let scan = { id: 's1', mode: 'baseline', status: 'queued', phase: 'queued', progress: 0, target_url: 'https://example.com/', config,
    zap_context: null, spider_id: null, ascan_id: null, cancel_requested: false, engine_state: null,
    deadline_at: new Date(Date.now() + 60_000).toISOString(), phase_started_at: new Date().toISOString() } as EngineScan;
  scan = { ...scan, ...(await launchNative(scan, deps)) } as EngineScan;
  for (let i = 0; i < 5 && scan.status === 'running'; i++) scan = { ...scan, ...(await advanceNative(scan, deps)) } as EngineScan;
  assert.equal(scan.status, 'completed');
  assert.ok(!fetched.some((u) => u.includes('evil.com')));
  assert.deepEqual(fetched.sort(), ['https://example.com/', 'https://example.com/about']);
  assert.ok(saved.some((r) => r.plugin_id === '10038' && r.instance_count === 2));
  assert.equal(scan.engine_state, null);
});
