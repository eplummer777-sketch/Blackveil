import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cleanOutput, sanitizeCommand, workerHealth } from '../supabase/functions/_lib/bvos.ts';
// @ts-expect-error plain JS worker module
import { parseSelfTest, sandboxArgs, validateCommand } from '../public/agent/blackveil-os-worker.mjs';

describe('bvos command sanitizer', () => {
  it('allows harmless allowlisted commands', () => {
    assert.deepEqual(sanitizeCommand('uname -a'), { ok: true, command: 'uname -a' });
    assert.equal(sanitizeCommand('id').ok, true);
  });
  it('rejects chaining, pipes, redirection, substitution and newlines', () => {
    for (const c of ['id; rm -rf /', 'id && ls', 'ls | sh', 'echo x > /tmp/a', 'echo `id`', 'echo $(id)', 'id\nls']) {
      assert.equal(sanitizeCommand(c).ok, false, c);
      assert.notEqual(validateCommand(c), null, c);
    }
  });
  it('rejects commands outside the allowlist', () => {
    assert.equal(sanitizeCommand('curl http://x').ok, false);
    assert.equal(sanitizeCommand('docker ps').ok, false);
  });
});

describe('bvos output cleaning', () => {
  it('keeps newlines and tabs but strips ANSI and control characters', () => {
    assert.equal(cleanOutput('a\n\tb\u001b[31mred\u001b[0m\u0007'), 'a\n\tbred');
  });
});

describe('bvos worker health', () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  const fresh = new Date(now - 10_000).toISOString();
  const okCaps = { docker: true, sandbox_ok: true };
  it('online only with fresh heartbeat, docker and passing self-test', () => {
    assert.equal(workerHealth({ revoked: false, last_seen_at: fresh, caps: okCaps }, now).state, 'online');
  });
  it('unhealthy when docker missing or self-test failed', () => {
    assert.equal(workerHealth({ revoked: false, last_seen_at: fresh, caps: { docker: false } }, now).state, 'unhealthy');
    assert.equal(workerHealth({ revoked: false, last_seen_at: fresh, caps: { docker: true, sandbox_ok: false } }, now).state, 'unhealthy');
  });
  it('offline when never seen or heartbeat stale', () => {
    assert.equal(workerHealth({ revoked: false, last_seen_at: null, caps: {} }, now).state, 'offline');
    assert.equal(workerHealth({ revoked: false, last_seen_at: new Date(now - 120_000).toISOString(), caps: okCaps }, now).state, 'offline');
  });
  it('unauthorized when revoked or a token rejection is newer than the last heartbeat', () => {
    assert.equal(workerHealth({ revoked: true, last_seen_at: fresh, caps: okCaps }, now).state, 'unauthorized');
    const h = workerHealth({ revoked: false, last_seen_at: fresh, last_auth_fail_at: new Date(now - 1000).toISOString(), caps: okCaps }, now);
    assert.equal(h.state, 'unauthorized');
  });
});

describe('bvos sandbox', () => {
  it('runs with no network, read-only root, non-root user and dropped capabilities', () => {
    const a: string[] = sandboxArgs('busybox:1.36', 'bvos-x', 'id');
    const after = (flag: string) => a[a.indexOf(flag) + 1];
    assert.equal(after('--network'), 'none');
    assert.ok(a.includes('--read-only'));
    assert.equal(after('--user'), '65534:65534');
    assert.equal(after('--cap-drop'), 'ALL');
    assert.equal(after('--security-opt'), 'no-new-privileges');
    assert.ok(!a.includes('-v') && !a.includes('--volume') && !a.includes('--privileged') && !a.includes('-e'));
    assert.deepEqual(a.slice(-4), ['busybox:1.36', 'sh', '-c', 'id']);
  });
  it('self-test parser requires uid 65534 and loopback only', () => {
    assert.deepEqual(parseSelfTest('65534\nlo\n'), { uid: '65534', networkIsolated: true });
    assert.equal(parseSelfTest('0\neth0\nlo\n').networkIsolated, false);
  });
});
