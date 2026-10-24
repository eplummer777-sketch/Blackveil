import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, normalizeHostname, inScope } from '../supabase/functions/_lib/net.ts';
import type { Scope } from '../supabase/functions/_lib/net.ts';
import { computeScore } from '../supabase/functions/proof-of-breach/checks.ts';

describe('proof-of-breach: hostname normalization', () => {
  it('accepts public domains and strips scheme/path', () => {
    assert.equal(normalizeHostname('https://Example.com/path?x=1'), 'example.com');
    assert.equal(normalizeHostname('shop.example.co.uk'), 'shop.example.co.uk');
  });
  it('rejects IPs, ports, credentials and internal names', () => {
    for (const bad of ['127.0.0.1', '10.0.0.5', 'localhost', 'example.com:8080', 'user@example.com', 'db.internal', 'printer.local', '[::1]', '2130706433', 'metadata.google.internal', '']) {
      assert.equal(normalizeHostname(bad), null, bad);
    }
  });
});

describe('proof-of-breach: SSRF address blocking', () => {
  it('blocks private, loopback, link-local, metadata and reserved ranges', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', 'fc12::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::a00:1', 'garbage']) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
  });
  it('allows public addresses', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700::1111']) {
      assert.equal(isBlockedIp(ip), false, ip);
    }
  });
});

describe('proof-of-breach: scope enforcement', () => {
  const scope: Scope = { host: 'example.com', allowedPaths: ['/'], budget: { remaining: 5 }, signal: new AbortController().signal, violations: [] };
  it('allows the verified host and its www variant on standard ports', () => {
    assert.ok(inScope(new URL('https://example.com/a'), scope));
    assert.ok(inScope(new URL('http://www.example.com/'), scope));
  });
  it('rejects other hosts, look-alikes, non-standard ports and schemes', () => {
    for (const u of ['https://evil.com/', 'https://example.com.evil.com/', 'https://sub.example.com/', 'https://example.com:8443/', 'ftp://example.com/']) {
      assert.equal(inScope(new URL(u), scope), false, u);
    }
  });
  it('rejects paths outside the allowed list', () => {
    const narrow = { ...scope, allowedPaths: ['/app'] };
    assert.equal(inScope(new URL('https://example.com/admin'), narrow), false);
    assert.ok(inScope(new URL('https://example.com/app/x'), narrow));
  });
});

describe('proof-of-breach: scoring', () => {
  it('never awards 100 even when everything passes', () => {
    const { score } = computeScore([{ result: 'passed', severity: 'info', validation: 'detected' }]);
    assert.equal(score, 95);
  });
  it('penalizes incomplete and not-performed checks instead of treating them as passing', () => {
    const { score, counts } = computeScore([
      { result: 'passed', severity: 'info', validation: 'detected' },
      { result: 'incomplete', severity: 'info', validation: 'unresolved' },
      { result: 'not_performed', severity: 'info', validation: 'unresolved' },
    ]);
    assert.equal(counts.passed, 1);
    assert.equal(counts.incomplete, 1);
    assert.equal(counts.not_performed, 1);
    assert.ok(score < 95);
  });
  it('weights validated critical findings heavily', () => {
    const { score, counts } = computeScore([{ result: 'failed', severity: 'critical', validation: 'validated' }]);
    assert.equal(score, 65);
    assert.equal(counts.validated, 1);
  });
});
