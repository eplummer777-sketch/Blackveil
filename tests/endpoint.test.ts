import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isScopeAllowed, mapEngineStatus, mapSeverity, newDeviceToken, sha256Hex, statusAfterScan,
  validatePaths, validateThreats, validateVerifyItems, verifyOutcome, isTestSignature, jobTimeoutMinutes,
} from '../supabase/functions/_lib/endpoint.ts';

const EICAR = {
  threatId: '2147519003', name: 'Virus:DOS/EICAR_Test_File', severityId: 5, category: 'Virus',
  resources: ['file:_C:\\BlackveilTest\\eicar.com'], sha256: '275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F',
  active: true, statusId: 1,
};

test('device tokens are unique, well-formed and hashed deterministically', async () => {
  const a = newDeviceToken(); const b = newDeviceToken();
  assert.notEqual(a, b);
  assert.match(a, /^bvd_[A-Za-z0-9_-]{40,60}$/);
  assert.equal(await sha256Hex(a), await sha256Hex(a));
  assert.equal((await sha256Hex(a)).length, 64);
});

test('scan scope: only authorized scan types and folders are allowed', () => {
  const device = { allowed_scopes: ['quick', 'custom'], allowed_paths: ['C:\\BlackveilTest'] };
  assert.equal(isScopeAllowed(device, 'quick'), true);
  assert.equal(isScopeAllowed(device, 'full'), false);
  assert.equal(isScopeAllowed(device, 'custom', 'C:\\BlackveilTest\\sub'), true);
  assert.equal(isScopeAllowed(device, 'custom', 'c:/blackveiltest'), true);
  assert.equal(isScopeAllowed(device, 'custom', 'C:\\BlackveilTestEvil'), false);
  assert.equal(isScopeAllowed(device, 'custom', 'C:\\Windows'), false);
  assert.equal(isScopeAllowed(device, 'custom'), false);
  assert.equal(isScopeAllowed(device, 'rm -rf'), false);
});

test('path validation rejects traversal and non-absolute paths', () => {
  assert.deepEqual(validatePaths(['C:\\Users\\me\\Downloads']), ['C:\\Users\\me\\Downloads']);
  assert.equal(validatePaths(['..\\secret']), null);
  assert.equal(validatePaths(['C:\\a\\..\\Windows']), null);
  assert.equal(validatePaths(['/etc/passwd']), null);
  assert.equal(validatePaths('C:\\x'), null);
});

test('EICAR test detection is parsed from a Defender report', () => {
  const parsed = validateThreats([EICAR]);
  assert.ok(parsed);
  assert.equal(parsed[0].severity, 'critical');
  assert.equal(parsed[0].sha256, EICAR.sha256.toLowerCase());
  assert.equal(isTestSignature(parsed[0].name), true);
  assert.equal(statusAfterScan(null, parsed[0]), 'awaiting_approval');
});

test('malformed or oversized agent reports are rejected', () => {
  assert.equal(validateThreats('nope'), null);
  assert.equal(validateThreats([{ name: 'x' }]), null);
  assert.equal(validateThreats([{ ...EICAR, threatId: 'abc' }]), null);
  assert.equal(validateThreats(Array.from({ length: 201 }, () => EICAR)), null);
  const bad = validateThreats([{ ...EICAR, sha256: 'not-a-hash' }]);
  assert.equal(bad?.[0].sha256, null);
});

test('Defender status codes map to honest remediation states', () => {
  assert.equal(mapEngineStatus(3).status, 'quarantined');
  assert.equal(mapEngineStatus(4).status, 'removed');
  assert.equal(mapEngineStatus(2).status, 'removed');
  assert.equal(mapEngineStatus(102).status, 'failed');
  assert.equal(mapEngineStatus(103).status, 'failed');
  assert.equal(mapEngineStatus(1).status, 'detected');
  assert.equal(mapSeverity(1), 'low');
  assert.equal(mapSeverity(99), 'unknown');
});

test('repeat detection after removal goes back to awaiting approval', () => {
  const [t] = validateThreats([EICAR])!;
  assert.equal(statusAfterScan('removed', t), 'awaiting_approval');
  assert.equal(statusAfterScan('verified_clean', t), 'awaiting_approval');
});

test('inactive historical detections do not undo verified or restored states', () => {
  const [t] = validateThreats([{ ...EICAR, active: false, statusId: 3 }])!;
  assert.equal(statusAfterScan('verified_clean', t), 'verified_clean');
  assert.equal(statusAfterScan('restored', t), 'restored');
  assert.equal(statusAfterScan(null, t), 'quarantined');
});

test('false positive: Defender auto-quarantine without active threat is reported as quarantined, not removed', () => {
  const [t] = validateThreats([{ ...EICAR, active: false, statusId: 3 }])!;
  assert.equal(statusAfterScan('awaiting_approval', t), 'quarantined');
});

test('verification only passes when every indicator is gone', () => {
  assert.equal(verifyOutcome({ threatId: '1', activeDetection: false, existingResources: [], persistenceHits: [] }).status, 'verified_clean');
  const stillActive = verifyOutcome({ threatId: '1', activeDetection: true, existingResources: [], persistenceHits: [] });
  assert.equal(stillActive.status, 'failed');
  assert.equal(verifyOutcome({ threatId: '1', activeDetection: false, existingResources: ['C:\\x.exe'], persistenceHits: [] }).status, 'failed');
  const persisted = verifyOutcome({ threatId: '1', activeDetection: false, existingResources: [], persistenceHits: ['registry:HKCU\\Run\\x'] });
  assert.equal(persisted.status, 'failed');
  assert.equal(persisted.reasons.length, 1);
});

test('verify report validation rejects missing fields', () => {
  assert.equal(validateVerifyItems([{ threatId: '1' }]), null);
  assert.equal(validateVerifyItems([{ threatId: 'x', activeDetection: false }]), null);
  assert.ok(validateVerifyItems([{ threatId: '1', activeDetection: false }]));
});

test('interrupted jobs time out per action type', () => {
  assert.equal(jobTimeoutMinutes('scan', 'quick'), 45);
  assert.equal(jobTimeoutMinutes('scan', 'full'), 480);
  assert.equal(jobTimeoutMinutes('remediate'), 20);
});
