import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCertificate, daysRemaining, timeToMs, parseTlv } from '../supabase/functions/_lib/x509.ts';
import { cipherName } from '../supabase/functions/_lib/tls.ts';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/tls/${name}`, import.meta.url));

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/\s+/g, '');
  const bytes = Uint8Array.from(Buffer.from(b64, 'base64'));
  return bytes;
}

describe('native x509 parser', () => {
  const goodDer = new Uint8Array(fixture('good.der'));
  const good = parseCertificate(goodDer);
  const expired = parseCertificate(pemToDer(fixture('expired.pem').toString('utf8')));

  it('parses subject and issuer names with labels', () => {
    assert.match(good.subject, /CN=good\.test/);
  });

  it('extracts the serial number and public key size', () => {
    assert.ok(good.serial.length >= 2, 'serial present');
    assert.equal(good.publicKeyBits, 2048);
    assert.equal(good.publicKeyAlgorithm.oid, '1.2.840.113549.1.1.1');
  });

  it('reads validity dates and flags an expired certificate', () => {
    const goodDays = daysRemaining(good.notAfter);
    assert.ok(goodDays > 700, `good cert should be valid for ~800 days, got ${goodDays}`);
    const expiredDays = daysRemaining(expired.notAfter);
    assert.ok(expiredDays < 0, `expired cert should have negative days, got ${expiredDays}`);
  });

  it('computes absolute validity time correctly', () => {
    const nb = timeToMs(expired.notBefore);
    assert.equal(new Date(nb).toISOString(), '2019-01-01T00:00:00.000Z');
    const na = timeToMs(expired.notAfter);
    assert.equal(new Date(na).toISOString(), '2020-01-01T00:00:00.000Z');
  });

  it('round-trips DER into a navigable TLV tree', () => {
    const root = parseTlv(goodDer);
    assert.equal(root.tag, 0x10); // SEQUENCE (decoded tag number, class/constructed separate)
    assert.equal(root.constructed, true);
    assert.ok(root.children.length >= 2);
  });

  it('names common cipher suites', () => {
    assert.equal(cipherName(0xc02f), 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
    assert.match(cipherName(0x1302), /TLS 1\.3/);
  });
});
