import { test } from 'node:test';
import assert from 'node:assert/strict';

const testEnv: Record<string, string | undefined> = { FRONTEND_URL: 'https://blackveil.example' };
(globalThis as unknown as { Deno: unknown }).Deno = { env: { get: (k: string) => testEnv[k] } };

const {
  b64urlDecode, b64urlEncode, encryptPayload, isAllowedPushEndpoint, isValidSubscriptionKeys, sendPush, vapidHeader,
} = await import('../supabase/functions/_lib/webpush.ts');

const enc = new TextEncoder();

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8));
}

async function makeBrowser() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const auth = crypto.getRandomValues(new Uint8Array(16));
  return { pair, pub, auth, p256dh: b64urlEncode(pub), authB64: b64urlEncode(auth) };
}

async function makeVapid() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return {
    pair,
    keys: { publicKey: b64urlEncode(await crypto.subtle.exportKey('raw', pair.publicKey)), privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey) },
  };
}

// Independent RFC 8291 decryption, as a browser's push stack would do it.
async function browserDecrypt(body: Uint8Array, b: Awaited<ReturnType<typeof makeBrowser>>) {
  const salt = body.slice(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset).getUint32(16);
  const idlen = body[20];
  const asPub = body.slice(21, 21 + idlen);
  const ct = body.slice(21 + idlen);
  assert.equal(rs, 4096);
  assert.equal(idlen, 65);
  const asKey = await crypto.subtle.importKey('raw', asPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: asKey }, b.pair.privateKey, 256));
  const info = new Uint8Array([...enc.encode('WebPush: info\0'), ...b.pub, ...asPub]);
  const ikm = await hkdf(b.auth, shared, info, 32);
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aes, ct));
  assert.equal(plain[plain.length - 1], 2, 'last-record delimiter');
  return new TextDecoder().decode(plain.slice(0, -1));
}

test('encrypted payload decrypts on the receiving browser', async () => {
  const b = await makeBrowser();
  const msg = JSON.stringify({ title: 'Blackveil HIGH', body: 'Threat found', url: '/?open=incidents', tag: 't' });
  const body = await encryptPayload(enc.encode(msg), b.p256dh, b.authB64);
  assert.equal(await browserDecrypt(body, b), msg);
});

test('a different browser cannot decrypt the payload', async () => {
  const a = await makeBrowser();
  const other = await makeBrowser();
  const body = await encryptPayload(enc.encode('secret'), a.p256dh, a.authB64);
  await assert.rejects(browserDecrypt(body, { ...other, pub: a.pub }));
});

test('VAPID header is a valid ES256 JWT for the push service origin', async () => {
  const { pair, keys } = await makeVapid();
  const header = await vapidHeader('https://fcm.googleapis.com/fcm/send/abc', keys);
  const m = /^vapid t=([^.]+)\.([^.]+)\.([^,]+), k=(.+)$/.exec(header);
  assert.ok(m);
  assert.equal(m![4], keys.publicKey);
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(m![2])));
  assert.equal(claims.aud, 'https://fcm.googleapis.com');
  assert.equal(claims.sub, 'https://blackveil.example');
  assert.ok(claims.exp > Date.now() / 1000 && claims.exp <= Date.now() / 1000 + 24 * 3600);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, b64urlDecode(m![3]), enc.encode(`${m![1]}.${m![2]}`));
  assert.ok(ok);
});

test('VAPID_SUBJECT is used as the contact, with or without mailto:', async () => {
  const { keys } = await makeVapid();
  const subOf = async () => {
    const jwt = (await vapidHeader('https://web.push.apple.com/x', keys)).split(' ')[1].slice(2).split('.')[1];
    return JSON.parse(new TextDecoder().decode(b64urlDecode(jwt))).sub;
  };
  try {
    testEnv.VAPID_SUBJECT = 'mailto:owner@example.com';
    assert.equal(await subOf(), 'mailto:owner@example.com');
    testEnv.VAPID_SUBJECT = ' owner@example.com ';
    assert.equal(await subOf(), 'mailto:owner@example.com');
    testEnv.VAPID_SUBJECT = 'https://blackveil.example/contact';
    assert.equal(await subOf(), 'https://blackveil.example/contact');
    testEnv.VAPID_SUBJECT = 'not a contact';
    assert.equal(await subOf(), 'https://blackveil.example');
  } finally {
    delete testEnv.VAPID_SUBJECT;
  }
});

test('only real push services are accepted as endpoints', () => {
  assert.ok(isAllowedPushEndpoint('https://fcm.googleapis.com/fcm/send/x'));
  assert.ok(isAllowedPushEndpoint('https://web.push.apple.com/QK1'));
  assert.ok(isAllowedPushEndpoint('https://updates.push.services.mozilla.com/wpush/v2/x'));
  assert.ok(isAllowedPushEndpoint('https://wns2-par02p.notify.windows.com/w/?token=x'));
  assert.ok(!isAllowedPushEndpoint('http://fcm.googleapis.com/x'));
  assert.ok(!isAllowedPushEndpoint('https://evil.com/fcm.googleapis.com'));
  assert.ok(!isAllowedPushEndpoint('https://fcm.googleapis.com.evil.com/x'));
  assert.ok(!isAllowedPushEndpoint('https://fcm.googleapis.com:8443/x'));
  assert.ok(!isAllowedPushEndpoint('https://169.254.169.254/latest'));
  assert.ok(!isAllowedPushEndpoint(42));
});

test('subscription keys are validated', async () => {
  const b = await makeBrowser();
  assert.ok(isValidSubscriptionKeys(b.p256dh, b.authB64));
  assert.ok(!isValidSubscriptionKeys(b.p256dh, 'short'));
  assert.ok(!isValidSubscriptionKeys('abc', b.authB64));
  assert.ok(!isValidSubscriptionKeys(b.p256dh + '!', b.authB64));
});

test('push service responses map to delivered, expired and retry', async () => {
  const b = await makeBrowser();
  const { keys } = await makeVapid();
  const sub = { id: '1', endpoint: 'https://fcm.googleapis.com/fcm/send/x', p256dh: b.p256dh, auth_secret: b.authB64, failure_count: 0 };
  const payload = { title: 't', body: 'b', url: '/', tag: 'blackveil-test' };
  const realFetch = globalThis.fetch;
  let seen: RequestInit | undefined;
  const respond = (status: number) => { globalThis.fetch = (async (_u: string, init: RequestInit) => { seen = init; return new Response(null, { status }); }) as typeof fetch; };
  try {
    respond(201);
    assert.deepEqual(await sendPush(sub, payload, keys, 'high'), { ok: true });
    const h = seen!.headers as Record<string, string>;
    assert.equal(h['Content-Encoding'], 'aes128gcm');
    assert.equal(h.Urgency, 'high');
    assert.ok(h.Authorization.startsWith('vapid t='));
    assert.ok(!JSON.stringify(h).includes(String(keys.privateJwk.d)), 'private key never sent');
    respond(410);
    assert.deepEqual(await sendPush(sub, payload, keys, 'high'), { ok: false, gone: true, retryable: false, error: 'Device subscription expired' });
    respond(404);
    assert.equal((await sendPush(sub, payload, keys, 'high') as { gone: boolean }).gone, true);
    respond(429);
    assert.equal((await sendPush(sub, payload, keys, 'high') as { retryable: boolean }).retryable, true);
    respond(400);
    assert.deepEqual(await sendPush(sub, payload, keys, 'high'), { ok: false, gone: false, retryable: false, error: 'Push service error 400' });
    globalThis.fetch = (async () => { throw new Error('network'); }) as typeof fetch;
    assert.equal((await sendPush(sub, payload, keys, 'high') as { retryable: boolean }).retryable, true);
    assert.equal((await sendPush({ ...sub, endpoint: 'https://evil.com/x' }, payload, keys, 'high') as { gone: boolean }).gone, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});
