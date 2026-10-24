import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";

const enc = new TextEncoder();

const PUSH_HOSTS = [
  /^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/,
  /^push\.services\.mozilla\.com$/, /^web\.push\.apple\.com$/, /^[a-z0-9-]+\.push\.apple\.com$/, /^[a-z0-9-]+\.notify\.windows\.com$/,
];

export interface PushSubscriptionRow { id: string; endpoint: string; p256dh: string; auth_secret: string; failure_count: number }
export interface PushPayload { title: string; body: string; url: string; tag: string; id?: string }
export type PushSendResult = { ok: true } | { ok: false; gone: boolean; retryable: boolean; error: string };

export function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function isAllowedPushEndpoint(endpoint: unknown): endpoint is string {
  if (typeof endpoint !== "string" || endpoint.length > 1024) return false;
  try {
    const u = new URL(endpoint);
    return u.protocol === "https:" && !u.port && PUSH_HOSTS.some((re) => re.test(u.hostname));
  } catch { return false; }
}

export function isValidSubscriptionKeys(p256dh: unknown, auth: unknown): boolean {
  if (typeof p256dh !== "string" || typeof auth !== "string" || !/^[A-Za-z0-9_-]+$/.test(p256dh + auth)) return false;
  try {
    const k = b64urlDecode(p256dh);
    return k.length === 65 && k[0] === 4 && b64urlDecode(auth).length === 16;
  } catch { return false; }
}

interface VapidKeys { publicKey: string; privateJwk: JsonWebKey }

export async function getVapidKeys(svc: SupabaseClient): Promise<VapidKeys> {
  const read = async () => {
    const { data } = await svc.from("internal_config").select("value").eq("key", "vapid_keys").maybeSingle();
    return data ? JSON.parse(data.value) as VapidKeys : null;
  };
  const existing = await read();
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const keys: VapidKeys = {
    publicKey: b64urlEncode(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
  };
  await svc.from("internal_config").upsert({ key: "vapid_keys", value: JSON.stringify(keys) }, { onConflict: "key", ignoreDuplicates: true });
  const stored = await read();
  if (!stored) throw new Error("Could not store push signing key");
  return stored;
}

function vapidSubject(): string {
  const explicit = (Deno.env.get("VAPID_SUBJECT") ?? "").trim();
  if (/^(mailto:|https:\/\/)/i.test(explicit)) return explicit;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(explicit)) return `mailto:${explicit}`;
  const site = (Deno.env.get("FRONTEND_URL") ?? "").trim();
  if (site.startsWith("https://")) return site.replace(/\/+$/, "");
  return "mailto:security-alerts@blackveil.app";
}

export async function vapidHeader(endpoint: string, keys: VapidKeys): Promise<string> {
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64urlEncode(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: vapidSubject(),
  })));
  const key = await crypto.subtle.importKey("jwk", keys.privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64urlEncode(sig)}, k=${keys.publicKey}`;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

// RFC 8291 (Message Encryption for Web Push) with the aes128gcm content coding from RFC 8188.
export async function encryptPayload(plaintext: Uint8Array, p256dh: string, authSecret: string): Promise<Uint8Array> {
  const uaPub = b64urlDecode(p256dh);
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(b64urlDecode(authSecret), shared, concat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(plaintext, new Uint8Array([2]))));
  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPub.length;
  return concat(header, asPub, ct);
}

export async function sendPush(sub: PushSubscriptionRow, payload: PushPayload, keys: VapidKeys, urgency: "high" | "normal"): Promise<PushSendResult> {
  if (!isAllowedPushEndpoint(sub.endpoint)) return { ok: false, gone: true, retryable: false, error: "Unrecognised push service" };
  try {
    const body = await encryptPayload(enc.encode(JSON.stringify(payload)), sub.p256dh, sub.auth_secret);
    const res = await fetch(sub.endpoint, {
      method: "POST",
      headers: {
        Authorization: await vapidHeader(sub.endpoint, keys),
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
        TTL: "86400", Urgency: urgency, Topic: payload.tag.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32),
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    await res.body?.cancel();
    if (res.status >= 200 && res.status < 300) return { ok: true };
    if (res.status === 404 || res.status === 410) return { ok: false, gone: true, retryable: false, error: "Device subscription expired" };
    return { ok: false, gone: false, retryable: res.status === 429 || res.status >= 500, error: `Push service error ${res.status}` };
  } catch {
    return { ok: false, gone: false, retryable: true, error: "Push service unreachable" };
  }
}

const MAX_FAILURES = 5;

export async function pushToUser(svc: SupabaseClient, userId: string, payload: PushPayload, urgency: "high" | "normal", onlyEndpoint?: string) {
  let q = svc.from("push_subscriptions").select("id, endpoint, p256dh, auth_secret, failure_count").eq("user_id", userId);
  if (onlyEndpoint) q = q.eq("endpoint", onlyEndpoint);
  const { data: subs, error } = await q;
  if (error) return { devices: 0, sent: 0, removed: 0, retryable: true, error: "Could not load devices" };
  const rows = (subs ?? []) as PushSubscriptionRow[];
  if (rows.length === 0) return { devices: 0, sent: 0, removed: 0, retryable: false, error: "No devices have push notifications turned on" };

  const keys = await getVapidKeys(svc);
  let sent = 0, removed = 0, retryable = false, lastError = "";
  for (const sub of rows) {
    const r = await sendPush(sub, payload, keys, urgency);
    if (r.ok) {
      sent++;
      await svc.from("push_subscriptions").update({ last_success_at: new Date().toISOString(), failure_count: 0 }).eq("id", sub.id);
      continue;
    }
    lastError = r.error;
    if (r.gone || sub.failure_count + 1 >= MAX_FAILURES) {
      removed++;
      await svc.from("push_subscriptions").delete().eq("id", sub.id);
      await svc.from("endpoint_audit").insert({ user_id: userId, actor: "system", action: "push_device_removed", outcome: "succeeded", detail: { reason: r.error } });
    } else {
      retryable = retryable || r.retryable;
      await svc.from("push_subscriptions").update({ failure_count: sub.failure_count + 1 }).eq("id", sub.id);
    }
  }
  if (removed > 0 && sent === 0) {
    const { count } = await svc.from("push_subscriptions").select("id", { count: "exact", head: true }).eq("user_id", userId);
    if (!count) await svc.from("monitoring_settings").update({ push_alerts: false }).eq("user_id", userId);
  }
  return { devices: rows.length, sent, removed, retryable, error: sent > 0 ? "" : lastError };
}
