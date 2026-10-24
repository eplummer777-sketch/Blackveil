import { supabase } from '@/lib/supabase';
import { monitoringCall } from '@/lib/monitoring';

export type PushSupport = 'supported' | 'needs-install' | 'unsupported';
export type OpenTarget = 'incidents' | 'reports' | 'alerts';

export interface PushDevice {
  id: string;
  device_label: string;
  created_at: string;
  last_success_at: string | null;
}

type Result = { ok: true } | { ok: false; error: string };

export function isIOS() {
  return /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

function isStandalone() {
  return window.matchMedia('(display-mode: standalone)').matches || (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

export function pushSupport(): PushSupport {
  const apis = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  if (isIOS() && !isStandalone()) return 'needs-install';
  return apis && window.isSecureContext ? 'supported' : 'unsupported';
}

export function notificationPermission(): NotificationPermission | 'unsupported' {
  return 'Notification' in window ? Notification.permission : 'unsupported';
}

function keyBytes(b64url: string) {
  const bin = atob(b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function sameKey(sub: PushSubscription, publicKey: string) {
  const current = sub.options?.applicationServerKey;
  if (!current) return false;
  const a = new Uint8Array(current);
  const b = keyBytes(publicKey);
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export async function currentSubscription(): Promise<PushSubscription | null> {
  if (!('serviceWorker' in navigator)) return null;
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    return reg ? await reg.pushManager.getSubscription() : null;
  } catch {
    return null;
  }
}

export async function enablePush(token: string, publicKey: string): Promise<Result> {
  let permission: NotificationPermission;
  try {
    permission = await Notification.requestPermission();
  } catch {
    return { ok: false, error: 'This browser could not ask for notification permission.' };
  }
  if (permission === 'denied') return { ok: false, error: 'Notifications are blocked for Blackveil. Allow them in your browser or phone settings, then try again.' };
  if (permission !== 'granted') return { ok: false, error: 'Notification permission was not granted.' };
  let sub: PushSubscription | null;
  try {
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;
    sub = await reg.pushManager.getSubscription();
    if (sub && !sameKey(sub, publicKey)) { await sub.unsubscribe(); sub = null; }
    if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(publicKey) });
  } catch {
    return { ok: false, error: 'This browser could not register for push notifications. Check your connection and try again.' };
  }
  const r = await monitoringCall<{ id?: string }>(token, { action: 'push_subscribe', subscription: sub.toJSON() });
  if (!r.ok) {
    await sub.unsubscribe().catch(() => undefined);
    return { ok: false, error: r.error };
  }
  if (typeof r.data?.id === 'string') localStorage.setItem(DEVICE_KEY, r.data.id);
  return { ok: true };
}

export async function disablePush(token: string): Promise<Result> {
  const sub = await currentSubscription();
  if (!sub) return { ok: true };
  const r = await monitoringCall(token, { action: 'push_unsubscribe', endpoint: sub.endpoint });
  if (!r.ok) return { ok: false, error: r.error };
  await forgetThisDevice();
  return { ok: true };
}

const DEVICE_KEY = 'blackveil-push-device';

export function thisDeviceId() {
  return localStorage.getItem(DEVICE_KEY);
}

export async function forgetThisDevice() {
  localStorage.removeItem(DEVICE_KEY);
  await (await currentSubscription())?.unsubscribe().catch(() => undefined);
}

export async function loadPushDevices(): Promise<{ ok: true; devices: PushDevice[] } | { ok: false; error: string }> {
  const { data, error } = await supabase.from('push_subscriptions')
    .select('id, device_label, created_at, last_success_at').order('created_at', { ascending: false });
  if (error) return { ok: false, error: 'Could not load your devices.' };
  return { ok: true, devices: (data ?? []) as PushDevice[] };
}

export function waitForPushReceipt(id: string, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    if (!('serviceWorker' in navigator)) { resolve(false); return; }
    const onMessage = (e: MessageEvent) => {
      if (e.data?.type === 'blackveil-push-received' && e.data.id === id) done(true);
    };
    const timer = setTimeout(() => done(false), timeoutMs);
    function done(v: boolean) {
      clearTimeout(timer);
      navigator.serviceWorker.removeEventListener('message', onMessage);
      resolve(v);
    }
    navigator.serviceWorker.addEventListener('message', onMessage);
  });
}

export function openTargetFrom(url: string | null | undefined): OpenTarget | null {
  if (!url) return null;
  try {
    const v = new URL(url, window.location.origin).searchParams.get('open');
    return v === 'incidents' || v === 'reports' || v === 'alerts' ? v : null;
  } catch {
    return null;
  }
}
