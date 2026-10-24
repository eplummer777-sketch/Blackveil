// Cloudflare API client — least-privilege, read-mostly, official REST endpoints only.
// Docs: https://developers.cloudflare.com/api/

const BASE = "https://api.cloudflare.com/client/v4";

export interface CfResult<T = unknown> {
  ok: boolean;
  data?: T;
  errors: { code: number; message: string }[];
  status: number;
}

async function cf<T = unknown>(path: string, token: string, method: "GET" | "PUT" | "PATCH" = "GET", body?: Record<string, unknown>): Promise<CfResult<T>> {
  const url = path.startsWith("http") ? path : `${BASE}${path}`;
  try {
    const resp = await fetch(url, {
      method,
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": "Blackveil-Architect/1.0",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15000),
      redirect: "error",
    });
    let parsed: { success: boolean; result?: T; errors?: { code: number; message: string }[] } | null = null;
    const text = await resp.text();
    try { parsed = JSON.parse(text); } catch { /* non-JSON */ }
    if (!resp.ok || !parsed?.success) {
      return { ok: false, errors: parsed?.errors ?? [{ code: resp.status, message: `Cloudflare API returned ${resp.status}` }], status: resp.status };
    }
    return { ok: true, data: parsed.result as T, errors: [], status: resp.status };
  } catch (e) {
    return { ok: false, errors: [{ code: 0, message: (e as Error).message ?? "Network error" }], status: 0 };
  }
}

// --- Token verification ---
export interface CfTokenVerify {
  token_id: string;
  status: string;
  expires_on: string | null;
  policies: { id: string; effect: string; resources: Record<string, string>; permissions: { effect: string; resources: Record<string, string>; actions: string[] }[] }[];
}

export async function verifyToken(token: string): Promise<CfResult<CfTokenVerify>> {
  return cf<CfTokenVerify>("/user/tokens/verify", token);
}

// --- Zone listing ---
export interface CfZone {
  id: string;
  name: string;
  account: { id: string; name: string };
  status: string;
  permissions: string[];
}

export async function listZones(token: string): Promise<CfResult<CfZone[]>> {
  return cf<CfZone[]>(`/zones?per_page=50`, token);
}

export async function getZone(token: string, zoneId: string): Promise<CfResult<CfZone>> {
  return cf<CfZone>(`/zones/${zoneId}`, token);
}

// --- Settings we read and can write ---
export interface CfSetting {
  id: string;
  value: unknown;
  modified_on: string | null;
}

export async function getSetting(token: string, zoneId: string, key: string): Promise<CfResult<CfSetting>> {
  return cf<CfSetting>(`/zones/${zoneId}/settings/${key}`, token);
}

export async function putSetting(token: string, zoneId: string, key: string, value: unknown): Promise<CfResult<CfSetting>> {
  return cf<CfSetting>(`/zones/${zoneId}/settings/${key}`, token, "PUT", { value });
}

// Security Level
export async function getSecurityLevel(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "security_level");
}

// SSL/TLS mode
export async function getSslMode(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "ssl");
}

// Always Use HTTPS
export async function getAlwaysUseHttps(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "always_use_https");
}

// HSTS
export async function getHsts(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "ch/hsts");
}

// Automatic HTTPS Rewrites
export async function getAutoHttpsRewrites(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "automatic_https_rewrites");
}

// TLS 1.2/1.3
export async function getTls12(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "tls_1_2");
}

export async function getTls13(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "tls_1_3");
}

// Min TLS version
export async function getMinTls(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "min_tls_version");
}

// 0-RTT
export async function getZeroRtt(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "zero_rtt");
}

// Browser Integrity Check
export async function getBrowserCheck(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "browser_check");
}

// Privacy Pass
export async function getPrivacyPass(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "privacy_pass");
}

// Onion routing
export async function getOnion(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "onion");
}

// Hotlink protection
export async function getHotlink(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "hotlink_protection");
}

// Server-Side Exclude
export async function getServerSideExclude(token: string, zoneId: string): Promise<CfResult<CfSetting>> {
  return getSetting(token, zoneId, "server_side_exclude");
}

export function settingFrom(r: CfResult<CfSetting>): { value: unknown; modified_on: string | null; error?: string } {
  if (!r.ok) return { value: null, modified_on: null, error: r.errors[0]?.message ?? "Could not read this setting." };
  return { value: r.data?.value ?? null, modified_on: r.data?.modified_on ?? null };
}

export async function putSettingByKey(token: string, zoneId: string, key: string, value: unknown): Promise<CfResult> {
  return putSetting(token, zoneId, key, value);
}
