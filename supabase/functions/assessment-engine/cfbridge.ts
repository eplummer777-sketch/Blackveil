// Self-contained Cloudflare bridge for the assessment engine.
// Inlines the Cloudflare API client and settings catalog since cross-function
// imports are not supported by the Deno deploy bundler.

const CF_BASE = "https://api.cloudflare.com/client/v4";

interface CfResult<T = unknown> {
  ok: boolean;
  data?: T;
  errors: { code: number; message: string }[];
  status: number;
}

async function cfFetch<T = unknown>(path: string, token: string, method: "GET" | "PUT" = "GET", body?: Record<string, unknown>): Promise<CfResult<T>> {
  const url = path.startsWith("http") ? path : `${CF_BASE}${path}`;
  try {
    const resp = await fetch(url, {
      method,
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": "Blackveil-Remediation-Engine/1.0",
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

interface CfSetting {
  id: string;
  value: unknown;
  modified_on: string | null;
}

interface SettingDef {
  key: string;
  label: string;
  category: string;
  recommended: unknown;
  risk_level: "low" | "medium" | "high";
  explanation: string;
  risks: string[];
  rollback_instructions: string;
  gap: (current: unknown) => boolean;
}

const SETTING_CATALOG: SettingDef[] = [
  {
    key: "ssl", label: "SSL/TLS encryption mode", category: "Encryption",
    recommended: "full", risk_level: "medium",
    explanation: "Sets how Cloudflare encrypts traffic between visitors and your origin server.",
    risks: ["Switching from 'flexible' to 'full' means Cloudflare will connect to your origin over HTTPS. Your origin must have HTTPS enabled."],
    rollback_instructions: "Settings > SSL/TLS > Overview, set the mode back to its previous value.",
    gap: (c) => typeof c === "string" && c === "off",
  },
  {
    key: "always_use_https", label: "Always Use HTTPS", category: "Encryption",
    recommended: "on", risk_level: "low",
    explanation: "Redirects all HTTP requests to HTTPS automatically.",
    risks: ["Hardcoded HTTP URLs in scripts may show as mixed content."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'Always Use HTTPS'.",
    gap: (c) => c !== "on",
  },
  {
    key: "automatic_https_rewrites", label: "Automatic HTTPS Rewrites", category: "Encryption",
    recommended: "on", risk_level: "low",
    explanation: "Rewrites HTTP links on your pages to HTTPS automatically.",
    risks: ["Rare: may interfere with complex JavaScript applications."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'Automatic HTTPS Rewrites'.",
    gap: (c) => c !== "on",
  },
  {
    key: "min_tls_version", label: "Minimum TLS Version", category: "Encryption",
    recommended: "1.2", risk_level: "medium",
    explanation: "Rejects connections from browsers using TLS versions older than the minimum.",
    risks: ["Very old browsers will be unable to connect if TLS 1.2 is the minimum."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, set 'Minimum TLS Version' back to 1.0.",
    gap: (c) => typeof c === "string" && (c === "1.0" || c === "1.1"),
  },
  {
    key: "tls_1_3", label: "TLS 1.3", category: "Encryption",
    recommended: "on", risk_level: "low",
    explanation: "Enables TLS 1.3, the latest and most secure TLS protocol version.",
    risks: ["Extremely rare: old clients may not support TLS 1.3."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'TLS 1.3'.",
    gap: (c) => c !== "on",
  },
  {
    key: "security_level", label: "Security Level", category: "Bot protection",
    recommended: "medium", risk_level: "low",
    explanation: "Controls how aggressively Cloudflare challenges suspicious visitors.",
    risks: ["Setting to 'High' may show CAPTCHA to some legitimate visitors."],
    rollback_instructions: "Security > Settings, set Security Level back to its previous value.",
    gap: (c) => typeof c === "string" && (c === "essentially_off" || c === "low"),
  },
  {
    key: "browser_check", label: "Browser Integrity Check", category: "Bot protection",
    recommended: "on", risk_level: "low",
    explanation: "Blocks requests from common bot User-Agent headers.",
    risks: ["Some legitimate API clients with unusual User-Agent strings may be blocked."],
    rollback_instructions: "Security > Settings, turn off 'Browser Integrity Check'.",
    gap: (c) => c !== "on",
  },
  {
    key: "privacy_pass", label: "Privacy Pass", category: "Bot protection",
    recommended: "on", risk_level: "low",
    explanation: "Allows visitors who pass a challenge to get a token so they are not challenged again repeatedly.",
    risks: ["None significant."],
    rollback_instructions: "Security > Settings, turn off 'Privacy Pass'.",
    gap: (c) => c !== "on",
  },
  {
    key: "ch/hsts", label: "HSTS (HTTP Strict Transport Security)", category: "Headers",
    recommended: { enabled: true, max_age: 15552000, include_subdomains: true, preload: false, nosniff: false },
    risk_level: "high",
    explanation: "Tells browsers to only connect over HTTPS for the specified duration.",
    risks: [
      "HIGH RISK: Once browsers cache HSTS, they will refuse HTTP for the max-age period.",
      "Enabling include_subdomains affects every subdomain. Confirm all subdomains support HTTPS.",
      "Do not enable preload unless you are certain you will never need HTTP.",
    ],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, disable HSTS. Set max_age to 0 to speed up expiry.",
    gap: (c) => {
      const o = c as { enabled?: boolean; max_age?: number } | null;
      return !o || o.enabled !== true || !o.max_age || o.max_age < 86400;
    },
  },
  {
    key: "server_side_exclude", label: "Server-Side Exclude", category: "Bot protection",
    recommended: "on", risk_level: "low",
    explanation: "Allows hiding content from suspicious visitors using HTML comments.",
    risks: ["None significant."],
    rollback_instructions: "Security > Settings, turn off 'Server-Side Exclude'.",
    gap: (c) => c !== "on",
  },
];

function getSettingDef(key: string): SettingDef | undefined {
  return SETTING_CATALOG.find((s) => s.key === key);
}

async function readSetting(token: string, zoneId: string, key: string): Promise<{ value: unknown; error: string | null }> {
  const r = await cfFetch<CfSetting>(`/zones/${zoneId}/settings/${key}`, token);
  if (!r.ok) return { value: null, error: r.errors[0]?.message ?? "Could not read setting." };
  return { value: r.data?.value ?? null, error: null };
}

export interface CfFinding {
  check_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  source: "cloudflare";
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  verified: boolean;
  fixable: boolean;
  cf_setting_key: string;
  cf_api_path: string;
  current_value: unknown;
  proposed_value: unknown;
  recommended_value: unknown;
  rollback_value: unknown;
  rollback_supported: boolean;
  rollback_instructions: string;
  risks: string[];
  risk_level: "low" | "medium" | "high";
}

export interface CfCheckResult {
  check_id: string;
  status: "completed" | "skipped" | "failed";
  note?: string;
}

const SEVERITY_MAP: Record<string, "high" | "medium" | "low"> = {
  ssl: "high", always_use_https: "medium", automatic_https_rewrites: "low",
  min_tls_version: "high", tls_1_3: "low", security_level: "medium",
  browser_check: "low", privacy_pass: "low", "ch/hsts": "high", server_side_exclude: "low",
};

export async function runCloudflareChecks(token: string, zoneId: string): Promise<{ findings: CfFinding[]; checks: CfCheckResult[]; settings: { key: string; label: string; value: unknown; error: string | null }[] }> {
  const findings: CfFinding[] = [];
  const checks: CfCheckResult[] = [];
  const settingsOut: { key: string; label: string; value: unknown; error: string | null }[] = [];

  for (const def of SETTING_CATALOG) {
    const { value, error } = await readSetting(token, zoneId, def.key);
    settingsOut.push({ key: def.key, label: def.label, value, error });
    if (error) {
      checks.push({ check_id: `cf_${def.key.replace(/\//g, "_")}`, status: "failed", note: error });
      continue;
    }
    const hasGap = def.gap(value);
    if (hasGap) {
      const sev = SEVERITY_MAP[def.key] ?? "medium";
      findings.push({
        check_id: `cf_${def.key.replace(/\//g, "_")}`,
        title: `${def.label} needs hardening`,
        severity: sev,
        category: def.category,
        source: "cloudflare",
        description: def.explanation,
        evidence: `Current value: ${JSON.stringify(value)}. Recommended: ${JSON.stringify(def.recommended)}.`,
        impact: buildImpact(def.key),
        remediation: def.explanation,
        verified: true,
        fixable: true,
        cf_setting_key: def.key,
        cf_api_path: def.key,
        current_value: value,
        proposed_value: def.recommended,
        recommended_value: def.recommended,
        rollback_value: value,
        rollback_supported: true,
        rollback_instructions: def.rollback_instructions,
        risks: def.risks,
        risk_level: def.risk_level,
      });
    } else {
      findings.push({
        check_id: `cf_${def.key.replace(/\//g, "_")}`,
        title: `${def.label} is properly configured`,
        severity: "info",
        category: def.category,
        source: "cloudflare",
        description: `${def.label} is set to the recommended value.`,
        evidence: `Current value: ${JSON.stringify(value)}. Recommended: ${JSON.stringify(def.recommended)}.`,
        impact: "This setting is already secure. No action needed.",
        remediation: "Continue monitoring. No change required.",
        verified: true,
        fixable: false,
        cf_setting_key: def.key,
        cf_api_path: def.key,
        current_value: value,
        proposed_value: null,
        recommended_value: def.recommended,
        rollback_value: null,
        rollback_supported: false,
        rollback_instructions: "",
        risks: [],
        risk_level: def.risk_level,
      });
    }
    checks.push({ check_id: `cf_${def.key.replace(/\//g, "_")}`, status: "completed" });
  }

  return { findings, checks, settings: settingsOut };
}

function buildImpact(key: string): string {
  const impacts: Record<string, string> = {
    ssl: "Without proper SSL/TLS encryption, traffic between visitors and your server can be intercepted and read.",
    always_use_https: "Visitors who type your domain without https:// will browse over an unencrypted connection.",
    automatic_https_rewrites: "Mixed-content warnings may appear, degrading security and user experience.",
    min_tls_version: "Old TLS versions have known cryptographic weaknesses that attackers can exploit.",
    tls_1_3: "Without TLS 1.3, connections are slower and use older cryptographic algorithms.",
    security_level: "With a low security level, Cloudflare applies minimal bot filtering, allowing automated attacks through.",
    browser_check: "Without browser integrity checking, common bot User-Agent strings are not blocked.",
    privacy_pass: "Legitimate visitors may be challenged repeatedly, degrading their experience.",
    "ch/hsts": "Without HSTS, browsers may silently downgrade to HTTP, enabling man-in-the-middle attacks.",
    server_side_exclude: "You cannot selectively hide sensitive content from suspicious visitors.",
  };
  return impacts[key] ?? "This setting is not at its recommended value.";
}

export async function applyCloudflareFix(token: string, zoneId: string, settingKey: string, value: unknown): Promise<{ ok: boolean; error?: string; result?: unknown }> {
  const def = getSettingDef(settingKey);
  if (!def) return { ok: false, error: "This setting is not supported." };
  const r = await cfFetch<CfSetting>(`/zones/${zoneId}/settings/${settingKey}`, token, "PUT", { value });
  if (!r.ok) return { ok: false, error: r.errors[0]?.message ?? "Cloudflare rejected the change." };
  return { ok: true, result: r.data };
}

export async function verifyCloudflareFix(token: string, zoneId: string, settingKey: string): Promise<{ ok: boolean; value: unknown; error?: string }> {
  const def = getSettingDef(settingKey);
  if (!def) return { ok: false, value: null, error: "Setting is no longer supported." };
  const { value, error } = await readSetting(token, zoneId, settingKey);
  if (error) return { ok: false, value: null, error };
  return { ok: true, value };
}
