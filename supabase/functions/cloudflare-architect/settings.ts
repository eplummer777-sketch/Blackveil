// The catalog of Cloudflare security settings Architect supports.
// Each entry declares: how to read it, what a recommended value looks like,
// and what an analysis gap looks like. Only settings in this catalog are
// read or written — nothing else can be touched.

import { CfResult, CfSetting, getSetting, putSettingByKey, settingFrom } from "./cloudflare.ts";

export interface SettingDef {
  key: string;
  label: string;
  category: string;
  read: (token: string, zoneId: string) => Promise<CfResult<CfSetting>>;
  writable: boolean;
  value_type: "boolean" | "string" | "object";
  recommended: unknown;
  recommended_label: string;
  risk_level: "low" | "medium" | "high";
  explanation: string;
  risks: string[];
  rollback_instructions: string;
  gap: (current: unknown) => boolean;
}

export const SETTING_CATALOG: SettingDef[] = [
  {
    key: "ssl",
    label: "SSL/TLS encryption mode",
    category: "Encryption",
    read: (t, z) => getSetting(t, z, "ssl"),
    writable: true,
    value_type: "string",
    recommended: "full",
    recommended_label: "Full (end-to-end encryption)",
    risk_level: "medium",
    explanation: "Sets how Cloudflare encrypts traffic between visitors and your origin server. 'Full' encrypts both legs without requiring a valid certificate on the origin; 'Full (strict)' requires a valid origin certificate.",
    risks: [
      "Switching from 'flexible' to 'full' means Cloudflare will connect to your origin over HTTPS. Your origin server must have HTTPS enabled.",
      "If your origin has no valid certificate, 'Full (strict)' will break the connection. Use 'Full' if unsure.",
    ],
    rollback_instructions: "Settings > SSL/TLS > Overview, set the mode back to its previous value.",
    gap: (c) => typeof c === "string" && c === "off",
  },
  {
    key: "always_use_https",
    label: "Always Use HTTPS",
    category: "Encryption",
    read: (t, z) => getSetting(t, z, "always_use_https"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Redirects all HTTP requests to HTTPS automatically. This prevents visitors from accidentally browsing over an unencrypted connection.",
    risks: ["If your site has hardcoded HTTP URLs in scripts or images, those will not be redirected and may show as mixed content."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'Always Use HTTPS'.",
    gap: (c) => c !== "on",
  },
  {
    key: "automatic_https_rewrites",
    label: "Automatic HTTPS Rewrites",
    category: "Encryption",
    read: (t, z) => getSetting(t, z, "automatic_https_rewrites"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Rewrites HTTP links on your pages to HTTPS automatically, reducing mixed-content warnings without changing your source code.",
    risks: ["In rare cases, rewrite rules can interfere with complex JavaScript applications. Disable if you see rendering issues."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'Automatic HTTPS Rewrites'.",
    gap: (c) => c !== "on",
  },
  {
    key: "min_tls_version",
    label: "Minimum TLS Version",
    category: "Encryption",
    read: (t, z) => getSetting(t, z, "min_tls_version"),
    writable: true,
    value_type: "string",
    recommended: "1.2",
    recommended_label: "TLS 1.2",
    risk_level: "medium",
    explanation: "Rejects connections from browsers using TLS versions older than the minimum. TLS 1.0 and 1.1 have known weaknesses and are deprecated.",
    risks: ["Very old browsers (IE on Windows XP, some embedded devices) will be unable to connect if TLS 1.2 is the minimum."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, set 'Minimum TLS Version' back to 1.0.",
    gap: (c) => typeof c === "string" && (c === "1.0" || c === "1.1"),
  },
  {
    key: "tls_1_3",
    label: "TLS 1.3",
    category: "Encryption",
    read: (t, z) => getSetting(t, z, "tls_1_3"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Enables TLS 1.3, the latest version of the TLS protocol. It is faster and more secure than 1.2.",
    risks: ["Extremely rare: some old client libraries do not support TLS 1.3 and may fall back to 1.2 automatically."],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, turn off 'TLS 1.3'.",
    gap: (c) => c !== "on",
  },
  {
    key: "security_level",
    label: "Security Level (Bot/WAF challenge)",
    category: "Bot protection",
    read: (t, z) => getSetting(t, z, "security_level"),
    writable: true,
    value_type: "string",
    recommended: "medium",
    recommended_label: "Medium",
    risk_level: "low",
    explanation: "Controls how aggressively Cloudflare challenges suspicious visitors. 'Medium' challenges the most suspicious IPs; 'High' challenges more aggressively.",
    risks: ["Setting to 'High' may show CAPTCHA challenges to some legitimate visitors. 'Essentially Off' provides minimal protection."],
    rollback_instructions: "Security > Settings, set Security Level back to its previous value.",
    gap: (c) => typeof c === "string" && (c === "essentially_off" || c === "low"),
  },
  {
    key: "browser_check",
    label: "Browser Integrity Check",
    category: "Bot protection",
    read: (t, z) => getSetting(t, z, "browser_check"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Blocks requests from common bot/spider User-Agent headers (like those used by scraping tools) before they reach your server.",
    risks: ["Some legitimate API clients or monitoring tools that send unusual User-Agent strings may be blocked."],
    rollback_instructions: "Security > Settings, turn off 'Browser Integrity Check'.",
    gap: (c) => c !== "on",
  },
  {
    key: "privacy_pass",
    label: "Privacy Pass",
    category: "Bot protection",
    read: (t, z) => getSetting(t, z, "privacy_pass"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Allows visitors who pass a Cloudflare challenge to get a cryptographically-blinded token so they are not challenged again repeatedly.",
    risks: ["None significant. This improves visitor experience without reducing security."],
    rollback_instructions: "Security > Settings, turn off 'Privacy Pass'.",
    gap: (c) => c !== "on",
  },
  {
    key: "ch/hsts",
    label: "HSTS (HTTP Strict Transport Security)",
    category: "Headers",
    read: (t, z) => getSetting(t, z, "ch/hsts"),
    writable: true,
    value_type: "object",
    recommended: { enabled: true, max_age: 15552000, include_subdomains: true, preload: false, nosniff: false },
    recommended_label: "Enabled, max-age 180 days",
    risk_level: "high",
    explanation: "Tells browsers to only connect over HTTPS for the specified duration. This prevents protocol-downgrade attacks. Cloudflare applies HSTS at the edge.",
    risks: [
      "HIGH RISK: Once browsers cache HSTS, they will refuse to connect over HTTP for the max-age period. If you later need to serve HTTP, visitors will be locked out until the max-age expires.",
      "Enabling include_subdomains affects every subdomain of this zone. Confirm all subdomains support HTTPS.",
      "Do not enable preload unless you are certain you will never need HTTP. Preloading is very difficult to reverse.",
    ],
    rollback_instructions: "Settings > SSL/TLS > Edge Certificates, disable HSTS. Note: browsers will continue enforcing HSTS until the max-age expires. Set max_age to 0 to speed up expiry.",
    gap: (c) => {
      const o = c as { enabled?: boolean; max_age?: number } | null;
      return !o || o.enabled !== true || !o.max_age || o.max_age < 86400;
    },
  },
  {
    key: "server_side_exclude",
    label: "Server-Side Exclude",
    category: "Bot protection",
    read: (t, z) => getSetting(t, z, "server_side_exclude"),
    writable: true,
    value_type: "string",
    recommended: "on",
    recommended_label: "On",
    risk_level: "low",
    explanation: "Allows you to hide content from suspicious visitors using HTML comments. Content between <!--sse--> and <!--/sse--> is stripped for challenged visitors.",
    risks: ["None significant. This only affects content you explicitly wrap in SSE tags."],
    rollback_instructions: "Security > Settings, turn off 'Server-Side Exclude'.",
    gap: (c) => c !== "on",
  },
];

export function getSettingDef(key: string): SettingDef | undefined {
  return SETTING_CATALOG.find((s) => s.key === key);
}

export interface ReadSetting {
  key: string;
  label: string;
  category: string;
  value: unknown;
  modified_on: string | null;
  error: string | null;
  recommended: unknown;
  recommended_label: string;
  has_gap: boolean;
  writable: boolean;
  risk_level: "low" | "medium" | "high";
  explanation: string;
  risks: string[];
  rollback_instructions: string;
}

export async function readAllSettings(token: string, zoneId: string): Promise<{ settings: ReadSetting[]; errors: string[] }> {
  const errors: string[] = [];
  const settings: ReadSetting[] = [];
  for (const def of SETTING_CATALOG) {
    const r = await def.read(token, zoneId);
    const raw = settingFrom(r);
    if (raw.error) errors.push(`${def.label}: ${raw.error}`);
    settings.push({
      key: def.key,
      label: def.label,
      category: def.category,
      value: raw.value,
      modified_on: raw.modified_on,
      error: raw.error ?? null,
      recommended: def.recommended,
      recommended_label: def.recommended_label,
      has_gap: def.gap(raw.value),
      writable: def.writable,
      risk_level: def.risk_level,
      explanation: def.explanation,
      risks: def.risks,
      rollback_instructions: def.rollback_instructions,
    });
  }
  return { settings, errors };
}

export interface GapProposal {
  setting_key: string;
  setting_label: string;
  category: string;
  current_value: unknown;
  proposed_value: unknown;
  recommended_value: unknown;
  api_path: string;
  explanation: string;
  risks: string[];
  risk_level: "low" | "medium" | "high";
  rollback_supported: boolean;
  rollback_instructions: string;
}

export function identifyGaps(settings: ReadSetting[]): GapProposal[] {
  return settings.filter((s) => s.has_gap && s.writable).map((s) => ({
    setting_key: s.key,
    setting_label: s.label,
    category: s.category,
    current_value: s.value,
    proposed_value: s.recommended,
    recommended_value: s.recommended,
    api_path: s.key,
    explanation: s.explanation,
    risks: s.risks,
    risk_level: s.risk_level,
    rollback_supported: true,
    rollback_instructions: s.rollback_instructions,
  }));
}

export async function applySetting(token: string, zoneId: string, key: string, value: unknown): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const def = getSettingDef(key);
  if (!def) return { ok: false, error: "This setting is not supported by Architect." };
  if (!def.writable) return { ok: false, error: "This setting is read-only in Architect." };
  if (def.value_type === "object" && (typeof value !== "object" || value === null)) return { ok: false, error: "Invalid value for this setting." };
  if (def.value_type === "boolean" && value !== "on" && value !== "off") {
    // Cloudflare uses "on"/"off" for boolean settings
    return { ok: false, error: "Invalid value for this boolean setting." };
  }
  if (def.value_type === "string" && typeof value !== "string") return { ok: false, error: "Invalid value for this setting." };
  const r = await putSettingByKey(token, zoneId, key, value);
  if (!r.ok) return { ok: false, error: r.errors[0]?.message ?? "Cloudflare rejected the change." };
  return { ok: true, result: r.data };
}
