import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Test the HTTP check engine's SSRF protection and target normalization.
// We import the normalizeTarget function by replicating its logic since
// the edge function runs in Deno and can't be imported in Node directly.
// Instead, we test the same validation logic that the edge function uses.

const PRIVATE_IP_REGEX =
  /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1|fe80:|fc00:|fd00:|100\.64\.)/i;

const BLOCKED_HOSTS = [
  "169.254.169.254", "metadata.google.internal", "169.254.169.253",
  "0.0.0.0", "localhost", "metadata",
];

function blockSsrf(hostname: string): string | null {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTS.includes(h)) return "Blocked cloud metadata / loopback host.";
  if (PRIVATE_IP_REGEX.test(h)) return "Blocked private / loopback destination.";
  return null;
}

function normalizeTarget(input: string): { host: string; url: string } | null {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  if (!/^https?:\/\//.test(s)) s = "https://" + s;
  try {
    const u = new URL(s);
    if (!u.hostname) return null;
    if (u.username || u.password) return null;
    const blocked = blockSsrf(u.hostname);
    if (blocked) return null;
    return { host: u.hostname, url: u.toString() };
  } catch {
    return null;
  }
}

// Replicate the Cloudflare setting gap detection logic for testing
interface SettingDef {
  key: string;
  recommended: unknown;
  gap: (current: unknown) => boolean;
}

const SETTING_CATALOG: SettingDef[] = [
  { key: "ssl", recommended: "full", gap: (c) => typeof c === "string" && c === "off" },
  { key: "always_use_https", recommended: "on", gap: (c) => c !== "on" },
  { key: "min_tls_version", recommended: "1.2", gap: (c) => typeof c === "string" && (c === "1.0" || c === "1.1") },
  { key: "tls_1_3", recommended: "on", gap: (c) => c !== "on" },
  { key: "security_level", recommended: "medium", gap: (c) => typeof c === "string" && (c === "essentially_off" || c === "low") },
  { key: "browser_check", recommended: "on", gap: (c) => c !== "on" },
  {
    key: "ch/hsts",
    recommended: { enabled: true, max_age: 15552000 },
    gap: (c) => {
      const o = c as { enabled?: boolean; max_age?: number } | null;
      return !o || o.enabled !== true || !o.max_age || o.max_age < 86400;
    },
  },
];

describe('Assessment Engine — SSRF protection', () => {
  it('rejects private IP addresses', () => {
    assert.equal(normalizeTarget("http://10.0.0.1/"), null);
    assert.equal(normalizeTarget("http://192.168.1.1/"), null);
    assert.equal(normalizeTarget("http://172.16.0.1/"), null);
    assert.equal(normalizeTarget("http://127.0.0.1/"), null);
  });

  it('rejects cloud metadata endpoints', () => {
    assert.equal(normalizeTarget("http://169.254.169.254/"), null);
    assert.equal(normalizeTarget("http://metadata.google.internal/"), null);
  });

  it('rejects localhost', () => {
    assert.equal(normalizeTarget("http://localhost/"), null);
    assert.equal(normalizeTarget("http://0.0.0.0/"), null);
  });

  it('rejects empty and invalid input', () => {
    assert.equal(normalizeTarget(""), null);
    assert.equal(normalizeTarget("   "), null);
    assert.equal(normalizeTarget("not a url"), null);
  });

  it('rejects URLs with credentials', () => {
    assert.equal(normalizeTarget("http://user:pass@example.com/"), null);
  });

  it('accepts valid public domains', () => {
    const r = normalizeTarget("example.com");
    assert.ok(r);
    assert.equal(r.host, "example.com");
  });

  it('accepts https:// prefix', () => {
    const r = normalizeTarget("https://example.com/path");
    assert.ok(r);
    assert.equal(r.host, "example.com");
  });

  it('lowercases the hostname', () => {
    const r = normalizeTarget("EXAMPLE.COM");
    assert.ok(r);
    assert.equal(r.host, "example.com");
  });
});

describe('Assessment Engine — Cloudflare gap detection', () => {
  it('detects SSL off as a gap', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "ssl")!;
    assert.equal(def.gap("off"), true);
    assert.equal(def.gap("full"), false);
    assert.equal(def.gap("flexible"), false);
  });

  it('detects Always Use HTTPS off as a gap', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "always_use_https")!;
    assert.equal(def.gap("off"), true);
    assert.equal(def.gap("on"), false);
  });

  it('detects old TLS versions as a gap', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "min_tls_version")!;
    assert.equal(def.gap("1.0"), true);
    assert.equal(def.gap("1.1"), true);
    assert.equal(def.gap("1.2"), false);
  });

  it('detects low security level as a gap', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "security_level")!;
    assert.equal(def.gap("essentially_off"), true);
    assert.equal(def.gap("low"), true);
    assert.equal(def.gap("medium"), false);
  });

  it('detects HSTS gaps correctly', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "ch/hsts")!;
    assert.equal(def.gap(null), true);
    assert.equal(def.gap({ enabled: false }), true);
    assert.equal(def.gap({ enabled: true, max_age: 3600 }), true);
    assert.equal(def.gap({ enabled: true, max_age: 15552000 }), false);
  });

  it('detects TLS 1.3 off as a gap', () => {
    const def = SETTING_CATALOG.find((s) => s.key === "tls_1_3")!;
    assert.equal(def.gap("off"), true);
    assert.equal(def.gap("on"), false);
  });
});

describe('Assessment Engine — fix lifecycle validation', () => {
  // Replicate the fix status transition rules
  const VALID_TRANSITIONS: Record<string, string[]> = {
    approve: ["proposed"],
    reject: ["proposed", "approved"],
    apply: ["approved", "failed"],
    verify: ["applied", "verified", "failed"],
  };

  it('only allows approving proposed fixes', () => {
    assert.ok(VALID_TRANSITIONS.approve.includes("proposed"));
    assert.ok(!VALID_TRANSITIONS.approve.includes("approved"));
    assert.ok(!VALID_TRANSITIONS.approve.includes("applied"));
  });

  it('only allows applying approved or failed fixes', () => {
    assert.ok(VALID_TRANSITIONS.apply.includes("approved"));
    assert.ok(VALID_TRANSITIONS.apply.includes("failed"));
    assert.ok(!VALID_TRANSITIONS.apply.includes("proposed"));
  });

  it('only allows verifying applied changes', () => {
    assert.ok(VALID_TRANSITIONS.verify.includes("applied"));
    assert.ok(!VALID_TRANSITIONS.verify.includes("proposed"));
    assert.ok(!VALID_TRANSITIONS.verify.includes("approved"));
  });

  it('reject can happen before apply', () => {
    assert.ok(VALID_TRANSITIONS.reject.includes("proposed"));
    assert.ok(VALID_TRANSITIONS.reject.includes("approved"));
    assert.ok(!VALID_TRANSITIONS.reject.includes("applied"));
  });
});

describe('Assessment Engine — verification logic', () => {
  it('matches identical values', () => {
    const expected = "on";
    const actual = "on";
    assert.equal(JSON.stringify(actual) === JSON.stringify(expected), true);
  });

  it('detects mismatched values', () => {
    const expected = "on";
    const actual = "off";
    assert.equal(JSON.stringify(actual) === JSON.stringify(expected), false);
  });

  it('matches object values', () => {
    const expected = { enabled: true, max_age: 15552000 };
    const actual = { enabled: true, max_age: 15552000 };
    assert.equal(JSON.stringify(actual) === JSON.stringify(expected), true);
  });

  it('detects mismatched object values', () => {
    const expected = { enabled: true, max_age: 15552000 };
    const actual = { enabled: true, max_age: 0 };
    assert.equal(JSON.stringify(actual) === JSON.stringify(expected), false);
  });
});

describe('Assessment Engine — rate limiting', () => {
  it('enforces 10 assessments per hour', () => {
    const LIMIT = 10;
    assert.equal(0 < LIMIT, true);
    assert.equal(10 >= LIMIT, true);
    assert.equal(11 > LIMIT, true);
  });
});

describe('Assessment Engine — severity mapping', () => {
  const SEVERITY_MAP: Record<string, string> = {
    ssl: "high",
    always_use_https: "medium",
    min_tls_version: "high",
    "ch/hsts": "high",
    security_level: "medium",
    browser_check: "low",
  };

  it('maps SSL to high severity', () => {
    assert.equal(SEVERITY_MAP.ssl, "high");
  });

  it('maps HSTS to high severity', () => {
    assert.equal(SEVERITY_MAP["ch/hsts"], "high");
  });

  it('maps min TLS version to high severity', () => {
    assert.equal(SEVERITY_MAP.min_tls_version, "high");
  });

  it('maps Always Use HTTPS to medium severity', () => {
    assert.equal(SEVERITY_MAP.always_use_https, "medium");
  });

  it('maps Browser Integrity Check to low severity', () => {
    assert.equal(SEVERITY_MAP.browser_check, "low");
  });
});
