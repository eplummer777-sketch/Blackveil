export type DecoyType = "ssh" | "http_admin" | "database" | "smb_share" | "iot_telnet";
export type ProviderId = "simulator" | "isolated_test" | "cloud";
export type Environment = "simulated" | "isolated_test" | "cloud";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type HoneypotStatus = "deploying" | "active" | "degraded" | "failed" | "retiring" | "retired" | "stopped";

export const DECOY_TYPES: DecoyType[] = ["ssh", "http_admin", "database", "smb_share", "iot_telnet"];

export interface HoneypotSpec {
  id: string;
  name: string;
  decoyType: DecoyType;
  exposure: "internal_only" | "public";
  config: Record<string, unknown>;
}

export interface DeployResult {
  providerRef: string;
  environment: Environment;
  isSimulated: boolean;
}

export interface HealthCheckItem {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface HealthResult {
  healthy: boolean;
  checks: HealthCheckItem[];
  latencyMs: number;
}

export interface GeneratedEvent {
  eventType: string;
  severity: Severity;
  protocol: string;
  sourceIp: string;
  sourcePort: number;
  sourceLabel: string;
  summary: string;
  evidence: Record<string, unknown>;
  mitreTechnique: string | null;
  occurredAt: string;
}

/**
 * Contract every honeypot backend must satisfy. A cloud provider implements this
 * interface; it must only report healthy after verifying the decoy is truly reachable
 * inside its isolated network and that telemetry is flowing.
 */
export interface HoneypotProvider {
  readonly id: ProviderId;
  readonly environment: Environment;
  readonly producesRealDetections: boolean;
  deploy(spec: HoneypotSpec): Promise<DeployResult>;
  healthCheck(spec: HoneypotSpec, providerRef: string): Promise<HealthResult>;
  retire(providerRef: string): Promise<void>;
}
