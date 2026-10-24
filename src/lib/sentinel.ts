import { callEdge } from '@/lib/supabase';
import { Severity } from '@/lib/types';

export type DecoyType = 'ssh' | 'http_admin' | 'database' | 'smb_share' | 'iot_telnet';
export type HoneypotStatus = 'deploying' | 'active' | 'degraded' | 'failed' | 'retiring' | 'retired' | 'stopped';
export type InvestigationStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';
export type ActionType = 'add_watchlist' | 'notify_team' | 'escalate_incident' | 'block_source_ip' | 'isolate_host' | 'expose_publicly';
export type ActionStatus = 'pending_approval' | 'approved' | 'rejected' | 'executed_simulated' | 'blocked_by_policy';

export interface Honeypot {
  id: string;
  user_id: string;
  name: string;
  decoy_type: DecoyType;
  provider: 'simulator' | 'isolated_test' | 'cloud';
  environment: 'simulated' | 'isolated_test' | 'cloud';
  is_simulated: boolean;
  exposure: 'internal_only' | 'public';
  status: HoneypotStatus;
  provider_ref: string | null;
  config: Record<string, unknown>;
  last_health_status: 'unknown' | 'healthy' | 'unhealthy';
  last_health_check_at: string | null;
  verified_at: string | null;
  retired_at: string | null;
  created_at: string;
  cloud_resource_id?: string | null;
  cloud_resource_url?: string | null;
  cf_integration_id?: string | null;
  cost_estimate_usd?: number;
}

export interface HealthCheckItem {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface HealthCheck {
  id: string;
  honeypot_id: string;
  status: 'healthy' | 'unhealthy';
  checks: HealthCheckItem[];
  latency_ms: number | null;
  checked_at: string;
}

export interface ThreatAnalysis {
  headline: string;
  what_happened: string;
  observed: string[];
  inferred: string[];
  confidence: 'low' | 'medium' | 'high';
  recommended_steps: string[];
  suggested_actions: { action_type: ActionType; target: string | null; rationale: string }[];
  caveats: string[];
  source: 'ai' | 'rules';
  is_simulated: boolean;
}

export interface HoneypotEvent {
  id: string;
  honeypot_id: string;
  user_id: string;
  provider: string;
  is_simulated: boolean;
  event_type: string;
  severity: Severity;
  protocol: string | null;
  source_ip: string | null;
  source_port: number | null;
  source_label: string | null;
  summary: string;
  evidence: Record<string, unknown>;
  mitre_technique: string | null;
  investigation_status: InvestigationStatus;
  investigation_notes: string | null;
  ai_analysis: ThreatAnalysis | null;
  analyzed_at: string | null;
  occurred_at: string;
}

export interface PolicyAction {
  id: string;
  user_id: string;
  honeypot_id: string | null;
  event_id: string | null;
  action_type: ActionType;
  target: string | null;
  rationale: string;
  proposed_by: 'analyst_ai' | 'user';
  risk_level: 'low' | 'medium' | 'high';
  affects_real_systems: boolean;
  status: ActionStatus;
  policy_reason: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  created_at: string;
}

export const DECOY_CATALOG: Record<DecoyType, { label: string; port: string; desc: string }> = {
  ssh:        { label: 'SSH server decoy',    port: 'TCP 22',   desc: 'Fake Linux shell that records login attempts and scripted commands without running them.' },
  http_admin: { label: 'Web admin decoy',     port: 'TCP 443',  desc: 'Imitation admin panel that records scans, injection probes, and exploit signatures.' },
  database:   { label: 'Database decoy',      port: 'TCP 5432', desc: 'Empty decoy database that records login and bulk-read attempts.' },
  smb_share:  { label: 'File share decoy',    port: 'TCP 445',  desc: 'Canary file share with fake documents that flags enumeration and ransomware-like behavior.' },
  iot_telnet: { label: 'IoT device decoy',    port: 'TCP 23',   desc: 'Simulated camera or router that records botnet default-credential attempts.' },
};

export const ACTION_LABELS: Record<ActionType, string> = {
  add_watchlist: 'Add source to watchlist',
  notify_team: 'Notify security team',
  escalate_incident: 'Escalate to incident',
  block_source_ip: 'Block source IP',
  isolate_host: 'Isolate host',
  expose_publicly: 'Expose decoy publicly',
};

export const INVESTIGATION_LABELS: Record<InvestigationStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
};

export function prettyEventType(t: string): string {
  return t.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

export function timeAgo(iso: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function callSentinel<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('sentinel-manager', body, token);
}

export function callAnalyst(token: string, eventId: string) {
  return callEdge<{ analysis: ThreatAnalysis }>('threat-analyst', { event_id: eventId }, token);
}

export { callCloudflare } from '@/lib/cloudflare';
