import { supabase, callEdge, edgeUrl } from '@/lib/supabase';

export type ThreatStatus =
  | 'detected' | 'awaiting_approval' | 'quarantined' | 'removed' | 'failed' | 'restored' | 'verified_clean';
export type ScanType = 'quick' | 'full' | 'custom';

export interface EngineStatus {
  antivirusEnabled?: boolean;
  realTimeProtection?: boolean;
  runningMode?: string | null;
  signatureVersion?: string | null;
  signatureUpdated?: string | null;
}

export interface EndpointDevice {
  id: string;
  name: string;
  os: string;
  os_version: string | null;
  agent_version: string | null;
  allowed_scopes: ScanType[];
  allowed_paths: string[];
  engine_status: EngineStatus;
  last_seen_at: string | null;
  last_scan_at: string | null;
  last_scan_status: string | null;
  revoked_at: string | null;
  created_at: string;
  scan_schedule: 'off' | 'daily' | 'weekly';
  next_scan_at: string | null;
  last_monitored_at: string | null;
}

export type IncidentStatus = 'new' | 'investigating' | 'awaiting_approval' | 'remediation_in_progress' | 'resolved' | 'unresolved';

export interface EndpointIncident {
  id: string;
  device_id: string | null;
  kind: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: { summary?: string };
  status: IncidentStatus;
  opened_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolution: string | null;
}

export const INCIDENT_META: Record<IncidentStatus, { label: string; tone: 'rose' | 'amber' | 'cyan' | 'green' | 'slate' }> = {
  new: { label: 'New', tone: 'rose' },
  investigating: { label: 'Investigating', tone: 'amber' },
  awaiting_approval: { label: 'Awaiting approval', tone: 'amber' },
  remediation_in_progress: { label: 'Remediation in progress', tone: 'cyan' },
  resolved: { label: 'Resolved', tone: 'green' },
  unresolved: { label: 'Unresolved', tone: 'rose' },
};

export type MonitoringState = { label: string; tone: 'green' | 'amber' | 'rose' | 'slate'; gaps: string[] };

export function monitoringState(d: EndpointDevice): MonitoringState {
  const gaps: string[] = [];
  const e = d.engine_status ?? {};
  if (!d.last_seen_at) return { label: 'Monitoring unavailable', tone: 'slate', gaps: ['The agent has never connected from this device.'] };
  const seenRecently = Date.now() - new Date(d.last_seen_at).getTime() < 30 * 60_000;
  if (!seenRecently) gaps.push('The agent is not running, so no scans or health checks can reach this device.');
  if (e.antivirusEnabled === false) gaps.push('Microsoft Defender antivirus is disabled.');
  if (e.realTimeProtection === false) gaps.push('Real-time protection is off.');
  const sig = e.signatureUpdated ? new Date(e.signatureUpdated).getTime() : NaN;
  if (!Number.isNaN(sig) && Date.now() - sig > 3 * 86_400_000) gaps.push('Malware definitions are more than 3 days old.');
  if (d.scan_schedule === 'off') gaps.push('No scan schedule is set; scans only run when you start them.');
  if (!d.last_scan_at) gaps.push('This device has not been scanned yet.');
  if (!seenRecently) return { label: 'Monitoring unavailable', tone: 'rose', gaps };
  if (gaps.length > 0) return { label: 'Monitoring degraded', tone: 'amber', gaps };
  return { label: 'Monitoring active', tone: 'green', gaps };
}

export interface EndpointThreat {
  id: string;
  device_id: string;
  engine_threat_id: string;
  name: string;
  severity: string;
  category: string | null;
  resources: string[];
  sha256: string | null;
  detection_source: string;
  status: ThreatStatus;
  engine_action: string | null;
  times_seen: number;
  verification: { checked_at: string; reasons: string[]; existing_resources: string[]; persistence_hits: string[] } | null;
  first_seen_at: string;
  last_seen_at: string;
}

export interface EndpointJob {
  id: string;
  device_id: string;
  kind: 'scan' | 'remediate' | 'restore' | 'verify';
  params: Record<string, unknown>;
  status: 'pending_approval' | 'queued' | 'dispatched' | 'succeeded' | 'failed' | 'expired' | 'cancelled';
  result: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface EndpointAudit {
  id: string;
  device_id: string | null;
  actor: string;
  action: string;
  outcome: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export const AGENT_SCRIPT_PATH = '/agent/blackveil-agent.ps1';
export const AGENT_SERVER_URL = edgeUrl('endpoint-agent');

export const STATUS_META: Record<ThreatStatus, { label: string; tone: 'rose' | 'amber' | 'cyan' | 'green' | 'slate' }> = {
  detected: { label: 'Threat detected', tone: 'rose' },
  awaiting_approval: { label: 'Awaiting approval', tone: 'amber' },
  quarantined: { label: 'Quarantined', tone: 'cyan' },
  removed: { label: 'Removed', tone: 'cyan' },
  failed: { label: 'Failed', tone: 'rose' },
  restored: { label: 'Restored (false positive)', tone: 'slate' },
  verified_clean: { label: 'Verified clean', tone: 'green' },
};

export const SCAN_LABEL: Record<ScanType, string> = {
  quick: 'Quick scan',
  full: 'Full scan',
  custom: 'Folder scan',
};

export const isAgentOnline = (d: EndpointDevice) =>
  !!d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() < 2 * 60_000;

export const isTestSignature = (name: string) => /eicar/i.test(name);

export async function control<T = Record<string, unknown>>(token: string, body: Record<string, unknown>) {
  try {
    return await callEdge<T>('endpoint-control', body, token);
  } catch {
    return { ok: false as const, status: 0, error: 'Could not reach Blackveil. Check your connection.' };
  }
}

export async function loadEndpointData() {
  const [d, t, a, j, i] = await Promise.all([
    supabase.from('endpoint_devices')
      .select('id, name, os, os_version, agent_version, allowed_scopes, allowed_paths, engine_status, last_seen_at, last_scan_at, last_scan_status, revoked_at, created_at, scan_schedule, next_scan_at, last_monitored_at')
      .is('revoked_at', null).order('created_at'),
    supabase.from('endpoint_threats').select('*').order('last_seen_at', { ascending: false }),
    supabase.from('endpoint_audit').select('id, device_id, actor, action, outcome, detail, created_at').order('created_at', { ascending: false }).limit(40),
    supabase.from('endpoint_jobs').select('*').order('created_at', { ascending: false }).limit(30),
    supabase.from('endpoint_incidents').select('id, device_id, kind, severity, title, detail, status, opened_at, updated_at, resolved_at, resolution')
      .order('opened_at', { ascending: false }).limit(60),
  ]);
  const error = d.error ?? t.error ?? a.error ?? j.error ?? i.error;
  return {
    error: error ? 'Could not load your devices.' : null,
    devices: (d.data ?? []) as EndpointDevice[],
    threats: (t.data ?? []) as EndpointThreat[],
    audit: (a.data ?? []) as EndpointAudit[],
    jobs: (j.data ?? []) as EndpointJob[],
    incidents: (i.data ?? []) as EndpointIncident[],
  };
}

export async function getJob(jobId: string): Promise<EndpointJob | null> {
  const { data } = await supabase.from('endpoint_jobs').select('*').eq('id', jobId).maybeSingle();
  return (data as EndpointJob) ?? null;
}

export const JOB_DONE = ['succeeded', 'failed', 'expired', 'cancelled'];

export function formatWhen(iso: string | null) {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function recommendedAction(t: EndpointThreat): string {
  switch (t.status) {
    case 'detected':
    case 'awaiting_approval': return 'Review evidence, then approve quarantine and removal.';
    case 'quarantined':
    case 'removed': return 'Run a verification scan to confirm the threat is gone.';
    case 'failed': return 'Close programs using the file, restart the PC, then run Scan & Remediate again. If it persists, run a Microsoft Defender Offline scan.';
    case 'restored': return 'You marked this as a false positive. Rescan if the file was not trusted.';
    case 'verified_clean': return 'No action needed. Keep scanning regularly.';
  }
}

export function buildReport(device: EndpointDevice, threats: EndpointThreat[], jobs: EndpointJob[]): string {
  const lines = [
    'BLACKVEIL SECURITY - REMEDIATION REPORT',
    `Generated: ${new Date().toISOString()}`,
    `Device: ${device.name} (${device.os} ${device.os_version ?? ''})`.trim(),
    `Engine: Microsoft Defender Antivirus, signatures ${device.engine_status?.signatureVersion ?? 'unknown'}`,
    `Last scan: ${device.last_scan_at ?? 'never'} - ${device.last_scan_status ?? 'n/a'}`,
    '',
    'JOBS',
    ...jobs.map((j) => `- ${j.created_at} ${j.kind} ${j.status}${j.error ? ` (${j.error})` : ''}`),
    '',
    `THREATS (${threats.length})`,
  ];
  for (const t of threats) {
    lines.push(
      `- ${t.name} [${t.severity}] status=${STATUS_META[t.status].label}`,
      `  category: ${t.category ?? 'unknown'} | source: ${t.detection_source} | seen ${t.times_seen}x`,
      `  sha256: ${t.sha256 ?? 'not provided by engine'}`,
      ...t.resources.map((r) => `  file: ${filePath(r)}`),
      ...(t.verification?.reasons ?? []).map((r) => `  verification: ${r}`),
    );
  }
  lines.push('', 'NOTE: Verification confirms the listed indicators are no longer present. It does not guarantee the device is free of all malware.');
  return lines.join('\n');
}

export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function filePath(resource: string) {
  const m = resource.match(/^(?:file|containerfile):_(.+)$/);
  return m ? m[1] : resource;
}
