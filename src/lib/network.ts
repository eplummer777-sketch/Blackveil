import { callEdge } from '@/lib/supabase';

export type NetProfile = 'discovery' | 'tcp_basic' | 'service' | 'syn' | 'native_quick' | 'native_standard';
export type NetStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';

export interface NetSummary {
  hosts_up?: number; hosts_down?: number; hosts_total?: number; open?: number; closed?: number; filtered?: number; services?: number;
  elapsed?: number; out_of_scope_dropped?: number; checked?: number; planned?: number; complete?: boolean; coverage_note?: string; engine?: string;
}

export interface NetScan {
  id: string;
  target_input: string;
  target_kind: 'ip' | 'cidr' | 'hostname';
  targets: string[];
  auth_basis: 'verified_domain' | 'approved_scope';
  profile: NetProfile;
  engine: 'nmap_agent' | 'native';
  args: string[];
  status: NetStatus;
  progress: number | null;
  deadline_at: string | null;
  cancel_requested: boolean;
  authorization_statement: string;
  timeout_seconds: number;
  nmap_version: string | null;
  summary: NetSummary;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  ai_status: 'none' | 'pending' | 'ready' | 'failed';
  ai_analysis: Record<string, string> | null;
  ai_error: string | null;
}

export interface NetPort { port: number; protocol: string; state: string; reason: string; service: string; product: string; version: string; extrainfo: string; tunnel: string; confidence?: string; method?: string }
export interface NetHost { id: string; address: string; hostnames: string[]; state: string; reason: string; ports: NetPort[]; extraports: { state: string; count: number }[] }

export interface NativeInfo { version: string; profiles: Record<string, { label: string; ports: number; deadline: number; max_targets: number }> }
export interface NetStatusResp { elite: boolean; admin: boolean; paused?: boolean; native?: NativeInfo }

export function callNet<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('network-scanner', body, token);
}

export const PROFILE_INFO: Record<NetProfile, { label: string; hint: string; raw: boolean; native: boolean }> = {
  native_quick: { label: 'Quick discovery', hint: 'Built-in engine. Common ports on up to 4 addresses, finished within 90 seconds including AI analysis.', raw: false, native: true },
  native_standard: { label: 'Standard discovery', hint: 'Built-in engine. Wider port list on up to 16 addresses (a /28), up to 10 minutes.', raw: false, native: true },
  discovery: { label: 'Host discovery', hint: 'Retired Nmap profile. Finds which hosts are online. No port scanning.', raw: false, native: false },
  tcp_basic: { label: 'Basic TCP port scan', hint: 'Retired Nmap profile. Full TCP connections to the 100 most common ports.', raw: false, native: false },
  service: { label: 'Service & version detection', hint: 'Retired Nmap profile. Top 100 ports plus service and version identification.', raw: false, native: false },
  syn: { label: 'Raw TCP SYN scan', hint: 'Retired Nmap profile. Half-open scan of the top 1000 ports. Needs a privileged scanner.', raw: true, native: false },
};

export const NATIVE_PROFILES: NetProfile[] = ['native_quick', 'native_standard'];

export const NET_AI_SECTIONS: [string, string][] = [
  ['summary', 'Overview'],
  ['confirmed_facts', 'Confirmed observations'],
  ['possibilities', 'Hypotheses (not verified)'],
  ['prioritized_risks', 'Prioritized exposure'],
  ['remediation', 'Recommended remediation'],
  ['next_steps', 'Verify and next steps'],
];

export const isNetActive = (s: NetScan) => s.status === 'queued' || s.status === 'running';
export const isNetFinished = (s: NetScan) => s.status === 'completed' || s.status === 'partial';

export function netTone(s: NetStatus): 'green' | 'cyan' | 'rose' | 'slate' | 'amber' {
  return s === 'completed' ? 'green' : s === 'partial' ? 'amber' : s === 'running' || s === 'queued' ? 'cyan' : s === 'failed' ? 'rose' : 'slate';
}

export const NET_STATUS_LABEL: Record<NetStatus, string> = {
  queued: 'queued', running: 'running', completed: 'completed', partial: 'partial / timed out', failed: 'failed', cancelled: 'cancelled',
};

export interface PortRow extends NetPort { address: string; hostnames: string[] }

export const flattenPorts = (hosts: NetHost[]): PortRow[] =>
  hosts.flatMap((h) => h.ports.map((p) => ({ ...p, address: h.address, hostnames: h.hostnames })));

const csvCell = (v: unknown) => {
  const s = String(v ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

export function downloadFile(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportScan(scan: NetScan, hosts: NetHost[], format: 'csv' | 'json') {
  const base = `blackveil-network-${scan.target_input.replace(/[^a-z0-9.-]/gi, '_')}-${scan.created_at.slice(0, 10)}`;
  if (format === 'json') {
    const doc = { scan: { id: scan.id, target: scan.target_input, profile: scan.profile, status: scan.status, engine: scan.engine, created_at: scan.created_at, summary: scan.summary, ai_analysis: scan.ai_analysis }, hosts };
    return downloadFile(`${base}.json`, JSON.stringify(doc, null, 2), 'application/json');
  }
  const head = ['address', 'hostnames', 'port', 'protocol', 'state', 'service', 'product', 'version', 'confidence', 'reason'];
  const rows = flattenPorts(hosts).map((p) => [p.address, p.hostnames.join(' '), p.port, p.protocol, p.state, p.service, p.product, p.version, p.confidence ?? '', p.reason]);
  downloadFile(`${base}.csv`, [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\n'), 'text/csv');
}

export function fmtDuration(ms: number | null) {
  if (ms == null) return '-';
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}
