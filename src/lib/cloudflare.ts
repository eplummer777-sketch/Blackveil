import { callEdge } from '@/lib/supabase';

export type CfIntegrationStatus = 'connected' | 'disconnected' | 'error';
export type CfMode = 'read_only' | 'write';
export type CfProposalStatus = 'proposed' | 'approved' | 'applied' | 'verified' | 'failed' | 'rejected' | 'rolled_back';

export interface CfIntegration {
  id: string;
  user_id: string;
  provider: 'cloudflare';
  label: string;
  zone_id: string;
  zone_name: string;
  account_id: string | null;
  account_name: string | null;
  status: CfIntegrationStatus;
  mode: CfMode;
  token_permissions: unknown[];
  last_settings_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface CfZone {
  id: string;
  name: string;
  account: string;
  status: string;
}

export interface CfSetting {
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
  risk_level: 'low' | 'medium' | 'high';
  explanation: string;
  risks: string[];
  rollback_instructions: string;
}

export interface CfProposal {
  id: string;
  integration_id: string;
  user_id: string;
  setting_key: string;
  setting_label: string;
  category: string;
  current_value: unknown;
  proposed_value: unknown;
  recommended_value: unknown;
  api_path: string;
  explanation: string;
  risks: string[];
  risk_level: 'low' | 'medium' | 'high';
  rollback_supported: boolean;
  rollback_instructions: string;
  status: CfProposalStatus;
  approved_at: string | null;
  applied_at: string | null;
  apply_error: string | null;
  verified_at: string | null;
  verification_result: { ok: boolean; expected?: unknown; actual?: unknown; checked_at: string; error?: string } | null;
  rejected_at: string | null;
  rolled_back_at: string | null;
  rollback_error: string | null;
  created_at: string;
  updated_at: string;
}

export const CF_STATUS_META: Record<CfProposalStatus, { label: string; tone: 'cyan' | 'rose' | 'amber' | 'slate' | 'green'; hint: string }> = {
  proposed: { label: 'Proposed', tone: 'slate', hint: 'A gap was found. Review and approve to proceed.' },
  approved: { label: 'Approved', tone: 'amber', hint: 'You approved this. Apply it to make it live.' },
  applied: { label: 'Applied', tone: 'cyan', hint: 'Sent to Cloudflare. Verify to confirm it took effect.' },
  verified: { label: 'Verified', tone: 'green', hint: 'Re-read from Cloudflare confirmed the change is live.' },
  failed: { label: 'Failed', tone: 'rose', hint: 'Cloudflare rejected the change. See the error.' },
  rejected: { label: 'Rejected', tone: 'slate', hint: 'You decided not to make this change.' },
  rolled_back: { label: 'Rolled back', tone: 'slate', hint: 'Reverted to the previous value via the API.' },
};

export const CF_RISK_TONE: Record<'low' | 'medium' | 'high', 'green' | 'amber' | 'rose'> = { low: 'green', medium: 'amber', high: 'rose' };

export function callCloudflare<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('cloudflare-architect', body, token);
}

export function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'On' : 'Off';
  if (typeof v === 'string') {
    if (v === 'on') return 'On';
    if (v === 'off') return 'Off';
    if (v === 'essentially_off') return 'Essentially Off';
    return v.charAt(0).toUpperCase() + v.slice(1);
  }
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if (o.enabled !== undefined) return o.enabled ? 'On' : 'Off';
    return JSON.stringify(v);
  }
  return String(v);
}
