import { callEdge } from '@/lib/supabase';
import { Severity } from '@/lib/types';

export type FixStatus = 'none' | 'proposed' | 'approved' | 'applied' | 'verified' | 'failed' | 'rejected';
export type FindingSource = 'http' | 'cloudflare';

export interface RemediationFinding {
  id: string;
  assessment_id: string;
  user_id: string;
  check_id: string;
  title: string;
  severity: Severity;
  category: string;
  source: FindingSource;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  verified: boolean;
  fixable: boolean;
  cf_setting_key: string | null;
  cf_api_path: string | null;
  current_value: unknown;
  proposed_value: unknown;
  recommended_value: unknown;
  rollback_value: unknown;
  rollback_supported: boolean;
  rollback_instructions: string;
  risks: string[];
  risk_level: 'low' | 'medium' | 'high';
  fix_status: FixStatus;
  approved_at: string | null;
  applied_at: string | null;
  apply_error: string | null;
  verified_at: string | null;
  verification_result: { ok: boolean; expected?: unknown; actual?: unknown; checked_at: string; error?: string } | null;
  rejected_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationAssessment {
  id: string;
  user_id: string;
  target: string;
  integration_id: string | null;
  sources: string[];
  status: 'running' | 'completed' | 'failed';
  overall_status: string | null;
  summary: Record<string, number> & { total?: number; checks?: unknown[] };
  check_results: Array<{ check_id: string; status: string; note?: string }>;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface RemediationAuditEntry {
  id: string;
  assessment_id: string | null;
  finding_id: string | null;
  user_id: string;
  action: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export const FIX_STATUS_META: Record<FixStatus, { label: string; tone: 'cyan' | 'rose' | 'amber' | 'slate' | 'green'; hint: string }> = {
  none: { label: 'No fix', tone: 'slate', hint: 'No automatic fix is available for this finding.' },
  proposed: { label: 'Proposed', tone: 'slate', hint: 'A fix is ready. Review and approve to proceed.' },
  approved: { label: 'Approved', tone: 'amber', hint: 'You approved this. Apply it to make it live.' },
  applied: { label: 'Applied', tone: 'cyan', hint: 'Sent to Cloudflare. Verify to confirm it took effect.' },
  verified: { label: 'Verified', tone: 'green', hint: 'Re-read from Cloudflare confirmed the fix is live.' },
  failed: { label: 'Failed', tone: 'rose', hint: 'Cloudflare rejected the change. See the error.' },
  rejected: { label: 'Rejected', tone: 'slate', hint: 'You decided not to apply this fix.' },
};

export function callAssessment<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('assessment-engine', body, token);
}

export function formatVal(v: unknown): string {
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
