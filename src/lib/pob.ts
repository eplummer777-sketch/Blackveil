import { callEdge, supabase } from '@/lib/supabase';

export type CheckResult = 'passed' | 'failed' | 'partial' | 'incomplete' | 'not_performed';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RetestStatus = 'untested' | 'fixed_verified' | 'still_vulnerable' | 'partially_fixed' | 'inconclusive' | 'retest_failed';

export interface PobTarget {
  id: string;
  hostname: string;
  label: string;
  environment: string;
  verify_token: string;
  status: 'pending' | 'verified' | 'expired' | 'revoked';
  verified_at: string | null;
  expires_at: string | null;
  allowed_paths: string[];
  allowed_categories: string[];
  max_requests_per_scan: number;
  created_at: string;
}

export interface ScanCounts {
  passed: number; failed: number; partial: number; validated: number; suspected: number;
  incomplete: number; not_performed: number; total: number;
}

export interface PobScan {
  id: string;
  target_id: string;
  hostname: string;
  kind: string;
  status: 'running' | 'completed' | 'partial' | 'stopped' | 'failed';
  phase: string;
  deadline_at: string;
  score: number | null;
  counts: Partial<ScanCounts>;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface FixPlan {
  why: string;
  steps: string[];
  snippets: { label: string; code: string }[];
  side_effects: string;
  rollback: string;
}

export interface PobCheck {
  id: string;
  scan_id: string;
  check_key: string;
  title: string;
  category: string;
  result: CheckResult;
  severity: Severity;
  confidence: string;
  validation: string;
  affected_asset: string;
  summary: string;
  evidence: Record<string, unknown> & { remediation?: FixPlan };
  tool: string;
  tool_version: string;
  operation: string;
  finished_at: string | null;
  ai_status: 'none' | 'pending' | 'ready' | 'failed';
  ai_analysis: Record<string, string> | null;
  ai_error: string | null;
  remediation_status: 'open' | 'fix_approved' | 'fix_applied_by_user';
  retest_status: RetestStatus;
  retest_evidence: { result: string; summary: string; operation: string; tool: string; at: string; evidence: Record<string, unknown> } | null;
  retested_at: string | null;
}

export interface PobTool { name: string; version: string | null; status: 'connected' | 'not_connected'; detail: string }
export interface PobStatus { elite: boolean; paused: boolean; admin: boolean; tools: PobTool[]; quick_limit_seconds: number }

export function callPob<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('proof-of-breach', body, token);
}

export async function fetchChecks(scanId: string) {
  return supabase.from('pob_checks').select('*').eq('scan_id', scanId).order('finished_at', { ascending: true });
}

export const isIssue = (c: PobCheck) => c.result === 'failed' || c.result === 'partial';

export const RESULT_LABEL: Record<CheckResult, string> = {
  passed: 'Passed', failed: 'Failed', partial: 'Partially protected', incomplete: 'Incomplete', not_performed: 'Not performed',
};

export const RETEST_LABEL: Record<RetestStatus, string> = {
  untested: 'Fix not verified yet',
  fixed_verified: 'Fixed and verified',
  still_vulnerable: 'Still vulnerable',
  partially_fixed: 'Partially fixed',
  inconclusive: 'Verification inconclusive',
  retest_failed: 'Retest could not run',
};

export const AI_SECTIONS: [string, string][] = [
  ['what_was_discovered', 'What was discovered'],
  ['entry_point', 'Entry point'],
  ['testing_method', 'Testing method'],
  ['tool_used', 'Tool used'],
  ['what_actually_happened', 'What actually happened'],
  ['why_it_occurred', 'Why the issue occurred'],
  ['potential_impact', 'Potential impact'],
  ['attacker_approach', 'How an attacker might approach it'],
  ['how_to_prevent', 'How to prevent it'],
  ['repair_instructions', 'Repair instructions'],
  ['retest_procedure', 'Retest procedure'],
];

export const SCORE_METHOD = [
  'Starts at 100 and is capped at 95: a clean result only covers the checks that ran, never the whole site.',
  'Each failed check subtracts by severity: critical 35, high 20, medium 9, low 3.',
  'Deductions scale with evidence: validated 100%, detected 80%, suspected 50%, unresolved 30%.',
  'Partially protected checks count half.',
  'Every incomplete or not-performed check subtracts 3, so untested areas never count as secure.',
];

export function scoreTone(score: number | null) {
  if (score === null) return 'text-slate-400';
  if (score >= 80) return 'text-emerald-300';
  if (score >= 55) return 'text-amber-300';
  return 'text-rose-300';
}
