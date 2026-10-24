import { callEdge } from '@/lib/supabase';

export type ArtifactType =
  | 'nginx_conf' | 'apache_conf' | 'http_headers' | 'ufw_rules' | 'sshd_config'
  | 'fail2ban_jail' | 'json_policy' | 'bash_script' | 'powershell_script' | 'checklist';
export type ChangeStatus =
  | 'proposed' | 'test_failed' | 'tested' | 'approved' | 'deployed' | 'verified' | 'rejected' | 'rolled_back';
export type RiskLevel = 'low' | 'medium' | 'high';
export type ChangeAction = 'approve' | 'reject' | 'mark_deployed' | 'verify' | 'mark_rolled_back';

export interface Question {
  id: string;
  question: string;
  why: string;
  type: 'single' | 'multi' | 'text';
  options: string[];
}

export type Answers = Record<string, string | string[]>;

export interface Plan {
  title: string;
  summary: string;
  steps: { title: string; detail: string }[];
  not_covered: string[];
  assumptions: string[];
}

export interface ArchitectProject {
  id: string;
  title: string;
  description: string;
  status: 'needs_answers' | 'planned' | 'failed';
  questions: Question[];
  answers: Answers | null;
  plan: Plan | null;
  plan_source: 'ai' | 'template' | null;
  created_at: string;
  updated_at: string;
}

export interface VerificationResult {
  ok: boolean;
  checked_url: string;
  http_status: number | null;
  present: string[];
  missing: string[];
  checked_at: string;
  error?: string;
}

export interface ArchitectChange {
  id: string;
  project_id: string;
  position: number;
  title: string;
  category: string;
  target_system: string;
  artifact_type: ArtifactType;
  filename: string;
  content: string;
  explanation: string;
  risks: string[];
  risk_level: RiskLevel;
  rollback_supported: boolean;
  rollback_instructions: string | null;
  verification_supported: boolean;
  verification_spec: { type: 'http_headers'; url: string; expect_headers: string[] } | null;
  status: ChangeStatus;
  last_test_passed: boolean | null;
  last_tested_at: string | null;
  approved_at: string | null;
  approval_note: string | null;
  rejected_at: string | null;
  deployed_method: 'manual_self_reported' | 'integration' | null;
  deployed_at: string | null;
  deploy_note: string | null;
  verified_at: string | null;
  verification_result: VerificationResult | null;
  rolled_back_at: string | null;
  rollback_note: string | null;
  created_at: string;
}

export interface SandboxCheck {
  id: string;
  label: string;
  level: 'pass' | 'warning' | 'error';
  detail: string;
}

export interface ArchitectTest {
  id: string;
  change_id: string;
  passed: boolean;
  checks: SandboxCheck[];
  summary: string;
  content_hash: string;
  created_at: string;
}

export interface ArchitectEvent {
  id: string;
  project_id: string | null;
  change_id: string | null;
  actor: 'user' | 'ai' | 'system';
  action: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export const STATUS_META: Record<ChangeStatus, { label: string; tone: 'cyan' | 'rose' | 'amber' | 'slate' | 'green'; hint: string }> = {
  proposed: { label: 'Proposed', tone: 'slate', hint: 'Written by Architect. Not tested, not applied.' },
  test_failed: { label: 'Test failed', tone: 'rose', hint: 'The sandbox found problems. Fix or reject.' },
  tested: { label: 'Tested', tone: 'cyan', hint: 'Passed static sandbox checks. Awaiting your approval.' },
  approved: { label: 'Approved', tone: 'amber', hint: 'You approved it. It is not live until you apply it.' },
  deployed: { label: 'Applied by you', tone: 'cyan', hint: 'You reported applying this change yourself.' },
  verified: { label: 'Verified', tone: 'green', hint: 'A live check confirmed the change is in effect.' },
  rejected: { label: 'Rejected', tone: 'slate', hint: 'Will not be used.' },
  rolled_back: { label: 'Rolled back', tone: 'slate', hint: 'You reported reverting this change.' },
};

export const RISK_TONE: Record<RiskLevel, 'green' | 'amber' | 'rose'> = { low: 'green', medium: 'amber', high: 'rose' };

export const ARTIFACT_LABELS: Record<ArtifactType, string> = {
  nginx_conf: 'Nginx config',
  apache_conf: 'Apache config',
  http_headers: 'HTTP headers',
  ufw_rules: 'Firewall rules (UFW)',
  sshd_config: 'SSH server config',
  fail2ban_jail: 'Fail2ban jail',
  json_policy: 'Cloud policy (JSON)',
  bash_script: 'Bash script',
  powershell_script: 'PowerShell script',
  checklist: 'Checklist',
};

export const EVENT_LABELS: Record<string, string> = {
  project_created: 'Project created',
  questions_generated: 'Questions prepared',
  answers_submitted: 'Answers submitted',
  plan_generated: 'Plan generated',
  sandbox_passed: 'Sandbox test passed',
  sandbox_failed: 'Sandbox test failed',
  approved: 'Change approved',
  rejected: 'Change rejected',
  marked_applied: 'Marked as applied by you',
  marked_rolled_back: 'Marked as rolled back',
  verification_passed: 'Live verification passed',
  verification_failed: 'Live verification failed',
};

export function callArchitect<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('architect', body, token);
}
