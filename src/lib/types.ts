export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Profile {
  id: string;
  email: string;
  display_name: string | null;
  company: string | null;
  role: 'customer' | 'admin';
  created_at: string;
}

export interface Assessment {
  id: string;
  user_id: string;
  target: string;
  authorization_confirmed: boolean;
  status: 'pending' | 'running' | 'completed' | 'failed';
  overall_status: string | null;
  summary: Record<string, number> & { checks?: CheckResult[] };
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  created_at: string;
}

export interface CheckResult {
  check_id: string;
  status: 'completed' | 'skipped' | 'failed';
  note?: string;
}

export interface Finding {
  id: string;
  assessment_id: string;
  check_id: string;
  title: string;
  severity: Severity;
  description: string | null;
  evidence: string | null;
  remediation: string | null;
  verified: boolean;
  created_at: string;
}

export interface ChatThread {
  id: string;
  title: string;
  user_id: string;
  created_at: string;
  updated_at: string;
}

export interface ChatMessage {
  id: string;
  thread_id: string;
  role: 'user' | 'assistant';
  content: string;
  uncertain: boolean;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export type Plan = 'free' | 'malware_removal' | 'pro' | 'elite';

export interface Subscription {
  id: string;
  user_id: string;
  plan: Plan;
  status: 'free' | 'active' | 'canceled' | 'past_due' | 'trialing';
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  current_period_end: string | null;
  created_at: string;
  updated_at: string;
}

export const PLAN_LABELS: Record<Plan, string> = {
  free: 'Free',
  malware_removal: 'Malware Removal',
  pro: 'Pro',
  elite: 'Elite',
};

export const PLAN_PRICES: Record<Plan, number> = {
  free: 0,
  malware_removal: 5,
  pro: 10,
  elite: 25,
};

export const PLAN_AI_LIMITS: Record<Plan, number> = {
  free: 20,
  malware_removal: 100,
  pro: 1000,
  elite: 0, // 0 = unlimited
};

export const PLAN_RANK: Record<Plan, number> = {
  free: 0,
  malware_removal: 1,
  pro: 2,
  elite: 3,
};

export interface MalwareStepProgress {
  id: string;
  user_id: string;
  step_id: string;
  completed: boolean;
  completed_at: string | null;
  notes: string | null;
}

export type LinkVerdict = 'low_risk' | 'suspicious' | 'high_risk' | 'unable_to_determine';

export interface RiskIndicator {
  id: string;
  label: string;
  severity: Severity;
  detail: string;
}

export interface LinkScan {
  id: string;
  user_id: string;
  input: string;
  target_url: string | null;
  target_host: string | null;
  verdict: LinkVerdict;
  risk_score: number;
  indicators: RiskIndicator[];
  recommendations: string[];
  details: Record<string, unknown> | null;
  scan_type: 'url' | 'message' | 'qr';
  created_at: string;
}

export interface Notification {
  id: string;
  user_id: string;
  kind: 'scan_complete' | 'subscription' | 'security_alert' | 'system' | 'assessment';
  title: string;
  body: string | null;
  link: string | null;
  read: boolean;
  created_at: string;
}

export const VERDICT_STYLES: Record<LinkVerdict, { label: string; text: string; bg: string; border: string; dot: string }> = {
  high_risk:             { label: 'High Risk',     text: 'text-rose-300',   bg: 'bg-rose-500/10',   border: 'border-rose-500/40',   dot: 'bg-rose-400' },
  suspicious:            { label: 'Suspicious',    text: 'text-amber-300',  bg: 'bg-amber-500/10',  border: 'border-amber-500/40',  dot: 'bg-amber-400' },
  low_risk:              { label: 'Low Risk',      text: 'text-emerald-300',bg: 'bg-emerald-500/10',border: 'border-emerald-500/40',dot: 'bg-emerald-400' },
  unable_to_determine:   { label: 'Unable to Determine', text: 'text-slate-300', bg: 'bg-slate-500/10', border: 'border-slate-500/40', dot: 'bg-slate-400' },
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_STYLES: Record<Severity, { label: string; text: string; bg: string; border: string; dot: string }> = {
  critical: { label: 'Critical', text: 'text-rose-300', bg: 'bg-rose-500/10', border: 'border-rose-500/40', dot: 'bg-rose-400' },
  high:     { label: 'High',     text: 'text-orange-300', bg: 'bg-orange-500/10', border: 'border-orange-500/40', dot: 'bg-orange-400' },
  medium:   { label: 'Medium',   text: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-500/40', dot: 'bg-amber-400' },
  low:      { label: 'Low',      text: 'text-cyan-300', bg: 'bg-cyan-500/10', border: 'border-cyan-500/40', dot: 'bg-cyan-400' },
  info:     { label: 'Info',     text: 'text-slate-300', bg: 'bg-slate-500/10', border: 'border-slate-500/40', dot: 'bg-slate-400' },
};
