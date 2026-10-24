import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Assessment, AuditLog } from '@/lib/types';
import { Card, SectionTitle, Button, EmptyState, SeverityPill, Badge } from '@/components/ui';
import { SEVERITY_ORDER } from '@/lib/types';
import {
  ShieldAlert, Activity, ScanSearch, Bot, FileText, ArrowRight,
  ShieldCheck, AlertTriangle, Gauge, TrendingUp, Bug, Zap, Lightbulb, Wrench, Radar, Wand2,
} from 'lucide-react';
import { Route } from '@/components/AppShell';

export function Dashboard({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { user } = useAuth();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) return;
    (async () => {
      const [{ data: a }, { data: l }] = await Promise.all([
        supabase.from('assessments').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(8),
        supabase.from('audit_logs').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(8),
      ]);
      setAssessments((a as Assessment[]) ?? []);
      setLogs((l as AuditLog[]) ?? []);
      setLoading(false);
    })();
  }, [user]);

  const totalFindings = assessments.reduce((acc, a) => {
    const s = a.summary ?? {};
    return acc + (s.critical ?? 0) + (s.high ?? 0) + (s.medium ?? 0) + (s.low ?? 0);
  }, 0);
  const criticalCount = assessments.reduce((acc, a) => acc + (a.summary?.critical ?? 0), 0);
  const completedCount = assessments.filter((a) => a.status === 'completed').length;

  return (
    <div className="space-y-6 fade-up">
      <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-3">
        <div>
          <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">Security Operations Dashboard</h1>
          <p className="text-slate-400 mt-1 text-sm">Your cybersecurity posture at a glance. Run authorized assessments and track remediation.</p>
        </div>
        <Button variant="primary" onClick={() => onNavigate('assessments')}>
          <ScanSearch size={16} /> Start new assessment
        </Button>
      </div>

      {/* Quick actions — one tap to anywhere */}
      <div>
        <div className="flex items-center gap-2 mb-3 text-xs uppercase tracking-wider text-slate-500">
          <Zap size={13} className="text-cyan-400" /> Quick actions
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-3">
          <QuickAction icon={<ScanSearch size={20} />} label="Scan a site" desc="Run assessment" onClick={() => onNavigate('assessments')} tone="cyan" />
          <QuickAction icon={<Wrench size={20} />} label="Security tools" desc="Check links & passwords" onClick={() => onNavigate('tools')} tone="cyan" />
          <QuickAction icon={<Bot size={20} />} label="Ask AI" desc="Get answers" onClick={() => onNavigate('assistant')} tone="cyan" />
          <QuickAction icon={<Bug size={20} />} label="Remove malware" desc="Step-by-step" onClick={() => onNavigate('malware')} tone="rose" />
          <QuickAction icon={<Wand2 size={20} />} label="Architect" desc="Build a security plan" onClick={() => onNavigate('architect')} tone="cyan" />
          <QuickAction icon={<Radar size={20} />} label="Sentinel" desc="Honeypot decoys" onClick={() => onNavigate('sentinel')} tone="cyan" />
          <QuickAction icon={<FileText size={20} />} label="View reports" desc="History & PDF" onClick={() => onNavigate('reports')} tone="slate" />
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Gauge size={18} />}
          label="Overall status"
          value={overallLabel(assessments)}
          tone={overallTone(assessments)}
        />
        <StatCard
          icon={<ScanSearch size={18} />}
          label="Assessments run"
          value={String(assessments.length)}
          sub={`${completedCount} completed`}
        />
        <StatCard
          icon={<ShieldAlert size={18} />}
          label="Critical findings"
          value={String(criticalCount)}
          tone={criticalCount > 0 ? 'danger' : 'ok'}
        />
        <StatCard
          icon={<Activity size={18} />}
          label="Total findings"
          value={String(totalFindings)}
          sub="All severities"
        />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Recent assessments */}
        <Card className="lg:col-span-2 p-5">
          <SectionTitle
            title="Recent assessments"
            subtitle="Latest website security scans"
            icon={<FileText size={18} />}
            action={<Button size="sm" variant="ghost" onClick={() => onNavigate('reports')}>View all <ArrowRight size={14} /></Button>}
          />
          {loading ? (
            <Skeleton rows={4} />
          ) : assessments.length === 0 ? (
            <EmptyState
              icon={<ScanSearch size={28} />}
              title="No assessments yet"
              hint="Run your first authorized website security assessment to see results here."
              action={<Button size="sm" onClick={() => onNavigate('assessments')}><ScanSearch size={14} /> Start assessment</Button>}
            />
          ) : (
            <div className="divide-y divide-slate-800/60">
              {assessments.map((a) => (
                <AssessmentRow key={a.id} a={a} onClick={() => onNavigate('reports')} />
              ))}
            </div>
          )}
        </Card>

        {/* Right column */}
        <div className="space-y-6">
          <Card className="p-5">
            <SectionTitle title="Security posture" icon={<ShieldCheck size={18} />} />
            <PostureSummary assessments={assessments} />
          </Card>

          <Card className="p-5">
            <SectionTitle title="Recent activity" icon={<Activity size={18} />} />
            {logs.length === 0 ? (
              <p className="text-sm text-slate-500">No recent activity.</p>
            ) : (
              <ul className="space-y-2.5">
                {logs.map((log) => (
                  <li key={log.id} className="flex items-start gap-2.5 text-sm">
                    <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
                    <div className="min-w-0">
                      <div className="text-slate-300 truncate">{prettyAction(log.action)}</div>
                      <div className="text-[11px] text-slate-500 font-mono-tight">{new Date(log.created_at).toLocaleString()}</div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card className="p-5 bg-gradient-to-br from-cyan-500/5 to-transparent border-cyan-500/20">
            <div className="flex items-start gap-3">
              <div className="rounded-lg bg-cyan-500/15 p-2 text-cyan-300"><Bot size={20} /></div>
              <div className="flex-1">
                <h3 className="text-sm font-semibold text-slate-100">Ask the AI assistant</h3>
                <p className="text-xs text-slate-400 mt-1">Get plain-English explanations of vulnerabilities and step-by-step fixes.</p>
                <Button size="sm" variant="secondary" className="mt-3" onClick={() => onNavigate('assistant')}>
                  Open assistant <ArrowRight size={14} />
                </Button>
              </div>
            </div>
          </Card>

          <TipOfTheDay onNavigate={onNavigate} />
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub, tone = 'neutral' }: { icon: React.ReactNode; label: string; value: string; sub?: string; tone?: 'neutral' | 'ok' | 'danger' | 'warn' }) {
  const tones = {
    neutral: 'text-slate-100',
    ok: 'text-emerald-300',
    danger: 'text-rose-300',
    warn: 'text-amber-300',
  };
  return (
    <Card className="p-4 relative overflow-hidden">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        <span className="text-slate-500">{icon}</span>
      </div>
      <div className={`mt-2 text-2xl font-semibold tracking-tight ${tones[tone]}`}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </Card>
  );
}

function QuickAction({
  icon, label, desc, onClick, tone = 'slate',
}: {
  icon: React.ReactNode;
  label: string;
  desc: string;
  onClick: () => void;
  tone?: 'cyan' | 'rose' | 'slate';
}) {
  const tones = {
    cyan: 'text-cyan-300 group-hover:border-cyan-400/50 group-hover:bg-cyan-500/5',
    rose: 'text-rose-300 group-hover:border-rose-400/50 group-hover:bg-rose-500/5',
    slate: 'text-slate-300 group-hover:border-slate-600',
  };
  return (
    <button
      onClick={onClick}
      className={`group flex items-center gap-3 rounded-xl border border-slate-800/80 bg-veil-900/60 p-3.5 text-left transition-all hover:-translate-y-0.5 ${tones[tone]}`}
    >
      <span className={`shrink-0 ${tones[tone].split(' ')[0]}`}>{icon}</span>
      <span className="min-w-0">
        <span className="block text-sm font-medium text-slate-100 truncate">{label}</span>
        <span className="block text-[11px] text-slate-500 truncate">{desc}</span>
      </span>
    </button>
  );
}

function AssessmentRow({ a, onClick }: { a: Assessment; onClick: () => void }) {
  const statusTone =
    a.status === 'completed' ? 'green' :
    a.status === 'failed' ? 'rose' :
    a.status === 'running' ? 'cyan' : 'slate';
  return (
    <button onClick={onClick} className="w-full flex items-center gap-3 py-3 text-left hover:bg-veil-800/40 -mx-2 px-2 rounded-lg transition">
      <div className="w-9 h-9 rounded-lg bg-veil-800 border border-slate-700/60 flex items-center justify-center text-cyan-300">
        <FileText size={16} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-slate-200 truncate">{a.target}</div>
        <div className="text-[11px] text-slate-500 font-mono-tight">{new Date(a.created_at).toLocaleString()}</div>
      </div>
      <div className="hidden sm:flex items-center gap-1.5">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => {
          const c = a.summary?.[s] ?? 0;
          if (!c) return null;
          return <SeverityPill key={s} severity={s} />;
        })}
      </div>
      <Badge tone={statusTone as 'green' | 'rose' | 'cyan' | 'slate'}>{a.status}</Badge>
    </button>
  );
}

function PostureSummary({ assessments }: { assessments: Assessment[] }) {
  const totals: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of assessments) {
    for (const k of SEVERITY_ORDER) totals[k] += a.summary?.[k] ?? 0;
  }
  const total = Object.values(totals).reduce((a, b) => a + b, 0);
  if (total === 0) {
    return (
      <div className="flex flex-col items-center text-center py-4">
        <ShieldCheck size={28} className="text-emerald-400 mb-2" />
        <p className="text-sm text-slate-300">No findings recorded yet.</p>
        <p className="text-xs text-slate-500 mt-1">Run an assessment to populate your posture.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2.5">
      {SEVERITY_ORDER.map((s) => {
        const c = totals[s];
        const pct = total ? (c / total) * 100 : 0;
        const colors = {
          critical: 'bg-rose-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-cyan-500', info: 'bg-slate-500',
        };
        return (
          <div key={s}>
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="capitalize text-slate-300">{s}</span>
              <span className="text-slate-500 font-mono-tight">{c}</span>
            </div>
            <div className="h-1.5 rounded-full bg-veil-800 overflow-hidden">
              <div className={`h-full ${colors[s]} transition-all duration-500`} style={{ width: `${pct}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

const SECURITY_TIPS: { title: string; body: string; cta?: Route; ctaLabel?: string }[] = [
  { title: 'Turn on MFA everywhere', body: 'Multi-factor authentication blocks over 99% of automated account takeover attempts. Prioritize email, banking, and password manager accounts first.', cta: 'device', ctaLabel: 'Open device checklist' },
  { title: 'Use a password manager', body: 'Reusing passwords means one breach compromises many accounts. A password manager lets you use a unique, strong password for every site without memorizing them.', cta: 'assistant', ctaLabel: 'Ask AI for recommendations' },
  { title: 'Keep software updated', body: 'Most exploits target known vulnerabilities that already have patches. Enable automatic updates for your OS, browser, and apps to close the door before attackers walk in.' },
  { title: 'Check breach notifications', body: 'If a service you use announces a breach, change that password immediately and anywhere else you reused it. Enable MFA if you had not already.' },
  { title: 'Secure your home Wi-Fi', body: 'Change the default router admin password, use WPA3 (or WPA2) encryption, and disable WPS. Guest networks keep IoT devices away from your main devices.' },
  { title: 'Spot phishing emails', body: 'Watch for urgency, mismatched sender domains, and unexpected attachments. Hover over links before clicking. When in doubt, go to the site directly instead of clicking the link.' },
  { title: 'Backup with the 3-2-1 rule', body: 'Keep 3 copies of important data, on 2 different media, with 1 offsite. Ransomware cannot hold your data hostage if you can restore it.' },
  { title: 'Review app permissions', body: 'Smartphone apps often request more access than they need. Audit permissions monthly — a flashlight app does not need your contacts or location.' },
  { title: 'Use hardware keys for high-value accounts', body: 'For email, banking, and password managers, a hardware security key (like YubiKey) is stronger than SMS or app-based MFA and resists phishing by design.' },
  { title: 'Disable unused services', body: 'Every open port and running service is an attack surface. If you do not use remote desktop, file sharing, or SSH on a device, turn it off.' },
  { title: 'Encrypt your devices', body: 'Turn on BitLocker (Windows) or FileVault (macOS). If a device is lost or stolen, encryption prevents anyone from reading your files without your password.' },
  { title: 'Beware of public Wi-Fi', body: 'Avoid logging into sensitive accounts on public networks. If you must, use a reputable VPN. Cellular hotspots are generally safer than café Wi-Fi.' },
];

function TipOfTheDay({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const today = new Date();
  const dayIndex = Math.floor(
    Date.UTC(today.getFullYear(), today.getMonth(), today.getDate()) / 86_400_000
  ) % SECURITY_TIPS.length;
  const tip = SECURITY_TIPS[dayIndex];
  return (
    <Card className="p-5 relative overflow-hidden border-amber-500/20">
      <div className="absolute -top-16 -right-16 w-40 h-40 rounded-full bg-amber-500/10 blur-3xl pointer-events-none" />
      <div className="flex items-center gap-2 mb-2">
        <Lightbulb size={16} className="text-amber-300" />
        <span className="text-[11px] uppercase tracking-widest text-amber-300/80 font-medium">Tip of the day</span>
      </div>
      <h3 className="text-sm font-semibold text-slate-100">{tip.title}</h3>
      <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{tip.body}</p>
      {tip.cta && (
        <button
          onClick={() => onNavigate(tip.cta!)}
          className="mt-3 inline-flex items-center gap-1.5 text-xs text-amber-300 hover:text-amber-200 transition"
        >
          {tip.ctaLabel ?? 'Learn more'} <ArrowRight size={12} />
        </button>
      )}
    </Card>
  );
}

function Skeleton({ rows }: { rows: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 rounded-lg bg-veil-800/40 animate-pulse" />
      ))}
    </div>
  );
}

function overallLabel(assessments: Assessment[]): string {
  if (assessments.length === 0) return 'No data';
  const anyCritical = assessments.some((a) => (a.summary?.critical ?? 0) > 0);
  const anyHigh = assessments.some((a) => (a.summary?.high ?? 0) > 0);
  if (anyCritical) return 'Critical';
  if (anyHigh) return 'Needs attention';
  return 'Stable';
}

function overallTone(assessments: Assessment[]): 'ok' | 'danger' | 'warn' | 'neutral' {
  if (assessments.length === 0) return 'neutral';
  if (assessments.some((a) => (a.summary?.critical ?? 0) > 0)) return 'danger';
  if (assessments.some((a) => (a.summary?.high ?? 0) > 0)) return 'warn';
  return 'ok';
}

function prettyAction(action: string): string {
  return action.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export { TrendingUp, AlertTriangle };
