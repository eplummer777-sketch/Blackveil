import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase, callEdge } from '@/lib/supabase';
import { Assessment, Finding } from '@/lib/types';
import { Card, SectionTitle, Button, Input, Label, SeverityPill, Badge, EmptyState, Spinner } from '@/components/ui';
import { SEVERITY_ORDER } from '@/lib/types';
import {
  ScanSearch, ShieldCheck, AlertTriangle, FileText, Lock, Globe, CheckCircle2,
  Server, FileWarning, Network, RefreshCw,
} from 'lucide-react';

interface AssessmentResponse {
  assessmentId: string;
  target: string;
  status: string;
  overall_status: string;
  summary: Record<string, number>;
  checks: { check_id: string; status: string; note?: string }[];
  findings: Finding[];
}

export function Assessments() {
  const { user, session } = useAuth();
  const [target, setTarget] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AssessmentResponse | null>(null);
  const [recent, setRecent] = useState<Assessment[]>([]);

  async function loadRecent() {
    if (!user) return;
    const { data } = await supabase
      .from('assessments')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(5);
    setRecent((data as Assessment[]) ?? []);
  }

  useEffect(() => { loadRecent(); }, [user]);

  async function handleRun(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!target.trim()) { setError('Enter a domain to assess.'); return; }
    if (!confirmed) { setError('Confirm you own or have permission to assess this target.'); return; }
    if (!session?.access_token) { setError('Not authenticated.'); return; }
    setLoading(true);
    const r = await callEdge<AssessmentResponse>('website-assessment', {
      target,
      authorization_confirmed: confirmed,
    }, session.access_token);
    setLoading(false);
    if (!r.ok) { setError(r.error); return; }
    setResult(r.data);
    loadRecent();
  }

  return (
    <div className="space-y-6 fade-up">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">Website Security Assessment</h1>
        <p className="text-slate-400 mt-1 text-sm">Non-intrusive, defensive checks against domains you own or are authorized to test.</p>
      </div>

      <div className="grid lg:grid-cols-5 gap-6">
        <Card className="lg:col-span-2 p-5">
          <SectionTitle title="New assessment" subtitle="Enter a public domain" icon={<ScanSearch size={18} />} />
          <form onSubmit={handleRun} className="space-y-4">
            <div>
              <Label>Target domain</Label>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                autoComplete="off"
                spellCheck={false}
              />
              <p className="text-[11px] text-slate-500 mt-1.5">Use a root domain. http:// or https:// prefixes are accepted.</p>
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer text-sm group">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-slate-600 bg-veil-950 text-cyan-500 focus:ring-cyan-400/40"
              />
              <span className="text-slate-300 group-hover:text-slate-200">
                I own this domain or have <span className="text-cyan-300">explicit written permission</span> to assess it.
              </span>
            </label>

            {error && (
              <div className="flex items-start gap-2 text-sm text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
              </div>
            )}

            <Button type="submit" loading={loading} full disabled={!target || !confirmed}>
              <ScanSearch size={16} /> {loading ? 'Running assessment…' : 'Run authorized assessment'}
            </Button>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Rate-limited based on your plan (6/hour free, 12 Malware Removal, 30 Pro, unlimited Elite). Private, loopback, and cloud metadata destinations are blocked. No intrusive or exploit-based tests are performed.
            </p>
          </form>
        </Card>

        <div className="lg:col-span-3 space-y-6">
          {loading && <RunningState target={target} />}
          {!loading && result && <ResultView result={result} />}
          {!loading && !result && (
            <Card className="p-5">
              <SectionTitle title="What we check" subtitle="Non-intrusive, evidence-backed" icon={<ShieldCheck size={18} />} />
              <div className="grid sm:grid-cols-2 gap-3">
                {CHECKS.map((c) => (
                  <div key={c.id} className="flex items-start gap-2.5 rounded-lg border border-slate-800/70 bg-veil-950/40 p-3">
                    <span className="mt-0.5 text-cyan-300">{c.icon}</span>
                    <div>
                      <div className="text-sm font-medium text-slate-200">{c.title}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{c.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      <Card className="p-5">
        <SectionTitle title="Recent assessments" icon={<FileText size={18} />} />
        {recent.length === 0 ? (
          <EmptyState icon={<FileText size={26} />} title="No assessments yet" hint="Your completed assessments will appear here." />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {recent.map((a) => (
              <div key={a.id} className="flex items-center gap-3 py-3">
                <Globe size={16} className="text-cyan-300 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-slate-200 truncate">{a.target}</div>
                  <div className="text-[11px] text-slate-500 font-mono-tight">{new Date(a.created_at).toLocaleString()}</div>
                </div>
                <Badge tone={a.status === 'completed' ? 'green' : a.status === 'failed' ? 'rose' : 'slate'}>{a.status}</Badge>
                {a.overall_status && <Badge tone="cyan">{a.overall_status}</Badge>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function RunningState({ target }: { target: string }) {
  const steps = ['Resolving DNS', 'Verifying TLS handshake', 'Checking HTTPS redirect', 'Inspecting security headers', 'Reviewing well-known paths', 'Compiling evidence'];
  return (
    <Card className="p-5 relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-cyan-400/10 to-transparent scanline pointer-events-none" />
      <div className="flex items-center gap-2 text-cyan-300">
        <Spinner className="text-cyan-300" />
        <span className="text-sm font-medium">Assessing {target || 'target'}…</span>
      </div>
      <ul className="mt-4 space-y-2">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-2 text-sm text-slate-400 fade-up" style={{ animationDelay: `${i * 120}ms` }}>
            <CheckCircle2 size={14} className="text-cyan-400/70" /> {s}
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-slate-500 mt-4">Real non-intrusive checks are running server-side. This usually completes within a few seconds.</p>
    </Card>
  );
}

function ResultView({ result }: { result: AssessmentResponse }) {
  const findings = (result.findings ?? []).slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const summary = result.summary ?? {};
  const completed = result.checks?.filter((c) => c.status === 'completed').length ?? 0;
  const skipped = result.checks?.filter((c) => c.status === 'skipped').length ?? 0;

  return (
    <div className="space-y-5 fade-up">
      <Card className="p-5 border-cyan-500/30">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-500">Result</div>
            <div className="text-xl font-semibold text-slate-100">{result.target}</div>
          </div>
          <Badge tone={result.overall_status === 'Critical' ? 'rose' : result.overall_status === 'Needs attention' ? 'amber' : 'green'}>
            {result.overall_status}
          </Badge>
        </div>
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 mt-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
            <div key={s} className="rounded-lg bg-veil-950/60 border border-slate-800/70 p-2.5 text-center">
              <div className={`text-lg font-semibold ${summary[s] ? 'text-slate-100' : 'text-slate-600'}`}>{summary[s] ?? 0}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-500">{s}</div>
            </div>
          ))}
        </div>
        <div className="text-[11px] text-slate-500 mt-3">
          {completed} check(s) completed · {skipped} skipped · {result.checks?.length ?? 0} total. Untested systems are never labeled secure.
        </div>
      </Card>

      <Card className="p-5">
        <SectionTitle title="Checks performed" icon={<CheckCircle2 size={18} />} />
        <ul className="grid sm:grid-cols-2 gap-2">
          {result.checks?.map((c) => (
            <li key={c.check_id} className="flex items-center gap-2 text-sm">
              <span className={`w-1.5 h-1.5 rounded-full ${c.status === 'completed' ? 'bg-emerald-400' : c.status === 'skipped' ? 'bg-slate-500' : 'bg-rose-400'}`} />
              <span className="text-slate-300 font-mono-tight text-xs">{c.check_id}</span>
              <span className="text-slate-500 text-xs ml-auto">{c.status}{c.note ? ` · ${c.note}` : ''}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card className="p-5">
        <SectionTitle title={`Findings (${findings.length})`} subtitle="Sorted by severity" icon={<AlertTriangle size={18} />} />
        {findings.length === 0 ? (
          <EmptyState icon={<ShieldCheck size={28} />} title="No issues found" hint="All completed checks passed. Continue monitoring and re-scan after changes." />
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div key={f.id ?? f.check_id + f.title} className="rounded-lg border border-slate-800/70 bg-veil-950/40 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{f.title}</div>
                    <div className="text-xs text-slate-500 mt-0.5 font-mono-tight">{f.check_id}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {f.verified ? <Badge tone="green">Verified</Badge> : <Badge tone="slate">Inferred</Badge>}
                    <SeverityPill severity={f.severity} />
                  </div>
                </div>
                {f.description && <p className="text-sm text-slate-400 mt-2">{f.description}</p>}
                {f.evidence && (
                  <div className="mt-2.5">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Evidence</div>
                    <pre className="text-[12px] font-mono-tight text-slate-300 bg-veil-950/80 border border-slate-800/70 rounded-md p-2.5 overflow-x-auto whitespace-pre-wrap">{f.evidence}</pre>
                  </div>
                )}
                {f.remediation && (
                  <div className="mt-2.5 text-sm">
                    <div className="text-[10px] uppercase tracking-wider text-cyan-400 mb-1">Remediation</div>
                    <p className="text-slate-300">{f.remediation}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

const CHECKS = [
  { id: 'tls', title: 'TLS / HTTPS', desc: 'Handshake success and HTTPS availability', icon: <Lock size={16} /> },
  { id: 'redirect', title: 'HTTP→HTTPS redirect', desc: 'Plain HTTP should redirect', icon: <RefreshCw size={16} /> },
  { id: 'headers', title: 'Security headers', desc: 'HSTS, CSP, X-Frame-Options, etc.', icon: <ShieldCheck size={16} /> },
  { id: 'banner', title: 'Server banner', desc: 'Software version disclosure', icon: <Server size={16} /> },
  { id: 'wellknown', title: 'Well-known files', desc: 'security.txt and robots.txt', icon: <FileWarning size={16} /> },
  { id: 'dns', title: 'DNS records', desc: 'A record resolution', icon: <Network size={16} /> },
];
