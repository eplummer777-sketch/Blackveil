import { useCallback, useEffect, useState } from 'react';
import { Crosshair, Globe, History, ShieldAlert, Lock, Power, Server } from 'lucide-react';
import { Badge, Button, Card, EmptyState, ErrorBanner, Spinner } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { callPob, PobScan, PobStatus, PobTarget, scoreTone } from '@/lib/pob';
import { Route } from '@/components/AppShell';
import { Challenge } from '@/components/pob/Challenge';
import { Targets } from '@/components/pob/Targets';
import { ScanReport } from '@/components/pob/ScanReport';

type Tab = 'challenge' | 'targets' | 'history' | 'controls';
interface AuditRow { id: string; action: string; detail: Record<string, unknown>; created_at: string }

const TABS: { id: Tab; label: string; icon: typeof Crosshair }[] = [
  { id: 'challenge', label: 'Web Scanner', icon: Crosshair },
  { id: 'targets', label: 'Authorized Targets', icon: Globe },
  { id: 'history', label: 'Test History', icon: History },
  { id: 'controls', label: 'Tools & Audit', icon: Server },
];

export function ProofOfBreach({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [status, setStatus] = useState<PobStatus | null>(null);
  const [tab, setTab] = useState<Tab>('challenge');
  const [targets, setTargets] = useState<PobTarget[]>([]);
  const [scans, setScans] = useState<PobScan[]>([]);
  const [auditRows, setAuditRows] = useState<AuditRow[]>([]);
  const [openScan, setOpenScan] = useState<string | null>(null);
  const [error, setError] = useState('');

  const loadData = useCallback(async () => {
    const [t, s, a] = await Promise.all([
      supabase.from('pob_targets').select('*').order('created_at', { ascending: false }),
      supabase.from('pob_scans').select('*').order('started_at', { ascending: false }).limit(50),
      supabase.from('pob_audit').select('id, action, detail, created_at').order('created_at', { ascending: false }).limit(40),
    ]);
    if (t.error || s.error) setError('Could not load your data.');
    setTargets((t.data ?? []) as PobTarget[]);
    setScans((s.data ?? []) as PobScan[]);
    setAuditRows((a.data ?? []) as AuditRow[]);
  }, []);

  useEffect(() => {
    if (!token) return;
    callPob<PobStatus>(token, { action: 'status' }).then((r) => {
      if (r.ok) setStatus(r.data); else setError(r.error);
    });
    loadData();
  }, [token, loadData]);

  const togglePause = async () => {
    if (!status) return;
    const r = await callPob<{ paused: boolean }>(token, { action: 'set_pause', paused: !status.paused });
    if (r.ok) setStatus({ ...status, paused: r.data.paused }); else setError(r.error);
    loadData();
  };

  if (!status) return error ? <ErrorBanner message={error} /> : <div className="flex justify-center py-24"><Spinner /></div>;

  if (!status.elite) {
    return (
      <Card className="relative overflow-hidden p-10 text-center fade-up">
        <div className="pointer-events-none absolute inset-x-0 -top-20 mx-auto h-48 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
        <Lock size={32} className="relative mx-auto text-cyan-300" />
        <h1 className="relative mt-4 text-2xl font-semibold text-slate-100">Proof-of-Breach AI is an Elite feature</h1>
        <p className="relative mx-auto mt-2 max-w-lg text-sm text-slate-400 leading-relaxed">
          Verified-target testing, the 60-Second Hacker Challenge, evidence-backed AI explanations, guided fixes and retest verification are included with the $25/month Elite plan.
        </p>
        <Button className="relative mt-6" onClick={() => onNavigate('settings')}>View plans</Button>
      </Card>
    );
  }

  const targetFor = (id: string) => targets.find((t) => t.id === id);

  if (openScan) {
    const s = scans.find((x) => x.id === openScan);
    return <ScanReport token={token} scanId={openScan} target={s ? targetFor(s.target_id) : undefined}
      onBack={() => { setOpenScan(null); loadData(); }} onDeleted={() => { setOpenScan(null); loadData(); }} />;
  }

  return (
    <div className="space-y-6 fade-up">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-300/80">Elite</p>
          <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight text-slate-100"><ShieldAlert className="text-cyan-300" size={24} />Blackveil Proof-of-Breach AI</h1>
          <p className="mt-1 text-sm text-slate-400">Evidence-driven testing of websites you have proven you own.</p>
        </div>
        {status.paused && <Badge tone="amber">Emergency stop active</Badge>}
      </header>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      <nav className="flex gap-1 overflow-x-auto rounded-xl border border-slate-800 bg-veil-900/60 p-1 scrollbar-thin" role="tablist">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
            className={`flex shrink-0 items-center gap-2 rounded-lg px-4 py-2 text-sm transition focus:outline-none focus:ring-2 focus:ring-cyan-400/40 ${tab === id ? 'bg-cyan-400/10 text-cyan-200 shadow-glow-cyan' : 'text-slate-400 hover:text-slate-200 hover:bg-veil-800/60'}`}>
            <Icon size={15} />{label}
          </button>
        ))}
      </nav>

      {tab === 'challenge' && <Challenge token={token} targets={targets} limit={status.quick_limit_seconds} paused={status.paused}
        onOpenScan={(id) => { loadData(); setOpenScan(id); }} onGoTargets={() => setTab('targets')} />}
      {tab === 'targets' && <Targets token={token} targets={targets} onChange={loadData} />}
      {tab === 'history' && (scans.length === 0 ? (
        <EmptyState icon={<History size={28} />} title="No tests yet" hint="Run the Web Scanner to create your first report." />
      ) : (
        <Card className="divide-y divide-slate-800/80">
          {scans.map((s) => (
            <button key={s.id} onClick={() => setOpenScan(s.id)} className="flex w-full items-center gap-4 px-5 py-4 text-left transition hover:bg-veil-800/40">
              <span className={`w-12 text-2xl font-semibold ${scoreTone(s.score)}`}>{s.score ?? '–'}</span>
              <div className="min-w-0 flex-1">
                <p className="font-mono text-sm text-slate-200 truncate">{s.hostname}</p>
                <p className="text-xs text-slate-500">{new Date(s.started_at).toLocaleString()}</p>
              </div>
              <span className="hidden sm:block text-xs text-slate-400">{(s.counts.failed ?? 0) + (s.counts.partial ?? 0)} issues · {s.counts.incomplete ?? 0} incomplete</span>
              <Badge tone={s.status === 'completed' ? 'green' : s.status === 'running' ? 'cyan' : 'amber'}>{s.status}</Badge>
            </button>
          ))}
        </Card>
      ))}
      {tab === 'controls' && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="p-5">
            <h3 className="text-xs uppercase tracking-widest text-slate-500">Testing tools</h3>
            <ul className="mt-4 space-y-3">
              {status.tools.map((t) => (
                <li key={t.name} className="flex items-start gap-3">
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${t.status === 'connected' ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  <div>
                    <p className="text-sm text-slate-200">{t.name} {t.version && <span className="text-xs text-slate-500">v{t.version}</span>} <span className="text-xs text-slate-500">· {t.status === 'connected' ? 'Connected' : 'Not connected'}</span></p>
                    <p className="text-xs text-slate-400 leading-relaxed">{t.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
            {status.admin && (
              <div className="mt-6 border-t border-slate-800 pt-4">
                <Button variant={status.paused ? 'secondary' : 'danger'} onClick={togglePause}><Power size={14} />{status.paused ? 'Resume all testing' : 'Emergency stop all testing'}</Button>
              </div>
            )}
          </Card>
          <Card className="p-5">
            <h3 className="text-xs uppercase tracking-widest text-slate-500">Audit log</h3>
            <ul className="mt-4 max-h-96 space-y-2 overflow-y-auto scrollbar-thin">
              {auditRows.map((a) => (
                <li key={a.id} className="flex items-baseline justify-between gap-3 text-xs">
                  <span className="text-slate-300">{a.action.replace(/_/g, ' ')}{typeof a.detail.hostname === 'string' ? ` · ${a.detail.hostname}` : ''}{typeof a.detail.outcome === 'string' ? ` · ${a.detail.outcome.replace(/_/g, ' ')}` : ''}</span>
                  <span className="shrink-0 text-slate-500">{new Date(a.created_at).toLocaleString()}</span>
                </li>
              ))}
              {auditRows.length === 0 && <li className="text-xs text-slate-500">No activity yet.</li>}
            </ul>
          </Card>
        </div>
      )}
    </div>
  );
}
