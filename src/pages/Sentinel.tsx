import { useCallback, useEffect, useState } from 'react';
import { FlaskConical, Gavel, LayoutDashboard, Lock, Radar, RefreshCw, ScrollText, Server, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Button, Card, Spinner, ErrorBanner } from '@/components/ui';
import type { Route } from '@/components/AppShell';
import { DecoyType, Honeypot, HoneypotEvent, PolicyAction, callSentinel } from '@/lib/sentinel';
import { Overview, SentinelTab } from '@/components/sentinel/Overview';
import { HoneypotList } from '@/components/sentinel/HoneypotList';
import { EventList } from '@/components/sentinel/EventList';
import { EventDrawer } from '@/components/sentinel/EventDrawer';
import { Approvals } from '@/components/sentinel/Approvals';
import { DeployModal, DeployOpts } from '@/components/sentinel/DeployModal';

const TABS: { id: SentinelTab; label: string; icon: typeof Radar }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'honeypots', label: 'Honeypots', icon: Server },
  { id: 'events', label: 'Events', icon: Radar },
  { id: 'approvals', label: 'Approvals', icon: Gavel },
];

export function Sentinel({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { isPro, isAdmin, loading } = useAuth();
  if (loading) return <div className="flex justify-center py-24"><Spinner /></div>;
  if (!isPro && !isAdmin) return <Paywall onNavigate={onNavigate} />;
  return <SentinelConsole onNavigate={onNavigate} />;
}

function SentinelConsole({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { session, user } = useAuth();
  const token = session?.access_token ?? '';
  const [tab, setTab] = useState<SentinelTab>('overview');
  const [honeypots, setHoneypots] = useState<Honeypot[]>([]);
  const [events, setEvents] = useState<HoneypotEvent[]>([]);
  const [actions, setActions] = useState<PolicyAction[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [deployOpen, setDeployOpen] = useState(false);
  const [openEvent, setOpenEvent] = useState<HoneypotEvent | null>(null);

  const load = useCallback(async () => {
    if (!user) return;
    setRefreshing(true);
    const [h, e, a] = await Promise.all([
      supabase.from('honeypots').select('*').eq('user_id', user.id).order('created_at', { ascending: false }),
      supabase.from('honeypot_events').select('*').eq('user_id', user.id).order('occurred_at', { ascending: false }).limit(500),
      supabase.from('policy_actions').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(200),
    ]);
    setRefreshing(false);
    setLoaded(true);
    if (h.error || e.error || a.error) {
      setError('Could not load Sentinel data. Check your connection and try refreshing.');
      return;
    }
    setError(null);
    setHoneypots((h.data ?? []) as Honeypot[]);
    setEvents((e.data ?? []) as HoneypotEvent[]);
    setActions((a.data ?? []) as PolicyAction[]);
  }, [user]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(null), 4500);
    return () => clearTimeout(t);
  }, [notice]);

  async function run(id: string | null, body: Record<string, unknown>, success: (data: Record<string, unknown>) => string) {
    setBusyId(id);
    setError(null);
    const res = await callSentinel<Record<string, unknown>>(token, body);
    setBusyId(null);
    if (!res.ok) { setError(res.error); return false; }
    setNotice(success(res.data ?? {}));
    await load();
    return true;
  }

  async function deploy(name: string, decoyType: DecoyType, opts: DeployOpts): Promise<string | null> {
    const res = await callSentinel<{ health?: { healthy?: boolean } }>(token, {
      action: 'deploy',
      name,
      decoy_type: decoyType,
      provider: opts.provider,
      inject_health_fault: opts.injectFault,
      cf_integration_id: opts.cfIntegrationId,
    });
    if (!res.ok) return res.error;
    setDeployOpen(false);
    const healthy = res.data?.health?.healthy;
    const isCloud = opts.provider === 'cloud';
    setNotice(healthy
      ? isCloud
        ? `${name} passed its health check and is now live on Cloudflare. Real interactions will be captured automatically.`
        : `${name} passed its health check and is now active in the simulator.`
      : `${name} was created but failed its health check, so it is not marked active.`);
    setTab('honeypots');
    await load();
    return null;
  }

  const healthCheck = (id: string) => run(id, { action: 'health_check', honeypot_id: id }, (d) =>
    (d.health as { healthy?: boolean } | undefined)?.healthy ? 'Health verified. The decoy is active.' : 'Health check failed. The decoy is not marked active.');

  const retire = (id: string) => run(id, { action: 'retire', honeypot_id: id }, () => 'Honeypot retired and cloud resource deleted.');

  const stop = (id: string) => run(id, { action: 'stop', honeypot_id: id }, () => 'Honeypot stopped. The cloud Worker is disabled but not deleted.');

  const start = (id: string) => run(id, { action: 'start', honeypot_id: id }, (d) =>
    (d.health as { healthy?: boolean } | undefined)?.healthy ? 'Honeypot restarted and health verified.' : 'Honeypot restarted but health check failed.');

  async function simulate(id?: string) {
    if (id) setBusyId(id); else setSimulating(true);
    await run(id ?? null, { action: 'simulate', honeypot_id: id, count: 6 }, (d) =>
      `Generated ${Number(d.inserted) || 0} simulated events${Number(d.high_severity) ? `, ${d.high_severity} high severity` : ''}.`);
    setSimulating(false);
  }

  const pendingCount = actions.filter((a) => a.status === 'pending_approval').length;
  const honeypotName = (id: string) => honeypots.find((h) => h.id === id)?.name ?? 'Unknown decoy';

  return (
    <div className="space-y-6 fade-in">
      <header className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-cyan-300/80 font-mono-tight">
            <Radar size={13} /> Active defense
          </div>
          <h1 className="mt-1 text-2xl md:text-3xl font-semibold text-slate-50 tracking-tight">Blackveil Sentinel</h1>
          <p className="mt-1 text-sm text-slate-400 max-w-xl">Isolated decoys that attract and record attacker behavior so you can study it safely.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => onNavigate('limitations')}><ScrollText size={14} /> Limitations</Button>
          <Button variant="secondary" size="sm" onClick={load} loading={refreshing}>{!refreshing && <RefreshCw size={14} />} Refresh</Button>
        </div>
      </header>

      <div className="rounded-xl border border-amber-400/30 bg-amber-400/[0.06] px-4 py-3 flex items-start gap-3">
        <FlaskConical size={18} className="text-amber-300 shrink-0 mt-0.5" />
        <p className="text-sm text-amber-100/90 leading-relaxed">
          <span className="font-medium text-amber-200">How it works.</span> Simulator decoys run in a sealed sandbox with no network exposure and generate synthetic events. Cloud decoys deploy as isolated Cloudflare Workers that capture real attacker interactions safely. Simulated events are always labeled and never shown as real attacks.
        </p>
      </div>

      <nav className="flex gap-1 overflow-x-auto rounded-xl border border-slate-800 bg-veil-900/60 p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm whitespace-nowrap transition-colors ${tab === t.id ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/30' : 'text-slate-400 hover:text-slate-200 hover:bg-veil-800/60'}`}
          >
            <t.icon size={15} /> {t.label}
            {t.id === 'approvals' && pendingCount > 0 && (
              <span className="ml-1 rounded-full bg-amber-400/20 px-1.5 text-[10px] font-medium text-amber-200">{pendingCount}</span>
            )}
          </button>
        ))}
      </nav>

      {error && <ErrorBanner message={error} />}
      {notice && (
        <div className="fade-in rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-4 py-2.5 text-sm text-cyan-100 flex items-center gap-2">
          <ShieldCheck size={15} /> {notice}
        </div>
      )}

      {!loaded ? (
        <div className="flex justify-center py-20"><Spinner /></div>
      ) : (
        <div key={tab} className="fade-in">
          {tab === 'overview' && (
            <Overview honeypots={honeypots} events={events} actions={actions} simulating={simulating}
              onSimulate={() => simulate()} onOpenEvent={setOpenEvent} onGoTab={setTab} />
          )}
          {tab === 'honeypots' && (
            <HoneypotList honeypots={honeypots} events={events} busyId={busyId} onDeployClick={() => setDeployOpen(true)}
              onHealthCheck={healthCheck} onSimulate={(id) => simulate(id)} onRetire={retire}
              onStop={stop} onStart={start} token={token} />
          )}
          {tab === 'events' && <EventList events={events} honeypots={honeypots} onOpen={setOpenEvent} />}
          {tab === 'approvals' && <Approvals actions={actions} token={token} onChanged={load} />}
        </div>
      )}

      {deployOpen && <DeployModal onClose={() => setDeployOpen(false)} onDeploy={deploy} token={token} />}
      {openEvent && (
        <EventDrawer event={openEvent} honeypotName={honeypotName(openEvent.honeypot_id)} token={token}
          onClose={() => setOpenEvent(null)} onChanged={load} />
      )}
    </div>
  );
}

function Paywall({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const perks = [
    'Deploy up to 3 isolated decoys on Pro, 10 on Elite',
    'Verified health checks before anything is marked active',
    'AI analyst that explains every event from the evidence',
    'Human approval queue with a complete activity trail',
  ];
  return (
    <div className="max-w-3xl mx-auto py-8 fade-in">
      <Card className="relative overflow-hidden p-8 md:p-10">
        <div className="radar-sweep pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full opacity-40" />
        <div className="relative">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">
            <Lock size={12} /> Pro and Elite
          </div>
          <h1 className="mt-4 text-3xl font-semibold text-slate-50 tracking-tight">Blackveil Sentinel</h1>
          <p className="mt-2 text-slate-400 leading-relaxed max-w-xl">
            Set up decoy systems that lure attackers away from what matters, record exactly what they try, and let an AI analyst explain it to you in plain language.
          </p>
          <ul className="mt-6 grid sm:grid-cols-2 gap-3">
            {perks.map((p) => (
              <li key={p} className="flex items-start gap-2 text-sm text-slate-300">
                <ShieldCheck size={16} className="text-cyan-300 shrink-0 mt-0.5" /> {p}
              </li>
            ))}
          </ul>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button onClick={() => onNavigate('malware')}>See plans</Button>
            <Button variant="secondary" onClick={() => onNavigate('limitations')}>How it stays safe</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
