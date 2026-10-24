import { useMemo } from 'react';
import { Activity, AlertTriangle, ArrowRight, Gavel, HeartPulse, Radar, ServerCog, Zap } from 'lucide-react';
import { Card, SectionTitle, Button, EmptyState, SeverityPill } from '@/components/ui';
import { SEVERITY_ORDER, SEVERITY_STYLES } from '@/lib/types';
import { Honeypot, HoneypotEvent, PolicyAction, DECOY_CATALOG, prettyEventType, timeAgo } from '@/lib/sentinel';
import { HealthBadge, SimulatedBadge } from '@/components/sentinel/badges';

export type SentinelTab = 'overview' | 'honeypots' | 'events' | 'approvals';

interface Props {
  honeypots: Honeypot[];
  events: HoneypotEvent[];
  actions: PolicyAction[];
  simulating: boolean;
  onSimulate: () => void;
  onOpenEvent: (e: HoneypotEvent) => void;
  onGoTab: (t: SentinelTab) => void;
}

function isVerified(h: Honeypot) {
  return h.status === 'active' && h.last_health_status === 'healthy' && !!h.verified_at;
}

export function Overview({ honeypots, events, actions, simulating, onSimulate, onOpenEvent, onGoTab }: Props) {
  const live = honeypots.filter((h) => h.status !== 'retired');
  const verified = live.filter(isVerified);
  const unhealthy = live.filter((h) => h.last_health_status === 'unhealthy');
  const dayAgo = Date.now() - 86_400_000;
  const recent = events.filter((e) => new Date(e.occurred_at).getTime() >= dayAgo);
  const alerts = recent.filter((e) => e.severity === 'critical' || e.severity === 'high');
  const pending = actions.filter((a) => a.status === 'pending_approval');
  const realCount = events.filter((e) => !e.is_simulated).length;

  const health =
    live.length === 0 ? { label: 'No decoys', tone: 'text-slate-300', sub: 'Deploy a simulated honeypot to begin' }
    : unhealthy.length > 0 ? { label: 'Degraded', tone: 'text-amber-300', sub: `${unhealthy.length} failing health check` }
    : verified.length === live.length ? { label: 'Nominal', tone: 'text-emerald-300', sub: 'All decoys verified' }
    : { label: 'Checking', tone: 'text-slate-300', sub: 'Some decoys unverified' };

  const buckets = useMemo(() => {
    const b = Array.from({ length: 24 }, () => ({ total: 0, serious: 0 }));
    const now = Date.now();
    for (const e of events) {
      const h = Math.floor((now - new Date(e.occurred_at).getTime()) / 3_600_000);
      if (h >= 0 && h < 24) {
        b[23 - h].total++;
        if (e.severity === 'critical' || e.severity === 'high') b[23 - h].serious++;
      }
    }
    return b;
  }, [events]);
  const maxBucket = Math.max(1, ...buckets.map((b) => b.total));

  const sevTotals = SEVERITY_ORDER.map((s) => ({ s, c: recent.filter((e) => e.severity === s).length }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat icon={<ServerCog size={18} />} label="Verified decoys" value={`${verified.length}/${live.length}`} sub="Passed latest health check" />
        <Stat icon={<AlertTriangle size={18} />} label="Alerts (24h)" value={String(alerts.length)} sub="High + critical" tone={alerts.length ? 'text-rose-300' : 'text-slate-100'} />
        <Stat icon={<Gavel size={18} />} label="Awaiting approval" value={String(pending.length)} sub="Human decision required" tone={pending.length ? 'text-amber-300' : 'text-slate-100'} />
        <Stat icon={<HeartPulse size={18} />} label="System health" value={health.label} sub={health.sub} tone={health.tone} />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-5">
          <SectionTitle
            title="Activity, last 24 hours"
            subtitle={`${recent.length} interactions recorded${realCount === 0 ? ' · all simulated' : ` · ${realCount} real, ${recent.length - realCount} simulated`}`}
            icon={<Activity size={18} />}
            action={
              <Button size="sm" onClick={onSimulate} loading={simulating} disabled={verified.length === 0}>
                <Zap size={14} /> Run simulated attack
              </Button>
            }
          />
          <div className="flex items-end gap-1 h-36">
            {buckets.map((b, i) => (
              <div key={i} className="group relative flex-1 h-full flex flex-col justify-end">
                <div
                  className="w-full rounded-t bg-cyan-400/30 group-hover:bg-cyan-300/60 transition-all duration-500"
                  style={{ height: `${(b.total / maxBucket) * 100}%`, minHeight: b.total ? 4 : 2 }}
                >
                  {b.serious > 0 && <div className="w-full rounded-t bg-rose-400/80" style={{ height: `${(b.serious / b.total) * 100}%` }} />}
                </div>
                <span className="pointer-events-none absolute -top-7 left-1/2 -translate-x-1/2 whitespace-nowrap rounded bg-veil-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-200 opacity-0 group-hover:opacity-100 transition">
                  {b.total} events
                </span>
              </div>
            ))}
          </div>
          <div className="mt-2 flex justify-between text-[10px] text-slate-500 font-mono-tight">
            <span>24h ago</span><span>12h ago</span><span>now</span>
          </div>
          {verified.length === 0 && (
            <p className="mt-3 text-xs text-slate-500">Simulated attacks can only run against decoys that passed a health check.</p>
          )}
        </Card>

        <Card className="p-5">
          <SectionTitle title="Threat severity" subtitle="Last 24 hours" icon={<Radar size={18} />} />
          <div className="space-y-3">
            {sevTotals.map(({ s, c }) => (
              <div key={s}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className={SEVERITY_STYLES[s].text}>{SEVERITY_STYLES[s].label}</span>
                  <span className="text-slate-500 font-mono-tight">{c}</span>
                </div>
                <div className="h-1.5 rounded-full bg-veil-800 overflow-hidden">
                  <div className={`h-full ${SEVERITY_STYLES[s].dot} transition-all duration-700`} style={{ width: `${recent.length ? (c / recent.length) * 100 : 0}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-5">
          <SectionTitle
            title="Recent alerts"
            icon={<AlertTriangle size={18} />}
            action={<Button size="sm" variant="ghost" onClick={() => onGoTab('events')}>All events <ArrowRight size={14} /></Button>}
          />
          {alerts.length === 0 ? (
            <EmptyState icon={<AlertTriangle size={26} />} title="No high-severity alerts" hint="High and critical interactions with your decoys will appear here." />
          ) : (
            <ul className="divide-y divide-slate-800/60">
              {alerts.slice(0, 6).map((e) => (
                <li key={e.id}>
                  <button onClick={() => onOpenEvent(e)} className="w-full flex items-center gap-3 py-3 -mx-2 px-2 rounded-lg text-left hover:bg-veil-800/40 transition">
                    <SeverityPill severity={e.severity} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-slate-200 truncate">{e.summary}</div>
                      <div className="text-[11px] text-slate-500 font-mono-tight">{e.source_ip} · {prettyEventType(e.event_type)} · {timeAgo(e.occurred_at)}</div>
                    </div>
                    <SimulatedBadge simulated={e.is_simulated} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="p-5">
          <SectionTitle
            title="Decoy health"
            icon={<HeartPulse size={18} />}
            action={<Button size="sm" variant="ghost" onClick={() => onGoTab('honeypots')}>Manage <ArrowRight size={14} /></Button>}
          />
          {live.length === 0 ? (
            <p className="text-sm text-slate-500">No decoys deployed.</p>
          ) : (
            <ul className="space-y-3">
              {live.slice(0, 6).map((h) => (
                <li key={h.id} className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm text-slate-200 truncate">{h.name}</div>
                    <div className="text-[11px] text-slate-500">{DECOY_CATALOG[h.decoy_type].label}</div>
                  </div>
                  <HealthBadge hp={h} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function Stat({ icon, label, value, sub, tone = 'text-slate-100' }: { icon: React.ReactNode; label: string; value: string; sub: string; tone?: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        <span className="text-slate-500">{icon}</span>
      </div>
      <div className={`mt-2 text-2xl font-semibold tracking-tight ${tone}`}>{value}</div>
      <div className="text-xs text-slate-500 mt-1 truncate">{sub}</div>
    </Card>
  );
}
