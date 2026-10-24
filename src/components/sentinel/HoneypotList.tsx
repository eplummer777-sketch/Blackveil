import { useEffect, useState } from 'react';
import { Activity, CheckCircle2, Cloud, ExternalLink, HeartPulse, Play, Plus, Power, ServerCog, XCircle, Zap } from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { Button, Card, EmptyState, Spinner, Drawer, ErrorBanner } from '@/components/ui';
import { DECOY_CATALOG, HealthCheck, Honeypot, HoneypotEvent, timeAgo } from '@/lib/sentinel';
import { HealthBadge, SimulatedBadge } from '@/components/sentinel/badges';

interface Props {
  honeypots: Honeypot[];
  events: HoneypotEvent[];
  busyId: string | null;
  onDeployClick: () => void;
  onHealthCheck: (id: string) => void;
  onSimulate: (id: string) => void;
  onRetire: (id: string) => void;
  onStop: (id: string) => void;
  onStart: (id: string) => void;
  token: string;
}

export function HoneypotList({ honeypots, events, busyId, onDeployClick, onHealthCheck, onSimulate, onRetire, onStop, onStart }: Props) {
  const [showRetired, setShowRetired] = useState(false);
  const [detail, setDetail] = useState<Honeypot | null>(null);
  const [confirmRetire, setConfirmRetire] = useState<string | null>(null);

  const visible = honeypots.filter((h) => showRetired || h.status !== 'retired');
  const retiredCount = honeypots.filter((h) => h.status === 'retired').length;

  if (honeypots.length === 0) {
    return (
      <Card>
        <EmptyState
          icon={<ServerCog size={30} />}
          title="No decoys yet"
          hint="Deploy a simulated or cloud decoy to start recording attacker activity. Simulator decoys are safe for testing; cloud decoys capture real interactions."
          action={<Button onClick={onDeployClick}><Plus size={15} /> Deploy decoy</Button>}
        />
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        {retiredCount > 0 ? (
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
            <input type="checkbox" checked={showRetired} onChange={(e) => setShowRetired(e.target.checked)} className="accent-cyan-400" />
            Show retired ({retiredCount})
          </label>
        ) : <span />}
        <Button size="sm" onClick={onDeployClick}><Plus size={14} /> Deploy decoy</Button>
      </div>

      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
        {visible.map((h) => {
          const count = events.filter((e) => e.honeypot_id === h.id).length;
          const verified = h.status === 'active' && h.last_health_status === 'healthy';
          const retired = h.status === 'retired';
          const stopped = h.status === 'stopped';
          const isCloud = h.provider === 'cloud';
          const busy = busyId === h.id;
          return (
            <Card key={h.id} className={`p-5 flex flex-col transition hover:border-slate-700 ${retired ? 'opacity-60' : ''} ${stopped ? 'opacity-70' : ''}`}>
              <div className="flex items-start justify-between gap-2">
                <button onClick={() => setDetail(h)} className="text-left min-w-0 group">
                  <div className="text-sm font-semibold text-slate-100 truncate group-hover:text-cyan-200 transition">{h.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{DECOY_CATALOG[h.decoy_type].label} · {DECOY_CATALOG[h.decoy_type].port}</div>
                </button>
                <div className="flex items-center gap-1.5">
                  {isCloud && <span className="inline-flex items-center gap-1 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-300"><Cloud size={11} /> Cloud</span>}
                  <SimulatedBadge simulated={h.is_simulated} />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <HealthBadge hp={h} />
                <span className="text-[11px] text-slate-500 font-mono-tight">
                  {h.last_health_check_at ? `checked ${timeAgo(h.last_health_check_at)}` : 'never checked'}
                </span>
              </div>

              <p className="mt-3 text-xs text-slate-400 leading-relaxed">
                {retired
                  ? 'Retired. Cloud resource has been deleted.'
                  : stopped
                    ? 'Stopped. The Worker is disabled but not deleted. Use Start to re-enable it.'
                    : verified
                      ? isCloud
                        ? 'Live on Cloudflare. Capturing real interactions automatically.'
                        : 'Simulation running. Not protecting any real system.'
                      : 'Not verified. Sentinel will not treat this decoy as active until a health check passes.'}
              </p>

              {isCloud && h.cloud_resource_url && !retired && (
                <a href={h.cloud_resource_url} target="_blank" rel="noopener noreferrer" className="mt-2 inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                  <ExternalLink size={11} /> {h.cloud_resource_url.replace(/^https?:\/\//, '')}
                </a>
              )}

              <div className="mt-3 flex items-center gap-1.5 text-xs text-slate-500">
                <Activity size={13} /> {count} recorded interaction{count === 1 ? '' : 's'}
                {isCloud && h.cost_estimate_usd ? <span className="ml-auto text-slate-600">~${Number(h.cost_estimate_usd).toFixed(2)}/mo</span> : null}
              </div>

              {!retired && (
                <div className="mt-4 pt-4 border-t border-slate-800/70 flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" onClick={() => onHealthCheck(h.id)} loading={busy} disabled={!!busyId}>
                    <HeartPulse size={13} /> Health check
                  </Button>
                  {!isCloud && (
                    <Button size="sm" variant="secondary" onClick={() => onSimulate(h.id)} disabled={!verified || !!busyId}>
                      <Zap size={13} /> Simulate
                    </Button>
                  )}
                  {isCloud && stopped && (
                    <Button size="sm" variant="secondary" onClick={() => onStart(h.id)} loading={busy} disabled={!!busyId}>
                      <Play size={13} /> Start
                    </Button>
                  )}
                  {isCloud && !stopped && (
                    <Button size="sm" variant="secondary" onClick={() => onStop(h.id)} loading={busy} disabled={!!busyId}>
                      <Power size={13} /> Stop
                    </Button>
                  )}
                  {confirmRetire === h.id ? (
                    <div className="flex gap-1.5 ml-auto">
                      <Button size="sm" variant="danger" onClick={() => { setConfirmRetire(null); onRetire(h.id); }}>Confirm</Button>
                      <Button size="sm" variant="ghost" onClick={() => setConfirmRetire(null)}>Cancel</Button>
                    </div>
                  ) : (
                    <Button size="sm" variant="ghost" className="ml-auto text-slate-400 hover:text-rose-300" onClick={() => setConfirmRetire(h.id)} disabled={!!busyId}>
                      <Power size={13} /> Retire
                    </Button>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>

      {detail && <HealthDrawer hp={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function HealthDrawer({ hp, onClose }: { hp: Honeypot; onClose: () => void }) {
  const [checks, setChecks] = useState<HealthCheck[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const { data, error: err } = await supabase
        .from('honeypot_health_checks').select('*').eq('honeypot_id', hp.id)
        .order('checked_at', { ascending: false }).limit(10);
      if (err) setError('Could not load health history.');
      else setChecks((data as HealthCheck[]) ?? []);
    })();
  }, [hp.id]);

  const isCloud = hp.provider === 'cloud';

  return (
    <Drawer title={hp.name} subtitle={<div className="flex gap-2"><HealthBadge hp={hp} /><SimulatedBadge simulated={hp.is_simulated} /></div>} onClose={onClose}>
      <dl className="grid grid-cols-2 gap-3 text-sm mb-6">
        <Field label="Type" value={DECOY_CATALOG[hp.decoy_type].label} />
        <Field label="Provider" value={isCloud ? 'Cloudflare Workers' : 'Safe simulator'} />
        <Field label="Exposure" value={hp.exposure === 'internal_only' ? 'Internal only' : 'Public'} />
        <Field label="Reference" value={hp.provider_ref ?? 'none'} mono />
        <Field label="Deployed" value={new Date(hp.created_at).toLocaleString()} />
        <Field label="Last verified" value={hp.verified_at ? new Date(hp.verified_at).toLocaleString() : 'Never'} />
        {isCloud && hp.cloud_resource_url && <Field label="Worker URL" value={hp.cloud_resource_url} mono />}
        {isCloud && <Field label="Est. cost" value={`$${Number(hp.cost_estimate_usd ?? 0).toFixed(2)}/mo`} />}
      </dl>

      <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-3">Health check history</h3>
      {error && <ErrorBanner message={error} />}
      {!checks && !error && <div className="flex items-center gap-2 text-sm text-slate-400"><Spinner /> Loading…</div>}
      {checks?.length === 0 && <p className="text-sm text-slate-500">No health checks recorded.</p>}
      <div className="space-y-3">
        {checks?.map((c) => (
          <div key={c.id} className={`rounded-xl border p-4 ${c.status === 'healthy' ? 'border-emerald-500/25 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'}`}>
            <div className="flex items-center justify-between text-xs mb-2.5">
              <span className={c.status === 'healthy' ? 'text-emerald-300 font-medium' : 'text-rose-300 font-medium'}>{c.status === 'healthy' ? 'Passed' : 'Failed'}</span>
              <span className="text-slate-500 font-mono-tight">{new Date(c.checked_at).toLocaleString()}</span>
            </div>
            <ul className="space-y-1.5">
              {c.checks.map((item) => (
                <li key={item.id} className="flex items-start gap-2 text-xs">
                  {item.passed ? <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-px" /> : <XCircle size={14} className="text-rose-400 shrink-0 mt-px" />}
                  <span className="text-slate-300">{item.label}<span className="block text-slate-500">{item.detail}</span></span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Drawer>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-veil-950/40 px-3 py-2">
      <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={`text-slate-200 mt-0.5 truncate ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </div>
  );
}
