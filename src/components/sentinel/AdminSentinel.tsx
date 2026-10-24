import { useEffect, useState } from 'react';
import { Radar } from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { Card, EmptyState, SectionTitle, Spinner } from '@/components/ui';
import { DECOY_CATALOG, Honeypot, timeAgo } from '@/lib/sentinel';
import { HealthBadge } from '@/components/sentinel/badges';

export function AdminSentinel() {
  const [honeypots, setHoneypots] = useState<Honeypot[]>([]);
  const [counts, setCounts] = useState({ events: 0, pending: 0, blocked: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const [h, e, p, b] = await Promise.all([
        supabase.from('honeypots').select('*').neq('status', 'retired').order('created_at', { ascending: false }).limit(100),
        supabase.from('honeypot_events').select('id', { count: 'exact', head: true }),
        supabase.from('policy_actions').select('id', { count: 'exact', head: true }).eq('status', 'pending_approval'),
        supabase.from('policy_actions').select('id', { count: 'exact', head: true }).eq('status', 'blocked_by_policy'),
      ]);
      setLoading(false);
      if (h.error || e.error || p.error || b.error) { setError('Could not load Sentinel operations data.'); return; }
      setHoneypots((h.data ?? []) as Honeypot[]);
      setCounts({ events: e.count ?? 0, pending: p.count ?? 0, blocked: b.count ?? 0 });
    })();
  }, []);

  if (loading) return <div className="p-4"><Spinner className="text-slate-500" /></div>;

  const verified = honeypots.filter((x) => x.status === 'active' && x.last_health_status === 'healthy' && x.verified_at).length;

  return (
    <Card className="p-5">
      <SectionTitle title="Sentinel operations" subtitle="All customer decoys across the platform" icon={<Radar size={18} />} />
      {error ? <p className="text-sm text-rose-300">{error}</p> : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
            {[
              ['Live decoys', honeypots.length],
              ['Verified healthy', verified],
              ['Events recorded', counts.events],
              ['Awaiting approval', counts.pending],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-800 bg-veil-950/40 p-3">
                <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
                <div className="mt-1 text-xl font-semibold text-slate-100 font-mono-tight">{value}</div>
              </div>
            ))}
          </div>
          {counts.blocked > 0 && <p className="mb-4 text-xs text-slate-400">{counts.blocked} proposed actions were blocked automatically by policy.</p>}
          {honeypots.length === 0 ? (
            <EmptyState icon={<Radar size={24} />} title="No live decoys" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <tr><th className="py-2 pr-4 font-medium">Name</th><th className="py-2 pr-4 font-medium">Type</th><th className="py-2 pr-4 font-medium">Health</th><th className="py-2 font-medium">Created</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {honeypots.map((x) => (
                    <tr key={x.id}>
                      <td className="py-2.5 pr-4 text-slate-200">{x.name}</td>
                      <td className="py-2.5 pr-4 text-slate-400">{DECOY_CATALOG[x.decoy_type].label}</td>
                      <td className="py-2.5 pr-4"><HealthBadge hp={x} /></td>
                      <td className="py-2.5 text-slate-500 text-xs">{timeAgo(x.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Card>
  );
}
