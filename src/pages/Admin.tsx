import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Card, SectionTitle, Badge, Spinner, EmptyState } from '@/components/ui';
import { Gauge, Users, Activity, Cpu, AlertTriangle, FileText, TrendingUp } from 'lucide-react';
import { AdminSentinel } from '@/components/sentinel/AdminSentinel';

export function Admin() {
  const { isAdmin } = useAuth();
  const [tab, setTab] = useState<'overview' | 'users' | 'events' | 'ai' | 'sentinel'>('overview');
  const [users, setUsers] = useState<{ id: string; email: string; display_name: string | null; role: string; created_at: string }[]>([]);
  const [events, setEvents] = useState<{ id: string; kind: string; detail: Record<string, unknown>; created_at: string }[]>([]);
  const [aiUsage, setAiUsage] = useState<{ id: string; feature: string; model: string | null; input_tokens: number; output_tokens: number; cost_usd: number; created_at: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({ users: 0, assessments: 0, events: 0, aiCost: 0 });

  useEffect(() => {
    if (!isAdmin) return;
    setLoading(true);
    (async () => {
      const [u, e, a, ua, ev] = await Promise.all([
        supabase.from('profiles').select('id,email,display_name,role,created_at').order('created_at', { ascending: false }).limit(100),
        supabase.from('admin_events').select('*').order('created_at', { ascending: false }).limit(50),
        supabase.from('assessments').select('id', { count: 'exact', head: true }),
        supabase.from('ai_usage').select('*').order('created_at', { ascending: false }).limit(50),
        supabase.from('admin_events').select('id', { count: 'exact', head: true }),
      ]);
      setUsers(u.data ?? []);
      setEvents((e.data as { id: string; kind: string; detail: Record<string, unknown>; created_at: string }[]) ?? []);
      setAiUsage((ua.data as { id: string; feature: string; model: string | null; input_tokens: number; output_tokens: number; cost_usd: number; created_at: string }[]) ?? []);
      const cost = ((ua.data as { cost_usd: number }[]) ?? []).reduce((s, r) => s + Number(r.cost_usd ?? 0), 0);
      setStats({
        users: u.data?.length ?? 0,
        assessments: a.count ?? 0,
        events: ev.count ?? 0,
        aiCost: Number(cost.toFixed(4)),
      });
      setLoading(false);
    })();
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <div className="max-w-2xl">
        <Card className="p-8">
          <EmptyState
            icon={<AlertTriangle size={28} />}
            title="Administrator access required"
            hint="This area is protected by server-side authorization. Your account does not have the admin role."
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 fade-up">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100 flex items-center gap-2.5">
          <Gauge size={26} className="text-cyan-300" /> Administration
        </h1>
        <p className="text-slate-400 mt-1 text-sm">Service health, users, AI usage, and audit events.</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat icon={<Users size={18} />} label="Users" value={String(stats.users)} />
        <Stat icon={<FileText size={18} />} label="Assessments" value={String(stats.assessments)} />
        <Stat icon={<Activity size={18} />} label="Admin events" value={String(stats.events)} />
        <Stat icon={<TrendingUp size={18} />} label="AI cost (USD)" value={`$${stats.aiCost.toFixed(4)}`} />
      </div>

      <div className="flex gap-1 border-b border-slate-800/70">
        {(['overview', 'users', 'events', 'ai', 'sentinel'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2.5 text-sm font-medium capitalize transition border-b-2 -mb-px ${
              tab === t ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {t === 'ai' ? 'AI usage' : t}
          </button>
        ))}
      </div>

      {loading && <div className="p-4"><Spinner className="text-slate-500" /></div>}

      {!loading && tab === 'overview' && (
        <Card className="p-5">
          <SectionTitle title="Service health" icon={<Cpu size={18} />} />
          <div className="grid sm:grid-cols-2 gap-3">
            <Health label="Authentication" ok />
            <Health label="Database" ok />
            <Health label="Edge functions" ok />
            <Health label="AI assistant" ok={aiUsage.length > 0 ? true : null} note={aiUsage.length === 0 ? 'No usage recorded yet — verify OPENAI_API_KEY is set' : undefined} />
          </div>
        </Card>
      )}

      {!loading && tab === 'users' && (
        <Card className="p-5">
          <SectionTitle title="Users" icon={<Users size={18} />} />
          <div className="divide-y divide-slate-800/60">
            {users.map((u) => (
              <div key={u.id} className="flex items-center gap-3 py-3">
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-400/30 to-slate-700 flex items-center justify-center text-xs font-semibold text-cyan-200">
                  {(u.display_name || u.email).charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-slate-200 truncate">{u.display_name || '—'}</div>
                  <div className="text-[11px] text-slate-500 truncate">{u.email}</div>
                </div>
                <Badge tone={u.role === 'admin' ? 'cyan' : 'slate'}>{u.role}</Badge>
                <span className="text-[11px] text-slate-500 font-mono-tight hidden sm:block">{new Date(u.created_at).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {!loading && tab === 'events' && (
        <Card className="p-5">
          <SectionTitle title="Admin events" subtitle="Service-level events from edge functions" icon={<Activity size={18} />} />
          {events.length === 0 ? (
            <EmptyState icon={<Activity size={26} />} title="No events recorded" />
          ) : (
            <ul className="space-y-2">
              {events.map((e) => (
                <li key={e.id} className="flex items-start gap-2.5 text-sm rounded-lg border border-slate-800/70 bg-veil-950/40 px-3 py-2.5">
                  <span className={`mt-1.5 w-1.5 h-1.5 rounded-full ${e.kind.includes('error') || e.kind.includes('failed') ? 'bg-rose-400' : 'bg-cyan-400'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-slate-200 font-mono-tight text-xs">{e.kind}</div>
                    <pre className="text-[11px] text-slate-500 mt-1 font-mono-tight whitespace-pre-wrap break-all">{JSON.stringify(e.detail)}</pre>
                  </div>
                  <span className="text-[11px] text-slate-500 font-mono-tight">{new Date(e.created_at).toLocaleTimeString()}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {!loading && tab === 'sentinel' && <AdminSentinel />}

      {!loading && tab === 'ai' && (
        <Card className="p-5">
          <SectionTitle title="AI usage & cost controls" subtitle="Per-request accounting" icon={<Cpu size={18} />} />
          {aiUsage.length === 0 ? (
            <EmptyState icon={<Cpu size={26} />} title="No AI usage recorded" hint="Once the assistant is used, requests will appear here for monitoring." />
          ) : (
            <div className="divide-y divide-slate-800/60">
              {aiUsage.map((u) => (
                <div key={u.id} className="flex items-center gap-3 py-2.5 text-sm">
                  <span className="text-cyan-300 font-mono-tight text-xs">{u.feature}</span>
                  <span className="text-slate-500 text-xs">{u.model ?? '—'}</span>
                  <span className="text-slate-400 text-xs ml-auto">{u.input_tokens} in / {u.output_tokens} out</span>
                  <span className="text-slate-300 font-mono-tight text-xs w-20 text-right">${Number(u.cost_usd).toFixed(5)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        <span className="text-slate-500">{icon}</span>
      </div>
      <div className="mt-2 text-2xl font-semibold text-slate-100">{value}</div>
    </Card>
  );
}

function Health({ label, ok, note }: { label: string; ok: boolean | null; note?: string }) {
  return (
    <div className="rounded-lg border border-slate-800/70 bg-veil-950/40 p-3.5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-300">{label}</span>
        {ok === true ? <Badge tone="green">Healthy</Badge> : ok === false ? <Badge tone="rose">Down</Badge> : <Badge tone="amber">Unknown</Badge>}
      </div>
      {note && <p className="text-[11px] text-slate-500 mt-1.5">{note}</p>}
    </div>
  );
}
