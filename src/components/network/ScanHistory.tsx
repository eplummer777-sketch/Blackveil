import { useMemo, useState } from 'react';
import { ArrowDownUp, GitCompare, Network, Search } from 'lucide-react';
import { Badge, Button, Card, EmptyState, Input } from '@/components/ui';
import { NET_STATUS_LABEL, NetScan, NetStatus, netTone, PROFILE_INFO } from '@/lib/network';

type Sort = 'newest' | 'oldest' | 'open' | 'target';
const STATUSES: (NetStatus | 'all')[] = ['all', 'completed', 'partial', 'running', 'cancelled', 'failed'];

export function ScanHistory({ scans, onOpen, onCompare }: { scans: NetScan[]; onOpen: (id: string) => void; onCompare: (a: NetScan, b: NetScan) => void }) {
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<NetStatus | 'all'>('all');
  const [sort, setSort] = useState<Sort>('newest');
  const [picked, setPicked] = useState<string[]>([]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const list = scans.filter((s) => (status === 'all' || s.status === status)
      && (!needle || s.target_input.includes(needle) || s.targets.some((t) => t.includes(needle)) || PROFILE_INFO[s.profile].label.toLowerCase().includes(needle)));
    const by: Record<Sort, (a: NetScan, b: NetScan) => number> = {
      newest: (a, b) => b.created_at.localeCompare(a.created_at),
      oldest: (a, b) => a.created_at.localeCompare(b.created_at),
      open: (a, b) => (b.summary.open ?? 0) - (a.summary.open ?? 0),
      target: (a, b) => a.target_input.localeCompare(b.target_input),
    };
    return [...list].sort(by[sort]);
  }, [scans, q, status, sort]);

  const toggle = (id: string) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p.slice(-1), id]));
  const pickedScans = picked.map((id) => scans.find((s) => s.id === id)).filter(Boolean) as NetScan[];
  const compare = () => {
    const [a, b] = [...pickedScans].sort((x, y) => x.created_at.localeCompare(y.created_at));
    onCompare(a, b);
  };

  if (!scans.length) return <EmptyState icon={<Network size={28} />} title="No network scans yet" hint="Start with Quick discovery on a verified hostname or approved range." />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search target, address or profile" className="pl-9" />
        </div>
        <select value={status} onChange={(e) => setStatus(e.target.value as NetStatus | 'all')} aria-label="Filter by status"
          className="rounded-lg border border-slate-800 bg-veil-900 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
          {STATUSES.map((s) => <option key={s} value={s}>{s === 'all' ? 'All statuses' : NET_STATUS_LABEL[s]}</option>)}
        </select>
        <label className="flex items-center gap-2 rounded-lg border border-slate-800 bg-veil-900 px-3 py-2 text-sm text-slate-300">
          <ArrowDownUp size={14} className="text-slate-500" />
          <select value={sort} onChange={(e) => setSort(e.target.value as Sort)} aria-label="Sort" className="bg-transparent focus:outline-none">
            <option value="newest">Newest first</option><option value="oldest">Oldest first</option>
            <option value="open">Most open ports</option><option value="target">Target A-Z</option>
          </select>
        </label>
        <Button size="sm" variant="secondary" disabled={pickedScans.length !== 2} onClick={compare}><GitCompare size={14} />Compare {pickedScans.length}/2</Button>
      </div>

      {rows.length === 0 ? <Card className="p-6 text-sm text-slate-400">No scans match these filters.</Card> : (
        <Card className="divide-y divide-slate-800/80">
          {rows.map((s) => {
            const sel = picked.includes(s.id);
            const done = s.status === 'completed' || s.status === 'partial';
            return (
              <div key={s.id} className={`flex items-center gap-4 px-5 py-4 transition ${sel ? 'bg-cyan-400/5' : 'hover:bg-veil-800/40'}`}>
                <input type="checkbox" checked={sel} disabled={!done} onChange={() => toggle(s.id)} aria-label="Select for comparison"
                  className="h-4 w-4 accent-cyan-400 disabled:opacity-30" title={done ? 'Select to compare' : 'Only finished scans can be compared'} />
                <button onClick={() => onOpen(s.id)} className="flex min-w-0 flex-1 items-center gap-4 text-left">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm text-slate-200">{s.target_input}</p>
                    <p className="text-xs text-slate-500">{PROFILE_INFO[s.profile].label} · {new Date(s.created_at).toLocaleString()}</p>
                  </div>
                  <span className="hidden text-xs text-slate-400 sm:block">{s.summary.hosts_total != null ? `${s.summary.hosts_up ?? 0} up · ${s.summary.open ?? 0} open` : ''}</span>
                  <Badge tone={netTone(s.status)}>{NET_STATUS_LABEL[s.status]}</Badge>
                </button>
              </div>
            );
          })}
        </Card>
      )}
    </div>
  );
}
