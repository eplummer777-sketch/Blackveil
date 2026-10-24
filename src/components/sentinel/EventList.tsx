import { useMemo, useState } from 'react';
import { Bot, ListFilter, Search } from 'lucide-react';
import { Card, EmptyState, SeverityPill } from '@/components/ui';
import { Severity, SEVERITY_ORDER } from '@/lib/types';
import { Honeypot, HoneypotEvent, INVESTIGATION_LABELS, InvestigationStatus, prettyEventType, timeAgo } from '@/lib/sentinel';
import { SimulatedBadge } from '@/components/sentinel/badges';

interface Props {
  events: HoneypotEvent[];
  honeypots: Honeypot[];
  onOpen: (e: HoneypotEvent) => void;
}

const STATUS_TONE: Record<InvestigationStatus, string> = {
  new: 'text-cyan-300',
  investigating: 'text-amber-300',
  resolved: 'text-emerald-300',
  false_positive: 'text-slate-400',
};

export function EventList({ events, honeypots, onOpen }: Props) {
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [status, setStatus] = useState<InvestigationStatus | 'all'>('all');
  const [origin, setOrigin] = useState<'all' | 'simulated' | 'real'>('all');
  const [query, setQuery] = useState('');

  const names = useMemo(() => Object.fromEntries(honeypots.map((h) => [h.id, h.name])), [honeypots]);
  const filtered = events.filter((e) =>
    (severity === 'all' || e.severity === severity) &&
    (status === 'all' || e.investigation_status === status) &&
    (origin === 'all' || (origin === 'simulated') === e.is_simulated) &&
    (!query || (e.source_ip ?? '').includes(query.trim()) || e.summary.toLowerCase().includes(query.trim().toLowerCase()))
  );

  return (
    <Card className="p-5">
      <div className="flex flex-col lg:flex-row lg:items-center gap-3 mb-4">
        <div className="relative flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by source IP or description"
            className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 outline-none transition"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ListFilter size={15} className="text-slate-500" />
          <Select value={severity} onChange={(v) => setSeverity(v as Severity | 'all')} options={[['all', 'All severities'], ...SEVERITY_ORDER.map((s) => [s, s[0].toUpperCase() + s.slice(1)] as [string, string])]} />
          <Select value={status} onChange={(v) => setStatus(v as InvestigationStatus | 'all')} options={[['all', 'Any status'], ...Object.entries(INVESTIGATION_LABELS)]} />
          <Select value={origin} onChange={(v) => setOrigin(v as 'all' | 'simulated' | 'real')} options={[['all', 'Simulated + real'], ['simulated', 'Simulated only'], ['real', 'Real only']]} />
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={<ListFilter size={26} />} title={events.length ? 'No events match these filters' : 'No events recorded yet'} hint={events.length ? undefined : 'Run a simulated attack against a verified decoy to generate events.'} />
      ) : (
        <div className="overflow-x-auto scrollbar-thin -mx-5">
          <table className="w-full text-sm min-w-[760px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500 border-b border-slate-800/70">
                <th className="px-5 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Event</th>
                <th className="px-3 py-2 font-medium">Source</th>
                <th className="px-3 py-2 font-medium">Decoy</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-5 py-2 font-medium text-right">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.slice(0, 200).map((e) => (
                <tr key={e.id} onClick={() => onOpen(e)} className="cursor-pointer hover:bg-veil-800/40 transition">
                  <td className="px-5 py-3"><SeverityPill severity={e.severity} /></td>
                  <td className="px-3 py-3 max-w-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-200 truncate">{prettyEventType(e.event_type)}</span>
                      <SimulatedBadge simulated={e.is_simulated} />
                      {e.ai_analysis && <Bot size={13} className="text-cyan-300 shrink-0" aria-label="Analyzed" />}
                    </div>
                    <div className="text-xs text-slate-500 truncate">{e.summary}</div>
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-slate-300">{e.source_ip ?? 'unknown'}</td>
                  <td className="px-3 py-3 text-xs text-slate-400 truncate max-w-[10rem]">{names[e.honeypot_id] ?? '—'}</td>
                  <td className={`px-3 py-3 text-xs font-medium ${STATUS_TONE[e.investigation_status]}`}>{INVESTIGATION_LABELS[e.investigation_status]}</td>
                  <td className="px-5 py-3 text-right text-xs text-slate-500 font-mono-tight whitespace-nowrap">{timeAgo(e.occurred_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-slate-700/80 bg-veil-950/60 px-2.5 py-2 text-xs text-slate-200 focus:border-cyan-400/60 outline-none"
    >
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}
