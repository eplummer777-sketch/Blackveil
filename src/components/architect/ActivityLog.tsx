import { Bot, Cpu, ScrollText, User } from 'lucide-react';
import { Card, EmptyState } from '@/components/ui';
import { ArchitectChange, ArchitectEvent, EVENT_LABELS } from '@/lib/architect';

const ACTOR = {
  user: { icon: User, label: 'You', cls: 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10' },
  ai: { icon: Bot, label: 'Architect AI', cls: 'text-slate-200 border-slate-500/40 bg-slate-500/10' },
  system: { icon: Cpu, label: 'System', cls: 'text-slate-400 border-slate-700 bg-veil-800' },
};

function describe(e: ArchitectEvent): string | null {
  const d = e.detail ?? {};
  if (typeof d.summary === 'string') return d.summary;
  if (typeof d.note === 'string' && d.note) return `Note: ${d.note}`;
  if (Array.isArray(d.missing) && d.missing.length) return `Missing: ${d.missing.join(', ')}`;
  if (typeof d.error === 'string' && d.error) return d.error;
  if (typeof d.changes === 'number') return `${d.changes} proposed change(s) · ${d.source === 'ai' ? 'AI' : 'templates'}`;
  if (typeof d.count === 'number') return `${d.count} follow-up question(s) · ${d.source === 'ai' ? 'AI' : 'templates'}`;
  return null;
}

export function ActivityLog({ events, changes }: { events: ArchitectEvent[]; changes: ArchitectChange[] }) {
  const titles = new Map(changes.map((c) => [c.id, c.title]));
  if (events.length === 0) {
    return <Card><EmptyState icon={<ScrollText size={28} />} title="No activity yet" /></Card>;
  }
  return (
    <Card className="p-5">
      <p className="mb-4 text-xs text-slate-500">Every step is recorded and cannot be edited. Shows the latest 200 entries.</p>
      <ol className="relative space-y-4 before:absolute before:left-[15px] before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
        {events.map((e) => {
          const a = ACTOR[e.actor];
          const Icon = a.icon;
          const detail = describe(e);
          return (
            <li key={e.id} className="relative flex gap-3">
              <span className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${a.cls}`}>
                <Icon size={14} />
              </span>
              <div className="min-w-0 flex-1 pt-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="text-sm font-medium text-slate-200">{EVENT_LABELS[e.action] ?? e.action}</span>
                  <span className="text-xs text-slate-500">{a.label}</span>
                  <span className="ml-auto text-xs text-slate-600 font-mono-tight">{new Date(e.created_at).toLocaleString()}</span>
                </div>
                {e.change_id && titles.get(e.change_id) && (
                  <p className="text-xs text-cyan-300/80 truncate">{titles.get(e.change_id)}</p>
                )}
                {detail && <p className="mt-0.5 text-xs text-slate-400 leading-relaxed">{detail}</p>}
              </div>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}
