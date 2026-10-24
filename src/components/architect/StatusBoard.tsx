import { CheckCircle2, ChevronRight, FlaskConical, Hand, ShieldCheck, Sparkles } from 'lucide-react';
import { Badge, Card } from '@/components/ui';
import { ARTIFACT_LABELS, ArchitectChange, ChangeStatus, RISK_TONE, STATUS_META } from '@/lib/architect';

const COLUMNS: { id: string; title: string; caption: string; icon: typeof Sparkles; statuses: ChangeStatus[] }[] = [
  { id: 'proposed', title: 'Proposed', caption: 'Not tested yet', icon: Sparkles, statuses: ['proposed', 'test_failed'] },
  { id: 'tested', title: 'Tested', caption: 'Passed sandbox, awaiting you', icon: FlaskConical, statuses: ['tested', 'approved'] },
  { id: 'deployed', title: 'Applied by you', caption: 'Self-reported, not yet confirmed', icon: Hand, statuses: ['deployed'] },
  { id: 'verified', title: 'Verified', caption: 'Confirmed by a live check', icon: ShieldCheck, statuses: ['verified'] },
];

export function StatusBoard({ changes, onOpen }: { changes: ArchitectChange[]; onOpen: (id: string) => void }) {
  const closed = changes.filter((c) => c.status === 'rejected' || c.status === 'rolled_back');

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {COLUMNS.map((col) => {
          const items = changes.filter((c) => col.statuses.includes(c.status));
          const Icon = col.icon;
          return (
            <div key={col.id} className="rounded-xl border border-slate-800/80 bg-veil-950/40 p-3 flex flex-col min-h-[180px]">
              <div className="flex items-center gap-2 px-1 pb-3 border-b border-slate-800/80">
                <Icon size={15} className={col.id === 'verified' ? 'text-emerald-300' : 'text-cyan-300'} />
                <span className="text-sm font-semibold text-slate-200">{col.title}</span>
                <span className="ml-auto rounded-md bg-veil-800 px-1.5 py-0.5 text-xs text-slate-400 font-mono-tight">{items.length}</span>
              </div>
              <p className="px-1 pt-2 text-[11px] uppercase tracking-wider text-slate-600">{col.caption}</p>
              <div className="mt-2 space-y-2 flex-1">
                {items.map((c) => <ChangeCard key={c.id} change={c} onOpen={onOpen} />)}
                {items.length === 0 && <p className="px-1 py-6 text-center text-xs text-slate-600">Nothing here</p>}
              </div>
            </div>
          );
        })}
      </div>

      {closed.length > 0 && (
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 mb-3">Rejected or rolled back</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {closed.map((c) => <ChangeCard key={c.id} change={c} onOpen={onOpen} />)}
          </div>
        </Card>
      )}
    </div>
  );
}

function ChangeCard({ change, onOpen }: { change: ArchitectChange; onOpen: (id: string) => void }) {
  const meta = STATUS_META[change.status];
  return (
    <button
      onClick={() => onOpen(change.id)}
      className="group w-full rounded-lg border border-slate-800 bg-veil-900/80 p-3 text-left hover:border-cyan-500/40 hover:-translate-y-0.5 hover:shadow-glow-cyan transition"
    >
      <div className="flex items-start gap-2">
        <p className="flex-1 text-sm font-medium text-slate-100 leading-snug">{change.title}</p>
        <ChevronRight size={14} className="mt-0.5 shrink-0 text-slate-600 group-hover:text-cyan-300 transition" />
      </div>
      <p className="mt-1 text-xs text-slate-500">{ARTIFACT_LABELS[change.artifact_type]} · {change.target_system}</p>
      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
        <Badge tone={meta.tone}>
          {change.status === 'verified' && <CheckCircle2 size={11} />}
          {meta.label}
        </Badge>
        <Badge tone={RISK_TONE[change.risk_level]}>{change.risk_level} risk</Badge>
      </div>
    </button>
  );
}
