import { useState } from 'react';
import { Bot, Check, Gavel, ShieldAlert, User, X } from 'lucide-react';
import { Badge, Button, Card, EmptyState, SectionTitle, ErrorBanner } from '@/components/ui';
import { ACTION_LABELS, ActionStatus, PolicyAction, callSentinel, timeAgo } from '@/lib/sentinel';

const STATUS_BADGE: Record<ActionStatus, { tone: 'cyan' | 'rose' | 'amber' | 'slate' | 'green'; label: string }> = {
  pending_approval: { tone: 'amber', label: 'Pending approval' },
  approved: { tone: 'cyan', label: 'Approved · manual follow-up' },
  rejected: { tone: 'slate', label: 'Rejected' },
  executed_simulated: { tone: 'green', label: 'Approved · simulated execution' },
  blocked_by_policy: { tone: 'rose', label: 'Blocked by policy' },
};

const RISK_TONE = { low: 'slate', medium: 'amber', high: 'rose' } as const;

export function Approvals({ actions, token, onChanged }: { actions: PolicyAction[]; token: string; onChanged: () => void }) {
  const pending = actions.filter((a) => a.status === 'pending_approval');
  const history = actions.filter((a) => a.status !== 'pending_approval');

  return (
    <div className="space-y-6">
      <Card className="p-5">
        <SectionTitle
          title="Approval queue"
          subtitle="Nothing happens until a person approves it. The AI analyst can only suggest."
          icon={<Gavel size={18} />}
        />
        {pending.length === 0 ? (
          <EmptyState icon={<Gavel size={26} />} title="Nothing waiting for approval" hint="Suggested or proposed actions from the event details will appear here." />
        ) : (
          <div className="space-y-3">
            {pending.map((a) => <PendingCard key={a.id} action={a} token={token} onChanged={onChanged} />)}
          </div>
        )}
      </Card>

      <Card className="p-5">
        <SectionTitle title="Decision history" subtitle="Every decision is also written to your activity log" icon={<ShieldAlert size={18} />} />
        {history.length === 0 ? (
          <p className="text-sm text-slate-500">No decisions yet.</p>
        ) : (
          <ul className="divide-y divide-slate-800/60">
            {history.map((a) => (
              <li key={a.id} className="py-3 flex flex-col sm:flex-row sm:items-center gap-2">
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200">{ACTION_LABELS[a.action_type]}{a.target && <span className="font-mono text-xs text-slate-400"> · {a.target}</span>}</div>
                  <div className="text-xs text-slate-500 truncate">
                    {a.status === 'blocked_by_policy' ? a.policy_reason : a.decision_note || a.rationale}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge tone={STATUS_BADGE[a.status].tone}>{STATUS_BADGE[a.status].label}</Badge>
                  <span className="text-[11px] text-slate-500 font-mono-tight">{timeAgo(a.decided_at ?? a.created_at)}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function PendingCard({ action, token, onChanged }: { action: PolicyAction; token: string; onChanged: () => void }) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const needsNote = action.risk_level === 'high';

  async function decide(decision: 'approve' | 'reject') {
    setBusy(decision);
    setError(null);
    const res = await callSentinel<{ execution_note: string }>(token, { action: 'decide_action', action_id: action.id, decision, note: note.trim() || null });
    setBusy(null);
    if (!res.ok) { setError(res.error); return; }
    setResult(res.data?.execution_note ?? 'Decision recorded.');
    setTimeout(onChanged, 1400);
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-veil-950/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-medium text-slate-100">{ACTION_LABELS[action.action_type]}{action.target && <span className="font-mono text-xs text-slate-400"> · {action.target}</span>}</div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1">{action.proposed_by === 'analyst_ai' ? <Bot size={12} /> : <User size={12} />}{action.proposed_by === 'analyst_ai' ? 'Suggested by AI analyst' : 'Proposed by you'}</span>
            <span>· {timeAgo(action.created_at)}</span>
          </div>
        </div>
        <div className="flex gap-1.5">
          <Badge tone={RISK_TONE[action.risk_level]}>{action.risk_level} risk</Badge>
          {action.affects_real_systems && <Badge tone="rose">Affects real systems</Badge>}
        </div>
      </div>
      <p className="mt-3 text-sm text-slate-300 leading-relaxed">{action.rationale}</p>
      {action.affects_real_systems && (
        <p className="mt-2 text-xs text-amber-200/90">This action could affect real users if it were executed. In simulation mode it will only be recorded, never carried out.</p>
      )}

      {result ? (
        <div className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200">{result}</div>
      ) : (
        <div className="mt-4 space-y-2.5">
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            maxLength={1000}
            placeholder={needsNote ? 'Justification (required for high-risk approvals)' : 'Decision note (optional)'}
            className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 outline-none"
          />
          {error && <ErrorBanner message={error} />}
          <div className="flex gap-2">
            <Button size="sm" onClick={() => decide('approve')} loading={busy === 'approve'} disabled={!!busy || (needsNote && note.trim().length < 10)}>
              <Check size={13} /> Approve
            </Button>
            <Button size="sm" variant="secondary" onClick={() => decide('reject')} loading={busy === 'reject'} disabled={!!busy}>
              <X size={13} /> Reject
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
