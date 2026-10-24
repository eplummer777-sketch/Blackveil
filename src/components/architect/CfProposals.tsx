import { useState } from 'react';
import { AlertTriangle, Ban, Check, CheckCircle2, Cloud, Lightbulb, Loader2, RefreshCw, RotateCcw, Search, ShieldCheck, Zap } from 'lucide-react';
import { Badge, Button, Card } from '@/components/ui';
import { CF_RISK_TONE, CF_STATUS_META, CfProposal, formatValue } from '@/lib/cloudflare';

export function CfProposals({ proposals, busyId, onAnalyze, onApprove, onReject, onApply, onVerify, onRollback }: {
  proposals: CfProposal[];
  busyId: string | null;
  onAnalyze: () => void;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  onApply: (id: string) => void;
  onVerify: (id: string) => void;
  onRollback: (id: string) => void;
}) {
  const [openId, setOpenId] = useState<string | null>(null);
  const [ackIds, setAckIds] = useState<Set<string>>(new Set());
  const [confirmIds, setConfirmIds] = useState<Set<string>>(new Set());

  const toggle = (set: Set<string>, id: string) => {
    const next = new Set(set);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  };

  const active = proposals.filter((p) => ['proposed', 'approved', 'applied', 'failed'].includes(p.status));
  const done = proposals.filter((p) => ['verified', 'rejected', 'rolled_back'].includes(p.status));

  return (
    <div className="space-y-4">
      <Card className="p-4 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex items-center gap-2 flex-1">
          <Lightbulb size={16} className="text-amber-300" />
          <p className="text-sm text-slate-300">
            {active.length === 0
              ? 'No open recommendations. Run a new analysis to check for gaps.'
              : `${active.length} recommendation${active.length === 1 ? '' : 's'} need${active.length === 1 ? 's' : ''} your review.`}
          </p>
        </div>
        <Button size="sm" onClick={onAnalyze} loading={busyId === 'analyze'}>
          {!busyId && <Search size={14} />} Analyze for gaps
        </Button>
      </Card>

      {active.length === 0 && done.length === 0 && (
        <Card className="p-8 text-center">
          <Cloud size={32} className="mx-auto text-slate-600 mb-2" />
          <p className="text-sm text-slate-400">No recommendations yet. Run an analysis to let Architect identify security gaps in your Cloudflare zone.</p>
        </Card>
      )}

      {active.length > 0 && (
        <div className="space-y-2">
          {active.map((p) => {
            const meta = CF_STATUS_META[p.status];
            const isHigh = p.risk_level === 'high';
            const isOpen = openId === p.id;
            const acked = ackIds.has(p.id);
            const confirmed = confirmIds.has(p.id);
            return (
              <Card key={p.id} className={`overflow-hidden transition ${isOpen ? 'border-cyan-500/30' : ''}`}>
                <button onClick={() => setOpenId(isOpen ? null : p.id)} className="w-full p-4 text-left">
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <p className="text-sm font-medium text-slate-100">{p.setting_label}</p>
                        <Badge tone={meta.tone}>{meta.label}</Badge>
                        <Badge tone={CF_RISK_TONE[p.risk_level]}>{p.risk_level} risk</Badge>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">{p.category}</p>
                      <div className="mt-2 flex items-center gap-3 text-xs">
                        <span className="text-slate-500">From <span className="font-mono-tight text-amber-200">{formatValue(p.current_value)}</span></span>
                        <span className="text-slate-600">→</span>
                        <span className="text-slate-500">To <span className="font-mono-tight text-cyan-200">{formatValue(p.proposed_value)}</span></span>
                      </div>
                    </div>
                  </div>
                </button>

                {isOpen && (
                  <div className="border-t border-slate-800/80 px-4 py-4 space-y-4 fade-in">
                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">Why</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{p.explanation}</p>
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">Risks</p>
                      <ul className="space-y-1.5">
                        {p.risks.map((r, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-slate-400 leading-relaxed">
                            <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-300" /> {r}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {p.rollback_supported && (
                      <div>
                        <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">Rollback</p>
                        <div className="flex items-start gap-2 rounded-lg border border-slate-800 bg-veil-950/50 p-3">
                          <RotateCcw size={13} className="mt-0.5 shrink-0 text-cyan-300" />
                          <p className="text-sm text-slate-300 leading-relaxed">{p.rollback_instructions}</p>
                        </div>
                      </div>
                    )}

                    {p.status === 'failed' && p.apply_error && (
                      <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3">
                        <p className="text-sm text-rose-200">{p.apply_error}</p>
                      </div>
                    )}

                    {p.verification_result && (
                      <div className={`rounded-lg border p-3 ${p.status === 'verified' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}>
                        <div className="flex items-center gap-2">
                          {p.status === 'verified' ? <CheckCircle2 size={14} className="text-emerald-300" /> : <ShieldCheck size={14} className="text-amber-300" />}
                          <span className="text-sm text-slate-200">{p.status === 'verified' ? 'Verified live' : 'Verification result'}</span>
                        </div>
                        {p.verification_result.actual !== undefined && (
                          <p className="mt-1 text-xs text-slate-400">Actual value now: <span className="font-mono-tight text-slate-300">{formatValue(p.verification_result.actual)}</span></p>
                        )}
                        {p.verification_result.error && <p className="mt-1 text-xs text-rose-300">{p.verification_result.error}</p>}
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-800/60">
                      {p.status === 'proposed' && (
                        <>
                          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer mr-auto">
                            <input type="checkbox" checked={acked} onChange={() => setAckIds(toggle(ackIds, p.id))} className="accent-cyan-400" />
                            I've read the risks
                          </label>
                          <Button size="sm" disabled={!acked || (isHigh)} loading={busyId === p.id} onClick={() => onApprove(p.id)}>
                            <Check size={14} /> Approve
                          </Button>
                          <Button size="sm" variant="ghost" loading={busyId === `reject-${p.id}`} onClick={() => onReject(p.id)}>
                            <Ban size={14} /> Reject
                          </Button>
                        </>
                      )}
                      {p.status === 'approved' && (
                        <>
                          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer mr-auto">
                            <input type="checkbox" checked={confirmed} onChange={() => setConfirmIds(toggle(confirmIds, p.id))} className="accent-cyan-400" />
                            Apply this to my live zone
                          </label>
                          <Button size="sm" disabled={!confirmed} loading={busyId === p.id} onClick={() => onApply(p.id)}>
                            <Zap size={14} /> Apply now
                          </Button>
                          <Button size="sm" variant="ghost" loading={busyId === `reject-${p.id}`} onClick={() => onReject(p.id)}>
                            <Ban size={14} /> Reject
                          </Button>
                        </>
                      )}
                      {p.status === 'applied' && (
                        <>
                          <Button size="sm" loading={busyId === p.id} onClick={() => onVerify(p.id)}>
                            <ShieldCheck size={14} /> Verify
                          </Button>
                          <Button size="sm" variant="secondary" loading={busyId === `rb-${p.id}`} onClick={() => onRollback(p.id)}>
                            <RotateCcw size={14} /> Roll back
                          </Button>
                        </>
                      )}
                      {p.status === 'failed' && (
                        <Button size="sm" variant="secondary" loading={busyId === p.id} onClick={() => onApply(p.id)}>
                          <RefreshCw size={14} /> Retry apply
                        </Button>
                      )}
                    </div>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}

      {done.length > 0 && (
        <div>
          <p className="text-xs uppercase tracking-wider text-slate-500 mb-2">Completed</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {done.map((p) => {
              const meta = CF_STATUS_META[p.status];
              return (
                <div key={p.id} className="rounded-lg border border-slate-800 bg-veil-950/40 p-3">
                  <div className="flex items-center gap-1.5">
                    <Badge tone={meta.tone}>{meta.label}</Badge>
                    <span className="text-xs text-slate-500 truncate">{p.setting_label}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {busyId === 'global' && (
        <div className="flex items-center justify-center py-8 text-slate-500">
          <Loader2 size={20} className="animate-spin mr-2" /> Working...
        </div>
      )}
    </div>
  );
}
