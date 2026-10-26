import { useMemo, useState } from 'react';
import { Drawer, Button, Badge, ErrorBanner } from '@/components/ui';
import { changeInProgress, MAX_REPAIRS, WbChange, WbChangeFile, WbCheck } from '@/lib/builder';
import { lineDiff } from '@/lib/builderTools';
import { AlertTriangle, Check, ChevronDown, ChevronRight, CircleAlert, CircleCheck, ListChecks, Play, RotateCcw, Wand2, X } from 'lucide-react';

function FileDiff({ before, after }: { before: string | null; after: string | null }) {
  const lines = useMemo(() => lineDiff(before, after), [before, after]);
  return (
    <pre className="text-[12px] leading-5 font-mono overflow-x-auto scrollbar-thin bg-veil-950/80 rounded-lg border border-slate-800 py-2 max-h-[420px]">
      {lines.map((l, i) => (
        <div key={i} className={l.kind === 'add' ? 'bg-emerald-500/10 text-emerald-200' : l.kind === 'del' ? 'bg-rose-500/10 text-rose-200' : 'text-slate-400'}>
          <span className="inline-block w-6 text-center select-none opacity-60">{l.kind === 'add' ? '+' : l.kind === 'del' ? '-' : ' '}</span>{l.text}
        </div>
      ))}
    </pre>
  );
}

function label(f: WbChangeFile) {
  if (f.renamed_from) return { text: 'renamed', tone: 'amber' as const };
  if (f.renamed_to) return { text: 'moved', tone: 'amber' as const };
  return { text: f.action, tone: f.action === 'delete' ? 'rose' as const : f.action === 'create' ? 'green' as const : 'cyan' as const };
}

function lineStats(f: WbChangeFile) {
  const d = lineDiff(f.before, f.after);
  return { add: d.filter((l) => l.kind === 'add').length, del: d.filter((l) => l.kind === 'del').length };
}

export function CheckList({ checks, title }: { checks: WbCheck[]; title: string }) {
  if (!checks.length) return null;
  const failing = checks.filter((c) => !c.ok && !c.warn).length;
  return (
    <section>
      <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2">{title} ({checks.length - failing}/{checks.length} passed)</h3>
      <ul className="space-y-1.5">
        {checks.map((c) => (
          <li key={c.name} className="flex gap-2 text-sm">
            {c.ok ? <CircleCheck size={15} className="text-emerald-400 mt-0.5 shrink-0" /> : c.warn ? <CircleAlert size={15} className="text-amber-400 mt-0.5 shrink-0" /> : <CircleAlert size={15} className="text-rose-400 mt-0.5 shrink-0" />}
            <span><span className="text-slate-200">{c.name}</span> <span className="text-slate-500 break-words">{c.detail}</span></span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ChangeReview({ change, progress, onClose, onApply, onReject, onContinue, onUndo, onFix }: {
  change: WbChange;
  progress: string | null;
  onClose: () => void;
  onApply: (force: boolean, confirmRisks: boolean) => Promise<{ error: string | null; checks?: WbCheck[] }>;
  onReject: () => Promise<string | null>;
  onContinue: () => Promise<string | null>;
  onUndo: (force: boolean) => Promise<string | null>;
  onFix: (checks: WbCheck[]) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [riskOk, setRiskOk] = useState(false);
  const [open, setOpen] = useState<Set<string>>(() => new Set(change.files.length <= 3 ? change.files.map((f) => f.path) : []));
  const [result, setResult] = useState<WbCheck[] | null>(null);
  const a = change.analysis ?? {};
  const requirements = a.requirements_state ?? [];
  const unresolved = a.unresolved ?? [];
  const verification = a.verification;
  const risks = a.risks ?? [];
  const pending = change.status === 'pending';
  const working = changeInProgress(change);
  const ready = pending && !working;
  const totalSteps = a.batches?.length ?? 0;

  async function run(kind: string, fn: () => Promise<string | null>) {
    setBusy(kind);
    setError(null);
    const err = await fn();
    setBusy(null);
    if (err) { setError(err); setConflict(/changed since|edited after/.test(err)); }
  }

  const apply = (force: boolean) => run('apply', async () => {
    const r = await onApply(force, riskOk);
    if (r.checks) setResult(r.checks);
    return r.error;
  });

  const toggle = (p: string) => setOpen((s) => { const n = new Set(s); if (n.has(p)) n.delete(p); else n.add(p); return n; });
  const failing = (result ?? []).filter((c) => !c.ok && !c.warn);
  const tone = change.status === 'applied' ? 'green' : change.status === 'pending' ? 'amber' : 'slate';

  return (
    <Drawer wide title={result ? 'Change applied' : 'Review project-wide change'} onClose={onClose}
      subtitle={<div className="flex items-center gap-2"><Badge tone={result ? 'green' : tone}>{result ? 'applied' : working ? 'in progress' : change.status}</Badge><span className="text-xs text-slate-400">{change.files.length} file(s)</span></div>}>
      <div className="space-y-6">
        <p className="text-sm text-slate-300 leading-relaxed">{a.understanding || change.summary}</p>
        {error && <ErrorBanner message={error} />}

        {result && (
          <div className="space-y-4 rounded-xl border border-slate-800 p-4 bg-veil-950/40">
            <CheckList title="Re-read and cross-file checks" checks={result} />
            <p className="text-xs text-slate-500">These are static checks of the saved files. Nothing was installed, built, run or tested because no isolated execution environment is connected.</p>
            <div className="flex flex-wrap gap-2">
              {failing.length > 0 && (a.repairs ?? 0) < MAX_REPAIRS && <Button size="sm" onClick={() => onFix(failing)}><Wand2 size={14} /> Ask the AI to fix {failing.length} problem(s) (attempt {(a.repairs ?? 0) + 1} of {MAX_REPAIRS})</Button>}
              {failing.length > 0 && (a.repairs ?? 0) >= MAX_REPAIRS && <p className="w-full text-xs text-amber-300">Automatic repairs used up for this change. Undo it from History or fix the listed lines yourself.</p>}
              <Button size="sm" variant="secondary" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}

        {requirements.length > 0 && (
          <section>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5"><ListChecks size={13} /> Requirements ({requirements.length})</h3>
            <ol className="space-y-1 text-sm text-slate-300">
              {requirements.map((r) => (
                <li key={r.id} className="flex flex-wrap gap-2">
                  <span className="text-slate-600 tabular-nums shrink-0">{r.id}</span>
                  <span className="break-words">{r.text}</span>
                  <span className={`ml-auto shrink-0 rounded-full border px-1.5 text-[10px] ${r.status === 'completed' ? 'border-emerald-500/40 text-emerald-300' : r.status === 'failed' ? 'border-rose-500/40 text-rose-300' : r.status === 'unresolved' ? 'border-amber-500/40 text-amber-300' : r.status === 'in_progress' ? 'border-cyan-500/40 text-cyan-300' : 'border-slate-700 text-slate-400'}`}>{r.status}</span>
                  {r.note && <span className="w-full text-[11px] text-slate-500">{r.note}</span>}
                </li>
              ))}
            </ol>
          </section>
        )}

        {!!a.plan?.length && (
          <section>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5"><ListChecks size={13} /> Plan</h3>
            <ol className="list-decimal list-inside space-y-1 text-sm text-slate-300">{a.plan.map((s, i) => <li key={i}>{s}</li>)}</ol>
          </section>
        )}

        {unresolved.length > 0 && (
          <section className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4">
            <h3 className="text-sm font-medium text-amber-100 flex items-center gap-2 mb-2"><AlertTriangle size={15} /> Not covered by this plan</h3>
            <p className="text-xs text-amber-100/70 mb-2">The plan did not claim to satisfy these. Nothing here says they are done.</p>
            <ul className="list-disc list-inside space-y-1 text-sm text-amber-100/90">{unresolved.map((r) => <li key={r}>{r}</li>)}</ul>
          </section>
        )}

        {working && (
          <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4 flex flex-wrap items-center gap-3">
            <span className="text-sm text-cyan-100">
              {progress ?? `The AI has written ${a.next ?? 0} of ${totalSteps} step(s). The rest has not been generated yet.`}
            </span>
            {!progress && <Button size="sm" className="ml-auto" onClick={() => run('continue', onContinue)} loading={busy === 'continue'}><Play size={14} /> {a.awaiting_retry ? `Retry step ${(a.next ?? 0) + 1}` : 'Continue writing'}</Button>}
          </div>
        )}

        {ready && risks.length > 0 && (
          <section className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4">
            <h3 className="text-sm font-medium text-amber-100 flex items-center gap-2 mb-2"><AlertTriangle size={15} /> Needs your attention</h3>
            <ul className="list-disc list-inside space-y-1 text-sm text-amber-100/90">{risks.map((r) => <li key={r}>{r}</li>)}</ul>
            <label className="mt-3 flex items-center gap-2 text-sm text-amber-50 cursor-pointer">
              <input type="checkbox" checked={riskOk} onChange={(e) => setRiskOk(e.target.checked)} className="accent-amber-400" /> I understand these effects and want to apply them
            </label>
          </section>
        )}

        {ready && !result && a.checks && <CheckList title="Checks on the proposed result" checks={a.checks.map((c) => (!c.ok && a.baseline_failed?.includes(c.name) ? { ...c, detail: `${c.detail} (already failing before)` } : c))} />}

        {verification && (
          <section className="rounded-xl border border-slate-800 p-4 space-y-3">
            <h3 className="text-xs uppercase tracking-wider text-slate-500">Verification</h3>
            {verification.performed.length > 0 && (
              <div>
                <p className="text-xs text-emerald-300 mb-1">Checks actually performed</p>
                <ul className="list-disc list-inside space-y-0.5 text-sm text-slate-300">{verification.performed.map((v) => <li key={v}>{v}</li>)}</ul>
              </div>
            )}
            {verification.failed.length > 0 && (
              <div>
                <p className="text-xs text-rose-300 mb-1">Verification problems</p>
                <ul className="list-disc list-inside space-y-0.5 text-sm text-rose-200">{verification.failed.map((v) => <li key={v}>{v}</li>)}</ul>
              </div>
            )}
            {verification.notPerformed.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Not checked here</p>
                <ul className="list-disc list-inside space-y-0.5 text-sm text-slate-400">{verification.notPerformed.map((v) => <li key={v}>{v}</li>)}</ul>
              </div>
            )}
          </section>
        )}

        {!!a.notes?.length && (
          <section>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2">Notes</h3>
            <ul className="list-disc list-inside space-y-1 text-sm text-slate-400">{a.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          </section>
        )}
        {!!a.context_omitted?.length && <p className="text-xs text-slate-500">Too large to show the AI in full: {a.context_omitted.join(', ')}</p>}

        {change.files.length > 0 && (
          <section>
            <div className="flex items-center mb-2">
              <h3 className="text-xs uppercase tracking-wider text-slate-500">Files changed</h3>
              <button className="ml-auto text-xs text-cyan-300 hover:text-cyan-200" onClick={() => setOpen(open.size ? new Set() : new Set(change.files.map((f) => f.path)))}>{open.size ? 'Collapse all' : 'Expand all'}</button>
            </div>
            <div className="rounded-xl border border-slate-800 divide-y divide-slate-800">
              {change.files.map((f) => {
                const l = label(f);
                const s = lineStats(f);
                return (
                  <div key={f.path}>
                    <button onClick={() => toggle(f.path)} className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-veil-800/40 transition">
                      {open.has(f.path) ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
                      <span className="font-mono text-sm text-slate-100 truncate">{f.path}</span>
                      {f.renamed_from && <span className="text-xs text-slate-500 truncate">from {f.renamed_from}</span>}
                      {f.renamed_to && <span className="text-xs text-slate-500 truncate">to {f.renamed_to}</span>}
                      <span className="ml-auto flex items-center gap-2 shrink-0">
                        <span className="text-xs text-emerald-300">+{s.add}</span><span className="text-xs text-rose-300">-{s.del}</span>
                        <Badge tone={l.tone}>{l.text}</Badge>
                      </span>
                    </button>
                    {open.has(f.path) && <div className="px-3 pb-3"><FileDiff before={f.before} after={f.after} /></div>}
                  </div>
                );
              })}
            </div>
          </section>
        )}
      </div>

      {!result && (ready || change.status === 'applied') && (
        <div className="sticky bottom-0 -mx-6 -mb-5 mt-6 px-6 py-4 bg-veil-900 border-t border-slate-800 flex flex-wrap justify-end gap-2">
          {ready ? (
            <>
              <p className="mr-auto text-xs text-slate-500 self-center">A checkpoint is saved before applying, so you can undo.</p>
              <Button variant="secondary" onClick={() => run('reject', onReject)} loading={busy === 'reject'} disabled={!!busy}><X size={16} /> Reject</Button>
              {conflict
                ? <Button variant="danger" onClick={() => apply(true)} loading={busy === 'apply'} disabled={!!busy || (risks.length > 0 && !riskOk)}>Apply anyway</Button>
                : <Button onClick={() => apply(false)} loading={busy === 'apply'} disabled={!!busy || !change.files.length || (risks.length > 0 && !riskOk)}><Check size={16} /> Apply {change.files.length} file(s)</Button>}
            </>
          ) : (
            <>
              <p className="mr-auto text-xs text-slate-500 self-center">Undo puts every file in this change back the way it was.</p>
              <Button variant={conflict ? 'danger' : 'secondary'} onClick={() => run('undo', () => onUndo(conflict))} loading={busy === 'undo'} disabled={!!busy}>
                <RotateCcw size={15} /> {conflict ? 'Undo anyway' : 'Undo this change'}
              </Button>
            </>
          )}
        </div>
      )}
    </Drawer>
  );
}
