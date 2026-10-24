import { useState } from 'react';
import { Sparkles, Wrench, ShieldCheck, Copy, Check, AlertTriangle, RotateCcw } from 'lucide-react';
import { Badge, Button, Drawer, ErrorBanner, SeverityPill } from '@/components/ui';
import { AI_SECTIONS, callPob, isIssue, PobCheck, RESULT_LABEL, RETEST_LABEL } from '@/lib/pob';
import { RESULT_ICON } from '@/components/pob/resultIcons';

function Snippet({ label, code }: { label: string; code: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="rounded-lg border border-slate-800 bg-black/50">
      <div className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5 text-[11px] text-slate-400">
        {label}
        <button onClick={() => { navigator.clipboard.writeText(code); setDone(true); setTimeout(() => setDone(false), 1500); }} className="hover:text-cyan-300" aria-label="Copy snippet">
          {done ? <Check size={12} /> : <Copy size={12} />}
        </button>
      </div>
      <pre className="overflow-x-auto px-3 py-2 text-xs text-cyan-100 scrollbar-thin"><code>{code}</code></pre>
    </div>
  );
}

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <section className="mt-6">
    <h4 className="text-xs uppercase tracking-widest text-slate-500">{title}</h4>
    <div className="mt-2 text-sm text-slate-300 leading-relaxed">{children}</div>
  </section>
);

const RETEST_TONE = { untested: 'slate', fixed_verified: 'green', still_vulnerable: 'rose', partially_fixed: 'amber', inconclusive: 'amber', retest_failed: 'rose' } as const;

export function FindingDrawer({ token, check, onClose, onUpdated }: { token: string; check: PobCheck; onClose: () => void; onUpdated: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [showFix, setShowFix] = useState(check.remediation_status !== 'open');
  const [agree, setAgree] = useState(false);
  const fix = check.evidence.remediation;
  const { remediation: _r, ...evidence } = check.evidence;
  void _r;

  const act = async (key: string, body: Record<string, unknown>) => {
    setBusy(key); setError('');
    const r = await callPob(token, body);
    setBusy(null);
    if (!r.ok) setError(r.error);
    onUpdated();
  };

  return (
    <Drawer wide title={check.title} onClose={onClose}
      subtitle={<div className="flex flex-wrap items-center gap-2">{RESULT_ICON[check.result]}<span className="text-xs text-slate-300">{RESULT_LABEL[check.result]}</span>{isIssue(check) && <SeverityPill severity={check.severity} />}<Badge>{check.validation}</Badge><Badge>confidence: {check.confidence}</Badge></div>}>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      <Section title="Observed result">{check.summary}</Section>
      <Section title="Tool and exact operation">
        <p className="text-slate-200">{check.tool} v{check.tool_version}</p>
        <p className="mt-1 font-mono text-xs text-slate-400 break-all">{check.operation}</p>
        <p className="mt-1 text-xs text-slate-500">Asset: <span className="font-mono">{check.affected_asset}</span></p>
      </Section>
      <Section title="Sanitized evidence">
        <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black/50 p-3 text-xs text-slate-300 scrollbar-thin">{JSON.stringify(evidence, null, 2)}</pre>
      </Section>

      <div className="mt-8 rounded-xl border border-cyan-500/20 bg-cyan-500/[0.03] p-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold tracking-wide text-cyan-200"><Sparkles size={16} />BLACKVEIL PROOF-OF-BREACH AI</h3>
          {check.ai_status !== 'ready' && (
            <Button size="sm" onClick={() => act('ai', { action: 'analyze', check_id: check.id })} loading={busy === 'ai' || check.ai_status === 'pending'}>
              {check.ai_status === 'failed' ? <><RotateCcw size={14} />Retry analysis</> : 'Explain this result'}
            </Button>
          )}
        </div>
        {check.ai_status === 'failed' && (
          <p className="mt-3 flex items-start gap-2 text-xs text-amber-200"><AlertTriangle size={14} className="mt-0.5 shrink-0" />The AI analyst is unavailable. Your findings are preserved, and the built-in repair guidance below still applies.</p>
        )}
        {check.ai_status === 'ready' && check.ai_analysis && (
          <>
            <p className="mt-2 text-[11px] text-slate-500">Based only on finding {check.id.slice(0, 8)} and its recorded evidence. Generated {new Date(check.ai_analysis.generated_at).toLocaleString()}.</p>
            {AI_SECTIONS.map(([k, label], i) => (
              <Section key={k} title={`${i + 1}. ${label}`}><p className="whitespace-pre-wrap">{check.ai_analysis![k]}</p></Section>
            ))}
            <Section title="12. Final verification">
              <Badge tone={RETEST_TONE[check.retest_status]}>{RETEST_LABEL[check.retest_status]}</Badge>
            </Section>
          </>
        )}
        {check.ai_status === 'none' && <p className="mt-2 text-xs text-slate-400">Get a plain-language explanation grounded in this exact evidence.</p>}
      </div>

      {isIssue(check) && fix && (
        <div className="mt-8">
          {!showFix ? (
            <Button full onClick={() => setShowFix(true)}><Wrench size={16} />HELP ME FIX THIS</Button>
          ) : (
            <div className="rounded-xl border border-slate-800 p-5">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100"><Wrench size={16} className="text-cyan-300" />Proposed fix</h3>
              <p className="mt-2 text-sm text-slate-300 leading-relaxed">{fix.why}</p>
              <ol className="mt-3 list-decimal space-y-1 pl-5 text-sm text-slate-300">{fix.steps.map((s) => <li key={s}>{s}</li>)}</ol>
              <div className="mt-4 grid gap-3">{fix.snippets.map((s) => <Snippet key={s.label} {...s} />)}</div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 text-xs">
                <div className="rounded-lg bg-amber-500/5 border border-amber-500/20 p-3"><p className="font-medium text-amber-200">Possible side effects</p><p className="mt-1 text-slate-300">{fix.side_effects}</p></div>
                <div className="rounded-lg bg-veil-800/60 border border-slate-800 p-3"><p className="font-medium text-slate-200">Backup and rollback</p><p className="mt-1 text-slate-300">Save a copy of the current config first. {fix.rollback}</p></div>
              </div>
              <p className="mt-4 text-xs text-slate-500">Blackveil does not change your server directly. Apply these steps yourself, or use the Assessment Engine for supported Cloudflare settings.</p>

              {check.remediation_status === 'open' && (
                <div className="mt-4 space-y-3">
                  <label className="flex items-start gap-2 text-sm text-slate-300">
                    <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} className="mt-1 accent-cyan-400" />
                    I reviewed the change, side effects and rollback plan, and approve applying it.
                  </label>
                  <Button disabled={!agree} loading={busy === 'approve'} onClick={() => act('approve', { action: 'remediation', step: 'approve', check_id: check.id })}>Approve fix plan</Button>
                </div>
              )}
              {check.remediation_status === 'fix_approved' && (
                <Button className="mt-4" loading={busy === 'applied'} onClick={() => act('applied', { action: 'remediation', step: 'applied', check_id: check.id })}>I've applied this change</Button>
              )}
              {check.remediation_status === 'fix_applied_by_user' && (
                <div className="mt-4">
                  <Button full loading={busy === 'retest'} onClick={() => act('retest', { action: 'retest', check_id: check.id })}><ShieldCheck size={16} />VERIFY THE FIX</Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {check.retest_evidence && (
        <Section title="Retest comparison">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-slate-800 p-3"><p className="text-xs text-slate-500">Original</p><p className="mt-1 text-slate-200">{RESULT_LABEL[check.result]}</p><p className="mt-1 text-xs text-slate-400">{check.summary}</p></div>
            <div className="rounded-lg border border-slate-800 p-3"><p className="text-xs text-slate-500">Retest · {new Date(check.retest_evidence.at).toLocaleString()}</p><p className="mt-1"><Badge tone={RETEST_TONE[check.retest_status]}>{RETEST_LABEL[check.retest_status]}</Badge></p><p className="mt-1 text-xs text-slate-400">{check.retest_evidence.summary}</p></div>
          </div>
          <p className="mt-2 text-xs text-slate-500">Only this specific check was re-run. Other findings and untested areas are unaffected.</p>
        </Section>
      )}
    </Drawer>
  );
}
