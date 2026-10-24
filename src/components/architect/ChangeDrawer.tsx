import { ReactNode, useEffect, useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, Copy, Download, FlaskConical, Globe, RotateCcw, XCircle } from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { Badge, Drawer, ErrorBanner, Spinner } from '@/components/ui';
import { ARTIFACT_LABELS, ArchitectChange, ArchitectTest, ChangeAction, RISK_TONE, STATUS_META } from '@/lib/architect';
import { ActionPayload, ChangeActions } from '@/components/architect/ChangeActions';

export function ChangeDrawer({ change, busy, onClose, onTest, onAction }: {
  change: ArchitectChange;
  busy: string | null;
  onClose: () => void;
  onTest: () => void;
  onAction: (action: ChangeAction, payload: ActionPayload) => void;
}) {
  const meta = STATUS_META[change.status];
  const [tests, setTests] = useState<ArchitectTest[] | null>(null);
  const [testsError, setTestsError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    supabase
      .from('architect_tests')
      .select('*')
      .eq('change_id', change.id)
      .order('created_at', { ascending: false })
      .limit(5)
      .then(({ data, error }) => {
        if (!active) return;
        if (error) setTestsError('Could not load test history.');
        else setTests((data ?? []) as ArchitectTest[]);
      });
    return () => { active = false; };
  }, [change.id, change.last_tested_at]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(change.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  const download = () => {
    const blob = new Blob([change.content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = change.filename.split('/').pop() || 'blackveil-change.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  return (
    <Drawer
      wide
      title={change.title}
      onClose={onClose}
      subtitle={
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone={meta.tone}>{meta.label}</Badge>
          <Badge tone={RISK_TONE[change.risk_level]}>{change.risk_level} risk</Badge>
          <Badge>{ARTIFACT_LABELS[change.artifact_type]}</Badge>
          <span className="text-xs text-slate-500">{meta.hint}</span>
        </div>
      }
    >
      <div className="space-y-6">
        <Section title="What it does">
          <p className="text-sm text-slate-300 leading-relaxed">{change.explanation}</p>
          <p className="mt-2 text-xs text-slate-500">Applies to: {change.target_system}</p>
        </Section>

        <Section
          title={change.filename}
          action={
            <div className="flex gap-1">
              <IconBtn onClick={copy} label="Copy">{copied ? <Check size={14} /> : <Copy size={14} />}</IconBtn>
              <IconBtn onClick={download} label="Download"><Download size={14} /></IconBtn>
            </div>
          }
        >
          <pre className="max-h-80 overflow-auto scrollbar-thin rounded-lg border border-slate-800 bg-black/60 p-4 text-xs leading-relaxed text-slate-300 font-mono-tight whitespace-pre">
            {change.content}
          </pre>
        </Section>

        <Section title="Risks">
          <ul className="space-y-2">
            {change.risks.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300 leading-relaxed">
                <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-300" /> {r}
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Rollback">
          {change.rollback_supported && change.rollback_instructions ? (
            <div className="flex items-start gap-2 rounded-lg border border-slate-800 bg-veil-950/50 p-3">
              <RotateCcw size={14} className="mt-0.5 shrink-0 text-cyan-300" />
              <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">{change.rollback_instructions}</p>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No automatic rollback steps for this change. Keep a backup of anything you modify.</p>
          )}
        </Section>

        <Section title="Sandbox tests">
          {testsError && <ErrorBanner message={testsError} />}
          {!tests && !testsError && <Spinner className="text-slate-500" />}
          {tests && tests.length === 0 && <p className="text-sm text-slate-500">Not tested yet.</p>}
          {tests && tests.length > 0 && (
            <div className="space-y-3">
              {tests.map((t, idx) => <TestResult key={t.id} test={t} latest={idx === 0} />)}
            </div>
          )}
        </Section>

        {change.verification_result && (
          <Section title="Live verification">
            <VerificationBox result={change.verification_result} verified={change.status === 'verified'} />
          </Section>
        )}

        <Section title="Actions">
          <ChangeActions key={change.id + change.status} change={change} busy={busy} onTest={onTest} onAction={onAction} />
        </Section>

        <Timeline change={change} />
      </div>
    </Drawer>
  );
}

function TestResult({ test, latest }: { test: ArchitectTest; latest: boolean }) {
  const [open, setOpen] = useState(latest);
  return (
    <div className={`rounded-lg border p-3 ${test.passed ? 'border-cyan-500/25 bg-cyan-500/5' : 'border-rose-500/30 bg-rose-500/5'}`}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 text-left">
        {test.passed ? <FlaskConical size={14} className="text-cyan-300" /> : <XCircle size={14} className="text-rose-300" />}
        <span className="text-sm font-medium text-slate-200">{test.passed ? 'Passed' : 'Failed'}</span>
        <span className="ml-auto text-xs text-slate-500">{new Date(test.created_at).toLocaleString()}</span>
      </button>
      <p className="mt-1 text-xs text-slate-400">{test.summary}</p>
      {open && (
        <ul className="mt-3 space-y-1.5">
          {test.checks.map((c) => (
            <li key={c.id} className="flex items-start gap-2 text-xs">
              <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${c.level === 'pass' ? 'bg-emerald-400' : c.level === 'warning' ? 'bg-amber-400' : 'bg-rose-400'}`} />
              <span className="text-slate-300">{c.label}</span>
              <span className="text-slate-500">{c.detail}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-[10px] text-slate-600 font-mono-tight">content hash {test.content_hash.slice(0, 16)}</p>
    </div>
  );
}

function VerificationBox({ result, verified }: { result: NonNullable<ArchitectChange['verification_result']>; verified: boolean }) {
  return (
    <div className={`rounded-lg border p-3 text-sm ${verified ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}>
      <div className="flex items-center gap-2">
        {verified ? <CheckCircle2 size={14} className="text-emerald-300" /> : <Globe size={14} className="text-amber-300" />}
        <span className="text-slate-200 truncate">{result.checked_url}</span>
        {result.http_status && <span className="ml-auto text-xs text-slate-500 font-mono-tight">HTTP {result.http_status}</span>}
      </div>
      {result.error && <p className="mt-2 text-xs text-amber-200">{result.error}</p>}
      {result.present.length > 0 && <p className="mt-2 text-xs text-slate-400">Found: {result.present.join(', ')}</p>}
      {result.missing.length > 0 && <p className="mt-1 text-xs text-amber-200">Missing: {result.missing.join(', ')}</p>}
      <p className="mt-1 text-[11px] text-slate-500">Checked {new Date(result.checked_at).toLocaleString()}</p>
    </div>
  );
}

function Timeline({ change }: { change: ArchitectChange }) {
  const rows: [string, string | null, string | null][] = [
    ['Proposed', change.created_at, null],
    ['Last sandbox test', change.last_tested_at, change.last_test_passed === null ? null : change.last_test_passed ? 'passed' : 'failed'],
    ['Approved', change.approved_at, change.approval_note],
    ['Rejected', change.rejected_at, null],
    ['Applied (reported by you)', change.deployed_at, change.deploy_note],
    ['Verified live', change.verified_at, null],
    ['Rolled back (reported by you)', change.rolled_back_at, change.rollback_note],
  ];
  return (
    <Section title="History">
      <dl className="space-y-1.5">
        {rows.filter(([, at]) => at).map(([label, at, note]) => (
          <div key={label} className="flex flex-wrap gap-x-3 text-xs">
            <dt className="text-slate-500 w-48">{label}</dt>
            <dd className="text-slate-300">{new Date(at as string).toLocaleString()}{note ? ` · ${note}` : ''}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Section({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 truncate font-mono-tight">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function IconBtn({ onClick, label, children }: { onClick: () => void; label: string; children: ReactNode }) {
  return (
    <button onClick={onClick} aria-label={label} title={label} className="rounded-md p-1.5 text-slate-400 hover:bg-veil-800 hover:text-cyan-200 transition">
      {children}
    </button>
  );
}
