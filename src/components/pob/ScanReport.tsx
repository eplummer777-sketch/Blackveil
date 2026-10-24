import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Download, Trash2, Info, ChevronRight } from 'lucide-react';
import { Badge, Button, Card, ErrorBanner, SeverityPill, Spinner } from '@/components/ui';
import { supabase } from '@/lib/supabase';
import { callPob, fetchChecks, isIssue, PobCheck, PobScan, PobTarget, RESULT_LABEL, RETEST_LABEL, SCORE_METHOD, scoreTone } from '@/lib/pob';
import { RESULT_ICON } from '@/components/pob/resultIcons';
import { FindingDrawer } from '@/components/pob/FindingDrawer';
import { printReport } from '@/components/pob/printReport';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function ScanReport({ token, scanId, target, onBack, onDeleted }: { token: string; scanId: string; target?: PobTarget; onBack: () => void; onDeleted: () => void }) {
  const [scan, setScan] = useState<PobScan | null>(null);
  const [checks, setChecks] = useState<PobCheck[]>([]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [showMethod, setShowMethod] = useState(false);

  const load = useCallback(async () => {
    const [{ data: s, error: e1 }, { data: c, error: e2 }] = await Promise.all([
      supabase.from('pob_scans').select('*').eq('id', scanId).maybeSingle(),
      fetchChecks(scanId),
    ]);
    if (e1 || e2 || !s) { setError('Could not load this report.'); return; }
    setScan(s as PobScan);
    setChecks((c ?? []) as PobCheck[]);
  }, [scanId]);

  useEffect(() => { load(); }, [load]);

  if (!scan) return error ? <ErrorBanner message={error} /> : <div className="flex justify-center py-16"><Spinner /></div>;

  const issues = checks.filter(isIssue).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const rest = checks.filter((c) => !isIssue(c));
  const open = checks.find((c) => c.id === openId);
  const c = scan.counts;
  const stats: [string, number | undefined, string][] = [
    ['Passed', c.passed, 'text-emerald-300'], ['Failed', c.failed, 'text-rose-300'], ['Partial', c.partial, 'text-amber-300'],
    ['Validated', c.validated, 'text-orange-300'], ['Detected / suspected', c.suspected, 'text-amber-200'],
    ['Incomplete', c.incomplete, 'text-slate-300'], ['Not performed', c.not_performed, 'text-slate-400'],
  ];

  const exportPdf = async () => {
    if (printReport(scan, target, checks)) await callPob(token, { action: 'log_export', scan_id: scan.id });
    else setError('Allow pop-ups to download the report.');
  };

  const remove = async () => {
    if (!confirm('Delete this scan and its findings? The audit log keeps a record that it existed.')) return;
    const { error: e } = await supabase.from('pob_scans').delete().eq('id', scan.id);
    if (e) setError('Could not delete this scan.'); else onDeleted();
  };

  return (
    <div className="space-y-6 fade-up">
      <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"><ArrowLeft size={14} />Back</button>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      <Card className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <p className="font-mono text-lg text-slate-100">{scan.hostname}</p>
            <p className="mt-1 text-xs text-slate-500">{new Date(scan.started_at).toLocaleString()} · {scan.kind} assessment · <span className="capitalize">{scan.status}</span></p>
            <div className="mt-3 flex gap-2">
              <Button size="sm" onClick={exportPdf}><Download size={14} />Download PDF</Button>
              {scan.status !== 'running' && <Button size="sm" variant="ghost" onClick={remove}><Trash2 size={14} />Delete</Button>}
            </div>
          </div>
          <div className="text-right">
            <p className={`text-5xl font-semibold ${scoreTone(scan.score)}`}>{scan.score ?? '–'}<span className="text-lg text-slate-500">/100</span></p>
            <button onClick={() => setShowMethod((v) => !v)} className="mt-1 inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200"><Info size={12} />How is this calculated?</button>
          </div>
        </div>
        {showMethod && (
          <ul className="mt-4 space-y-1 rounded-lg border border-slate-800 bg-black/30 p-4 text-xs text-slate-400 fade-in">
            {SCORE_METHOD.map((s) => <li key={s}>{s}</li>)}
            <li className="text-slate-300">The score reflects only the checks completed and evidence collected — not proof the site is fully secure.</li>
          </ul>
        )}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          {stats.map(([label, n, tone]) => (
            <div key={label} className="rounded-lg border border-slate-800 bg-veil-950/60 p-3">
              <p className={`text-xl font-semibold ${tone}`}>{n ?? 0}</p>
              <p className="text-[11px] text-slate-500">{label}</p>
            </div>
          ))}
        </div>
      </Card>

      <div>
        <h3 className="mb-3 text-xs uppercase tracking-widest text-slate-500">Security findings</h3>
        {issues.length === 0 ? (
          <Card className="p-5 text-sm text-slate-400">No checks failed in this scan. Review incomplete checks below before drawing conclusions.</Card>
        ) : (
          <div className="space-y-2">
            {issues.map((f) => (
              <button key={f.id} onClick={() => setOpenId(f.id)} className="group w-full text-left rounded-xl border border-slate-800 bg-veil-900/60 p-4 transition hover:border-cyan-500/40 hover:bg-veil-900 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
                <div className="flex items-start gap-3">
                  {RESULT_ICON[f.result]}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-slate-100">{f.title}</span>
                      <SeverityPill severity={f.severity} />
                      <Badge>{f.validation}</Badge>
                      {f.retest_status !== 'untested' && <Badge tone={f.retest_status === 'fixed_verified' ? 'green' : 'amber'}>{RETEST_LABEL[f.retest_status]}</Badge>}
                    </div>
                    <p className="mt-1 text-xs text-slate-400 leading-relaxed">{f.summary}</p>
                  </div>
                  <ChevronRight size={16} className="text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-cyan-300" />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      <div>
        <h3 className="mb-3 text-xs uppercase tracking-widest text-slate-500">Other checks</h3>
        <Card className="divide-y divide-slate-800/80">
          {rest.map((r) => (
            <button key={r.id} onClick={() => setOpenId(r.id)} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-veil-800/40 transition">
              {RESULT_ICON[r.result]}
              <div className="min-w-0 flex-1">
                <span className="text-sm text-slate-200">{r.title}</span> <span className="text-[11px] text-slate-500">{RESULT_LABEL[r.result]}</span>
                <p className="text-xs text-slate-400">{r.summary}</p>
              </div>
            </button>
          ))}
        </Card>
      </div>

      {open && <FindingDrawer token={token} check={open} onClose={() => setOpenId(null)} onUpdated={load} />}
    </div>
  );
}
