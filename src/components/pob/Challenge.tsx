import { useEffect, useRef, useState } from 'react';
import { Crosshair, Square, CheckCircle2, Loader2, RotateCcw, FileText, Globe } from 'lucide-react';
import { Button, Card, ErrorBanner, EmptyState } from '@/components/ui';
import { supabase } from '@/lib/supabase';
import { callPob, fetchChecks, PobCheck, PobScan, PobTarget, RESULT_LABEL, scoreTone } from '@/lib/pob';
import { RESULT_ICON } from '@/components/pob/resultIcons';

const PHASES = [
  { key: 'authorization', label: 'Validate authorization and scope' },
  { key: 'reconnaissance', label: 'Safe reconnaissance (DNS safety validation)' },
  { key: 'checks', label: 'Approved non-destructive checks' },
  { key: 'done', label: 'Results and next steps' },
];

interface Props {
  token: string; targets: PobTarget[]; limit: number; paused: boolean;
  onOpenScan: (id: string) => void; onGoTargets: () => void;
}

export function Challenge({ token, targets, limit, paused, onOpenScan, onGoTargets }: Props) {
  const verified = targets.filter((t) => t.status === 'verified');
  const [targetId, setTargetId] = useState('');
  const [running, setRunning] = useState(false);
  const [scan, setScan] = useState<PobScan | null>(null);
  const [checks, setChecks] = useState<PobCheck[]>([]);
  const [now, setNow] = useState(Date.now());
  const [error, setError] = useState('');
  const startRef = useRef(0);

  useEffect(() => {
    if (!targetId && verified[0]) setTargetId(verified[0].id);
  }, [verified, targetId]);

  useEffect(() => {
    if (!running) return;
    const tick = setInterval(() => setNow(Date.now()), 250);
    const poll = setInterval(async () => {
      const { data } = await supabase.from('pob_scans').select('*').eq('target_id', targetId)
        .gte('started_at', new Date(startRef.current - 5000).toISOString()).order('started_at', { ascending: false }).limit(1).maybeSingle();
      if (data) {
        setScan(data as PobScan);
        const { data: c } = await fetchChecks(data.id);
        if (c) setChecks(c as PobCheck[]);
      }
    }, 1200);
    return () => { clearInterval(tick); clearInterval(poll); };
  }, [running, targetId]);

  const start = async () => {
    setError(''); setScan(null); setChecks([]);
    startRef.current = Date.now();
    setRunning(true);
    const r = await callPob<{ scan_id: string }>(token, { action: 'run_quick', target_id: targetId });
    setRunning(false);
    if (!r.ok) { setError(r.error); return; }
    const [{ data: s }, { data: c }] = await Promise.all([
      supabase.from('pob_scans').select('*').eq('id', r.data.scan_id).maybeSingle(),
      fetchChecks(r.data.scan_id),
    ]);
    if (s) setScan(s as PobScan);
    if (c) setChecks(c as PobCheck[]);
  };

  const stop = async () => {
    if (scan) await callPob(token, { action: 'stop_scan', scan_id: scan.id });
  };

  if (verified.length === 0) {
    return (
      <EmptyState icon={<Globe size={28} />} title="Verify a target first"
        hint="The 60-second challenge only runs against domains you have proven you control."
        action={<Button onClick={onGoTargets}>Manage targets</Button>} />
    );
  }

  const elapsed = running ? (now - startRef.current) / 1000 : 0;
  const remaining = Math.max(0, limit - elapsed);
  const phaseIdx = scan ? PHASES.findIndex((p) => p.key === scan.phase) : running ? 0 : -1;
  const finished = !running && scan && scan.status !== 'running';
  const issues = checks.filter((c) => c.result === 'failed' || c.result === 'partial');

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      <Card className="relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute -top-24 -right-24 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="relative grid gap-8 lg:grid-cols-[1fr_auto] items-center">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300/80">60-Second Hacker Challenge</p>
            <h2 className="mt-2 text-2xl sm:text-3xl font-semibold text-slate-100 leading-tight">How long would your defenses hold?</h2>
            <p className="mt-2 max-w-xl text-sm text-slate-400 leading-relaxed">
              A real, time-boxed set of passive checks against your verified domain. Every result shown comes from an actual request; anything unfinished at the deadline is labelled incomplete.
            </p>
            <div className="mt-5 flex flex-wrap items-center gap-3">
              <select value={targetId} onChange={(e) => setTargetId(e.target.value)} disabled={running}
                className="rounded-lg border border-slate-700 bg-veil-950 px-3 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
                {verified.map((t) => <option key={t.id} value={t.id}>{t.hostname}</option>)}
              </select>
              {running ? (
                <Button variant="danger" onClick={stop}><Square size={14} />Stop</Button>
              ) : (
                <button onClick={start} disabled={paused || !targetId}
                  className="group inline-flex items-center gap-2 rounded-lg border border-cyan-400/60 bg-cyan-400/10 px-6 py-3 text-sm font-semibold tracking-[0.15em] text-cyan-200 shadow-glow-cyan transition hover:bg-cyan-400 hover:text-veil-950 disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan-400/50">
                  <Crosshair size={16} className="transition group-hover:rotate-90" />
                  {finished ? 'RETEST MY DEFENSES' : 'TEST MY DEFENSES'}
                </button>
              )}
            </div>
            {paused && <p className="mt-3 text-xs text-amber-300">Testing is paused platform-wide by an administrator.</p>}
          </div>
          <div className="relative mx-auto h-36 w-36">
            <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
              <circle cx="50" cy="50" r="44" className="fill-none stroke-slate-800" strokeWidth="6" />
              <circle cx="50" cy="50" r="44" className="fill-none stroke-cyan-400 transition-all duration-300" strokeWidth="6" strokeLinecap="round"
                strokeDasharray={276.5} strokeDashoffset={276.5 * (1 - (running ? remaining / limit : finished ? 0 : 1))} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              {finished && scan?.score !== null && scan?.score !== undefined ? (
                <><span className={`text-3xl font-semibold ${scoreTone(scan.score)}`}>{scan.score}</span><span className="text-[10px] uppercase tracking-widest text-slate-500">score</span></>
              ) : (
                <><span className="text-3xl font-semibold tabular-nums text-slate-100">{Math.ceil(running ? remaining : limit)}</span><span className="text-[10px] uppercase tracking-widest text-slate-500">seconds</span></>
              )}
            </div>
          </div>
        </div>
      </Card>

      {(running || scan) && (
        <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
          <Card className="p-5">
            <h3 className="text-xs uppercase tracking-widest text-slate-500">Phases</h3>
            <ol className="mt-4 space-y-3">
              {PHASES.filter((_, i) => i <= Math.max(phaseIdx, 0)).map((p, i) => {
                const active = i === phaseIdx && running;
                return (
                  <li key={p.key} className="flex items-center gap-3 text-sm fade-in">
                    {active ? <Loader2 size={16} className="animate-spin text-cyan-300" /> : <CheckCircle2 size={16} className="text-cyan-400" />}
                    <span className={active ? 'text-slate-100' : 'text-slate-400'}>{p.label}</span>
                  </li>
                );
              })}
            </ol>
          </Card>
          <Card className="p-5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-widest text-slate-500">Live security events</h3>
              <span className="text-xs text-slate-500">{checks.length} checks completed</span>
            </div>
            <ul className="mt-4 divide-y divide-slate-800/80" aria-live="polite">
              {checks.map((c) => (
                <li key={c.id} className="flex items-start gap-3 py-2.5 fade-in">
                  {RESULT_ICON[c.result]}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-2">
                      <span className="text-sm text-slate-200">{c.title}</span>
                      <span className="text-[11px] text-slate-500">{RESULT_LABEL[c.result]}</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{c.summary}</p>
                  </div>
                </li>
              ))}
              {running && <li className="flex items-center gap-3 py-2.5 text-xs text-slate-500"><Loader2 size={14} className="animate-spin" />Waiting for the next check result…</li>}
            </ul>
            {finished && scan && (
              <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-slate-800 pt-4">
                <p className="flex-1 text-sm text-slate-300">
                  {scan.status === 'failed' ? scan.error : `${issues.length} issue(s) found. ${scan.status === 'partial' ? 'Some checks did not finish.' : ''} ${scan.status === 'stopped' ? 'Stopped by you.' : ''}`}
                </p>
                <Button variant="secondary" onClick={start}><RotateCcw size={14} />Retry</Button>
                <Button onClick={() => onOpenScan(scan.id)}><FileText size={14} />Open full report</Button>
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
