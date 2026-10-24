import { useEffect, useRef, useState } from 'react';
import { TerminalSquare, CornerDownLeft, Square, X, Loader2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { callBv, BvJob, JOB_LABEL, jobOutput } from '@/lib/bvos';
import { useAuth } from '@/lib/auth';

export interface TerminalLine {
  kind: 'input' | 'output' | 'error' | 'system';
  text: string;
  meta?: string;
}

const BANNER = [
  'BLACKVEIL OS — isolated Linux terminal',
  'Each command runs in a fresh Docker container: no network, read-only root, unprivileged user.',
  'Restricted command list only. Type "help" for the available commands.',
  'The terminal is offline until an execution worker is connected by an administrator.',
  '',
];

const HELP = [
  'Available commands (restricted shell):',
  '  pwd  ls  cat  head  tail  wc  grep  sort  uniq  find  du  stat  file  less  more',
  '  echo  printf  seq  date  uptime  sleep  hostname  whoami  id  uname  arch  nproc  lscpu',
  '  env  ps  top  free  df  true  false',
  '  python3  python  node  sh  bash  (for simple expressions and scripts)',
  'Shell chaining (; & | < >), pipes, redirection and command substitution are disabled.',
];

export function OsTerminal({
  sessionId, onSession,
}: {
  sessionId: string | null;
  onSession: (id: string) => void;
}) {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [lines, setLines] = useState<TerminalLine[]>(() => BANNER.map((t) => ({ kind: 'system' as const, text: t })));
  const [input, setInput] = useState('');
  const [running, setRunning] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [onlineWorkers, setOnlineWorkers] = useState<number | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const historyRef = useRef<string[]>([]);
  const historyIdxRef = useRef(-1);
  const cancelRef = useRef(false);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  useEffect(() => {
    if (!token) return;
    callBv<{ workersOnline?: number }>(token, { action: 'status' }).then((r) => {
      if (r.ok) setOnlineWorkers(typeof r.data?.workersOnline === 'number' ? r.data.workersOnline : 0);
    });
  }, [token]);

  useEffect(() => () => { if (pollRef.current) clearTimeout(pollRef.current); }, []);

  async function poll(jobId: string) {
    const res = await callBv<{ job: BvJob }>(token, { action: 'poll', job_id: jobId });
    if (!res.ok) {
      setLines((l) => [...l, { kind: 'error', text: res.error }]);
      setRunning(false);
      setActiveJobId(null);
      return;
    }
    const job = res.data?.job;
    const status = job?.status;
    if (status === 'completed' || status === 'failed' || status === 'cancelled') {
      setRunning(false);
      setActiveJobId(null);
      if (job) {
        const out = jobOutput(job);
        const kind: TerminalLine['kind'] = job.status === 'failed' ? 'error' : 'output';
        const meta = `[${JOB_LABEL[job.status]}${job.exit_code !== null ? ` · exit ${job.exit_code}` : ''}${job.duration_ms ? ` · ${job.duration_ms}ms` : ''}]`;
        const next: TerminalLine[] = [];
        if (out) next.push({ kind, text: out, meta });
        next.push({ kind: 'system', text: meta });
        setLines((l) => [...l, ...next]);
      }
      return;
    }
    if (status === 'running' || status === 'queued') {
      pollRef.current = setTimeout(() => poll(jobId), 800);
    }
  }

  async function runCommand(raw: string) {
    const cmd = raw.trim();
    if (!cmd || running) return;
    if (cmd === 'help') {
      setLines((l) => [...l, ...HELP.map((text) => ({ kind: 'system' as const, text }))]);
      return;
    }
    if (cmd === 'clear') {
      setLines([]);
      return;
    }
    setLines((l) => [...l, { kind: 'input', text: `blackveil@os:~$ ${cmd}` }]);
    historyRef.current = [cmd, ...historyRef.current].slice(0, 50);
    historyIdxRef.current = -1;
    setRunning(true);
    setActiveJobId(null);
    cancelRef.current = false;

    const start = await callBv<{ job: BvJob }>(token, { action: 'exec', command: cmd, session_id: sessionId });
    if (!start.ok) {
      setLines((l) => [...l, { kind: 'error', text: start.error }]);
      setRunning(false);
      return;
    }
    const job = start.data?.job;
    if (job?.session_id && onSession) onSession(job.session_id);
    setActiveJobId(job?.id ?? null);
    if (job?.status === 'completed' || job?.status === 'failed' || job?.status === 'cancelled') {
      setRunning(false);
      setActiveJobId(null);
      return;
    }
    pollRef.current = setTimeout(() => poll(job.id), 500);
  }

  async function cancel() {
    if (!activeJobId) return;
    cancelRef.current = true;
    await callBv(token, { action: 'cancel', job_id: activeJobId });
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      const v = input;
      setInput('');
      runCommand(v);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const h = historyRef.current;
      if (!h.length) return;
      historyIdxRef.current = Math.min(historyIdxRef.current + 1, h.length - 1);
      setInput(h[historyIdxRef.current] ?? '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      historyIdxRef.current = Math.max(historyIdxRef.current - 1, -1);
      setInput(historyIdxRef.current === -1 ? '' : historyRef.current[historyIdxRef.current] ?? '');
    }
  }

  const statusPill = onlineWorkers === null ? null : onlineWorkers === 0
    ? { text: 'Worker offline', cls: 'text-amber-200 bg-amber-500/10 border-amber-500/40', Icon: AlertTriangle }
    : { text: `${onlineWorkers} worker${onlineWorkers === 1 ? '' : 's'} online`, cls: 'text-emerald-200 bg-emerald-500/10 border-emerald-500/30', Icon: CheckCircle2 };

  return (
    <div className="flex h-full flex-col bg-[#06090e] font-mono text-[13px] leading-relaxed text-slate-200">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 bg-[#0a0e15] px-3 py-2">
        <div className="flex items-center gap-2 text-slate-400">
          <TerminalSquare size={14} className="text-cyan-300" />
          <span className="text-xs font-medium text-slate-200">BLACKVEIL OS Terminal</span>
          {statusPill && (
            <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] ${statusPill.cls}`}>
              <statusPill.Icon size={10} /> {statusPill.text}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          {running && (
            <button onClick={cancel} className="flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 hover:bg-rose-500/20 transition">
              <Square size={10} /> Stop
            </button>
          )}
          <span className="rounded-md border border-slate-800 px-2 py-1 text-[10px] text-slate-500">
            {running ? 'executing…' : 'ready'}
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-3 py-3 space-y-0.5">
        {lines.map((line, i) => (
          <div key={i} className="whitespace-pre-wrap break-words">
            {line.kind === 'input' && <span className="text-slate-100">{line.text}</span>}
            {line.kind === 'output' && (
              <span className="text-slate-300">
                {line.text}
                {line.meta && <span className="text-slate-500"> {line.meta}</span>}
              </span>
            )}
            {line.kind === 'error' && <span className="text-rose-300">{line.text}</span>}
            {line.kind === 'system' && <span className="text-cyan-200/70">{line.text}</span>}
          </div>
        ))}
        {running && (
          <div className="text-cyan-300/70"><Loader2 size={12} className="inline animate-spin" /> running…</div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="flex items-center gap-2 border-t border-slate-800 bg-[#0a0e15] px-3 py-2">
        <span className="shrink-0 text-cyan-300">blackveil@os:~$</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          disabled={running}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          placeholder={running ? 'command running…' : 'type a command (e.g. uname -a) and press Enter'}
          className="flex-1 bg-transparent text-slate-100 placeholder:text-slate-600 outline-none disabled:opacity-50"
        />
        <button
          onClick={() => { const v = input; setInput(''); runCommand(v); }}
          disabled={running || !input.trim()}
          className="rounded-md border border-slate-700 p-1.5 text-slate-400 hover:text-cyan-300 hover:border-cyan-400/40 transition disabled:opacity-40"
          aria-label="Run command"
        >
          <CornerDownLeft size={13} />
        </button>
        <span className="hidden sm:inline-flex h-2.5 w-2.5 rounded-full border border-slate-700" title="window control" />
      </div>
    </div>
  );
}
