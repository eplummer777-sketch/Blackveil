import { Fragment, ReactNode, useState } from 'react';
import { changeInProgress, WbChange, WbChangeFile, WbMessage, type WbRating } from '@/lib/builder';
import {
  ArrowRightLeft, Brain, Check, ChevronRight, Circle, FileMinus, FilePen, FilePlus, FileSearch, Loader2, Sparkles, Undo2, X, FileDiff, Play,
  ThumbsUp, ThumbsDown, CircleDashed, BadgeCheck,
} from 'lucide-react';

const RATINGS: { value: WbRating; label: string; Icon: typeof ThumbsUp; on: string }[] = [
  { value: 'helpful', label: 'Helpful', Icon: ThumbsUp, on: 'text-emerald-300 bg-emerald-500/10' },
  { value: 'incorrect', label: 'Incorrect', Icon: ThumbsDown, on: 'text-rose-300 bg-rose-500/10' },
  { value: 'incomplete', label: 'Incomplete', Icon: CircleDashed, on: 'text-amber-300 bg-amber-500/10' },
  { value: 'verified', label: 'I tested it and it works', Icon: BadgeCheck, on: 'text-cyan-300 bg-cyan-500/10' },
];

function Feedback({ rating, onRate }: { rating?: WbRating; onRate: (r: WbRating) => Promise<void> }) {
  const [saving, setSaving] = useState<WbRating | null>(null);
  return (
    <div className="flex items-center gap-0.5" aria-label="Rate this answer">
      {RATINGS.map(({ value, label, Icon, on }) => (
        <button key={value} title={label} aria-label={label} aria-pressed={rating === value} disabled={!!saving}
          onClick={async () => { setSaving(value); try { await onRate(value); } finally { setSaving(null); } }}
          className={`h-6 w-6 grid place-content-center rounded-md transition ${rating === value ? on : 'text-slate-600 hover:text-slate-300 hover:bg-slate-800/70'}`}>
          {saving === value ? <Loader2 size={11} className="animate-spin" /> : <Icon size={11} />}
        </button>
      ))}
    </div>
  );
}

const WORKFLOW_LABEL: Record<string, string> = { ask: 'Ask', explain: 'Explain', plan: 'Plan', code: 'Code', debug: 'Debug', review: 'Review' };

function inline(text: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) return <code key={i} className="rounded bg-slate-800 px-1 py-0.5 font-mono text-[12px] text-cyan-200">{part.slice(1, -1)}</code>;
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) return <strong key={i} className="font-semibold text-slate-100">{part.slice(2, -2)}</strong>;
    return <Fragment key={i}>{part}</Fragment>;
  });
}

export function RichText({ text }: { text: unknown }) {
  const blocks = (typeof text === 'string' ? text : '').trim().split(/\n{2,}/).filter(Boolean);
  if (!blocks.length) return <p className="text-[13px] italic text-slate-500">No reply text.</p>;
  return (
    <div className="space-y-2.5 text-[13.5px] leading-relaxed text-slate-300">
      {blocks.map((b, i) => {
        const lines = b.split('\n');
        if (lines.every((l) => /^\s*(?:[-*]|\d+\.)\s+/.test(l))) {
          const ordered = /^\s*\d+\./.test(lines[0]);
          const items = lines.map((l, j) => <li key={j}>{inline(l.replace(/^\s*(?:[-*]|\d+\.)\s+/, ''))}</li>);
          return ordered ? <ol key={i} className="list-decimal pl-5 space-y-1 marker:text-slate-500">{items}</ol>
            : <ul key={i} className="list-disc pl-5 space-y-1 marker:text-slate-500">{items}</ul>;
        }
        const heading = lines[0].length < 60 && lines.length > 1 && /:$/.test(lines[0]);
        return (
          <div key={i} className="whitespace-pre-wrap break-words">
            {heading ? <><div className="font-semibold text-slate-100">{lines[0].slice(0, -1)}</div>{inline(lines.slice(1).join('\n'))}</> : inline(b)}
          </div>
        );
      })}
    </div>
  );
}

const ACTION: Record<string, { label: string; Icon: typeof FilePlus; tone: string }> = {
  create: { label: 'Create', Icon: FilePlus, tone: 'text-emerald-300' },
  update: { label: 'Update', Icon: FilePen, tone: 'text-cyan-300' },
  delete: { label: 'Delete', Icon: FileMinus, tone: 'text-rose-300' },
  rename: { label: 'Rename', Icon: ArrowRightLeft, tone: 'text-amber-300' },
};

function fileAction(f: WbChangeFile) {
  return f.renamed_from || f.renamed_to ? ACTION.rename : ACTION[f.action] ?? ACTION.update;
}

function Thinking({ change, writing }: { change: WbChange; writing: boolean }) {
  const a = change.analysis ?? {};
  const busy = changeInProgress(change);
  const [open, setOpen] = useState(busy);
  const batches = a.batches ?? [];
  const next = a.next ?? batches.length;
  const isOpen = open || busy;

  return (
    <div className="rounded-xl border border-slate-800 bg-veil-950/40 overflow-hidden">
      <button onClick={() => setOpen(!isOpen)} className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 transition">
        <Brain size={13} className={writing ? 'text-cyan-300 animate-pulse' : 'text-slate-500'} />
        <span className="font-medium">{writing ? 'Thinking and writing…' : a.awaiting_go ? 'Plan ready' : busy ? 'Paused mid-way' : `Thought through ${Math.max(batches.length, 1)} step${batches.length === 1 ? '' : 's'}`}</span>
        {a.workflow && <span className="rounded-full border border-slate-700 px-1.5 py-px text-[10px] text-slate-400">{WORKFLOW_LABEL[a.workflow] ?? a.workflow}</span>}
        <ChevronRight size={13} className={`ml-auto transition-transform ${isOpen ? 'rotate-90' : ''}`} />
      </button>
      <div className={`grid transition-all duration-300 ${isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
        <div className="overflow-hidden">
          <div className="px-3 pb-3 space-y-3 text-xs text-slate-400 border-t border-slate-800/80 pt-2.5">
            {a.understanding && <p className="leading-relaxed text-slate-300">{a.understanding}</p>}
            {!!a.inspected?.length && (
              <div>
                <div className="mb-1.5 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-slate-500"><FileSearch size={11} /> Read {a.inspected.length} file{a.inspected.length === 1 ? '' : 's'}</div>
                <div className="flex flex-wrap gap-1">
                  {a.inspected.slice(0, 14).map((p) => <span key={p} className="rounded-md bg-slate-800/70 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">{p}</span>)}
                  {a.inspected.length > 14 && <span className="px-1 text-[11px] text-slate-500">+{a.inspected.length - 14} more</span>}
                </div>
              </div>
            )}
            {!!a.plan?.length && (
              <div>
                <div className="mb-1.5 text-[11px] uppercase tracking-wider text-slate-500">Plan</div>
                <ol className="space-y-1">
                  {a.plan.map((s, i) => <li key={i} className="flex gap-2"><span className="text-slate-600 tabular-nums">{i + 1}.</span><span className="text-slate-300">{s}</span></li>)}
                </ol>
              </div>
            )}
            {batches.length > 0 && (
              <div className="space-y-1.5">
                {batches.map((files, i) => {
                  const done = i < next;
                  const current = writing && i === next;
                  return (
                    <div key={i} className="flex items-start gap-2">
                      {done ? <Check size={13} className="mt-0.5 text-emerald-400 shrink-0" />
                        : current ? <Loader2 size={13} className="mt-0.5 text-cyan-300 animate-spin shrink-0" />
                        : <Circle size={11} className="mt-1 text-slate-600 shrink-0" />}
                      <span className={done ? 'text-slate-300' : current ? 'text-cyan-100' : 'text-slate-500'}>
                        Step {i + 1} of {batches.length}: <span className="font-mono text-[11px]">{files.slice(0, 3).join(', ')}{files.length > 3 ? ` +${files.length - 3}` : ''}</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Actions({ change, writing, onReview, onContinue }: { change: WbChange; writing: boolean; onReview: () => void; onContinue: () => void }) {
  const busy = changeInProgress(change);
  if (!busy && !change.files.length) return null;
  const status = {
    applied: { text: 'Applied', Icon: Check, cls: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30' },
    reverted: { text: 'Undone', Icon: Undo2, cls: 'text-amber-300 bg-amber-500/10 border-amber-500/30' },
    rejected: { text: 'Rejected', Icon: X, cls: 'text-slate-400 bg-slate-500/10 border-slate-600/40' },
    pending: null,
  }[change.status];

  return (
    <div className="rounded-xl border border-slate-700/80 bg-veil-900/80 overflow-hidden shadow-lg shadow-black/20">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-800/30">
        <FileDiff size={13} className="text-cyan-300" />
        <span className="text-xs font-medium text-slate-200 truncate">{busy ? 'Writing changes' : `${change.files.length} file change${change.files.length === 1 ? '' : 's'}`}</span>
        {status && <span className={`ml-auto inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${status.cls}`}><status.Icon size={10} /> {status.text}</span>}
      </div>
      {change.files.length > 0 && (
        <ul className="max-h-56 overflow-y-auto scrollbar-thin py-1">
          {change.files.map((f) => {
            const a = fileAction(f);
            return (
              <li key={f.path + f.action} className="flex items-center gap-2 px-3 py-1 text-xs">
                <Check size={12} className="text-emerald-400 shrink-0" />
                <a.Icon size={12} className={`${a.tone} shrink-0`} />
                <span className="text-slate-400">{a.label}</span>
                <span className="font-mono text-slate-200 truncate">{f.renamed_from ? `${f.renamed_from} → ${f.path}` : f.path}</span>
              </li>
            );
          })}
        </ul>
      )}
      {change.status === 'pending' && (
        <div className="flex items-center gap-2 px-3 py-2 border-t border-slate-800">
          {busy ? (
            writing ? <span className="flex items-center gap-1.5 text-xs text-cyan-200"><Loader2 size={12} className="animate-spin" /> Writing step {(change.analysis?.next ?? 0) + 1} of {change.analysis?.batches?.length ?? 1}…</span>
              : <button onClick={onContinue} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3 py-1.5 text-xs font-medium text-veil-950 hover:bg-cyan-400 transition"><Play size={12} /> {change.analysis?.awaiting_go ? 'Write changes' : 'Continue writing'}</button>
          ) : (
            <>
              <span className="text-[11px] text-slate-500">Nothing is saved until you approve.</span>
              <button onClick={onReview} className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3 py-1.5 text-xs font-medium text-veil-950 hover:bg-cyan-400 transition">Review and apply</button>
            </>
          )}
        </div>
      )}
      {change.status !== 'pending' && (
        <button onClick={onReview} className="w-full px-3 py-1.5 border-t border-slate-800 text-left text-[11px] text-slate-400 hover:text-cyan-200 transition">View details</button>
      )}
    </div>
  );
}

export function AssistantAvatar({ busy = false }: { busy?: boolean }) {
  return (
    <div className={`h-7 w-7 shrink-0 rounded-lg bg-gradient-to-br from-cyan-400 to-emerald-400 grid place-content-center text-veil-950 ${busy ? 'animate-pulse' : ''}`}>
      <Sparkles size={14} />
    </div>
  );
}

export function ChatMessage({ message, change, writing, rating, onReview, onContinue, onRate }: {
  message: WbMessage;
  change?: WbChange;
  writing: boolean;
  rating?: WbRating;
  onReview: (c: WbChange) => void;
  onContinue: (c: WbChange) => void;
  onRate: (messageId: string, rating: WbRating) => Promise<void>;
}) {
  if (message.role === 'user') {
    return (
      <div className="flex justify-end fade-up">
        <div className="max-w-[92%] rounded-2xl rounded-tr-md bg-slate-800/80 border border-slate-700/60 px-3.5 py-2.5 text-[13.5px] leading-relaxed text-slate-100 whitespace-pre-wrap break-words">
          {message.content}
        </div>
      </div>
    );
  }
  if (message.role === 'system') {
    const failed = String(message.content ?? '').startsWith('AI request failed');
    return (
      <div className={`mx-auto max-w-[95%] rounded-lg border px-3 py-1.5 text-[11.5px] leading-relaxed text-center ${failed ? 'border-rose-500/30 bg-rose-500/5 text-rose-200' : 'border-emerald-500/20 bg-emerald-500/5 text-emerald-200/90'}`}>
        {message.content}
      </div>
    );
  }
  const busy = change ? changeInProgress(change) : false;
  const fromApp = message.model === 'blackveil-app';
  return (
    <div className="flex gap-2.5 fade-up">
      <AssistantAvatar busy={writing} />
      <div className="min-w-0 flex-1 space-y-2.5 pt-0.5">
        <div className="flex items-baseline gap-2">
          <span className="text-xs font-semibold text-slate-200">Blackveil AI</span>
          {message.model && <span className="text-[10px] text-slate-500 truncate">{fromApp ? 'app message, not AI-written' : message.model.replace(/^[^:]+:/, '')}</span>}
          {!fromApp && !writing && !busy && <span className="ml-auto"><Feedback rating={rating} onRate={(r) => onRate(message.id, r)} /></span>}
        </div>
        {change?.analysis && <Thinking key={busy ? 'busy' : 'done'} change={change} writing={writing} />}
        {(!change || !busy || change.analysis?.awaiting_go) && <RichText text={message.content} />}
        {change && <Actions change={change} writing={writing} onReview={() => onReview(change)} onContinue={() => onContinue(change)} />}
      </div>
    </div>
  );
}
