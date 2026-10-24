import { useEffect, useRef, useState } from 'react';
import { WbChange, WbMessage, type WbRating, type WbWorkflow } from '@/lib/builder';
import { useLocalAi, type LocalAiStatus } from '@/lib/localAi/LocalAiContext';
import { AssistantAvatar, ChatMessage } from '@/components/builder/ChatMessage';
import { ErrorBanner, ErrorBoundary } from '@/components/ui';
import { ArrowUp, Cpu, Loader2, Sparkles, Square } from 'lucide-react';

const SUGGESTIONS = [
  'Add an About page and link it from the navigation on every page',
  'Make the design feel more premium with better spacing and typography',
  'Add a contact form with name, email and message fields',
  'Make every page look great on mobile',
];

const MODES: { value: WbWorkflow | 'auto'; label: string; hint: string }[] = [
  { value: 'auto', label: 'Auto', hint: 'Blackveil AI picks the best mode from your message' },
  { value: 'ask', label: 'Ask', hint: 'A quick answer, no file changes' },
  { value: 'explain', label: 'Explain', hint: 'Explains how your code works, no file changes' },
  { value: 'plan', label: 'Plan', hint: 'Shows a plan first; nothing is written until you tap Write changes' },
  { value: 'code', label: 'Code', hint: 'Plans and writes the changes for you to review' },
  { value: 'debug', label: 'Debug', hint: 'Paste the error: ranks likely causes from the code, then proposes a fix' },
  { value: 'review', label: 'Review', hint: 'Reads your code and lists problems, no file changes' },
];

const CHIP: Record<LocalAiStatus, string> = {
  checking: 'Checking device', unsupported: 'Not supported here', idle: 'Start Blackveil AI', loading: 'Loading model',
  ready: 'On-device AI ready', generating: 'Working on device', error: 'Blackveil AI stopped',
};

function PlanningTurn({ prompt, tokens }: { prompt: string; tokens: number | null }) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const stage = tokens === null ? 'Preparing your request…' : tokens === 0 ? 'Reading your request on your device…' : 'Writing a reply…';
  const hint = tokens === 0
    ? 'The first words can take a minute on a phone. Keep this screen open. If nothing starts in about 2 minutes, Blackveil AI stops and tells you.'
    : 'Keep this screen open while Blackveil AI works.';
  return (
    <>
      <div className="flex justify-end fade-up">
        <div className="max-w-[92%] rounded-2xl rounded-tr-md bg-slate-800/80 border border-slate-700/60 px-3.5 py-2.5 text-[13.5px] leading-relaxed text-slate-100 whitespace-pre-wrap break-words">{prompt}</div>
      </div>
      <div className="flex gap-2.5 fade-up">
        <AssistantAvatar busy />
        <div className="flex-1 pt-0.5 space-y-2">
          <span className="text-xs font-semibold text-slate-200">Blackveil AI</span>
          <div className="rounded-xl border border-slate-800 bg-veil-950/40 px-3 py-2.5 space-y-1.5 text-xs">
            <div className="flex items-center gap-2 text-cyan-100"><Loader2 size={13} className="animate-spin text-cyan-300" /> {stage} <span className="ml-auto tabular-nums text-slate-500">{tokens ? `about ${tokens} tokens · ` : ''}{seconds}s</span></div>
            <p className="text-slate-500 leading-relaxed">{hint}</p>
          </div>
        </div>
      </div>
    </>
  );
}

export function ChatPanel({ messages, changes, feedback, aiTokens, pending, writingId, busy, error, onDismissError, onRetry, onSend, onRate, onReview, onContinue, onAiSettings }: {
  error: string | null;
  onDismissError: () => void;
  onRetry?: () => void;
  messages: WbMessage[];
  changes: WbChange[];
  feedback: { message_id: string; rating: WbRating }[];
  aiTokens: number | null;
  pending: string | null;
  writingId: string | null;
  busy: boolean;
  onSend: (text: string, mode?: WbWorkflow) => Promise<boolean>;
  onRate: (messageId: string, rating: WbRating) => Promise<void>;
  onReview: (c: WbChange) => void;
  onContinue: (c: WbChange) => void;
  onAiSettings: () => void;
}) {
  const ai = useLocalAi();
  const aiConnected = ai.status === 'ready' || ai.status === 'generating';
  const [text, setText] = useState('');
  const [mode, setMode] = useState<WbWorkflow | 'auto'>('auto');
  const ratings = new Map(feedback.map((f) => [f.message_id, f.rating]));
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const byMessage = new Map(changes.filter((c) => c.message_id).map((c) => [c.message_id!, c]));
  const writing = writingId ? changes.find((c) => c.id === writingId) : undefined;

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages.length, pending, writing?.analysis?.next, error]);

  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  }, [text]);

  async function submit(value = text) {
    const t = value.trim();
    if (!t || busy || !aiConnected) return;
    setText('');
    if (!(await onSend(t, mode === 'auto' ? undefined : mode))) setText(t);
  }

  const empty = messages.length === 0 && !pending;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
        <Sparkles size={14} className="text-cyan-300" />
        <span className="text-sm font-medium text-slate-200">Chat</span>
        <button onClick={onAiSettings} className={`ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] border transition hover:bg-slate-800/60 ${aiConnected ? 'border-emerald-500/40 text-emerald-300' : 'border-amber-500/40 text-amber-300'}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${aiConnected ? 'bg-emerald-400' : 'bg-amber-400'}`} />
          <Cpu size={11} /> {ai.status === 'loading' && ai.progress ? `Loading ${Math.round(ai.progress.fraction * 100)}%` : CHIP[ai.status]}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-4 py-4 space-y-5">
        {empty && (
          <div className="h-full flex flex-col justify-center gap-5 fade-up">
            <div>
              <div className="mb-3 h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-400 grid place-content-center text-veil-950"><Sparkles size={18} /></div>
              <h2 className="text-lg font-semibold leading-tight text-slate-100">What should we build?</h2>
              <p className="mt-1.5 text-[13px] leading-relaxed text-slate-400">Describe a change in plain words. The AI reads your whole project, shows its thinking and plan, then writes every affected file for you to review.</p>
            </div>
            <div className="grid gap-2">
              {SUGGESTIONS.map((s) => (
                <button key={s} disabled={!aiConnected || busy} onClick={() => submit(s)}
                  className="text-left rounded-xl border border-slate-800 bg-veil-950/40 px-3 py-2 text-[12.5px] text-slate-300 hover:border-cyan-500/40 hover:text-cyan-100 hover:bg-cyan-500/5 transition disabled:opacity-50 disabled:pointer-events-none">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m) => (
          <ErrorBoundary key={m.id} label="message" compact>
            <ChatMessage message={m} change={byMessage.get(m.id)} writing={!!writingId && byMessage.get(m.id)?.id === writingId}
              rating={ratings.get(m.id)} onRate={onRate} onReview={onReview} onContinue={onContinue} />
          </ErrorBoundary>
        ))}
        {pending && <PlanningTurn prompt={pending} tokens={aiTokens} />}
        {error && !pending && (
          <div role="alert" className="fade-up">
            <ErrorBanner message={error} onDismiss={onDismissError} action={onRetry ? { label: 'Try again', onClick: onRetry } : undefined} />
          </div>
        )}
        <div ref={endRef} />
      </div>

      <div className="p-3">
        <div role="radiogroup" aria-label="Mode" className="mb-2 flex gap-1 overflow-x-auto scrollbar-thin">
          {MODES.map((m) => (
            <button key={m.value} role="radio" aria-checked={mode === m.value} title={m.hint} onClick={() => setMode(m.value)}
              className={`shrink-0 rounded-full border px-2.5 py-0.5 text-[11px] transition ${mode === m.value ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-200' : 'border-slate-800 text-slate-500 hover:text-slate-300 hover:border-slate-700'}`}>
              {m.label}
            </button>
          ))}
        </div>
        <div className={`rounded-2xl border bg-veil-950/70 transition focus-within:border-cyan-500/50 focus-within:shadow-[0_0_0_3px_rgba(34,211,238,0.08)] ${aiConnected ? 'border-slate-700' : 'border-slate-800 opacity-70'}`}>
          <textarea ref={inputRef} value={text} onChange={(e) => setText(e.target.value)} rows={2} maxLength={8000} disabled={!aiConnected}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); } }}
            placeholder={aiConnected ? 'How can Blackveil AI help you today?' : 'Start Blackveil AI to begin chatting'}
            className="block w-full resize-none bg-transparent px-3.5 pt-3 pb-1 text-[13.5px] leading-relaxed text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:cursor-not-allowed" />
          <div className="flex items-center gap-2 px-3 pb-2.5">
            <span className="text-[10.5px] text-slate-500 truncate">{MODES.find((m) => m.value === mode)?.hint}</span>
            {ai.status === 'generating' ? (
              <button onClick={ai.cancel} aria-label="Stop" title="Stop Blackveil AI"
                className="ml-auto h-8 w-8 rounded-lg grid place-content-center bg-slate-200 text-veil-950 hover:bg-white active:scale-95 transition">
                <Square size={12} fill="currentColor" />
              </button>
            ) : (
              <button onClick={() => submit()} disabled={!aiConnected || busy || !text.trim()} aria-label="Send"
                className="ml-auto h-8 w-8 rounded-lg grid place-content-center bg-cyan-500 text-veil-950 hover:bg-cyan-400 active:scale-95 transition disabled:bg-slate-800 disabled:text-slate-500">
                {busy ? <Loader2 size={15} className="animate-spin" /> : <ArrowUp size={16} />}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
