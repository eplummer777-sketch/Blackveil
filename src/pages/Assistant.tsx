import { useEffect, useRef, useState, FormEvent, useCallback } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase, edgeUrl } from '@/lib/supabase';
import { ChatThread, ChatMessage, Plan, PLAN_AI_LIMITS, PLAN_LABELS } from '@/lib/types';
import { Card, Button, Spinner } from '@/components/ui';
import {
  Bot, Send, Plus, MessageSquare, Trash2, AlertCircle, Info, Zap, Sparkles,
  RefreshCw, Copy, Check, AlertTriangle, CreditCard, Lock,
} from 'lucide-react';
import { Route } from '@/components/AppShell';
import { AssistantAction, AssistantActionCard } from '@/components/AssistantActionCard';

const hideActionBlocks = (text: string) => text.replace(/```blackveil-action[\s\S]*$/, '').trimEnd();

const DAILY_LIMIT = 20;
const SAMPLE_PROMPTS = [
  'Explain what HTTPS and TLS do in plain English',
  'What is SQL injection and how do I prevent it?',
  'How should I secure my small business WiFi?',
  'Audit these HTTP headers: Strict-Transport-Security: max-age=86400',
  'Help me create a strong password policy',
  'My computer is acting weird — how do I check for malware?',
  'Scan my device and remove anything dangerous',
  'Check if this link is safe: example.com/login',
];

const FOLLOWUPS = [
  'Tell me more about this',
  'How do I fix it?',
  'Give me a concrete example',
  'What are the risks if I do nothing?',
];

type Severity = 'urgent' | 'normal';

export function Assistant({ onNavigate }: { onNavigate?: (r: Route) => void } = {}) {
  const { user, session, plan } = useAuth();
  const [threads, setThreads] = useState<ChatThread[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [actions, setActions] = useState<AssistantAction[]>([]);
  const [streamingReply, setStreamingReply] = useState<string>('');
  const [streamSeverity, setStreamSeverity] = useState<Severity>('normal');
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingThreads, setLoadingThreads] = useState(true);
  const [remaining, setRemaining] = useState<number>(DAILY_LIMIT);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // For paid plans the server enforces a monthly window; the client-side
  // quota indicator is an approximation. Elite (limit 0) means unlimited.
  const effectiveLimit = PLAN_AI_LIMITS[plan];
  const isUnlimited = effectiveLimit === 0;
  const windowLabel = plan === 'free' ? 'today' : 'this month';

  async function loadThreads() {
    if (!user) return;
    setLoadingThreads(true);
    const { data } = await supabase
      .from('chat_threads')
      .select('*')
      .eq('user_id', user.id)
      .order('updated_at', { ascending: false });
    setThreads((data as ChatThread[]) ?? []);
    setLoadingThreads(false);
  }

  const loadQuota = useCallback(async () => {
    if (!user) return;
    if (isUnlimited) { setRemaining(-1); return; }
    const ms = plan === 'free' ? 24 * 60 * 60_000 : 30 * 24 * 60 * 60_000;
    const since = new Date(Date.now() - ms).toISOString();
    const { count } = await supabase
      .from('ai_usage')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', user.id)
      .eq('feature', 'assistant')
      .gte('created_at', since);
    setRemaining(Math.max(0, effectiveLimit - (count ?? 0)));
  }, [user, effectiveLimit, isUnlimited, plan]);

  useEffect(() => { loadThreads(); loadQuota(); }, [user, loadQuota]);

  async function loadMessages(threadId: string) {
    const { data } = await supabase
      .from('chat_messages')
      .select('*')
      .eq('thread_id', threadId)
      .order('created_at', { ascending: true });
    setMessages((data as ChatMessage[]) ?? []);
    const { data: acts } = await supabase
      .from('assistant_actions')
      .select('id, message_id, kind, summary, status, result, created_at, expires_at')
      .eq('thread_id', threadId)
      .order('created_at', { ascending: true });
    setActions((acts as AssistantAction[]) ?? []);
    setActiveId(threadId);
  }

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, streamingReply]);

  // Auto-resize the textarea as the user types
  useEffect(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 160) + 'px';
  }, [input]);

  async function streamAssistant(
    payload: { threadId?: string; message?: string; regenerate?: boolean },
    onDone?: (assistant: ChatMessage) => void,
  ) {
    if (!session?.access_token) return;
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const resp = await fetch(edgeUrl('ai-assistant'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!resp.ok) {
        let errMsg = `Request failed (${resp.status})`;
        try {
          const j = await resp.json();
          if (j?.message) errMsg = j.message;
          if (j?.error === 'quota_reached' || j?.error === 'daily_limit_reached') setRemaining(0);
        } catch { /* ignore */ }
        throw new Error(errMsg);
      }
      if (!resp.body) throw new Error('No response stream');

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let accumulated = '';
      let finalThreadId = payload.threadId ?? '';
      let uncertain = false;
      let severity: Severity = 'normal';
      let messageId = '';
      let newActions: AssistantAction[] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() ?? '';
        for (const evt of lines) {
          const line = evt.trim();
          if (!line.startsWith('data:')) continue;
          try {
            const p = JSON.parse(line.slice(5).trim());
            if (p.type === 'meta') {
              finalThreadId = p.threadId ?? finalThreadId;
              setRemaining(p.remaining ?? remaining);
              if (p.severity) {
                severity = p.severity as Severity;
                setStreamSeverity(severity);
              }
            } else if (p.type === 'delta') {
              accumulated += p.delta;
              setStreamingReply(hideActionBlocks(accumulated));
            } else if (p.type === 'done') {
              uncertain = !!p.uncertain;
              severity = (p.severity as Severity) ?? severity;
              setRemaining(p.remaining ?? remaining);
              if (typeof p.messageId === 'string') messageId = p.messageId;
              if (typeof p.content === 'string') accumulated = p.content;
              if (Array.isArray(p.actions)) newActions = p.actions as AssistantAction[];
              if (!payload.threadId && p.threadId) {
                setActiveId(p.threadId);
                finalThreadId = p.threadId;
              }
            } else if (p.type === 'error') {
              throw new Error(p.message ?? 'AI error');
            }
          } catch (parseErr) {
            if (parseErr instanceof Error && parseErr.message.includes('AI')) throw parseErr;
          }
        }
      }

      const assistant: ChatMessage = {
        id: messageId || 'a-' + Date.now(),
        thread_id: finalThreadId,
        role: 'assistant',
        content: hideActionBlocks(accumulated),
        uncertain,
        created_at: new Date().toISOString(),
      };
      if (newActions.length) setActions((a) => [...a, ...newActions]);
      onDone?.(assistant);
      loadThreads();
      loadQuota();
    } finally {
      abortRef.current = null;
    }
  }

  async function handleSend(e?: FormEvent, override?: string) {
    e?.preventDefault();
    const text = (override ?? input).trim();
    if (!text || !session?.access_token || sending) return;
    if (!isUnlimited && remaining <= 0) {
      setError(`You've used all your AI messages for ${windowLabel}. Your quota resets at the start of the next cycle.`);
      return;
    }
    setError(null);
    setSending(true);
    setStreamingReply('');
    setStreamSeverity('normal');

    const tempUser: ChatMessage = {
      id: 'tmp-u-' + Date.now(), thread_id: activeId ?? '', role: 'user',
      content: text, uncertain: false, created_at: new Date().toISOString(),
    };
    setMessages((m) => [...m, tempUser]);
    setInput('');

    try {
      await streamAssistant({ threadId: activeId ?? undefined, message: text }, (assistant) => {
        const persistedUser: ChatMessage = { ...tempUser, id: 'u-' + Date.now(), thread_id: assistant.thread_id };
        setMessages((m) => [...m.filter((x) => x.id !== tempUser.id), persistedUser, assistant]);
        setStreamingReply('');
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Something went wrong';
      if (msg.includes('aborted') || msg.includes('Abort')) {
        // user canceled
      } else {
        setError(msg);
        setMessages((m) => m.filter((x) => x.id !== tempUser.id));
      }
    } finally {
      setSending(false);
      setStreamingReply('');
      setStreamSeverity('normal');
    }
  }

  async function handleRegenerate() {
    if (!activeId || !session?.access_token || sending || (!isUnlimited && remaining <= 0)) return;
    if (messages.length === 0) return;
    // Find the last assistant message
    const lastAssistantIdx = [...messages].reverse().findIndex((m) => m.role === 'assistant');
    if (lastAssistantIdx === -1) return;
    const lastAssistant = messages[messages.length - 1 - lastAssistantIdx];

    setSending(true);
    setStreamingReply('');
    setStreamSeverity('normal');
    // Remove the last assistant message locally while regenerating
    setMessages((m) => m.filter((x) => x.id !== lastAssistant.id));
    setActions((a) => a.filter((x) => x.message_id !== lastAssistant.id));

    try {
      await streamAssistant({ threadId: activeId, regenerate: true }, (assistant) => {
        setMessages((m) => [...m, assistant]);
        setStreamingReply('');
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Something went wrong';
      if (!msg.includes('aborted') && !msg.includes('Abort')) {
        setError(msg);
        // Restore the removed message on failure
        setMessages((m) => [...m, lastAssistant]);
      }
    } finally {
      setSending(false);
      setStreamingReply('');
      setStreamSeverity('normal');
    }
  }

  function stopStreaming() {
    abortRef.current?.abort();
    setSending(false);
    setStreamingReply('');
  }

  async function newThread() {
    setActiveId(null);
    setMessages([]);
    setActions([]);
    setError(null);
    setStreamingReply('');
  }

  async function deleteThread(id: string) {
    await supabase.from('chat_threads').delete().eq('id', id);
    if (activeId === id) { setActiveId(null); setMessages([]); setActions([]); }
    loadThreads();
  }

  async function copyMessage(m: ChatMessage) {
    try {
      await navigator.clipboard.writeText(m.content);
      setCopiedId(m.id);
      setTimeout(() => setCopiedId(null), 1800);
    } catch { /* ignore */ }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  const lastAssistant = messages.length > 0 && messages[messages.length - 1].role === 'assistant'
    ? messages[messages.length - 1]
    : null;

  const quotaPct = isUnlimited ? 100 : Math.round((remaining / effectiveLimit) * 100);

  return (
    <div className="space-y-4 fade-up h-[calc(100vh-160px)] flex flex-col">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/30 flex items-center justify-center text-cyan-300">
            <Sparkles size={22} />
          </div>
          <div>
            <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">
              Blackveil AI
            </h1>
            <p className="text-slate-400 text-sm flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              Senior security assistant · streaming
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <QuotaBadge remaining={remaining} limit={effectiveLimit} pct={quotaPct} plan={plan} unlimited={isUnlimited} />
          <Button size="sm" variant="secondary" onClick={newThread}><Plus size={14} /> New chat</Button>
        </div>
      </div>

      <div className="flex-1 grid lg:grid-cols-[260px_1fr] gap-4 min-h-0">
        {/* Threads */}
        <Card className="p-3 flex flex-col min-h-0 hidden lg:flex">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 px-2 py-2">Conversations</div>
          <div className="flex-1 overflow-y-auto scrollbar-thin space-y-1">
            {loadingThreads ? (
              <div className="p-3"><Spinner className="text-slate-500" /></div>
            ) : threads.length === 0 ? (
              <p className="text-xs text-slate-500 px-2 py-3">No conversations yet.</p>
            ) : (
              threads.map((t) => (
                <div key={t.id} className={`group flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm cursor-pointer transition ${activeId === t.id ? 'bg-cyan-400/10 text-cyan-200' : 'text-slate-400 hover:bg-veil-800/60'}`} onClick={() => loadMessages(t.id)}>
                  <MessageSquare size={14} className="shrink-0 opacity-70" />
                  <span className="truncate flex-1">{t.title}</span>
                  <button onClick={(e) => { e.stopPropagation(); deleteThread(t.id); }} className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-rose-300 transition">
                    <Trash2 size={13} />
                  </button>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Chat */}
        <Card className="flex flex-col min-h-0 relative">
          <div ref={scrollRef} className="flex-1 overflow-y-auto scrollbar-thin p-4 lg:p-5 space-y-4">
            {messages.length === 0 && !sending && (
              <div className="h-full flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/15 to-transparent border border-cyan-500/30 flex items-center justify-center text-cyan-300 mb-4 relative">
                  <Sparkles size={28} />
                  <span className="absolute -inset-1 rounded-2xl border border-cyan-400/20 animate-pulse" />
                </div>
                <h3 className="text-lg font-semibold text-slate-100">Ask Blackveil AI</h3>
                <p className="text-sm text-slate-500 mt-1 max-w-md">Senior defensive cybersecurity guidance. It can also scan your devices, check links and add protections, but only after you confirm each action.</p>
                <div className="mt-5 grid sm:grid-cols-2 gap-2 max-w-xl w-full">
                  {SAMPLE_PROMPTS.map((p) => (
                    <button key={p} onClick={() => handleSend(undefined, p)} className="text-left text-sm text-slate-300 rounded-lg border border-slate-800/70 bg-veil-950/40 px-3 py-2.5 hover:border-cyan-500/40 hover:bg-cyan-500/5 transition flex items-start gap-2">
                      <Zap size={13} className="text-cyan-400 mt-0.5 shrink-0" />
                      <span>{p}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((m) => (
              <MessageBubble
                key={m.id}
                m={m}
                onCopy={() => copyMessage(m)}
                copied={copiedId === m.id}
              >
                {actions.filter((a) => a.message_id === m.id).map((a) => (
                  <AssistantActionCard
                    key={a.id}
                    action={a}
                    accessToken={session?.access_token}
                    outOfUses={!isUnlimited && remaining <= 0}
                    onNavigate={(page) => onNavigate?.(page as Route)}
                    onChange={(next, quota) => {
                      setActions((list) => list.map((x) => (x.id === next.id ? next : x)));
                      if (quota) setRemaining(quota.remaining);
                    }}
                  />
                ))}
              </MessageBubble>
            ))}

            {sending && (
              <StreamingBubble content={streamingReply} severity={streamSeverity} />
            )}

            {/* Follow-up chips after the most recent assistant reply */}
            {!sending && lastAssistant && messages.length > 0 && (
              <div className="flex flex-wrap gap-2 pl-11 pt-1">
                {FOLLOWUPS.map((f) => (
                  <button
                    key={f}
                    onClick={() => handleSend(undefined, f)}
                    className="text-xs text-slate-300 rounded-full border border-slate-800 bg-veil-950/50 px-3 py-1.5 hover:border-cyan-500/40 hover:text-cyan-200 hover:bg-cyan-500/5 transition"
                  >
                    {f}
                  </button>
                ))}
                <button
                  onClick={handleRegenerate}
                  disabled={!isUnlimited && remaining <= 0}
                  className="text-xs text-slate-300 rounded-full border border-slate-800 bg-veil-950/50 px-3 py-1.5 hover:border-cyan-500/40 hover:text-cyan-200 hover:bg-cyan-500/5 transition flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <RefreshCw size={12} /> Regenerate
                </button>
              </div>
            )}
          </div>

          {error && (
            <div className="mx-4 mb-2 flex items-start gap-2 text-sm text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">
              <AlertCircle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
            </div>
          )}

          {!isUnlimited && remaining <= 0 && (
            <div className="mx-4 mb-2 rounded-lg border border-cyan-500/30 bg-gradient-to-br from-cyan-500/10 to-transparent p-3.5">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-300 shrink-0">
                  <Lock size={16} />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-semibold text-slate-100">
                    {plan === 'free' ? "You've hit the free daily limit" : `You've used all your ${PLAN_LABELS[plan]} messages`}
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {plan === 'free'
                      ? 'Upgrade to a paid plan for a much higher monthly allowance —'
                      : 'Upgrade to a higher tier for more messages, or wait for your cycle to reset.'}
                    {plan === 'free' && (
                      <>
                        <span className="text-cyan-300 font-medium"> 100</span> messages at $5/mo,
                        <span className="text-cyan-300 font-medium"> 1,000</span> at $10/mo, or
                        <span className="text-cyan-300 font-medium"> unlimited</span> at $25/mo.
                      </>
                    )}
                  </p>
                  <button
                    onClick={() => onNavigate?.('malware')}
                    className="mt-2.5 inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-veil-950 font-semibold text-xs px-3 py-2 transition"
                  >
                    <CreditCard size={13} /> {plan === 'free' ? 'View plans' : 'Upgrade plan'}
                  </button>
                </div>
              </div>
            </div>
          )}

          <form onSubmit={handleSend} className="border-t border-slate-800/70 p-3 flex items-end gap-2">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask anything about cybersecurity…  (Shift+Enter for a new line)"
              rows={1}
              disabled={sending}
              className="flex-1 resize-none rounded-lg bg-veil-950/60 border border-slate-800 text-slate-100 placeholder:text-slate-500 px-3.5 py-2.5 text-sm focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition disabled:opacity-50 scrollbar-thin"
            />
            {sending ? (
              <Button type="button" variant="danger" onClick={stopStreaming}>
                Stop
              </Button>
            ) : (
              <Button type="submit" disabled={!input.trim() || (!isUnlimited && remaining <= 0)}>
                <Send size={15} /> Send
              </Button>
            )}
          </form>
          {!isUnlimited && remaining <= 0 && (
            <div className="px-3 pb-2 text-[11px] text-amber-300 text-center">
              {plan === 'free'
                ? 'Daily limit reached — resets in 24 hours. Upgrade for a higher monthly allowance.'
                : `Monthly limit reached on the ${PLAN_LABELS[plan]} plan — resets at the next billing cycle.`}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function QuotaBadge({ remaining, limit, pct, plan, unlimited }: { remaining: number; limit: number; pct: number; plan: Plan; unlimited: boolean }) {
  const low = !unlimited && remaining <= 3;
  const out = !unlimited && remaining <= 0;
  const tone = out ? 'rose' : low ? 'amber' : plan === 'elite' ? 'amber' : plan === 'pro' ? 'cyan' : 'cyan';
  const tones = {
    cyan: 'border-cyan-500/30 text-cyan-200 bg-cyan-500/5',
    amber: 'border-amber-500/30 text-amber-200 bg-amber-500/5',
    rose: 'border-rose-500/30 text-rose-200 bg-rose-500/5',
  };
  const tierLabel = plan === 'elite' ? 'ELITE' : plan === 'pro' ? 'PRO' : plan === 'malware_removal' ? 'PLUS' : null;
  return (
    <div className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs ${tones[tone]}`}>
      <Zap size={12} />
      {unlimited ? (
        <span className="font-mono-tight">∞</span>
      ) : (
        <span className="font-mono-tight">{remaining}/{limit}</span>
      )}
      <span className="text-slate-500 hidden sm:inline">{plan === 'free' ? 'today' : 'this month'}</span>
      {tierLabel && <span className="text-[9px] uppercase tracking-wider bg-cyan-500/20 px-1.5 py-0.5 rounded">{tierLabel}</span>}
      <span className="hidden sm:block w-16 h-1 rounded-full bg-veil-800 overflow-hidden">
        <span className="block h-full bg-current transition-all" style={{ width: `${pct}%` }} />
      </span>
    </div>
  );
}

function UrgentBanner() {
  return (
    <div className="mb-2 flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
      <AlertTriangle size={14} className="mt-0.5 shrink-0 animate-pulse" />
      <span><strong className="font-semibold">Urgent:</strong> If this is an active attack, disconnect the affected device from the network now and consider contacting a professional incident response firm or law enforcement.</span>
    </div>
  );
}

function StreamingBubble({ content, severity }: { content: string; severity: Severity }) {
  return (
    <div className="flex gap-3 fade-up">
      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 bg-cyan-500/15 text-cyan-300">
        <Bot size={16} />
      </div>
      <div className="max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed bg-veil-900/80 border border-slate-800/70 text-slate-200">
        {severity === 'urgent' && <UrgentBanner />}
        {content ? (
          <FormattedReply content={content} />
        ) : (
          <span className="inline-flex items-center gap-1.5 text-slate-400">
            <span className="flex gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '120ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '240ms' }} />
            </span>
            thinking…
          </span>
        )}
        {content && <span className="inline-block w-2 h-4 ml-0.5 bg-cyan-400/80 animate-pulse align-middle" />}
      </div>
    </div>
  );
}

function MessageBubble({ m, onCopy, copied, children }: { m: ChatMessage; onCopy: () => void; copied: boolean; children?: React.ReactNode }) {
  const isUser = m.role === 'user';
  const isUrgent = m.role === 'assistant' && /^\[URGENT\]/i.test(m.content.trim());
  return (
    <div className={`flex gap-3 fade-up ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${isUser ? 'bg-veil-800 text-slate-300' : 'bg-cyan-500/15 text-cyan-300'}`}>
        {isUser ? <span className="text-xs font-semibold">You</span> : <Bot size={16} />}
      </div>
      <div className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${isUser ? 'bg-veil-800 text-slate-200' : 'bg-veil-900/80 border border-slate-800/70 text-slate-200'}`}>
        {!isUser && isUrgent && <UrgentBanner />}
        {isUser ? (
          <p className="whitespace-pre-wrap">{m.content}</p>
        ) : (
          <FormattedReply content={isUrgent ? m.content.replace(/^\[URGENT\][^\n]*\n?/i, '') : m.content} />
        )}
        {m.uncertain && (
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1">
            <Info size={12} /> AI is uncertain or lacks sufficient evidence — verify before acting.
          </div>
        )}
        {children}
        {!isUser && (
          <div className="mt-2 flex items-center gap-1">
            <button
              onClick={onCopy}
              className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 transition px-1.5 py-0.5 rounded hover:bg-veil-800/60"
            >
              {copied ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function FormattedReply({ content }: { content: string }) {
  const blocks: React.ReactNode[] = [];
  const parts = content.split(/```/);
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      blocks.push(
        <pre key={`c-${i}`} className="my-2 text-[12px] font-mono-tight text-cyan-200 bg-veil-950/90 border border-slate-800/70 rounded-md p-3 overflow-x-auto whitespace-pre-wrap">{part.replace(/^\w*\n/, '').trim()}</pre>
      );
    } else {
      const lines = part.split('\n');
      let list: string[] = [];
      let ordered = false;
      const flushList = () => {
        if (list.length) {
          const ListTag = ordered ? 'ol' : 'ul';
          blocks.push(<ListTag key={`l-${blocks.length}`} className={`${ordered ? 'list-decimal' : 'list-disc'} pl-5 my-1.5 space-y-1 text-slate-300`}>{list.map((x, j) => <li key={j}>{inline(x)}</li>)}</ListTag>);
          list = [];
          ordered = false;
        }
      };
      lines.forEach((line) => {
        const t = line.trim();
        if (/^[-*]\s+/.test(t)) { ordered = false; list.push(t.replace(/^[-*]\s+/, '')); return; }
        if (/^\d+\.\s+/.test(t)) { ordered = true; list.push(t.replace(/^\d+\.\s+/, '')); return; }
        flushList();
        if (/^#{1,3}\s+/.test(t)) {
          blocks.push(<div key={`h-${blocks.length}`} className="font-semibold text-slate-100 mt-2 mb-1">{t.replace(/^#{1,3}\s+/, '')}</div>);
        } else if (t === '') {
          blocks.push(<div key={`s-${blocks.length}`} className="h-1.5" />);
        } else {
          blocks.push(<p key={`p-${blocks.length}`} className="my-1 text-slate-300">{inline(t)}</p>);
        }
      });
      flushList();
    }
  });
  return <div>{blocks}</div>;
}

function inline(text: string): React.ReactNode {
  const nodes: React.ReactNode[] = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0; let m: RegExpExecArray | null; let key = 0;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('**')) nodes.push(<strong key={key++} className="text-slate-100 font-semibold">{tok.slice(2, -2)}</strong>);
    else nodes.push(<code key={key++} className="text-[12px] font-mono-tight text-cyan-200 bg-veil-950/80 border border-slate-800/70 rounded px-1 py-0.5">{tok.slice(1, -1)}</code>);
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}
