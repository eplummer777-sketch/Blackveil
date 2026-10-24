export type ChatRole = 'system' | 'user' | 'assistant';
export type ReplyFormat = 'json' | 'text';

export interface CompletionInput {
  messages: { role: ChatRole; content: string }[];
  max_tokens: number;
  format?: ReplyFormat;
}

export function normalizeMessages(messages: CompletionInput['messages']) {
  const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n');
  const rest: { role: 'user' | 'assistant'; content: string }[] = [];
  for (const m of messages) {
    if (m.role === 'system') continue;
    const last = rest[rest.length - 1];
    if (last && last.role === m.role) last.content += `\n\n${m.content}`;
    else rest.push({ role: m.role, content: m.content });
  }
  while (rest.length && rest[0].role !== 'user') rest.shift();
  return system ? [{ role: 'system' as const, content: system }, ...rest] : rest;
}

// No response_format: WebLLM 0.2.86 passes an undefined schema to its grammar compiler for
// {type:"json_object"}, which throws GrammarMatcherInitError. JSON is requested by the prompt
// and checked by checkReply instead.
export function buildCompletion(input: CompletionInput) {
  return {
    messages: normalizeMessages(input.messages),
    max_tokens: input.max_tokens,
    temperature: 0.2,
    stream: true as const,
    stream_options: { include_usage: true },
  };
}

// Text of the first complete top-level {...} (string-aware), or null while it is still unfinished.
export function firstJsonObject(raw: string): string | null {
  const start = raw.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < raw.length; i++) {
    const c = raw[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return raw.slice(start, i + 1);
  }
  return null;
}

export function extractJsonObject(raw: string): Record<string, unknown> | null {
  const text = firstJsonObject(raw);
  if (!text) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// Malformed JSON is passed through: the server owns validation and runs its own repair round or plain-text fallback.
export function checkReply(content: string, format: ReplyFormat = 'json'): string {
  if (!content.trim()) throw new LocalAiError('Blackveil AI produced an empty reply. Try again or rephrase the request.');
  if (format === 'json' && extractJsonObject(content)) return firstJsonObject(content) as string;
  return content;
}

interface StreamChunk {
  choices: { delta?: { content?: string | null }; finish_reason?: string | null }[];
  usage?: { prompt_tokens: number; completion_tokens: number } | null;
}

export interface CompletionEngine {
  chat: { completions: { create: (req: ReturnType<typeof buildCompletion>) => Promise<AsyncIterable<StreamChunk>> } };
  interruptGenerate: () => void;
}

export interface CompletionUsage { input_tokens: number; output_tokens: number; estimated: boolean; duration_ms: number }
export interface CompletionResult { content: string; usage: CompletionUsage }

export class LocalAiError extends Error {
  release: boolean;
  constructor(message: string, release = false) {
    super(message);
    this.release = release;
  }
}

export interface CompletionLimits { firstTokenMs: number; idleMs: number; pollMs: number }
export const DEFAULT_LIMITS: CompletionLimits = { firstTokenMs: 150_000, idleMs: 45_000, pollMs: 250 };

const STOPPED = 'Stopped. Nothing was saved.';

// A stuck WebGPU prefill never yields and never errors, so every await is raced against
// cancel and a deadline; otherwise the screen sits on "Thinking" forever.
function watch<T>(p: Promise<T>, deadline: number, isCancelled: () => boolean, pollMs: number, slow: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setInterval(() => {
      if (isCancelled()) { clearInterval(timer); reject(new LocalAiError(STOPPED)); }
      else if (Date.now() > deadline) { clearInterval(timer); reject(new LocalAiError(slow, true)); }
    }, pollMs);
    p.then((v) => { clearInterval(timer); resolve(v); }, (e) => { clearInterval(timer); reject(e); });
  });
}

const NO_START = 'Blackveil AI did not start answering in time, so it was stopped and unloaded to free memory. Nothing was changed. Open Blackveil AI, tap Start, and try again with a shorter message.';
const STALLED = 'Blackveil AI stopped responding partway through, so it was stopped and unloaded to free memory. Nothing was changed. Open Blackveil AI, tap Start, and try again.';

export async function runCompletion(
  engine: CompletionEngine,
  input: CompletionInput,
  onTokens?: (n: number) => void,
  isCancelled: () => boolean = () => false,
  limits: CompletionLimits = DEFAULT_LIMITS,
): Promise<CompletionResult> {
  const format = input.format ?? 'json';
  let content = '';
  let tokens = 0;
  let measured: { input_tokens: number; output_tokens: number } | null = null;
  const started = Date.now();
  const firstDeadline = Date.now() + limits.firstTokenMs;
  const deadline = () => (tokens ? Date.now() + limits.idleMs : firstDeadline);
  let iter: AsyncIterator<StreamChunk> | null = null;
  try {
    const stream = await watch(engine.chat.completions.create(buildCompletion(input)), firstDeadline, isCancelled, limits.pollMs, NO_START);
    iter = stream[Symbol.asyncIterator]();
    for (;;) {
      const step = await watch(iter.next(), deadline(), isCancelled, limits.pollMs, tokens ? STALLED : NO_START);
      if (step.done) break;
      const chunk = step.value;
      const delta = chunk.choices[0]?.delta?.content ?? '';
      if (chunk.usage) measured = { input_tokens: chunk.usage.prompt_tokens, output_tokens: chunk.usage.completion_tokens };
      if (!delta) continue;
      content += delta;
      tokens++;
      onTokens?.(tokens);
      // Without a grammar the model keeps going after the JSON closes, so stop at the first complete object.
      if (format === 'json' && delta.includes('}') && extractJsonObject(content)) {
        engine.interruptGenerate();
        void iter.return?.()?.catch(() => undefined);
        break;
      }
    }
  } catch (err) {
    engine.interruptGenerate();
    void iter?.return?.()?.catch(() => undefined);
    throw err;
  }
  if (isCancelled()) throw new LocalAiError(STOPPED);
  // Interrupted streams never send the engine's usage chunk; then the count of streamed pieces is only an estimate.
  const usage: CompletionUsage = measured?.output_tokens
    ? { ...measured, estimated: false, duration_ms: Date.now() - started }
    : { input_tokens: measured?.input_tokens ?? 0, output_tokens: tokens, estimated: true, duration_ms: Date.now() - started };
  return { content: checkReply(content, format), usage };
}
