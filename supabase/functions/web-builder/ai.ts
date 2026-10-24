import { LOCAL_MODEL_IDS } from "../_lib/localModels.ts";
import { HttpError, str, type Body } from "./store.ts";

export interface AiMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AiResult {
  content: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  tokensEstimated: boolean;
  durationMs: number | null;
}

export type ProviderChoice = "none" | "local";
export const LOCAL_PROVIDER = "blackveil-local";

export interface LocalAiRequest {
  purpose: string;
  messages: AiMessage[];
  max_tokens: number;
  prompt_hash: string;
}

// Inference never happens on the server: the request is handed to the owner's browser, which runs the model
// on-device and calls the same action again with `ai_replies` (earlier answers in order, then the new one).
export class NeedsLocalAi extends Error {
  request: LocalAiRequest;
  constructor(request: LocalAiRequest) {
    super("Local AI reply required.");
    this.request = request;
  }
}

export async function promptHash(messages: AiMessage[], maxTokens: number): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify({ messages, maxTokens }));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export const MAX_AI_ROUNDS = 2;
const CURSOR = Symbol("ai-reply-cursor");

function nextReply(body: Body): Record<string, unknown> | undefined {
  const list = Array.isArray(body.ai_replies) ? body.ai_replies.slice(0, MAX_AI_ROUNDS) : body.ai_reply ? [body.ai_reply] : [];
  const holder = body as Body & { [CURSOR]?: number };
  const i = holder[CURSOR] ?? 0;
  holder[CURSOR] = i + 1;
  if (i >= MAX_AI_ROUNDS) throw new HttpError(422, "Blackveil AI could not produce a usable answer within the allowed attempts. Nothing was saved. Try a shorter, more specific request.");
  return list[i] as Record<string, unknown> | undefined;
}

export async function localReply(body: Body, purpose: string, messages: AiMessage[], maxTokens: number): Promise<AiResult> {
  const hash = await promptHash(messages, maxTokens);
  const raw = nextReply(body);
  if (!raw || typeof raw !== "object") throw new NeedsLocalAi({ purpose, messages, max_tokens: maxTokens, prompt_hash: hash });
  if (raw.prompt_hash !== hash) {
    throw new HttpError(409, "Your website changed while Blackveil AI was thinking. Nothing was saved. Please send the request again.");
  }
  const model = str(raw.model, 80);
  if (!LOCAL_MODEL_IDS.includes(model)) throw new HttpError(400, "Reply came from an unknown model.");
  const content = typeof raw.content === "string" ? raw.content.slice(0, 200_000) : "";
  if (!content.trim()) throw new HttpError(422, "Blackveil AI returned an empty reply. Try again or rephrase the request.");
  const usage = (raw.usage ?? {}) as Record<string, unknown>;
  const duration = Number(usage.duration_ms);
  return {
    content, model, inputTokens: Number(usage.input_tokens) || 0, outputTokens: Number(usage.output_tokens) || 0,
    tokensEstimated: usage.estimated !== false, durationMs: Number.isFinite(duration) && duration >= 0 ? Math.min(Math.round(duration), 3_600_000) : null,
  };
}
