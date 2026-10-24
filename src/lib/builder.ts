import { callEdge, supabase } from '@/lib/supabase';
import type { FileMap } from '@/lib/builderTools';
import type { LocalAiReply, LocalAiRequest } from '@/lib/localAi/LocalAiContext';

export interface WbProject { id: string; name: string; description: string; kind: string; created_at: string; updated_at: string }
export interface WbMessage { id: string; role: 'user' | 'assistant' | 'system'; content: string; model: string | null; created_at: string }
export interface WbChangeFile { path: string; action: 'create' | 'update' | 'delete'; before: string | null; after: string | null; renamed_from?: string; renamed_to?: string }
export interface WbCheck { name: string; ok: boolean; detail: string; warn?: boolean }
export interface WbAnalysis {
  understanding?: string; plan?: string[]; inspected?: string[]; targets?: string[]; creates?: string[];
  batches?: string[][]; next?: number; complete?: boolean; replies?: string[]; notes?: string[];
  context_omitted?: string[]; risks?: string[]; checks?: WbCheck[]; baseline_failed?: string[];
  workflow?: WbWorkflow; causes?: { cause: string; evidence: string; likelihood: string }[]; repairs?: number; awaiting_go?: boolean;
}
export type WbWorkflow = 'ask' | 'explain' | 'plan' | 'code' | 'debug' | 'review';
export type WbRating = 'helpful' | 'incorrect' | 'incomplete' | 'verified';
export interface WbMemory {
  id: string; kind: string; title: string; body: string; source: 'user' | 'system' | 'ai'; status: 'active' | 'unverified' | 'archived';
  files: string[]; stale: string[]; updated_at: string;
}
export interface WbFix {
  id: string; change_id: string | null; problem: string; root_cause: string; evidence: string; fix_summary: string; files: string[];
  limitations: string; status: 'hypothesis' | 'verified' | 'failed'; confidence: string; updated_at: string;
}
export interface WbAiStats { calls: number; readable_rate: number | null; repairs: number; avg_seconds: number | null; avg_output_tokens: number | null; estimated_token_share: number | null }
export interface WbMetrics {
  baseline: { ai: WbAiStats; changes: Record<string, number> }; current: { ai: WbAiStats; changes: Record<string, number> };
  feedback: Record<string, number>; fixes: Record<string, number>; note: string;
}
export interface WbChange {
  id: string; summary: string; files: WbChangeFile[]; status: 'pending' | 'applied' | 'rejected' | 'reverted';
  created_at: string; message_id: string | null; analysis: WbAnalysis | null;
}
export interface WbApplyResult { applied: boolean; verification: { checks: WbCheck[]; note: string } }
export interface WbIndexEntry { path: string; kind: string; size: number; refs: string[]; missing: string[]; packages: string[]; dependents: string[]; summary: string }
export interface WbIndex { entries: Record<string, WbIndexEntry>; pages: string[]; orphanPages: string[]; totalChars: number }

export const MAX_REPAIRS = 2;

export const changeInProgress = (c: WbChange) =>
  c.status === 'pending' && !!c.analysis?.batches && !c.analysis.complete;
export interface WbSnapshot { id: string; label: string; created_at: string }
export interface WbCapabilities { preview: string; execution: boolean; execution_reason: string; deploy: boolean }
export interface WbPublication { project_id: string; slug: string; entry: string; title: string; published_at: string }
export interface WbPublishResult { publication: WbPublication; pages: string[]; missing: string[]; checks: WbCheck[] }
export interface WbProjectData {
  project: WbProject; files: FileMap; messages: WbMessage[]; changes: WbChange[]; snapshots: WbSnapshot[];
  publication: WbPublication | null; suggested_slug: string; feedback?: { message_id: string; rating: WbRating }[];
}
export const publicSiteUrl = (slug: string) => `${window.location.origin}/site.html?s=${encodeURIComponent(slug)}`;
export interface WbAiSettings { settings: { ai_provider: 'none' | 'local' }; usage: { today: number } }

export class BuilderError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function wb<T>(action: string, payload: Record<string, unknown> = {}): Promise<T> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new BuilderError(401, 'You are signed out. Sign in again.');
  let res;
  try {
    res = await callEdge<T>('web-builder', { action, ...payload }, token);
  } catch {
    throw new BuilderError(0, 'Network error: could not reach the Web Builder service.');
  }
  if (!res.ok) throw new BuilderError(res.status, res.error);
  if (!res.data || typeof res.data !== 'object') throw new BuilderError(500, 'Unexpected response from the Web Builder service.');
  return res.data;
}

export const errText = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong.');

type Generate = (req: LocalAiRequest) => Promise<LocalAiReply>;

// Matches the server's limit: one answer plus at most one repair pass.
export const MAX_AI_ROUNDS = 2;

// The server prepares each prompt; Blackveil AI answers on this device; the server validates and stores the result.
// A reply the server cannot parse triggers one repair prompt, so earlier answers are resent in order.
export async function wbWithAi<T>(action: string, payload: Record<string, unknown>, generate: Generate): Promise<T> {
  const replies: LocalAiReply[] = [];
  for (;;) {
    const res = await wb<T | { needs_local_ai: LocalAiRequest }>(action, replies.length ? { ...payload, ai_replies: replies } : payload);
    if (!res || typeof res !== 'object' || !('needs_local_ai' in res)) return res as T;
    if (replies.length >= MAX_AI_ROUNDS) throw new BuilderError(500, 'Blackveil AI needed more attempts than allowed. Nothing was saved.');
    replies.push(await generate(res.needs_local_ai));
  }
}
