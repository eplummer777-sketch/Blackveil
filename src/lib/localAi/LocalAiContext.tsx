import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { MLCEngineInterface } from '@mlc-ai/web-llm';
import type { LocalModel } from '../../../supabase/functions/_lib/localModels.ts';
import {
  availableModels, checkDevice, clearCache, friendlyError, isCached, loadEngine, modelIdFor, type DeviceSupport,
} from '@/lib/localAi/runtime';
import { LocalAiError, runCompletion, type CompletionUsage, type ReplyFormat } from '@/lib/localAi/completion';

export type LocalAiStatus = 'checking' | 'unsupported' | 'idle' | 'loading' | 'ready' | 'generating' | 'error';

export interface LocalAiRequest {
  purpose: string;
  messages: { role: 'system' | 'user' | 'assistant'; content: string }[];
  max_tokens: number;
  prompt_hash: string;
  format?: ReplyFormat;
}
export interface LocalAiReply { content: string; model: string; prompt_hash: string; usage: CompletionUsage }

interface LocalAi {
  status: LocalAiStatus;
  support: DeviceSupport | null;
  models: LocalModel[];
  modelKey: string;
  modelId: string | null;
  loadedId: string | null;
  cached: Record<string, boolean>;
  progress: { text: string; fraction: number } | null;
  error: string | null;
  setModelKey: (key: string) => void;
  start: () => Promise<void>;
  unload: () => Promise<void>;
  clear: (key: string) => Promise<void>;
  generate: (req: LocalAiRequest, onTokens?: (n: number) => void) => Promise<LocalAiReply>;
  cancel: () => void;
}

const Ctx = createContext<LocalAi | null>(null);
const MODEL_KEY = 'bv-local-model';

export function LocalAiProvider({ children }: { children: ReactNode }) {
  const models = useMemo(availableModels, []);
  const [status, setStatus] = useState<LocalAiStatus>('checking');
  const [support, setSupport] = useState<DeviceSupport | null>(null);
  const [modelKey, setModelKeyState] = useState(() => localStorage.getItem(MODEL_KEY) || models[0]?.key || '');
  const [cached, setCached] = useState<Record<string, boolean>>({});
  const [progress, setProgress] = useState<{ text: string; fraction: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadedId, setLoadedId] = useState<string | null>(null);
  const engine = useRef<MLCEngineInterface | null>(null);
  const worker = useRef<Worker | null>(null);
  const stopReason = useRef<string | null>(null);
  const generating = useRef(false);

  const model = models.find((m) => m.key === modelKey) ?? models[0];
  const modelId = model && support?.ok ? modelIdFor(model, support.f16) : null;

  const refreshCache = useCallback(async (s: DeviceSupport) => {
    const entries = await Promise.all(models.map(async (m) => [m.key, await isCached(modelIdFor(m, s.f16))] as const));
    setCached(Object.fromEntries(entries));
  }, [models]);

  useEffect(() => {
    let live = true;
    checkDevice().then(async (s) => {
      if (!live) return;
      setSupport(s);
      setStatus(s.ok ? 'idle' : 'unsupported');
      if (s.ok) await refreshCache(s);
    });
    return () => { live = false; };
  }, [refreshCache]);

  const release = useCallback(async () => {
    const e = engine.current;
    engine.current = null;
    setLoadedId(null);
    try { await e?.unload(); } catch { /* engine may already be gone */ }
    worker.current?.terminate();
    worker.current = null;
  }, []);

  useEffect(() => () => { release(); }, [release]);

  useEffect(() => {
    const onHide = () => {
      if (document.visibilityState === 'hidden' && generating.current) {
        stopReason.current = 'Blackveil AI stopped because Safari went into the background. Nothing was saved. Keep the app open while it works, then send again.';
        engine.current?.interruptGenerate();
      }
    };
    document.addEventListener('visibilitychange', onHide);
    return () => document.removeEventListener('visibilitychange', onHide);
  }, []);

  const setModelKey = useCallback((key: string) => {
    setModelKeyState(key);
    localStorage.setItem(MODEL_KEY, key);
  }, []);

  const start = useCallback(async () => {
    if (!modelId || !support?.ok) return;
    setError(null);
    setStatus('loading');
    setProgress({ text: 'Preparing…', fraction: 0 });
    try {
      await release();
      try { await navigator.storage?.persist?.(); } catch { /* best effort */ }
      const r = await loadEngine(modelId, (p) => setProgress({ text: p.text, fraction: p.progress }));
      engine.current = r.engine;
      worker.current = r.worker;
      setLoadedId(modelId);
      setStatus('ready');
    } catch (e) {
      await release();
      setError(friendlyError(e));
      setStatus('error');
    } finally {
      setProgress(null);
      refreshCache(support);
    }
  }, [modelId, support, release, refreshCache]);

  const unload = useCallback(async () => {
    await release();
    setStatus(support?.ok ? 'idle' : 'unsupported');
  }, [release, support]);

  const clear = useCallback(async (key: string) => {
    const m = models.find((x) => x.key === key);
    if (!m || !support?.ok) return;
    const id = modelIdFor(m, support.f16);
    if (loadedId === id) await unload();
    try {
      await clearCache(id);
    } catch (e) {
      setError(friendlyError(e));
    }
    await refreshCache(support);
  }, [models, support, loadedId, unload, refreshCache]);

  const generate = useCallback(async (req: LocalAiRequest, onTokens?: (n: number) => void): Promise<LocalAiReply> => {
    const e = engine.current;
    if (!e || !loadedId) throw new Error('Blackveil AI is not running. Open Blackveil AI and tap Start.');
    if (generating.current) throw new Error('Blackveil AI is already working on a reply.');
    generating.current = true;
    stopReason.current = null;
    setStatus('generating');
    try {
      const { content, usage } = await runCompletion(e, req, onTokens, () => !!stopReason.current);
      return { content, model: loadedId, prompt_hash: req.prompt_hash, usage };
    } catch (err) {
      if (stopReason.current) throw new Error(stopReason.current);
      if (err instanceof LocalAiError) {
        if (err.release) await release();
        throw err;
      }
      const msg = friendlyError(err);
      if (/graphics memory|released the model/.test(msg)) await release();
      throw new Error(msg);
    } finally {
      generating.current = false;
      setStatus(engine.current ? 'ready' : 'idle');
    }
  }, [loadedId, release]);

  const cancel = useCallback(() => {
    if (!generating.current) return;
    stopReason.current = 'Stopped. Nothing was saved.';
    engine.current?.interruptGenerate();
  }, []);

  const value = useMemo<LocalAi>(() => ({
    status, support, models, modelKey: model?.key ?? '', modelId, loadedId, cached, progress, error,
    setModelKey, start, unload, clear, generate, cancel,
  }), [status, support, models, model, modelId, loadedId, cached, progress, error, setModelKey, start, unload, clear, generate, cancel]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLocalAi(): LocalAi {
  const v = useContext(Ctx);
  if (!v) throw new Error('useLocalAi must be used inside LocalAiProvider');
  return v;
}
