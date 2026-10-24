import {
  CreateMLCEngine, CreateWebWorkerMLCEngine, deleteModelAllInfoInCache, hasModelInCache, prebuiltAppConfig,
  type InitProgressReport, type MLCEngineInterface,
} from '@mlc-ai/web-llm';
import { LOCAL_CONTEXT_TOKENS, LOCAL_MODELS, type LocalModel } from '../../../supabase/functions/_lib/localModels.ts';

export interface DeviceSupport {
  ok: boolean;
  reason: string;
  f16: boolean;
  storageFreeMB: number | null;
  persisted: boolean | null;
}

interface GpuAdapterLike { features: { has(name: string): boolean } }
interface GpuLike { requestAdapter(opts?: { powerPreference?: string }): Promise<GpuAdapterLike | null> }

export const isAppleMobile = () => /iPhone|iPad|iPod/.test(navigator.userAgent)
  || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

export async function checkDevice(): Promise<DeviceSupport> {
  const gpu = (navigator as unknown as { gpu?: GpuLike }).gpu;
  let storageFreeMB: number | null = null;
  let persisted: boolean | null = null;
  try {
    const est = await navigator.storage?.estimate?.();
    if (est?.quota != null) storageFreeMB = Math.floor(((est.quota ?? 0) - (est.usage ?? 0)) / 1_048_576);
    persisted = (await navigator.storage?.persisted?.()) ?? null;
  } catch { /* storage estimate is optional */ }
  const base = { f16: false, storageFreeMB, persisted };
  if (!window.isSecureContext) return { ...base, ok: false, reason: 'Blackveil AI needs a secure (https) page.' };
  if (!gpu) {
    return {
      ...base, ok: false,
      reason: isAppleMobile()
        ? 'This browser does not offer WebGPU, which Blackveil AI needs to run on your phone. Use Safari on iOS 26 or newer.'
        : 'This browser does not offer WebGPU, which Blackveil AI needs to run on your device. Use a recent Safari, Chrome or Edge.',
    };
  }
  try {
    const adapter = await gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) return { ...base, ok: false, reason: 'WebGPU is present but no graphics adapter is available on this device.' };
    return { ...base, ok: true, reason: '', f16: adapter.features.has('shader-f16') };
  } catch {
    return { ...base, ok: false, reason: 'The graphics adapter could not be opened. Close other tabs and try again.' };
  }
}

export function modelIdFor(model: LocalModel, f16: boolean): string {
  return f16 ? model.ids.f16 : model.ids.f32;
}

export function availableModels(): LocalModel[] {
  const known = new Set(prebuiltAppConfig.model_list.map((m) => m.model_id));
  return LOCAL_MODELS.filter((m) => known.has(m.ids.f16) && known.has(m.ids.f32));
}

export function vramMB(modelId: string): number | null {
  return prebuiltAppConfig.model_list.find((m) => m.model_id === modelId)?.vram_required_MB ?? null;
}

export const isCached = (modelId: string) => hasModelInCache(modelId).catch(() => false);
export const clearCache = (modelId: string) => deleteModelAllInfoInCache(modelId);

export async function loadEngine(modelId: string, onProgress: (r: InitProgressReport) => void): Promise<{ engine: MLCEngineInterface; worker: Worker | null }> {
  const chatOpts = { context_window_size: LOCAL_CONTEXT_TOKENS };
  let worker: Worker | null = null;
  try {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    const engine = await CreateWebWorkerMLCEngine(worker, modelId, { initProgressCallback: onProgress }, chatOpts);
    return { engine, worker };
  } catch (e) {
    worker?.terminate();
    // Some browsers expose WebGPU only to the page, not to background workers; retry on the page itself.
    if (!/gpu/i.test(String((e as Error)?.message ?? e))) throw e;
  }
  return { engine: await CreateMLCEngine(modelId, { initProgressCallback: onProgress }, chatOpts), worker: null };
}

export function friendlyError(e: unknown): string {
  const msg = String((e as Error)?.message ?? e);
  if (/quota|storage|QuotaExceeded/i.test(msg)) return 'Not enough storage space on this device to save the model. Free up space or choose the smaller model.';
  if (/device.*lost|lost.*device|GPUDevice/i.test(msg)) return 'The device released the model from graphics memory (this happens when Safari is in the background or memory is low). Tap Start to reload it from the saved copy.';
  if (/out of memory|OOM|allocation|too large|maxBufferSize|maxStorageBuffer/i.test(msg)) return 'This device does not have enough graphics memory for this model. Choose the smaller model or close other apps and tabs.';
  if (/context window|exceed.*context|prompt.*too long/i.test(msg)) return 'This request is too large for the on-device model. Ask for a smaller, more focused change.';
  if (/fetch|network|Failed to load|NetworkError/i.test(msg)) return 'The model download was interrupted. Check your connection and tap Start to resume.';
  if (/shader-f16|feature/i.test(msg)) return 'This device does not support the features this model needs.';
  return `Blackveil AI stopped: ${msg.slice(0, 200)}`;
}
