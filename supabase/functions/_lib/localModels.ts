// Models verified against the WebLLM 0.2.86 prebuilt catalog. The f16/f32 variants are chosen at runtime
// based on whether the device's WebGPU adapter supports 16-bit shaders.
export interface LocalModel {
  key: string;
  label: string;
  ids: { f16: string; f32: string };
  approxDownloadMB: number;
  note: string;
}

export const LOCAL_MODELS: LocalModel[] = [
  {
    key: "coder-0.5b",
    label: "Qwen2.5 Coder 0.5B",
    ids: { f16: "Qwen2.5-Coder-0.5B-Instruct-q4f16_1-MLC", f32: "Qwen2.5-Coder-0.5B-Instruct-q4f32_1-MLC" },
    approxDownloadMB: 300,
    note: "Smallest and fastest. Fits most recent iPhones. Best for small, focused edits.",
  },
  {
    key: "coder-1.5b",
    label: "Qwen2.5 Coder 1.5B",
    ids: { f16: "Qwen2.5-Coder-1.5B-Instruct-q4f16_1-MLC", f32: "Qwen2.5-Coder-1.5B-Instruct-q4f32_1-MLC" },
    approxDownloadMB: 900,
    note: "Noticeably better code, but needs about 2 GB of graphics memory. Recommended for iPhone 15 Pro or newer.",
  },
];

export const LOCAL_MODEL_IDS = LOCAL_MODELS.flatMap((m) => [m.ids.f16, m.ids.f32]);
export const LOCAL_CONTEXT_TOKENS = 8192;
