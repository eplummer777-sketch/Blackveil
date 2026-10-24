export type ResourceLimits = { cpu: number; memoryMb: number };

export const DEFAULT_LIMITS: ResourceLimits = { cpu: 1, memoryMb: 1024 };
export const MAX_LIMITS: ResourceLimits = { cpu: 2, memoryMb: 4096 };

export type ProvisionResult =
  | { ok: true; externalId: string; baseUrl: string }
  | { ok: false; error: string };

export interface ScannerProvider {
  readonly id: string;
  readonly configured: boolean;
  create(ownerId: string, limits: ResourceLimits): Promise<ProvisionResult>;
  restart(externalId: string): Promise<{ ok: boolean; error?: string }>;
  shutdown(externalId: string): Promise<{ ok: boolean; error?: string }>;
  destroy(externalId: string): Promise<{ ok: boolean; error?: string }>;
}

export function validateLimits(raw: unknown): { value: ResourceLimits } | { error: string } {
  const r = (raw ?? {}) as Partial<ResourceLimits>;
  const cpu = r.cpu ?? DEFAULT_LIMITS.cpu;
  const memoryMb = r.memoryMb ?? DEFAULT_LIMITS.memoryMb;
  if (!Number.isFinite(cpu) || cpu < 0.5 || cpu > MAX_LIMITS.cpu) return { error: `CPU must be between 0.5 and ${MAX_LIMITS.cpu}.` };
  if (!Number.isInteger(memoryMb) || memoryMb < 512 || memoryMb > MAX_LIMITS.memoryMb) return { error: `Memory must be between 512 and ${MAX_LIMITS.memoryMb} MB.` };
  return { value: { cpu, memoryMb } };
}

const NOT_CONFIGURED = "Automatic scanner hosting is not set up yet. Connect your own ZAP server instead.";

export const unconfiguredProvider: ScannerProvider = {
  id: "none",
  configured: false,
  create: () => Promise.resolve({ ok: false, error: NOT_CONFIGURED }),
  restart: () => Promise.resolve({ ok: false, error: NOT_CONFIGURED }),
  shutdown: () => Promise.resolve({ ok: false, error: NOT_CONFIGURED }),
  destroy: () => Promise.resolve({ ok: false, error: NOT_CONFIGURED }),
};

export function getProvider(): ScannerProvider {
  return unconfiguredProvider;
}
