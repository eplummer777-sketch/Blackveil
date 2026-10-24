import { callEdge } from '@/lib/supabase';

export interface BvWorkerCap {
  docker: boolean;
  docker_version: string | null;
  image: string | null;
  platform: string | null;
  node?: string | null;
  sandbox_ok?: boolean;
  sandbox_error?: string | null;
  selftest_uid?: string | null;
  network_isolated?: boolean;
  checked_at?: string;
}

export type BvWorkerState = 'online' | 'unhealthy' | 'unauthorized' | 'offline';

export interface BvWorker {
  id: string;
  name: string;
  online: boolean;
  state: BvWorkerState;
  reason: string;
  revoked: boolean;
  created_at: string;
  last_seen_at: string | null;
  last_auth_fail_at: string | null;
  token_prefix: string | null;
  version: string | null;
  caps: BvWorkerCap | Record<string, never>;
}

export const WORKER_STATE_STYLE: Record<BvWorkerState, { label: string; dot: string; pill: string }> = {
  online: { label: 'Online', dot: 'bg-emerald-400', pill: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' },
  unhealthy: { label: 'Unhealthy', dot: 'bg-amber-400', pill: 'border-amber-500/30 bg-amber-500/10 text-amber-200' },
  unauthorized: { label: 'Unauthorized', dot: 'bg-rose-400', pill: 'border-rose-500/30 bg-rose-500/10 text-rose-200' },
  offline: { label: 'Offline', dot: 'bg-slate-600', pill: 'border-slate-700 text-slate-400' },
};

export interface BvSandbox {
  version: string;
  isolation: string;
  network: string;
  fs: string;
  user: string;
}

export type BvJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'rejected';

export interface BvJob {
  id: string;
  user_id: string;
  session_id: string | null;
  worker_id: string | null;
  kind: 'shell' | 'tool';
  command: string;
  status: BvJobStatus;
  cancel_requested: boolean;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  error: string | null;
  deadline_at: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface BvSession {
  id: string;
  user_id: string;
  label: string;
  created_at: string;
  last_used_at: string | null;
}

export interface BvStatus {
  sandbox: BvSandbox;
  workers: BvWorker[];
  workersOnline: number;
  workersTotal: number;
  sessions: BvSession[];
  jobs: BvJob[];
  admin: boolean;
}

export function callBv<T>(token: string, body: Record<string, unknown>) {
  return callEdge<T>('bv-terminal', body, token);
}

export function jobOutput(job: BvJob): string {
  const out = job.stdout ?? '';
  const err = job.stderr ?? '';
  if (!out && !err) return '';
  if (out && err) return out + '\n' + err;
  return out || err;
}

export const JOB_TONE: Record<BvJobStatus, 'green' | 'cyan' | 'rose' | 'slate' | 'amber'> = {
  completed: 'green',
  running: 'cyan',
  queued: 'cyan',
  failed: 'rose',
  cancelled: 'amber',
  rejected: 'slate',
};

export const JOB_LABEL: Record<BvJobStatus, string> = {
  queued: 'queued',
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  cancelled: 'cancelled',
  rejected: 'rejected',
};
