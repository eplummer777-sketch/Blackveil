/*
# BLACKVEIL OS — isolated Linux execution workspace

1. New Tables
- `bv_workers`: Linux execution hosts registered by an administrator. Each stores only a SHA-256
  hash of its secret token (the raw token is never stored), plus version, health capabilities,
  last-seen time and revocation status.
- `bv_sessions`: one row per user workspace session. Isolates a user's terminal from other users.
  Owned by the authenticated user.
- `bv_jobs`: one row per command execution inside the isolated sandbox. Carries the allowlisted
  command, lifecycle status, exit code, size-capped output, dispatch state, cancel flag and deadline.
- `bv_audit`: append-only audit trail of workspace actions for accountability.

2. Functions
- `bv_claim_job(p_worker uuid)`: atomically hands the oldest queued job to a worker
  (FOR UPDATE SKIP LOCKED), mirroring the existing nmap_claim_scan. service_role only.
- `bv_append_job_output(p_job uuid, p_stdout text, p_stderr text)`: appends sandbox output chunks
  with a server-side size cap so a worker can stream results across requests. service_role only.

3. Security
- RLS on every table. Users may only SELECT their own sessions, jobs and audit rows; all writes go
  through the bv-terminal / bv-worker edge functions via service_role, so commands, output and status
  cannot be forged from the browser. Workers have no browser-role access at all (token-hash column is
  not granted to any browser role). A partial unique index limits each user to one queued/running job.

4. Notes
1. The Docker sandbox itself is enforced by the external worker (network disabled, read-only root,
   non-root user, resource caps); this schema records the authorized jobs and their verified output,
   and holds the re-check policy a worker must honor before executing anything.
2. Additive only. No existing tables are modified.
*/

CREATE TABLE IF NOT EXISTS public.bv_workers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  revoked boolean NOT NULL DEFAULT false,
  last_seen_at timestamptz,
  version text,
  caps jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.bv_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  label text NOT NULL DEFAULT 'Terminal',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS public.bv_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  session_id uuid REFERENCES public.bv_sessions(id) ON DELETE SET NULL,
  worker_id uuid REFERENCES public.bv_workers(id) ON DELETE SET NULL,
  kind text NOT NULL DEFAULT 'shell' CHECK (kind IN ('shell','tool')),
  command text NOT NULL,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled','rejected')),
  cancel_requested boolean NOT NULL DEFAULT false,
  exit_code int,
  stdout text,
  stderr text,
  error text,
  deadline_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms int
);

CREATE TABLE IF NOT EXISTS public.bv_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bv_sessions_user_idx ON public.bv_sessions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bv_jobs_user_idx ON public.bv_jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bv_jobs_active_idx ON public.bv_jobs(status, created_at) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX IF NOT EXISTS bv_one_active_job ON public.bv_jobs(user_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS bv_jobs_session_idx ON public.bv_jobs(session_id);
CREATE INDEX IF NOT EXISTS bv_audit_user_idx ON public.bv_audit(user_id, created_at DESC);

ALTER TABLE public.bv_workers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bv_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bv_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bv_audit ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.bv_workers, public.bv_sessions, public.bv_jobs, public.bv_audit FROM anon, authenticated;
GRANT SELECT ON public.bv_sessions, public.bv_jobs, public.bv_audit TO authenticated;
GRANT ALL ON public.bv_workers, public.bv_sessions, public.bv_jobs, public.bv_audit TO service_role;

DROP POLICY IF EXISTS "select_own_bv_sessions" ON public.bv_sessions;
CREATE POLICY "select_own_bv_sessions" ON public.bv_sessions FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "select_own_bv_jobs" ON public.bv_jobs;
CREATE POLICY "select_own_bv_jobs" ON public.bv_jobs FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "select_own_bv_audit" ON public.bv_audit;
CREATE POLICY "select_own_bv_audit" ON public.bv_audit FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.bv_claim_job(p_worker uuid)
RETURNS SETOF public.bv_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM public.bv_jobs WHERE worker_id = p_worker AND status = 'running') THEN
    RETURN;
  END IF;
  SELECT j.id INTO v_id
  FROM public.bv_jobs j
  WHERE j.status = 'queued' AND j.cancel_requested = false AND j.deadline_at > now()
  ORDER BY j.created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;
  IF v_id IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY UPDATE public.bv_jobs
    SET status = 'running', worker_id = p_worker, started_at = now()
    WHERE id = v_id
    RETURNING *;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.bv_claim_job(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bv_claim_job(uuid) TO service_role;

CREATE OR REPLACE FUNCTION public.bv_append_job_output(p_job uuid, p_stdout text, p_stderr text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_out text;
  v_err text;
BEGIN
  SELECT stdout, stderr INTO v_out, v_err FROM public.bv_jobs WHERE id = p_job FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  UPDATE public.bv_jobs SET
    stdout = left(coalesce(v_out, '') || coalesce(p_stdout, ''), 60000),
    stderr = left(coalesce(v_err, '') || coalesce(p_stderr, ''), 60000)
  WHERE id = p_job;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.bv_append_job_output(uuid, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bv_append_job_output(uuid, text, text) TO service_role;
