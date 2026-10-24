/*
# Endpoint malware remediation (agent-based)

Adds the tables behind real device scanning and remediation. A user enrolls a
device; a locally-installed agent (Microsoft Defender based) authenticates with
a per-device token, pulls approved jobs, and reports results. The browser can
only READ these tables; every write goes through server functions, so the
browser can never claim a scan or removal succeeded.

1. New Tables
- `endpoint_devices`: one row per enrolled device.
  - `user_id` owner, `name`, `os`, `os_version`, `agent_version`
  - `token_hash` (sha256 of the device token; the raw token is never stored)
  - `allowed_scopes` (text[]: quick/full/custom), `allowed_paths` (text[] for custom scans)
  - `engine_status` (jsonb snapshot reported by the agent: Defender versions, realtime protection)
  - `last_seen_at`, `last_scan_at`, `last_scan_status`, `revoked_at`, `created_at`
- `endpoint_jobs`: commands for the agent.
  - `kind` scan | remediate | restore | verify, `params` jsonb, `status`
    pending_approval | queued | dispatched | succeeded | failed | expired | cancelled
  - `requested_by`, `approved_by`, `approved_at`, `dispatched_at`, `completed_at`,
    `expires_at`, `attempts`, `result` jsonb, `error`
- `endpoint_threats`: detections reported by the engine.
  - `engine_threat_id`, `name`, `severity`, `category`, `resources` text[],
    `sha256`, `detection_source`, `status` detected | awaiting_approval | quarantined |
    removed | failed | restored | verified_clean, `times_seen`, `first_seen_at`, `last_seen_at`,
    `verification` jsonb
- `endpoint_audit`: who authorized what, what was attempted and the verified outcome.

2. Security
- RLS enabled on all four tables.
- `authenticated` gets SELECT only, scoped to own rows. No INSERT/UPDATE/DELETE grants
  for browser roles; `service_role` (server functions) performs writes.
- `token_hash` is not granted to `authenticated` (column-level SELECT grant).

3. Notes
1. Device tokens are hashed with sha256; revocation sets `revoked_at`.
2. Threat rows are keyed on (device_id, engine_threat_id) for repeat-detection tracking.
*/

CREATE TABLE IF NOT EXISTS public.endpoint_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  os text NOT NULL DEFAULT 'windows',
  os_version text,
  agent_version text,
  token_hash text NOT NULL UNIQUE,
  allowed_scopes text[] NOT NULL DEFAULT ARRAY['quick']::text[],
  allowed_paths text[] NOT NULL DEFAULT ARRAY[]::text[],
  engine_status jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_seen_at timestamptz,
  last_scan_at timestamptz,
  last_scan_status text,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.endpoint_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES public.endpoint_devices(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('scan','remediate','restore','verify')),
  params jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('pending_approval','queued','dispatched','succeeded','failed','expired','cancelled')),
  requested_by uuid NOT NULL,
  approved_by uuid,
  approved_at timestamptz,
  dispatched_at timestamptz,
  completed_at timestamptz,
  expires_at timestamptz NOT NULL DEFAULT now() + interval '2 hours',
  attempts int NOT NULL DEFAULT 0,
  result jsonb,
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_jobs_device_status_idx ON public.endpoint_jobs(device_id, status);
CREATE INDEX IF NOT EXISTS endpoint_jobs_user_created_idx ON public.endpoint_jobs(user_id, created_at);

CREATE TABLE IF NOT EXISTS public.endpoint_threats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES public.endpoint_devices(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  engine_threat_id text NOT NULL,
  name text NOT NULL,
  severity text NOT NULL DEFAULT 'unknown',
  category text,
  resources text[] NOT NULL DEFAULT ARRAY[]::text[],
  sha256 text,
  detection_source text NOT NULL DEFAULT 'Microsoft Defender Antivirus',
  status text NOT NULL DEFAULT 'detected' CHECK (status IN ('detected','awaiting_approval','quarantined','removed','failed','restored','verified_clean')),
  engine_action text,
  times_seen int NOT NULL DEFAULT 1,
  verification jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, engine_threat_id)
);
CREATE INDEX IF NOT EXISTS endpoint_threats_user_idx ON public.endpoint_threats(user_id);

CREATE TABLE IF NOT EXISTS public.endpoint_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id uuid REFERENCES public.endpoint_devices(id) ON DELETE CASCADE,
  job_id uuid REFERENCES public.endpoint_jobs(id) ON DELETE SET NULL,
  actor text NOT NULL,
  action text NOT NULL,
  outcome text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_audit_device_idx ON public.endpoint_audit(device_id, created_at DESC);

ALTER TABLE public.endpoint_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.endpoint_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.endpoint_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.endpoint_audit ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.endpoint_devices, public.endpoint_jobs, public.endpoint_threats, public.endpoint_audit FROM anon, authenticated;
GRANT SELECT (id, user_id, name, os, os_version, agent_version, allowed_scopes, allowed_paths, engine_status, last_seen_at, last_scan_at, last_scan_status, revoked_at, created_at) ON public.endpoint_devices TO authenticated;
GRANT SELECT ON public.endpoint_jobs, public.endpoint_threats, public.endpoint_audit TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.endpoint_devices, public.endpoint_jobs, public.endpoint_threats, public.endpoint_audit TO service_role;

DROP POLICY IF EXISTS "select_own_endpoint_devices" ON public.endpoint_devices;
CREATE POLICY "select_own_endpoint_devices" ON public.endpoint_devices FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_endpoint_jobs" ON public.endpoint_jobs;
CREATE POLICY "select_own_endpoint_jobs" ON public.endpoint_jobs FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_endpoint_threats" ON public.endpoint_threats;
CREATE POLICY "select_own_endpoint_threats" ON public.endpoint_threats FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_endpoint_audit" ON public.endpoint_audit;
CREATE POLICY "select_own_endpoint_audit" ON public.endpoint_audit FOR SELECT TO authenticated USING (auth.uid() = user_id);
