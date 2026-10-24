/*
# Native Blackveil network discovery engine

Adds support for Blackveil's own built-in network scanner alongside the existing external Nmap agents.
Scans from both engines share the same history, hosts table, audit trail and AI analysis.

1. Modified Tables
- `nmap_scans`
  - `engine` (text, default 'nmap_agent'): which engine runs the scan, 'nmap_agent' or 'native'.
  - `engine_state` (jsonb, nullable): native engine work queue and partial results between progress steps. Server-only.
  - `progress` (int, default 0): real completed-work percentage reported by the native engine.
  - `deadline_at` (timestamptz, nullable): hard user-facing deadline for native scans.
  - `lease_until` (timestamptz, nullable): short worker lease so only one request advances a scan at a time.
  - `profile` check now also allows 'native_quick' and 'native_standard'.
  - `status` check now also allows 'partial' (deadline reached; only part of the planned work finished).

2. Functions
- `nmap_claim_scan` now only hands out scans whose engine is 'nmap_agent', so external agents can never pick up native scans.
- `nmap_native_lease(scan uuid, seconds int)`: atomically takes the worker lease on a running native scan. service_role only.

3. Security
- No policy changes. Users keep read-only access to their own rows; all writes still go through the server.
*/

ALTER TABLE nmap_scans ADD COLUMN IF NOT EXISTS engine text NOT NULL DEFAULT 'nmap_agent';
ALTER TABLE nmap_scans ADD COLUMN IF NOT EXISTS engine_state jsonb;
ALTER TABLE nmap_scans ADD COLUMN IF NOT EXISTS progress int NOT NULL DEFAULT 0;
ALTER TABLE nmap_scans ADD COLUMN IF NOT EXISTS deadline_at timestamptz;
ALTER TABLE nmap_scans ADD COLUMN IF NOT EXISTS lease_until timestamptz;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nmap_scans_engine_check') THEN
    ALTER TABLE nmap_scans ADD CONSTRAINT nmap_scans_engine_check CHECK (engine IN ('nmap_agent','native'));
  END IF;
END $$;

ALTER TABLE nmap_scans DROP CONSTRAINT IF EXISTS nmap_scans_profile_check;
ALTER TABLE nmap_scans ADD CONSTRAINT nmap_scans_profile_check CHECK (profile IN ('discovery','tcp_basic','service','syn','native_quick','native_standard'));
ALTER TABLE nmap_scans DROP CONSTRAINT IF EXISTS nmap_scans_status_check;
ALTER TABLE nmap_scans ADD CONSTRAINT nmap_scans_status_check CHECK (status IN ('queued','running','completed','partial','failed','cancelled'));

CREATE INDEX IF NOT EXISTS nmap_scans_engine_active_idx ON nmap_scans(engine, status) WHERE status IN ('queued','running');

CREATE OR REPLACE FUNCTION public.nmap_claim_scan(p_agent uuid, p_raw_ok boolean)
RETURNS SETOF nmap_scans
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
v_id uuid;
BEGIN
IF EXISTS (SELECT 1 FROM nmap_scans WHERE agent_id = p_agent AND status = 'running') THEN
RETURN;
END IF;
SELECT s.id INTO v_id FROM nmap_scans s
WHERE s.status = 'queued' AND s.engine = 'nmap_agent' AND s.cancel_requested = false AND (p_raw_ok OR s.profile <> 'syn')
ORDER BY s.created_at
FOR UPDATE SKIP LOCKED
LIMIT 1;
IF v_id IS NULL THEN
RETURN;
END IF;
RETURN QUERY UPDATE nmap_scans
SET status = 'running', agent_id = p_agent, started_at = now(), heartbeat_at = now()
WHERE id = v_id
RETURNING *;
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.nmap_claim_scan(uuid, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.nmap_claim_scan(uuid, boolean) TO service_role;

CREATE OR REPLACE FUNCTION public.nmap_native_lease(p_scan uuid, p_seconds int)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
v_id uuid;
BEGIN
UPDATE nmap_scans
SET lease_until = now() + make_interval(secs => LEAST(GREATEST(p_seconds, 5), 60))
WHERE id = p_scan AND engine = 'native' AND status IN ('queued','running')
  AND (lease_until IS NULL OR lease_until < now())
RETURNING id INTO v_id;
RETURN v_id IS NOT NULL;
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.nmap_native_lease(uuid, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.nmap_native_lease(uuid, int) TO service_role;
