/*
# Nmap network scanning (external scanner agents)

1. New Tables
- `nmap_agents`: admin-registered external scanner machines. Stores only a SHA-256 hash of the agent token,
  plus last health report (nmap version/path, privileged, raw packet capability, last_seen_at). Server-only.
- `nmap_scopes`: administrator-approved network ranges (CIDR) granted to a specific user. Required for scanning
  IP addresses / CIDR ranges and any private, loopback or reserved address.
- `nmap_scans`: one row per network scan: target input, resolved targets, authorization basis, profile, fixed
  nmap arguments, status lifecycle (queued, running, completed, failed, cancelled), timestamps, duration,
  summary counts, nmap version, errors, cancel flag, AI analysis fields.
- `nmap_hosts`: parsed results per discovered host (address, hostnames, state, ports jsonb incl. services,
  extraports counts).
- `nmap_audit`: append-only audit trail of requests, cancellations, agent and scope changes.

2. Functions
- `nmap_claim_scan(agent uuid, raw_ok boolean)`: atomically hands the oldest queued scan to an agent
  (FOR UPDATE SKIP LOCKED). Executable by service_role only.

3. Security
- RLS on every table. Users may SELECT their own scans, hosts, scopes and audit entries. Agents table has no
  user access at all. All writes go through edge functions using the service role, so results, scopes and
  approvals cannot be forged from the browser.
- One queued/running scan per user (partial unique index).
*/

CREATE TABLE IF NOT EXISTS nmap_agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  revoked boolean NOT NULL DEFAULT false,
  last_seen_at timestamptz,
  nmap_version text,
  nmap_available boolean NOT NULL DEFAULT false,
  privileged boolean NOT NULL DEFAULT false,
  raw_capable boolean NOT NULL DEFAULT false,
  health jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nmap_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  cidr text NOT NULL,
  label text NOT NULL DEFAULT '',
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nmap_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_input text NOT NULL,
  target_kind text NOT NULL CHECK (target_kind IN ('ip','cidr','hostname')),
  targets text[] NOT NULL,
  auth_basis text NOT NULL CHECK (auth_basis IN ('verified_domain','approved_scope')),
  pob_target_id uuid REFERENCES pob_targets(id) ON DELETE SET NULL,
  scope_id uuid REFERENCES nmap_scopes(id) ON DELETE SET NULL,
  profile text NOT NULL CHECK (profile IN ('discovery','tcp_basic','service','syn')),
  args text[] NOT NULL,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled')),
  agent_id uuid REFERENCES nmap_agents(id) ON DELETE SET NULL,
  cancel_requested boolean NOT NULL DEFAULT false,
  authorization_statement text NOT NULL,
  authorized_at timestamptz NOT NULL DEFAULT now(),
  timeout_seconds int NOT NULL,
  nmap_version text,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms int,
  heartbeat_at timestamptz,
  ai_status text NOT NULL DEFAULT 'none' CHECK (ai_status IN ('none','pending','ready','failed')),
  ai_analysis jsonb,
  ai_error text
);

CREATE TABLE IF NOT EXISTS nmap_hosts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES nmap_scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  address text NOT NULL,
  hostnames text[] NOT NULL DEFAULT '{}',
  state text NOT NULL,
  reason text NOT NULL DEFAULT '',
  ports jsonb NOT NULL DEFAULT '[]'::jsonb,
  extraports jsonb NOT NULL DEFAULT '[]'::jsonb,
  UNIQUE (scan_id, address)
);

CREATE TABLE IF NOT EXISTS nmap_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  actor text NOT NULL CHECK (actor IN ('user','admin','agent','system')),
  action text NOT NULL,
  scan_id uuid,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS nmap_scans_user_idx ON nmap_scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS nmap_scans_active_idx ON nmap_scans(status, created_at) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX IF NOT EXISTS nmap_one_active_scan ON nmap_scans(user_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS nmap_hosts_scan_idx ON nmap_hosts(scan_id);
CREATE INDEX IF NOT EXISTS nmap_hosts_user_idx ON nmap_hosts(user_id);
CREATE INDEX IF NOT EXISTS nmap_scopes_user_idx ON nmap_scopes(user_id);
CREATE INDEX IF NOT EXISTS nmap_audit_user_idx ON nmap_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS nmap_scans_agent_idx ON nmap_scans(agent_id);
CREATE INDEX IF NOT EXISTS nmap_scans_scope_idx ON nmap_scans(scope_id);
CREATE INDEX IF NOT EXISTS nmap_scans_pob_idx ON nmap_scans(pob_target_id);

ALTER TABLE nmap_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE nmap_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE nmap_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE nmap_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE nmap_audit ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON nmap_agents, nmap_scopes, nmap_scans, nmap_hosts, nmap_audit FROM anon, authenticated;
GRANT SELECT ON nmap_scopes, nmap_scans, nmap_hosts, nmap_audit TO authenticated;
GRANT ALL ON nmap_agents, nmap_scopes, nmap_scans, nmap_hosts, nmap_audit TO service_role;

DROP POLICY IF EXISTS "select_own_nmap_scopes" ON nmap_scopes;
CREATE POLICY "select_own_nmap_scopes" ON nmap_scopes FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_nmap_scans" ON nmap_scans;
CREATE POLICY "select_own_nmap_scans" ON nmap_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_nmap_hosts" ON nmap_hosts;
CREATE POLICY "select_own_nmap_hosts" ON nmap_hosts FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_nmap_audit" ON nmap_audit;
CREATE POLICY "select_own_nmap_audit" ON nmap_audit FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION nmap_claim_scan(p_agent uuid, p_raw_ok boolean)
RETURNS SETOF nmap_scans
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM nmap_scans WHERE agent_id = p_agent AND status = 'running') THEN
    RETURN;
  END IF;
  SELECT s.id INTO v_id FROM nmap_scans s
  WHERE s.status = 'queued' AND s.cancel_requested = false AND (p_raw_ok OR s.profile <> 'syn')
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
$$;

REVOKE EXECUTE ON FUNCTION nmap_claim_scan(uuid, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION nmap_claim_scan(uuid, boolean) TO service_role;