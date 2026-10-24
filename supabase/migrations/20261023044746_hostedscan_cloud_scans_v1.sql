/*
# HostedScan cloud Nmap scans

1. New Tables
- `hostedscan_scans` - one row per cloud Nmap scan launched through HostedScan
  - `id` (uuid, pk), `user_id` (owner)
  - `hs_scan_id` (text) HostedScan's scan id
  - `scan_type` (NMAP | NMAP_UDP)
  - `target` (text) validated hostname or public IPv4
  - `auth_basis` (verified_domain | approved_scope), `pob_target_id`, `scope_id`
  - `status` (queued | running | stopping | succeeded | failed | stopped | over_limit)
  - `progress` (0-100), `error`, `risks` (jsonb findings from HostedScan), `skipped` (jsonb)
  - `authorization_statement`, `created_at`, `updated_at`, `finished_at`
2. Security
- RLS enabled. Signed-in users may only SELECT their own rows.
- No INSERT/UPDATE/DELETE grants for users: all writes happen in the server function (service_role).
3. Notes
1. A partial unique index allows only one active cloud scan per user.
*/

CREATE TABLE IF NOT EXISTS hostedscan_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  hs_scan_id text,
  scan_type text NOT NULL CHECK (scan_type IN ('NMAP','NMAP_UDP')),
  target text NOT NULL,
  auth_basis text NOT NULL CHECK (auth_basis IN ('verified_domain','approved_scope')),
  pob_target_id uuid,
  scope_id uuid,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','stopping','succeeded','failed','stopped','over_limit')),
  progress int NOT NULL DEFAULT 0,
  error text,
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  skipped jsonb NOT NULL DEFAULT '[]'::jsonb,
  authorization_statement text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS hostedscan_scans_user_created_idx ON hostedscan_scans (user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS hostedscan_scans_one_active ON hostedscan_scans (user_id) WHERE status IN ('queued','running','stopping');

ALTER TABLE hostedscan_scans ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON hostedscan_scans TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON hostedscan_scans TO service_role;

DROP POLICY IF EXISTS "select_own_hostedscan_scans" ON hostedscan_scans;
CREATE POLICY "select_own_hostedscan_scans" ON hostedscan_scans FOR SELECT
  TO authenticated USING (auth.uid() = user_id);
