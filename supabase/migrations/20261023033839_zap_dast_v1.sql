/*
# OWASP ZAP dynamic scanning (DAST)

1. New Tables
- `zap_scans`: one row per ZAP scan of an ownership-verified target (pob_targets).
  - mode: baseline (spider + passive only), active (adds intrusive active scan), api (OpenAPI import + passive, optional active)
  - status: queued, running, completed, failed, cancelled; phase + progress (0-100) for live tracking
  - target_url, config (limits used), zap_context, spider_id, ascan_id (ZAP job ids, server-only meaning)
  - authorization_statement + authorized_at: the exact confirmation the user gave
  - cancel_requested, deadline_at, error, counts (alerts by risk), zap_version
- `zap_alerts`: one row per ZAP rule (pluginId) per scan, with all instances (url, method, param, evidence, attack)
  aggregated in `instances`. Stores description, solution, references, CWE/WASC, ZAP risk + confidence,
  and AI analysis fields (ai_status, ai_analysis, ai_error).

2. Security
- RLS enabled on both tables. Users may only SELECT their own rows; users may DELETE their own finished scans.
- All writes happen server-side (service role) so results cannot be forged from the browser.
- Partial unique index allows only one queued/running ZAP scan per user (duplicate prevention).

3. Notes
1. Additive only. Reuses pob_targets (ownership verification), pob_audit (audit trail) and pob_control (emergency stop).
*/

CREATE TABLE IF NOT EXISTS zap_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_id uuid NOT NULL REFERENCES pob_targets(id) ON DELETE CASCADE,
  hostname text NOT NULL,
  target_url text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('baseline','active','api')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled')),
  phase text NOT NULL DEFAULT 'queued',
  progress int NOT NULL DEFAULT 0,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  zap_context text,
  spider_id text,
  ascan_id text,
  zap_version text,
  authorization_statement text NOT NULL,
  authorized_at timestamptz NOT NULL DEFAULT now(),
  cancel_requested boolean NOT NULL DEFAULT false,
  counts jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  deadline_at timestamptz NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  phase_started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS zap_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES zap_scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  plugin_id text NOT NULL,
  name text NOT NULL,
  risk text NOT NULL CHECK (risk IN ('high','medium','low','info')),
  confidence text NOT NULL DEFAULT 'medium',
  description text NOT NULL DEFAULT '',
  solution text NOT NULL DEFAULT '',
  reference text NOT NULL DEFAULT '',
  other_info text NOT NULL DEFAULT '',
  cwe_id int,
  wasc_id int,
  source text NOT NULL DEFAULT 'passive',
  instance_count int NOT NULL DEFAULT 0,
  instances jsonb NOT NULL DEFAULT '[]'::jsonb,
  ai_status text NOT NULL DEFAULT 'none' CHECK (ai_status IN ('none','pending','ready','failed')),
  ai_analysis jsonb,
  ai_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS zap_scans_user_idx ON zap_scans(user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS zap_scans_target_idx ON zap_scans(target_id);
CREATE INDEX IF NOT EXISTS zap_scans_active_idx ON zap_scans(status) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX IF NOT EXISTS zap_one_active_scan ON zap_scans(user_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS zap_alerts_scan_idx ON zap_alerts(scan_id);
CREATE INDEX IF NOT EXISTS zap_alerts_user_idx ON zap_alerts(user_id);

ALTER TABLE zap_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE zap_alerts ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON zap_scans, zap_alerts FROM anon, authenticated;
GRANT SELECT, DELETE ON zap_scans TO authenticated;
GRANT SELECT ON zap_alerts TO authenticated;
GRANT ALL ON zap_scans, zap_alerts TO service_role;

DROP POLICY IF EXISTS "select_own_zap_scans" ON zap_scans;
CREATE POLICY "select_own_zap_scans" ON zap_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "delete_own_finished_zap_scans" ON zap_scans;
CREATE POLICY "delete_own_finished_zap_scans" ON zap_scans FOR DELETE TO authenticated
  USING (auth.uid() = user_id AND status NOT IN ('queued','running'));
DROP POLICY IF EXISTS "select_own_zap_alerts" ON zap_alerts;
CREATE POLICY "select_own_zap_alerts" ON zap_alerts FOR SELECT TO authenticated USING (auth.uid() = user_id);
