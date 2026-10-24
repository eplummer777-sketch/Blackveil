/*
# Proof-of-Breach AI (Elite plan)

1. New Tables
- `pob_targets`: websites a user wants to test. Testing is only allowed once ownership is proven
  with a DNS TXT record (`_blackveil-verify.<host>` = verify_token). Stores scope (allowed paths),
  allowed test categories, testing window expiry, rate limit and status.
- `pob_scans`: one row per quick assessment or retest. Status, phase, deadline, score, counts, duration.
- `pob_checks`: one row per security check inside a scan. Result (passed/failed/partial/incomplete/
  not_performed), severity, confidence, validation status (detected/suspected/validated), sanitized
  evidence, tool + version + exact operation executed, AI analysis, remediation and retest status.
- `pob_audit`: append-only audit trail (target changes, verifications, scans, scope violations,
  approvals, retests, report exports).
- `pob_control`: single-row emergency stop switch (paused flag). Server-only.

2. Security
- RLS enabled on all tables.
- Users may only SELECT their own rows; all writes go through the server (service role), so
  results, scores and authorization can not be forged from the browser.
- Users may DELETE their own finished scans (history deletion). Audit rows are kept (scan_id set null).
- `pob_control` has no client access.

3. Notes
1. Additive only; no existing data touched.
*/

CREATE TABLE IF NOT EXISTS pob_targets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  hostname text NOT NULL,
  label text NOT NULL DEFAULT '',
  environment text NOT NULL DEFAULT 'production' CHECK (environment IN ('production','staging','development')),
  verify_token text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','expired','revoked')),
  verification_method text,
  verified_at timestamptz,
  expires_at timestamptz,
  allowed_paths text[] NOT NULL DEFAULT ARRAY['/'],
  allowed_categories text[] NOT NULL DEFAULT ARRAY['transport','headers','cookies','exposure','cors'],
  max_requests_per_scan int NOT NULL DEFAULT 40,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, hostname)
);

CREATE TABLE IF NOT EXISTS pob_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_id uuid NOT NULL REFERENCES pob_targets(id) ON DELETE CASCADE,
  hostname text NOT NULL,
  kind text NOT NULL DEFAULT 'quick' CHECK (kind IN ('quick','retest')),
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','partial','stopped','failed')),
  phase text NOT NULL DEFAULT 'authorization',
  stop_requested boolean NOT NULL DEFAULT false,
  deadline_at timestamptz NOT NULL,
  score int,
  counts jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS pob_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES pob_scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  check_key text NOT NULL,
  title text NOT NULL,
  category text NOT NULL,
  result text NOT NULL CHECK (result IN ('passed','failed','partial','incomplete','not_performed')),
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('critical','high','medium','low','info')),
  confidence text NOT NULL DEFAULT 'high' CHECK (confidence IN ('high','medium','low')),
  validation text NOT NULL DEFAULT 'detected' CHECK (validation IN ('detected','suspected','validated','unresolved')),
  affected_asset text NOT NULL DEFAULT '',
  summary text NOT NULL DEFAULT '',
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  tool text NOT NULL,
  tool_version text NOT NULL,
  operation text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  ai_status text NOT NULL DEFAULT 'none' CHECK (ai_status IN ('none','pending','ready','failed')),
  ai_analysis jsonb,
  ai_error text,
  remediation_status text NOT NULL DEFAULT 'open' CHECK (remediation_status IN ('open','fix_approved','fix_applied_by_user')),
  retest_status text NOT NULL DEFAULT 'untested' CHECK (retest_status IN ('untested','fixed_verified','still_vulnerable','partially_fixed','inconclusive','retest_failed')),
  retest_evidence jsonb,
  retested_at timestamptz
);

CREATE TABLE IF NOT EXISTS pob_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  target_id uuid REFERENCES pob_targets(id) ON DELETE SET NULL,
  scan_id uuid REFERENCES pob_scans(id) ON DELETE SET NULL,
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pob_control (
  id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  paused boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO pob_control (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS pob_targets_user_idx ON pob_targets(user_id);
CREATE INDEX IF NOT EXISTS pob_scans_user_idx ON pob_scans(user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS pob_scans_target_idx ON pob_scans(target_id);
CREATE INDEX IF NOT EXISTS pob_checks_scan_idx ON pob_checks(scan_id);
CREATE INDEX IF NOT EXISTS pob_checks_user_idx ON pob_checks(user_id);
CREATE INDEX IF NOT EXISTS pob_audit_user_idx ON pob_audit(user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS pob_one_running_scan ON pob_scans(user_id) WHERE status = 'running';

ALTER TABLE pob_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE pob_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE pob_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pob_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE pob_control ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON pob_targets, pob_scans, pob_checks, pob_audit, pob_control FROM anon, authenticated;
GRANT SELECT ON pob_targets, pob_checks, pob_audit TO authenticated;
GRANT SELECT, DELETE ON pob_scans TO authenticated;
GRANT ALL ON pob_targets, pob_scans, pob_checks, pob_audit, pob_control TO service_role;

DROP POLICY IF EXISTS "select_own_pob_targets" ON pob_targets;
CREATE POLICY "select_own_pob_targets" ON pob_targets FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_pob_scans" ON pob_scans;
CREATE POLICY "select_own_pob_scans" ON pob_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "delete_own_finished_pob_scans" ON pob_scans;
CREATE POLICY "delete_own_finished_pob_scans" ON pob_scans FOR DELETE TO authenticated USING (auth.uid() = user_id AND status <> 'running');
DROP POLICY IF EXISTS "select_own_pob_checks" ON pob_checks;
CREATE POLICY "select_own_pob_checks" ON pob_checks FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "select_own_pob_audit" ON pob_audit;
CREATE POLICY "select_own_pob_audit" ON pob_audit FOR SELECT TO authenticated USING (auth.uid() = user_id);
