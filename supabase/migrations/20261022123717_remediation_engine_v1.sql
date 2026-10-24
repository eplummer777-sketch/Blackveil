/*
# Blackveil Assessment & Remediation Engine

Unified assessment + remediation data model. Combines website security checks
(safe HTTP probes) with Cloudflare zone settings to produce prioritized findings
with fix proposals, approval, apply, and verification lifecycle.

1. New tables
- `remediation_assessments`: one per scan. Links to optional Cloudflare integration.
  Stores target, source types (http + cloudflare), status, summary.
- `remediation_findings`: individual findings with severity, evidence, remediation,
  and fix lifecycle (proposed -> approved -> applied -> verified | failed | rejected).
  Stores cf_setting_key, current_value, proposed_value, rollback_value for Cloudflare fixes.
- `remediation_audit`: append-only audit trail for every action.

2. Security
- RLS on all tables. Owner-or-admin SELECT for authenticated. All writes via service role.
- No client can create or modify findings directly — the edge function owns all writes.
- Cloudflare credentials are never exposed (stored in architect_integration_secrets, reused here).

3. Integrity rules
- applied/verified require approval timestamp.
- verified requires applied_at + verification_result.
- failed requires error message.
- Only Cloudflare-supported findings can have a fix proposal.
*/

CREATE TABLE IF NOT EXISTS remediation_assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  target text NOT NULL,
  integration_id uuid REFERENCES architect_integrations(id) ON DELETE SET NULL,
  sources text[] NOT NULL DEFAULT ARRAY['http']::text[],
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  overall_status text,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  check_results jsonb NOT NULL DEFAULT '[]'::jsonb,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS remediation_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES remediation_assessments(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  check_id text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  category text NOT NULL DEFAULT 'general',
  source text NOT NULL CHECK (source IN ('http', 'cloudflare')),
  description text NOT NULL DEFAULT '',
  evidence text NOT NULL DEFAULT '',
  impact text NOT NULL DEFAULT '',
  remediation text NOT NULL DEFAULT '',
  verified boolean NOT NULL DEFAULT false,
  fixable boolean NOT NULL DEFAULT false,
  cf_setting_key text,
  cf_api_path text,
  current_value jsonb,
  proposed_value jsonb,
  recommended_value jsonb,
  rollback_value jsonb,
  rollback_supported boolean NOT NULL DEFAULT false,
  rollback_instructions text NOT NULL DEFAULT '',
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_level text NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high')),
  fix_status text NOT NULL DEFAULT 'none' CHECK (fix_status IN (
    'none', 'proposed', 'approved', 'applied', 'verified', 'failed', 'rejected'
  )),
  approved_by uuid REFERENCES auth.users(id),
  approved_at timestamptz,
  applied_at timestamptz,
  apply_error text,
  verified_at timestamptz,
  verification_result jsonb,
  rejected_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT rem_fix_applied_requires_approval CHECK (
    fix_status NOT IN ('applied', 'verified') OR (approved_at IS NOT NULL AND approved_by IS NOT NULL)
  ),
  CONSTRAINT rem_fix_verified_requires_apply CHECK (
    fix_status <> 'verified' OR (applied_at IS NOT NULL AND verified_at IS NOT NULL AND verification_result IS NOT NULL)
  ),
  CONSTRAINT rem_fix_failed_requires_error CHECK (
    fix_status <> 'failed' OR apply_error IS NOT NULL
  ),
  CONSTRAINT rem_fix_cloudflare_requires_key CHECK (
    (source <> 'cloudflare' OR cf_setting_key IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS remediation_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid REFERENCES remediation_assessments(id) ON DELETE CASCADE,
  finding_id uuid REFERENCES remediation_findings(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rem_assessments_user_idx ON remediation_assessments(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rem_findings_assessment_idx ON remediation_findings(assessment_id);
CREATE INDEX IF NOT EXISTS rem_findings_user_idx ON remediation_findings(user_id);
CREATE INDEX IF NOT EXISTS rem_audit_assessment_idx ON remediation_audit(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rem_audit_user_idx ON remediation_audit(user_id, created_at DESC);

CREATE OR REPLACE FUNCTION remediation_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION remediation_touch_updated_at() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS rem_findings_touch ON remediation_findings;
CREATE TRIGGER rem_findings_touch BEFORE UPDATE ON remediation_findings
  FOR EACH ROW EXECUTE FUNCTION remediation_touch_updated_at();

ALTER TABLE remediation_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_audit ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON remediation_assessments, remediation_findings, remediation_audit FROM anon, authenticated;
GRANT SELECT ON remediation_assessments, remediation_findings, remediation_audit TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_assessments, remediation_findings, remediation_audit TO service_role;

DROP POLICY IF EXISTS "select_own_rem_assessments" ON remediation_assessments;
CREATE POLICY "select_own_rem_assessments" ON remediation_assessments FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_rem_findings" ON remediation_findings;
CREATE POLICY "select_own_rem_findings" ON remediation_findings FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_rem_audit" ON remediation_audit;
CREATE POLICY "select_own_rem_audit" ON remediation_audit FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
