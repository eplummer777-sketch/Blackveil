/*
# Blackveil Architect v1

Adds the data model for Blackveil Architect, an AI assistant that turns a plain-English security need
into a tailored plan plus configuration files, tests them in an isolated static sandbox, and tracks each
change through a human-approved lifecycle.

1. New Tables
- `architect_projects`: one per user request.
  - `description` (the user's plain-English need), `questions` (clarifying questions), `answers`,
    `plan` (generated plan), `plan_source` ('ai' or 'template'), `status`.
- `architect_changes`: each proposed configuration / code / rule.
  - `artifact_type` (allowlisted kinds), `filename`, `content` (immutable after creation),
    `explanation`, `risks`, `risk_level`, `rollback_supported`, `rollback_instructions`,
    `verification_supported`, `verification_spec`.
  - Lifecycle: `status` in proposed, test_failed, tested, approved, deployed, verified, rejected, rolled_back,
    plus the timestamps and people behind each transition.
- `architect_tests`: every sandbox run with its individual checks and the hash of the content tested.
- `architect_events`: append-only audit trail of every action (who: user, ai or system).

2. Security
- RLS enabled on all four tables. Owners (and admins) may SELECT their rows.
- Authenticated users get SELECT only. Every write goes through the `architect` edge function
  using the service role, so the browser cannot fake a status, test result or audit entry.

3. Integrity rules (CHECK constraints)
- A change can only be tested/approved/deployed/verified if its latest sandbox test passed.
- approved/deployed/verified require an approval timestamp and approver.
- deployed/verified require a deployment timestamp and a deployment method.
- verified requires a verification timestamp and result.
- Deployment method is currently only 'manual_self_reported' (the user applied it themselves);
  'integration' is reserved for future authorized cloud/website integrations.
*/

CREATE TABLE IF NOT EXISTS architect_projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'Untitled security project' CHECK (char_length(title) <= 160),
  description text NOT NULL CHECK (char_length(description) BETWEEN 10 AND 4000),
  status text NOT NULL DEFAULT 'needs_answers' CHECK (status IN ('needs_answers', 'planned', 'failed')),
  questions jsonb NOT NULL DEFAULT '[]'::jsonb,
  answers jsonb NOT NULL DEFAULT '{}'::jsonb,
  plan jsonb,
  plan_source text CHECK (plan_source IS NULL OR plan_source IN ('ai', 'template')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS architect_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES architect_projects(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  position int NOT NULL DEFAULT 0,
  title text NOT NULL CHECK (char_length(title) <= 160),
  category text NOT NULL DEFAULT 'general',
  target_system text NOT NULL DEFAULT 'General',
  artifact_type text NOT NULL CHECK (artifact_type IN (
    'nginx_conf', 'apache_conf', 'http_headers', 'ufw_rules', 'sshd_config',
    'fail2ban_jail', 'json_policy', 'bash_script', 'powershell_script', 'checklist'
  )),
  filename text NOT NULL CHECK (char_length(filename) <= 120),
  content text NOT NULL CHECK (char_length(content) BETWEEN 1 AND 20000),
  explanation text NOT NULL DEFAULT '',
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_level text NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high')),
  rollback_supported boolean NOT NULL DEFAULT false,
  rollback_instructions text NOT NULL DEFAULT '',
  verification_supported boolean NOT NULL DEFAULT false,
  verification_spec jsonb,
  status text NOT NULL DEFAULT 'proposed' CHECK (status IN (
    'proposed', 'test_failed', 'tested', 'approved', 'deployed', 'verified', 'rejected', 'rolled_back'
  )),
  last_test_passed boolean,
  last_tested_at timestamptz,
  approved_by uuid REFERENCES auth.users(id),
  approved_at timestamptz,
  approval_note text,
  rejected_at timestamptz,
  deployed_method text CHECK (deployed_method IS NULL OR deployed_method IN ('manual_self_reported', 'integration')),
  deployed_at timestamptz,
  deploy_note text,
  verified_at timestamptz,
  verification_result jsonb,
  rolled_back_at timestamptz,
  rollback_note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT architect_tested_requires_pass CHECK (
    status NOT IN ('tested', 'approved', 'deployed', 'verified') OR (last_test_passed = true AND last_tested_at IS NOT NULL)
  ),
  CONSTRAINT architect_approval_recorded CHECK (
    status NOT IN ('approved', 'deployed', 'verified') OR (approved_at IS NOT NULL AND approved_by IS NOT NULL)
  ),
  CONSTRAINT architect_deploy_recorded CHECK (
    status NOT IN ('deployed', 'verified') OR (deployed_at IS NOT NULL AND deployed_method IS NOT NULL)
  ),
  CONSTRAINT architect_verify_recorded CHECK (
    status <> 'verified' OR (verified_at IS NOT NULL AND verification_result IS NOT NULL AND verification_supported = true)
  )
);

CREATE TABLE IF NOT EXISTS architect_tests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  change_id uuid NOT NULL REFERENCES architect_changes(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  sandbox text NOT NULL DEFAULT 'static_analysis' CHECK (sandbox IN ('static_analysis')),
  passed boolean NOT NULL,
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary text NOT NULL DEFAULT '',
  content_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS architect_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  project_id uuid REFERENCES architect_projects(id) ON DELETE CASCADE,
  change_id uuid REFERENCES architect_changes(id) ON DELETE CASCADE,
  actor text NOT NULL CHECK (actor IN ('user', 'ai', 'system')),
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS architect_projects_user_idx ON architect_projects(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS architect_changes_project_idx ON architect_changes(project_id, position);
CREATE INDEX IF NOT EXISTS architect_changes_user_idx ON architect_changes(user_id);
CREATE INDEX IF NOT EXISTS architect_tests_change_idx ON architect_tests(change_id, created_at DESC);
CREATE INDEX IF NOT EXISTS architect_events_project_idx ON architect_events(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS architect_events_user_idx ON architect_events(user_id);

CREATE OR REPLACE FUNCTION architect_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION architect_touch_updated_at() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS architect_projects_touch ON architect_projects;
CREATE TRIGGER architect_projects_touch BEFORE UPDATE ON architect_projects
  FOR EACH ROW EXECUTE FUNCTION architect_touch_updated_at();
DROP TRIGGER IF EXISTS architect_changes_touch ON architect_changes;
CREATE TRIGGER architect_changes_touch BEFORE UPDATE ON architect_changes
  FOR EACH ROW EXECUTE FUNCTION architect_touch_updated_at();

ALTER TABLE architect_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_events ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON architect_projects, architect_changes, architect_tests, architect_events FROM anon, authenticated;
GRANT SELECT ON architect_projects, architect_changes, architect_tests, architect_events TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON architect_projects, architect_changes, architect_tests, architect_events TO service_role;

DROP POLICY IF EXISTS "select_own_architect_projects" ON architect_projects;
CREATE POLICY "select_own_architect_projects" ON architect_projects FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_architect_changes" ON architect_changes;
CREATE POLICY "select_own_architect_changes" ON architect_changes FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_architect_tests" ON architect_tests;
CREATE POLICY "select_own_architect_tests" ON architect_tests FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_architect_events" ON architect_events;
CREATE POLICY "select_own_architect_events" ON architect_events FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
