/*
# Blackveil Architect — Cloudflare integration

Adds the data model for the first real Architect integration: Cloudflare.
Users connect a Cloudflare API token (scoped to a single zone) and Architect
reads the zone's security settings, identifies gaps, proposes specific
changes, and applies them through the official Cloudflare API after explicit
human approval. Every apply is verified by re-reading the setting.

1. New tables
- `architect_integrations`: a connected third-party service per user.
  provider, zone_id, zone_name, status, mode (read_only | write).
- `architect_integration_secrets`: encrypted API tokens. NO SELECT grant to
  authenticated — only the service role (edge function) can read them.
- `architect_cf_proposals`: one per security-setting change. Lifecycle:
  proposed -> approved -> applied -> verified (plus failed, rejected, rolled_back).
  CHECK constraints prevent an unapproved or unverifed change from being marked
  applied or verified.
- `architect_cf_settings_snapshots`: the raw settings read from Cloudflare,
  stored so the UI can show what was seen at analysis time.

2. Security
- RLS on all four tables. Owners (and admins) may SELECT their rows.
- `architect_integration_secrets` has NO policy and NO SELECT grant for
  authenticated — the browser can never read a token.
- Authenticated users get SELECT only on the other three tables. Every write
  goes through the `cloudflare-architect` edge function using the service role.
- Tokens are encrypted at rest with AES-GCM using a key derived from the
  service role environment (server-side only).

3. Integrity rules
- A proposal can only be `applied` or `verified` after approval.
- `verified` requires an applied timestamp and a verification result.
- `failed` requires an error message.
- `rolled_back` requires a timestamp.
*/

CREATE TABLE IF NOT EXISTS architect_integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('cloudflare')),
  label text NOT NULL DEFAULT 'Cloudflare',
  zone_id text NOT NULL,
  zone_name text NOT NULL,
  account_id text,
  account_name text,
  status text NOT NULL DEFAULT 'connected' CHECK (status IN ('connected', 'disconnected', 'error')),
  mode text NOT NULL DEFAULT 'read_only' CHECK (mode IN ('read_only', 'write')),
  token_permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_settings_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, zone_id)
);

CREATE TABLE IF NOT EXISTS architect_integration_secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id uuid NOT NULL REFERENCES architect_integrations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  encrypted_token text NOT NULL,
  iv text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS architect_cf_settings_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id uuid NOT NULL REFERENCES architect_integrations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  source text NOT NULL DEFAULT 'cloudflare_api' CHECK (source IN ('cloudflare_api', 'post_apply_verify')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS architect_cf_proposals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id uuid NOT NULL REFERENCES architect_integrations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  setting_key text NOT NULL,
  setting_label text NOT NULL,
  current_value jsonb,
  proposed_value jsonb NOT NULL,
  recommended_value jsonb,
  api_path text NOT NULL,
  explanation text NOT NULL DEFAULT '',
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_level text NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high')),
  rollback_value jsonb,
  rollback_supported boolean NOT NULL DEFAULT true,
  rollback_instructions text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'proposed' CHECK (status IN (
    'proposed', 'approved', 'applied', 'verified', 'failed', 'rejected', 'rolled_back'
  )),
  approved_by uuid REFERENCES auth.users(id),
  approved_at timestamptz,
  applied_at timestamptz,
  apply_error text,
  verified_at timestamptz,
  verification_result jsonb,
  rejected_at timestamptz,
  rolled_back_at timestamptz,
  rollback_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT cf_proposal_applied_requires_approval CHECK (
    status NOT IN ('applied', 'verified') OR (approved_at IS NOT NULL AND approved_by IS NOT NULL)
  ),
  CONSTRAINT cf_proposal_verified_requires_apply CHECK (
    status <> 'verified' OR (applied_at IS NOT NULL AND verified_at IS NOT NULL AND verification_result IS NOT NULL)
  ),
  CONSTRAINT cf_proposal_applied_requires_timestamp CHECK (
    status NOT IN ('applied', 'verified') OR applied_at IS NOT NULL
  ),
  CONSTRAINT cf_proposal_failed_requires_error CHECK (
    status <> 'failed' OR apply_error IS NOT NULL
  ),
  CONSTRAINT cf_proposal_rolled_back_requires_timestamp CHECK (
    status <> 'rolled_back' OR rolled_back_at IS NOT NULL
  )
);

CREATE INDEX IF NOT EXISTS architect_integrations_user_idx ON architect_integrations(user_id);
CREATE INDEX IF NOT EXISTS architect_integration_secrets_integration_idx ON architect_integration_secrets(integration_id);
CREATE INDEX IF NOT EXISTS architect_cf_snapshots_integration_idx ON architect_cf_settings_snapshots(integration_id, created_at DESC);
CREATE INDEX IF NOT EXISTS architect_cf_proposals_integration_idx ON architect_cf_proposals(integration_id, created_at DESC);
CREATE INDEX IF NOT EXISTS architect_cf_proposals_user_idx ON architect_cf_proposals(user_id);

CREATE OR REPLACE FUNCTION architect_integration_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION architect_integration_touch_updated_at() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS architect_integrations_touch ON architect_integrations;
CREATE TRIGGER architect_integrations_touch BEFORE UPDATE ON architect_integrations
  FOR EACH ROW EXECUTE FUNCTION architect_integration_touch_updated_at();
DROP TRIGGER IF EXISTS architect_cf_proposals_touch ON architect_cf_proposals;
CREATE TRIGGER architect_cf_proposals_touch BEFORE UPDATE ON architect_cf_proposals
  FOR EACH ROW EXECUTE FUNCTION architect_integration_touch_updated_at();

ALTER TABLE architect_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_integration_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_cf_settings_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE architect_cf_proposals ENABLE ROW LEVEL SECURITY;

-- Secrets: NO grant to authenticated at all. Only service_role can read.
REVOKE ALL ON architect_integration_secrets FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON architect_integration_secrets TO service_role;

-- Other tables: owner-or-admin SELECT for authenticated, full CRUD for service_role.
REVOKE ALL ON architect_integrations, architect_cf_settings_snapshots, architect_cf_proposals FROM anon, authenticated;
GRANT SELECT ON architect_integrations, architect_cf_settings_snapshots, architect_cf_proposals TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON architect_integrations, architect_cf_settings_snapshots, architect_cf_proposals TO service_role;

DROP POLICY IF EXISTS "select_own_integrations" ON architect_integrations;
CREATE POLICY "select_own_integrations" ON architect_integrations FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_cf_snapshots" ON architect_cf_settings_snapshots;
CREATE POLICY "select_own_cf_snapshots" ON architect_cf_settings_snapshots FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_cf_proposals" ON architect_cf_proposals;
CREATE POLICY "select_own_cf_proposals" ON architect_cf_proposals FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
