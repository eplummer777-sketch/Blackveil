/*
# ZAP scanner instances registry

1. New Tables
- `zap_instances`: one row per ZAP scanner a user has connected.
  - `id` (uuid, pk), `user_id` (owner, defaults to auth.uid())
  - `name` (display name), `base_url` (validated https root address)
  - `api_key_ciphertext` (AES-GCM encrypted API key, base64; never readable by browsers)
  - `api_key_hint` (last 4 characters only, for recognition)
  - `provider` ('manual' today; reserved for future provisioned instances)
  - `status` (configured | connected | disconnected | unhealthy)
  - `zap_version`, `last_checked_at`, `last_ok_at`, `connected_since`, `last_error`, `consecutive_failures`
  - `created_at`, `updated_at`

2. Security
- RLS enabled. Owners can SELECT their own rows.
- Column-level grant: `authenticated` may SELECT every column EXCEPT `api_key_ciphertext`.
- No INSERT/UPDATE/DELETE grants for browsers: all writes go through the
  `zap-instances` server function (service role), which validates URLs (SSRF
  protection), encrypts keys and enforces ownership + plan checks.

3. Notes
1. Instance names are unique per owner.
2. Deleting a user deletes their instances.
*/

CREATE TABLE IF NOT EXISTS zap_instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  base_url text NOT NULL CHECK (char_length(base_url) <= 300),
  api_key_ciphertext text NOT NULL,
  api_key_hint text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT 'manual' CHECK (provider IN ('manual')),
  status text NOT NULL DEFAULT 'configured' CHECK (status IN ('configured','connected','disconnected','unhealthy')),
  zap_version text,
  last_checked_at timestamptz,
  last_ok_at timestamptz,
  connected_since timestamptz,
  last_error text,
  consecutive_failures int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, name)
);

CREATE INDEX IF NOT EXISTS zap_instances_user_idx ON zap_instances(user_id);

ALTER TABLE zap_instances ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON zap_instances FROM anon, authenticated;
GRANT SELECT (id, user_id, name, base_url, api_key_hint, provider, status, zap_version, last_checked_at, last_ok_at,
  connected_since, last_error, consecutive_failures, created_at, updated_at) ON zap_instances TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON zap_instances TO service_role;

DROP POLICY IF EXISTS "select_own_zap_instances" ON zap_instances;
CREATE POLICY "select_own_zap_instances" ON zap_instances FOR SELECT
  TO authenticated USING (auth.uid() = user_id);