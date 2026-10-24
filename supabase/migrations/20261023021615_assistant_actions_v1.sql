/*
# AI assistant proposed actions

1. New Tables
- `assistant_actions`: actions the AI assistant proposes in chat (scan a device, remove threats,
  verify a device, change scan schedule, check a link, assess a website, apply a Cloudflare fix).
  Nothing runs until the owner confirms it.
  - `id` uuid PK
  - `user_id` uuid owner (auth.users)
  - `thread_id` uuid chat thread
  - `message_id` uuid assistant message that proposed it (deleted with the message)
  - `kind` text action type (checked list)
  - `params` jsonb validated parameters
  - `summary` text human-readable description shown on the confirmation card
  - `status` text pending | running | succeeded | failed | rejected | expired
  - `result` jsonb outcome message / error
  - `created_at`, `expires_at` (pending proposals expire after 30 minutes), `decided_at`

2. Security
- RLS enabled. Owners can only SELECT their own rows.
- No INSERT/UPDATE/DELETE for app users: only the server (service role) creates proposals and
  changes their status, so a user cannot forge or alter an action's parameters.

3. Notes
1. Confirmation is claimed atomically by the server (pending -> running) so an action cannot run twice.
*/

CREATE TABLE IF NOT EXISTS assistant_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  thread_id uuid NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
  message_id uuid NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('scan_device','remove_threats','verify_device','set_scan_schedule','scan_link','assess_website','apply_cloudflare_fix')),
  params jsonb NOT NULL DEFAULT '{}'::jsonb,
  summary text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','rejected','expired')),
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '30 minutes',
  decided_at timestamptz
);

CREATE INDEX IF NOT EXISTS assistant_actions_thread_idx ON assistant_actions(thread_id, created_at);
CREATE INDEX IF NOT EXISTS assistant_actions_user_idx ON assistant_actions(user_id, status);

ALTER TABLE assistant_actions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON assistant_actions FROM anon, authenticated;
GRANT SELECT ON assistant_actions TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON assistant_actions TO service_role;

DROP POLICY IF EXISTS "select_own_assistant_actions" ON assistant_actions;
CREATE POLICY "select_own_assistant_actions" ON assistant_actions FOR SELECT
  TO authenticated USING (auth.uid() = user_id);
