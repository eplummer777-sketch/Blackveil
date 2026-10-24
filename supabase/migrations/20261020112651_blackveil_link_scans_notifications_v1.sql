/*
# Link scans and notifications tables

## Purpose
Adds two new tables to support Stage 3 of the Blackveil Security platform:
1. `link_scans` — stores the result of suspicious-URL / phishing-link checks
   performed by the link-scanner edge function. Each row is a scan a user ran,
   with the verdict, risk indicators, and recommendations.
2. `notifications` — in-app notifications shown via a bell icon in the app
   shell. Covers scan completions, subscription events, security alerts, and
   general announcements.

## New tables

### link_scans
- `id` (uuid, PK)
- `user_id` (uuid, NOT NULL, defaults to auth.uid(), FK to auth.users, CASCADE)
- `input` (text, NOT NULL) — the raw URL or text the user submitted for scanning
- `target_url` (text) — normalized URL that was assessed
- `target_host` (text) — hostname extracted from the URL
- `verdict` (text, NOT NULL) — one of: 'low_risk', 'suspicious', 'high_risk', 'unable_to_determine'
- `risk_score` (int, default 0) — 0-100 heuristic score
- `indicators` (jsonb, default '[]') — array of risk indicator objects {id, label, severity, detail}
- `recommendations` (jsonb, default '[]') — array of recommendation strings
- `details` (jsonb) — extra metadata: domain age, redirect chain, TLS info, DNS
- `scan_type` (text, default 'url') — 'url' | 'message' | 'qr'
- `created_at` (timestamptz, default now())

### notifications
- `id` (uuid, PK)
- `user_id` (uuid, NOT NULL, defaults to auth.uid(), FK to auth.users, CASCADE)
- `kind` (text, NOT NULL) — 'scan_complete' | 'subscription' | 'security_alert' | 'system' | 'assessment'
- `title` (text, NOT NULL)
- `body` (text)
- `link` (text) — optional route name for navigation when clicked
- `read` (boolean, default false)
- `created_at` (timestamptz, default now())

## Security
- Both tables have RLS enabled.
- Owner-scoped CRUD: each authenticated user can only access their own rows.
- `user_id` defaults to `auth.uid()` so inserts from the client that omit
  `user_id` still satisfy the INSERT WITH CHECK policy.

## Indexes
- `link_scans_user_id_created_at_idx` — user's scan history sorted by date
- `notifications_user_id_created_at_idx` — user's notifications sorted by date
- `notifications_user_id_unread_idx` — quickly count unread notifications
*/

CREATE TABLE IF NOT EXISTS link_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  input text NOT NULL,
  target_url text,
  target_host text,
  verdict text NOT NULL DEFAULT 'unable_to_determine',
  risk_score int NOT NULL DEFAULT 0,
  indicators jsonb NOT NULL DEFAULT '[]'::jsonb,
  recommendations jsonb NOT NULL DEFAULT '[]'::jsonb,
  details jsonb,
  scan_type text NOT NULL DEFAULT 'url',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE link_scans ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS link_scans_user_id_created_at_idx
  ON link_scans (user_id, created_at DESC);

DROP POLICY IF EXISTS "select_own_link_scans" ON link_scans;
CREATE POLICY "select_own_link_scans" ON link_scans FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_link_scans" ON link_scans;
CREATE POLICY "insert_own_link_scans" ON link_scans FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_link_scans" ON link_scans;
CREATE POLICY "update_own_link_scans" ON link_scans FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_link_scans" ON link_scans;
CREATE POLICY "delete_own_link_scans" ON link_scans FOR DELETE
  TO authenticated USING (auth.uid() = user_id);


CREATE TABLE IF NOT EXISTS notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  kind text NOT NULL DEFAULT 'system',
  title text NOT NULL,
  body text,
  link text,
  read boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS notifications_user_id_created_at_idx
  ON notifications (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS notifications_user_id_unread_idx
  ON notifications (user_id) WHERE read = false;

DROP POLICY IF EXISTS "select_own_notifications" ON notifications;
CREATE POLICY "select_own_notifications" ON notifications FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_notifications" ON notifications;
CREATE POLICY "insert_own_notifications" ON notifications FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_notifications" ON notifications;
CREATE POLICY "update_own_notifications" ON notifications FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_notifications" ON notifications;
CREATE POLICY "delete_own_notifications" ON notifications FOR DELETE
  TO authenticated USING (auth.uid() = user_id);
