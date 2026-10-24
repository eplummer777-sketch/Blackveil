/*
# Web Builder private storage (owner-only)

Stores Blackveil Web Builder projects. These tables are reachable ONLY through the
`web-builder` server function (service role), which verifies the signed-in user is the
configured owner before every operation. Browsers (anon/authenticated) get no table access.

1. New tables
- `wb_config` (single row, id = 1): `owner_email` (lowercase), `owner_user_id` (pinned account id),
  `ai_provider` ('none' | 'free' | 'openai'; default 'none' = AI not connected),
  `paid_ai_approved` (must be true before the paid provider can be used), `updated_at`.
- `wb_projects`: `id`, `name`, `description`, `kind` ('static' | 'other'), `created_at`, `updated_at`.
- `wb_files`: `id`, `project_id`, `path` (unique per project), `content`, `updated_at`.
- `wb_snapshots`: recovery copies of a whole project: `id`, `project_id`, `label`, `files` (jsonb {path: content}), `created_at`.
- `wb_messages`: AI chat history: `id`, `project_id`, `role`, `content`, `model`, `input_tokens`, `output_tokens`, `created_at`.
- `wb_changes`: AI-proposed file changes awaiting review: `id`, `project_id`, `message_id`, `summary`,
  `files` (jsonb list of {path, action, before, after}), `status` ('pending'|'applied'|'rejected'),
  `snapshot_id`, `created_at`, `decided_at`.

2. Security
- RLS enabled on every table with NO policies: deny-by-default for anon and authenticated.
- All privileges explicitly REVOKED from anon and authenticated (the schema's default grants would otherwise apply).
- service_role granted only the verbs the server function uses.
- Owner is pinned to the existing account id + email; customers cannot change it (no grants, not in profile data).

3. Notes
1. Deleting a project cascades to its files, snapshots, messages and changes.
2. No existing tables are modified.
*/

CREATE TABLE IF NOT EXISTS wb_config (
  id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  owner_email text NOT NULL,
  owner_user_id uuid NOT NULL,
  ai_provider text NOT NULL DEFAULT 'none' CHECK (ai_provider IN ('none','free','openai')),
  paid_ai_approved boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wb_projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  description text NOT NULL DEFAULT '',
  kind text NOT NULL DEFAULT 'static' CHECK (kind IN ('static','other')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wb_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  path text NOT NULL,
  content text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, path)
);

CREATE TABLE IF NOT EXISTS wb_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  label text NOT NULL,
  files jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS wb_snapshots_project_idx ON wb_snapshots(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS wb_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('user','assistant','system')),
  content text NOT NULL,
  model text,
  input_tokens int NOT NULL DEFAULT 0,
  output_tokens int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS wb_messages_project_idx ON wb_messages(project_id, created_at);

CREATE TABLE IF NOT EXISTS wb_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  message_id uuid REFERENCES wb_messages(id) ON DELETE SET NULL,
  summary text NOT NULL DEFAULT '',
  files jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected')),
  snapshot_id uuid REFERENCES wb_snapshots(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz
);
CREATE INDEX IF NOT EXISTS wb_changes_project_idx ON wb_changes(project_id, created_at DESC);

ALTER TABLE wb_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_changes ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON wb_config, wb_projects, wb_files, wb_snapshots, wb_messages, wb_changes FROM anon, authenticated, PUBLIC;

GRANT SELECT, UPDATE ON wb_config TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON wb_projects, wb_files, wb_snapshots, wb_messages, wb_changes TO service_role;

INSERT INTO wb_config (id, owner_email, owner_user_id)
SELECT 1, lower(email), id FROM auth.users WHERE lower(email) = 'eplummer777@gmail.com'
ON CONFLICT (id) DO NOTHING;
