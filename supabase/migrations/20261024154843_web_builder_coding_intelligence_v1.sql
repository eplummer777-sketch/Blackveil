/*
# Blackveil AI coding intelligence: memory, fix library, feedback, metrics

1. New Tables
- `wb_memories` - persistent per-project coding memory
  - `id` uuid pk, `project_id` uuid -> wb_projects (cascade)
  - `kind` (architecture, convention, decision, bug, requirement, limitation, milestone, session, rule)
  - `title`, `body` text
  - `source` (user = written/approved by owner, system = computed by the app, ai = model claim, never trusted as fact)
  - `status` (active, unverified, archived)
  - `files` text[] - files the memory is about
  - `file_hashes` jsonb - content hashes when written, used to flag outdated memories
  - `created_at`, `updated_at`
- `wb_fixes` - verified fix library
  - problem, root_cause, environment, evidence, fix_summary, files, checks (jsonb), limitations
  - `status` (hypothesis, verified, failed), `confidence` (low, medium, high)
  - `change_id` -> wb_changes (set null on delete)
  - A CHECK constraint prevents a fix being marked verified without a root cause, a linked change and recorded checks.
- `wb_feedback` - owner ratings of AI results (helpful, incorrect, incomplete, verified)

2. Modified Tables
- `wb_ai_calls`: new nullable columns `duration_ms`, `parse_ok`, `tokens_estimated`, `pipeline` (null = original pipeline, 'v2' = upgraded). Existing rows untouched.

3. Security
- RLS enabled on all new tables with no client policies: only the owner-checked web-builder server function (service_role) can read or write them, matching the existing wb_* tables.
- Grants to service_role only.

4. Notes
1. Additive only; no existing data is changed or removed.
*/

CREATE TABLE IF NOT EXISTS wb_memories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('architecture','convention','decision','bug','requirement','limitation','milestone','session','rule')),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
  body text NOT NULL DEFAULT '' CHECK (char_length(body) <= 4000),
  source text NOT NULL CHECK (source IN ('user','system','ai')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','unverified','archived')),
  files text[] NOT NULL DEFAULT '{}',
  file_hashes jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS wb_memories_project_idx ON wb_memories(project_id, status);

CREATE TABLE IF NOT EXISTS wb_fixes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  change_id uuid REFERENCES wb_changes(id) ON DELETE SET NULL,
  problem text NOT NULL CHECK (char_length(problem) BETWEEN 1 AND 2000),
  root_cause text NOT NULL DEFAULT '' CHECK (char_length(root_cause) <= 2000),
  environment text NOT NULL DEFAULT '' CHECK (char_length(environment) <= 300),
  evidence text NOT NULL DEFAULT '' CHECK (char_length(evidence) <= 4000),
  fix_summary text NOT NULL DEFAULT '' CHECK (char_length(fix_summary) <= 2000),
  files text[] NOT NULL DEFAULT '{}',
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  limitations text NOT NULL DEFAULT '' CHECK (char_length(limitations) <= 1000),
  status text NOT NULL DEFAULT 'hypothesis' CHECK (status IN ('hypothesis','verified','failed')),
  confidence text NOT NULL DEFAULT 'low' CHECK (confidence IN ('low','medium','high')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT wb_fixes_verified_needs_evidence CHECK (
    status <> 'verified' OR (change_id IS NOT NULL AND root_cause <> '' AND jsonb_array_length(checks) > 0)
  )
);
CREATE INDEX IF NOT EXISTS wb_fixes_project_idx ON wb_fixes(project_id, status);

CREATE TABLE IF NOT EXISTS wb_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES wb_projects(id) ON DELETE CASCADE,
  message_id uuid NOT NULL REFERENCES wb_messages(id) ON DELETE CASCADE,
  change_id uuid REFERENCES wb_changes(id) ON DELETE SET NULL,
  rating text NOT NULL CHECK (rating IN ('helpful','incorrect','incomplete','verified')),
  note text NOT NULL DEFAULT '' CHECK (char_length(note) <= 1000),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (message_id)
);
CREATE INDEX IF NOT EXISTS wb_feedback_project_idx ON wb_feedback(project_id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='wb_ai_calls' AND column_name='duration_ms') THEN
    ALTER TABLE wb_ai_calls ADD COLUMN duration_ms integer;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='wb_ai_calls' AND column_name='parse_ok') THEN
    ALTER TABLE wb_ai_calls ADD COLUMN parse_ok boolean;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='wb_ai_calls' AND column_name='tokens_estimated') THEN
    ALTER TABLE wb_ai_calls ADD COLUMN tokens_estimated boolean;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='wb_ai_calls' AND column_name='pipeline') THEN
    ALTER TABLE wb_ai_calls ADD COLUMN pipeline text;
  END IF;
END $$;

ALTER TABLE wb_memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_fixes ENABLE ROW LEVEL SECURITY;
ALTER TABLE wb_feedback ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON wb_memories, wb_fixes, wb_feedback FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON wb_memories, wb_fixes, wb_feedback TO service_role;