/*
# Web Builder publishing

1. New Tables
- `wb_publications`: one live published copy per Web Builder project.
  - `project_id` (uuid, primary key, references wb_projects, cascade delete)
  - `slug` (text, unique, lowercase letters/digits/dashes) - the public address part
  - `pages` (jsonb) - map of page path to fully assembled HTML, frozen at publish time
  - `entry` (text) - the home page path
  - `title` (text) - project name shown in the viewer
  - `published_at` (timestamptz)
2. Security
- RLS enabled with NO policies and NO grants to anon/authenticated.
- Only the service role (used by the owner-gated web-builder function and the public
  read-only web-publish function) can read or write.
3. Notes
1. Publishing copies the project; later edits do not go live until published again.
*/

CREATE TABLE IF NOT EXISTS wb_publications (
  project_id uuid PRIMARY KEY REFERENCES wb_projects(id) ON DELETE CASCADE,
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{1,46})[a-z0-9]$'),
  pages jsonb NOT NULL DEFAULT '{}'::jsonb,
  entry text NOT NULL DEFAULT 'index.html',
  title text NOT NULL DEFAULT '',
  published_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE wb_publications ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON wb_publications FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON wb_publications TO service_role;
