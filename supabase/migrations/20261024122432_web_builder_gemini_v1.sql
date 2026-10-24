/*
# Web Builder: Gemini provider + AI call budget log

1. Modified tables
- `wb_config`
  - `ai_provider` now also accepts 'gemini' (constraint replaced; existing rows unaffected).
  - new `ai_daily_call_limit` (integer, default 150, 1-1000): a self-imposed cap on AI calls per UTC day,
    kept below the Gemini free-tier daily quota so the builder stops before Google does.

2. New tables
- `wb_ai_calls`: one row per outbound AI request (connection tests, agent inspect/edit steps, self-tests).
  - `id`, `created_at`
  - `provider` (text), `model` (text), `purpose` (text)
  - `ok` (boolean), `status` (integer HTTP status from the provider, 0 if none), `error` (text)
  - `input_tokens`, `output_tokens` (integer)
  - `project_id` (nullable, cascades on project delete)

3. Security
- RLS enabled on `wb_ai_calls` with NO policies; all privileges revoked from anon, authenticated and PUBLIC.
- Only `service_role` (used by the owner-gated web-builder server function) may SELECT/INSERT.
- The model ID is pinned in server code; nothing here lets a client choose a model.
*/

ALTER TABLE wb_config DROP CONSTRAINT IF EXISTS wb_config_ai_provider_check;
ALTER TABLE wb_config ADD CONSTRAINT wb_config_ai_provider_check CHECK (ai_provider IN ('none','free','openai','gemini'));

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'wb_config' AND column_name = 'ai_daily_call_limit') THEN
    ALTER TABLE wb_config ADD COLUMN ai_daily_call_limit integer NOT NULL DEFAULT 150 CHECK (ai_daily_call_limit BETWEEN 1 AND 1000);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS wb_ai_calls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  provider text NOT NULL,
  model text NOT NULL DEFAULT '',
  purpose text NOT NULL DEFAULT '',
  ok boolean NOT NULL DEFAULT false,
  status integer NOT NULL DEFAULT 0,
  error text NOT NULL DEFAULT '',
  input_tokens integer NOT NULL DEFAULT 0,
  output_tokens integer NOT NULL DEFAULT 0,
  project_id uuid REFERENCES wb_projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS wb_ai_calls_provider_created_idx ON wb_ai_calls (provider, created_at DESC);
CREATE INDEX IF NOT EXISTS wb_ai_calls_project_idx ON wb_ai_calls (project_id);

ALTER TABLE wb_ai_calls ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON wb_ai_calls FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON wb_ai_calls TO service_role;