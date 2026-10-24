/*
# Web Builder: change analysis and undo

1. Modified Tables
- `wb_changes`
  - New column `analysis` (jsonb, default '{}'): the project-wide plan, batch info,
    risk notes and pre-apply consistency checks recorded with each AI proposal.
  - New column `reverted_at` (timestamptz, nullable): when an applied change was undone.
  - Status check now also allows 'reverted' (an applied change that was undone by
    restoring its pre-apply checkpoint).

2. Security
- No grant or policy changes. `wb_changes` stays service-role only (RLS on, no policies).

3. Notes
1. Additive only: no data is removed or rewritten.
*/

ALTER TABLE wb_changes ADD COLUMN IF NOT EXISTS analysis jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE wb_changes ADD COLUMN IF NOT EXISTS reverted_at timestamptz;

ALTER TABLE wb_changes DROP CONSTRAINT IF EXISTS wb_changes_status_check;
ALTER TABLE wb_changes ADD CONSTRAINT wb_changes_status_check
  CHECK (status = ANY (ARRAY['pending'::text, 'applied'::text, 'rejected'::text, 'reverted'::text]));
