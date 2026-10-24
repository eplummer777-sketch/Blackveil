/*
# Web Builder: lock to a single website

1. Modified Tables
- `wb_config`: new column `site_project_id` (uuid, nullable, references wb_projects, set null on delete).
  The Web Builder may only read and change this one project.
2. Data
- Pins the most recently updated existing project as the owner's website.
3. Security
- No grant changes. wb_config stays service-role only (RLS on, no policies).
*/

ALTER TABLE wb_config ADD COLUMN IF NOT EXISTS site_project_id uuid REFERENCES wb_projects(id) ON DELETE SET NULL;

UPDATE wb_config
SET site_project_id = (SELECT id FROM wb_projects ORDER BY updated_at DESC LIMIT 1)
WHERE id = 1 AND site_project_id IS NULL;
