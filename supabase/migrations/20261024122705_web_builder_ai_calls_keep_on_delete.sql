/*
# Keep AI call records when a project is deleted

1. Modified tables
- `wb_ai_calls.project_id` foreign key changes from ON DELETE CASCADE to ON DELETE SET NULL.

2. Why
- The daily AI budget is counted from `wb_ai_calls`. Cascading deletes would erase usage when a project
  (for example the temporary self-test project) is deleted, letting the daily safety cap be bypassed.

3. Security
- No grant or policy changes; the table stays service-role only.
*/
ALTER TABLE wb_ai_calls DROP CONSTRAINT IF EXISTS wb_ai_calls_project_id_fkey;
ALTER TABLE wb_ai_calls ADD CONSTRAINT wb_ai_calls_project_id_fkey FOREIGN KEY (project_id) REFERENCES wb_projects(id) ON DELETE SET NULL;