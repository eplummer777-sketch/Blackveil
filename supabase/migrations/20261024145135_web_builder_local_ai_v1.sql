/*
# Web Builder: on-device Blackveil AI replaces hosted providers

1. Modified Tables
- `wb_config.ai_provider`: allowed values are now 'none' (AI off) or 'local' (Blackveil AI running on the owner's device).
  Hosted options ('free', 'openai', 'gemini') are removed; the existing row is switched to 'local' and paid approval is cleared.
2. Data
- No rows deleted. AI call history in `wb_ai_calls` is kept.
3. Security
- No grant or policy changes. wb_config stays service-role only.
*/

ALTER TABLE wb_config DROP CONSTRAINT IF EXISTS wb_config_ai_provider_check;

UPDATE wb_config SET ai_provider = 'local', paid_ai_approved = false, updated_at = now()
WHERE ai_provider NOT IN ('none', 'local');

ALTER TABLE wb_config ADD CONSTRAINT wb_config_ai_provider_check CHECK (ai_provider IN ('none', 'local'));
