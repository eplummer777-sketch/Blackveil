/*
# Native Blackveil scan engine state

1. Modified Tables
- zap_scans: new column engine_state (jsonb, nullable) holding the built-in engine's crawl queue,
  visited pages and pending findings between progress steps.

2. Security
- No policy changes. The column belongs to the scan owner's row and is written only by the server.
*/
ALTER TABLE zap_scans ADD COLUMN IF NOT EXISTS engine_state jsonb;
