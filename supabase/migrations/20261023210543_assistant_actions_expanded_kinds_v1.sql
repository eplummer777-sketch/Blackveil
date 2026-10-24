/*
# Expand AI Assistant action types

1. Modified Tables
- `assistant_actions`: the allowed `kind` list now also includes
  - `pob_quick_scan` (Proof-of-Breach quick test of a verified target)
  - `pentest_scan` (penetration test of a verified target)
  - `network_scan` (network discovery of a verified target)
  - `send_report_now` (email the monitoring report now)
  - `open_page` (take the user to a page in the app)
2. Security
- No policy or grant changes. Actions are still created only by the assistant server
  function and run only after the user confirms them.
3. Notes
- Constraint is replaced with a superset of the previous list, so existing rows stay valid.
*/

ALTER TABLE assistant_actions DROP CONSTRAINT IF EXISTS assistant_actions_kind_check;
ALTER TABLE assistant_actions ADD CONSTRAINT assistant_actions_kind_check CHECK (kind IN (
  'scan_device','remove_threats','verify_device','set_scan_schedule','scan_link','assess_website','apply_cloudflare_fix',
  'pob_quick_scan','pentest_scan','network_scan','send_report_now','open_page'
));
