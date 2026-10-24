/*
# Blackveil OS worker diagnostics

Adds fields that let administrators tell apart an offline, unauthorized,
unhealthy and online execution worker.

1. Modified tables
- `bv_workers`
  - `token_prefix` (text) - first characters of the worker token (non-secret) so a
    rejected connection attempt can be attributed to the right worker.
  - `last_auth_fail_at` (timestamptz) - last time this worker's token was rejected.
  - `last_auth_fail_reason` (text) - why it was rejected (revoked / invalid token).

2. Security
- No grant changes. `bv_workers` stays unreachable from the browser; only edge
  functions (service role) read or write it.
*/

ALTER TABLE public.bv_workers ADD COLUMN IF NOT EXISTS token_prefix text;
ALTER TABLE public.bv_workers ADD COLUMN IF NOT EXISTS last_auth_fail_at timestamptz;
ALTER TABLE public.bv_workers ADD COLUMN IF NOT EXISTS last_auth_fail_reason text;
CREATE INDEX IF NOT EXISTS bv_workers_token_prefix_idx ON public.bv_workers (token_prefix);