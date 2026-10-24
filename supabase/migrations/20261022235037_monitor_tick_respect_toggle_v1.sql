/*
# Monitor respects the 24/7 monitoring on/off switch

1. Modified functions
- `endpoint_monitor_tick()`: device health checks (agent offline, protection off, stale
  definitions, missed scans) and scheduled scans now only run for devices whose owner has
  monitoring switched on AND an active Pro/Elite plan (via `monitoring_active`).
  Job/threat incident tracking is unchanged for everyone.
2. Security
- No grant changes; function remains non-callable by anon/authenticated.

Notes
1. Implemented by rewriting the device loop filter in the existing function definition.
*/
DO $$
DECLARE src text; patched text;
BEGIN
  src := pg_get_functiondef('public.endpoint_monitor_tick()'::regprocedure);
  IF position('monitoring_active(dv.user_id)' IN src) > 0 THEN RETURN; END IF;
  patched := replace(src, 'FROM endpoint_devices dv WHERE dv.revoked_at IS NULL',
                          'FROM endpoint_devices dv WHERE dv.revoked_at IS NULL AND monitoring_active(dv.user_id)');
  IF patched = src THEN RAISE EXCEPTION 'monitor loop filter not found'; END IF;
  EXECUTE patched;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_monitor_tick() FROM PUBLIC, anon, authenticated;
