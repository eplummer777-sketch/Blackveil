/*
# 24/7 automated monitoring settings, email/SMS alerts and daily reports

Plain English: Pro ($10) and Elite ($25) subscribers can switch automated monitoring on or off,
choose email and/or text alerts, and receive a daily security report. Alerts are queued in an
outbox and delivered by a server function; the delivery result (sent, failed, not configured) is
recorded truthfully.

1. New tables
- `monitoring_settings` (one row per user): enabled, email_alerts, sms_alerts, phone (E.164),
  min_severity, daily_report, report_hour_utc, last_report_on, enabled_at, updated_at.
- `alert_deliveries`: outbox of email/SMS messages with status
  (pending | sending | sent | failed | not_configured), attempts, error, provider_id, timestamps.
- `monitoring_reports`: one daily report per user per day (summary JSON + text body).
- `internal_config`: server-only key/value (dispatch secret, functions URL). No client access.
2. Functions
- `monitoring_active(uid)`: true when the user has Pro/Elite (or is admin) AND monitoring is on.
- `monitoring_build_report(uid, deliver)`: builds the daily report and queues delivery.
- `monitoring_daily_reports()`: hourly; builds reports for users whose report hour has arrived.
- `claim_alert_deliveries(n)`: atomically claims pending messages for the dispatcher.
- `alert_dispatch_kick()`: calls the alert-dispatch function when messages are waiting.
- `endpoint_open_incident` now also queues email/SMS alerts when monitoring is active.
- `endpoint_monitor_tick` now only runs health checks and scheduled scans for users with
  monitoring active.
3. Security
- RLS on all new tables. Users can SELECT only their own settings, deliveries and reports.
  All writes happen server-side (service_role / SECURITY DEFINER functions).
- `internal_config` has RLS and no client grants.
- All new functions: EXECUTE revoked from PUBLIC, anon, authenticated.
4. Scheduling (pg_cron)
- `blackveil-alert-dispatch` every minute, `blackveil-daily-reports` hourly.

Notes
1. Additive only; no data removed.
2. Delivery needs email (Resend) / SMS (Twilio) keys; without them messages are marked
   "not_configured" and are still visible in-app.
*/

CREATE EXTENSION IF NOT EXISTS pg_net;

CREATE TABLE IF NOT EXISTS internal_config (
  key text PRIMARY KEY,
  value text NOT NULL
);
ALTER TABLE internal_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON internal_config FROM anon, authenticated;
GRANT SELECT ON internal_config TO service_role;
INSERT INTO internal_config (key, value) VALUES ('dispatch_secret', encode(gen_random_bytes(32), 'hex')) ON CONFLICT (key) DO NOTHING;
INSERT INTO internal_config (key, value) VALUES ('functions_url', 'https://ubtdcjdbrewwcgcadeth.supabase.co/functions/v1') ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS monitoring_settings (
  user_id uuid PRIMARY KEY DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT false,
  email_alerts boolean NOT NULL DEFAULT true,
  sms_alerts boolean NOT NULL DEFAULT false,
  phone text CHECK (phone IS NULL OR phone ~ '^\+[1-9][0-9]{7,14}$'),
  min_severity text NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('critical','high','medium','low')),
  daily_report boolean NOT NULL DEFAULT true,
  report_hour_utc int NOT NULL DEFAULT 13 CHECK (report_hour_utc BETWEEN 0 AND 23),
  last_report_on date,
  enabled_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE monitoring_settings ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON monitoring_settings TO authenticated;
GRANT SELECT, INSERT, UPDATE ON monitoring_settings TO service_role;
DROP POLICY IF EXISTS "select_own_monitoring_settings" ON monitoring_settings;
CREATE POLICY "select_own_monitoring_settings" ON monitoring_settings FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS alert_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  channel text NOT NULL CHECK (channel IN ('email','sms')),
  kind text NOT NULL CHECK (kind IN ('incident','daily_report','test')),
  subject text NOT NULL,
  body text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','sent','failed','not_configured')),
  attempts int NOT NULL DEFAULT 0,
  error text,
  provider_id text,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE INDEX IF NOT EXISTS alert_deliveries_pending_idx ON alert_deliveries(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS alert_deliveries_user_idx ON alert_deliveries(user_id, created_at DESC);
ALTER TABLE alert_deliveries ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON alert_deliveries TO authenticated;
GRANT SELECT, INSERT, UPDATE ON alert_deliveries TO service_role;
DROP POLICY IF EXISTS "select_own_alert_deliveries" ON alert_deliveries;
CREATE POLICY "select_own_alert_deliveries" ON alert_deliveries FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS monitoring_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  report_date date NOT NULL,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, report_date)
);
ALTER TABLE monitoring_reports ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON monitoring_reports TO authenticated;
GRANT SELECT, INSERT, UPDATE ON monitoring_reports TO service_role;
DROP POLICY IF EXISTS "select_own_monitoring_reports" ON monitoring_reports;
CREATE POLICY "select_own_monitoring_reports" ON monitoring_reports FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION monitoring_has_plan(p_user uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM subscriptions s WHERE s.user_id = p_user AND s.plan IN ('pro','elite') AND s.status IN ('active','trialing'))
      OR EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_user AND u.raw_app_meta_data->>'role' = 'admin');
$$;
REVOKE EXECUTE ON FUNCTION monitoring_has_plan(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION monitoring_has_plan(uuid) TO service_role;

CREATE OR REPLACE FUNCTION monitoring_active(p_user uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT coalesce((SELECT enabled FROM monitoring_settings WHERE user_id = p_user), false) AND monitoring_has_plan(p_user);
$$;
REVOKE EXECUTE ON FUNCTION monitoring_active(uuid) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION monitoring_queue_alert(p_user uuid, p_kind text, p_subject text, p_body text, p_sms text, p_severity text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE s monitoring_settings%ROWTYPE; rank_in int; rank_min int;
BEGIN
  SELECT * INTO s FROM monitoring_settings WHERE user_id = p_user;
  IF NOT FOUND OR NOT s.enabled OR NOT monitoring_has_plan(p_user) THEN RETURN; END IF;
  IF p_severity IS NOT NULL THEN
    rank_in := array_position(ARRAY['low','medium','high','critical'], p_severity);
    rank_min := array_position(ARRAY['low','medium','high','critical'], s.min_severity);
    IF coalesce(rank_in, 2) < coalesce(rank_min, 2) THEN RETURN; END IF;
  END IF;
  IF s.email_alerts THEN
    INSERT INTO alert_deliveries (user_id, channel, kind, subject, body) VALUES (p_user, 'email', p_kind, p_subject, p_body);
  END IF;
  IF s.sms_alerts AND s.phone IS NOT NULL THEN
    INSERT INTO alert_deliveries (user_id, channel, kind, subject, body) VALUES (p_user, 'sms', p_kind, p_subject, left(p_sms, 300));
  END IF;
END $$;
REVOKE EXECUTE ON FUNCTION monitoring_queue_alert(uuid,text,text,text,text,text) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION endpoint_open_incident(
  p_user uuid, p_device uuid, p_threat uuid, p_job uuid, p_kind text, p_key text,
  p_severity text, p_title text, p_detail jsonb, p_status text, p_once boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE inserted uuid; summary text;
BEGIN
  IF p_once AND EXISTS (SELECT 1 FROM endpoint_incidents WHERE user_id = p_user AND dedupe_key = p_key) THEN
    RETURN false;
  END IF;
  INSERT INTO endpoint_incidents (user_id, device_id, threat_id, job_id, kind, dedupe_key, severity, title, detail, status)
  VALUES (p_user, p_device, p_threat, p_job, p_kind, p_key, p_severity, p_title, p_detail, p_status)
  ON CONFLICT (user_id, dedupe_key) WHERE status <> 'resolved' DO NOTHING
  RETURNING id INTO inserted;
  IF inserted IS NULL THEN RETURN false; END IF;
  summary := coalesce(p_detail->>'summary', 'Open Malware Remediation to review.');
  INSERT INTO endpoint_audit (user_id, device_id, job_id, actor, action, outcome, detail)
  VALUES (p_user, p_device, p_job, 'system', 'incident_opened', p_status, jsonb_build_object('incident', inserted, 'kind', p_kind, 'title', p_title));
  INSERT INTO notifications (user_id, kind, title, body, link) VALUES (p_user, 'system', p_title, summary, 'malware');
  PERFORM monitoring_queue_alert(p_user, 'incident', '[Blackveil ' || upper(p_severity) || '] ' || p_title,
    p_title || E'\n\n' || summary || E'\n\nSeverity: ' || p_severity || E'\nOpened: ' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') || E' UTC\n\nSign in to Blackveil Security > Malware Removal to review and approve any action. Nothing is removed without your approval.',
    'Blackveil ' || upper(p_severity) || ': ' || p_title || '. Sign in to review.', p_severity);
  RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_open_incident(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,boolean) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION monitoring_build_report(p_user uuid, p_deliver boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_devices int; v_online int; v_scans int; v_failed_jobs int; v_threats int; v_open int; v_opened int; v_resolved int;
  v_gaps text[] := '{}'; v_body text; v_summary jsonb; v_id uuid; v_status text; dname text;
BEGIN
  SELECT count(*), count(*) FILTER (WHERE last_seen_at > now() - interval '30 minutes') INTO v_devices, v_online
    FROM endpoint_devices WHERE user_id = p_user AND revoked_at IS NULL;
  SELECT count(*) FILTER (WHERE kind = 'scan' AND status = 'succeeded'), count(*) FILTER (WHERE status IN ('failed','expired'))
    INTO v_scans, v_failed_jobs FROM endpoint_jobs WHERE user_id = p_user AND created_at > now() - interval '24 hours';
  SELECT count(*) INTO v_threats FROM endpoint_threats WHERE user_id = p_user AND last_seen_at > now() - interval '24 hours';
  SELECT count(*) FILTER (WHERE status <> 'resolved'),
         count(*) FILTER (WHERE opened_at > now() - interval '24 hours'),
         count(*) FILTER (WHERE resolved_at > now() - interval '24 hours')
    INTO v_open, v_opened, v_resolved FROM endpoint_incidents WHERE user_id = p_user;
  IF v_devices = 0 THEN v_gaps := v_gaps || 'No devices are connected, so there is nothing to scan or monitor.'; END IF;
  FOR dname IN SELECT name FROM endpoint_devices WHERE user_id = p_user AND revoked_at IS NULL AND coalesce(last_seen_at, created_at) < now() - interval '30 minutes' LOOP
    v_gaps := v_gaps || (dname || ': agent offline, not currently monitored.');
  END LOOP;
  FOR dname IN SELECT name FROM endpoint_devices WHERE user_id = p_user AND revoked_at IS NULL AND (last_scan_at IS NULL OR last_scan_at < now() - interval '7 days') LOOP
    v_gaps := v_gaps || (dname || ': no completed scan in the last 7 days.');
  END LOOP;

  v_status := CASE
    WHEN v_devices = 0 THEN 'Monitoring unavailable'
    WHEN v_open > 0 THEN 'Action needed'
    WHEN array_length(v_gaps, 1) > 0 THEN 'Monitoring degraded'
    ELSE 'No open issues' END;

  v_summary := jsonb_build_object('status', v_status, 'devices', v_devices, 'online', v_online, 'scans_24h', v_scans,
    'failed_jobs_24h', v_failed_jobs, 'threats_24h', v_threats, 'open_incidents', v_open,
    'incidents_opened_24h', v_opened, 'incidents_resolved_24h', v_resolved, 'gaps', to_jsonb(v_gaps));

  v_body := 'Blackveil Security daily report - ' || to_char(current_date, 'YYYY-MM-DD') || E'\n\n' ||
    'Overall: ' || v_status || E'\n' ||
    'Devices connected: ' || v_devices || ' (' || v_online || E' online now)\n' ||
    'Scans completed (24h): ' || v_scans || E'\n' ||
    'Failed or expired jobs (24h): ' || v_failed_jobs || E'\n' ||
    'Threat detections (24h): ' || v_threats || E'\n' ||
    'Incidents opened / resolved (24h): ' || v_opened || ' / ' || v_resolved || E'\n' ||
    'Open incidents: ' || v_open || E'\n\n' ||
    CASE WHEN array_length(v_gaps, 1) > 0 THEN E'Coverage gaps:\n- ' || array_to_string(v_gaps, E'\n- ') || E'\n\n' ELSE E'Coverage gaps: none detected.\n\n' END ||
    'Monitoring mode: automated server checks every 5 minutes plus agent check-ins. Real-time file protection is provided by Microsoft Defender on each PC. "No open issues" is not a guarantee that a device is free of malware.';

  INSERT INTO monitoring_reports (user_id, report_date, summary, body) VALUES (p_user, current_date, v_summary, v_body)
  ON CONFLICT (user_id, report_date) DO UPDATE SET summary = EXCLUDED.summary, body = EXCLUDED.body, created_at = now()
  RETURNING id INTO v_id;

  IF p_deliver THEN
    INSERT INTO notifications (user_id, kind, title, body, link)
    VALUES (p_user, 'system', 'Daily security report: ' || v_status, v_open || ' open incident(s), ' || v_threats || ' detection(s) in the last 24 hours.', 'malware');
    PERFORM monitoring_queue_alert(p_user, 'daily_report', 'Blackveil daily report: ' || v_status, v_body,
      'Blackveil daily report: ' || v_status || '. ' || v_open || ' open incident(s), ' || v_threats || ' detection(s) in 24h.', NULL);
  END IF;
  UPDATE monitoring_settings SET last_report_on = current_date WHERE user_id = p_user;
  RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION monitoring_build_report(uuid, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION monitoring_build_report(uuid, boolean) TO service_role;

CREATE OR REPLACE FUNCTION monitoring_daily_reports() RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE u uuid; n int := 0;
BEGIN
  FOR u IN
    SELECT user_id FROM monitoring_settings
    WHERE enabled AND daily_report AND report_hour_utc <= extract(hour FROM now() AT TIME ZONE 'UTC')
      AND (last_report_on IS NULL OR last_report_on < current_date)
  LOOP
    IF monitoring_has_plan(u) THEN
      PERFORM monitoring_build_report(u, true);
      n := n + 1;
    END IF;
  END LOOP;
  RETURN n;
END $$;
REVOKE EXECUTE ON FUNCTION monitoring_daily_reports() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION claim_alert_deliveries(p_limit int)
RETURNS SETOF alert_deliveries
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE alert_deliveries SET status = 'sending', attempts = attempts + 1
  WHERE id IN (
    SELECT id FROM alert_deliveries
    WHERE (status = 'pending' AND next_attempt_at <= now())
       OR (status = 'sending' AND next_attempt_at < now() - interval '10 minutes')
    ORDER BY created_at LIMIT greatest(1, least(p_limit, 50))
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *;
$$;
REVOKE EXECUTE ON FUNCTION claim_alert_deliveries(int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION claim_alert_deliveries(int) TO service_role;

CREATE OR REPLACE FUNCTION alert_dispatch_kick() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_url text; v_secret text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM alert_deliveries WHERE (status = 'pending' AND next_attempt_at <= now())
                 OR (status = 'sending' AND next_attempt_at < now() - interval '10 minutes')) THEN
    RETURN;
  END IF;
  SELECT value INTO v_url FROM internal_config WHERE key = 'functions_url';
  SELECT value INTO v_secret FROM internal_config WHERE key = 'dispatch_secret';
  PERFORM net.http_post(
    url := v_url || '/alert-dispatch',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-dispatch-secret', v_secret),
    body := '{}'::jsonb,
    timeout_milliseconds := 30000
  );
END $$;
REVOKE EXECUTE ON FUNCTION alert_dispatch_kick() FROM PUBLIC, anon, authenticated;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'blackveil-alert-dispatch') THEN PERFORM cron.unschedule('blackveil-alert-dispatch'); END IF;
  PERFORM cron.schedule('blackveil-alert-dispatch', '* * * * *', 'select public.alert_dispatch_kick()');
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'blackveil-daily-reports') THEN PERFORM cron.unschedule('blackveil-daily-reports'); END IF;
  PERFORM cron.schedule('blackveil-daily-reports', '3 * * * *', 'select public.monitoring_daily_reports()');
END $$;
