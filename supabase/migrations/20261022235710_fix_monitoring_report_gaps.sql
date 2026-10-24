/*
# Fix daily report crash when listing coverage gaps

1. Changes
- `monitoring_build_report` appended plain text to a text array with `||`, which Postgres
  parsed as an array literal and failed. It now uses `array_append`.
2. Security
- Unchanged: still SECURITY DEFINER, EXECUTE only for service_role.
*/
CREATE OR REPLACE FUNCTION public.monitoring_build_report(p_user uuid, p_deliver boolean)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public', 'pg_temp'
AS $function$
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
IF v_devices = 0 THEN v_gaps := array_append(v_gaps, 'No devices are connected, so there is nothing to scan or monitor.'::text); END IF;
FOR dname IN SELECT name FROM endpoint_devices WHERE user_id = p_user AND revoked_at IS NULL AND coalesce(last_seen_at, created_at) < now() - interval '30 minutes' LOOP
v_gaps := array_append(v_gaps, dname || ': agent offline, not currently monitored.');
END LOOP;
FOR dname IN SELECT name FROM endpoint_devices WHERE user_id = p_user AND revoked_at IS NULL AND (last_scan_at IS NULL OR last_scan_at < now() - interval '7 days') LOOP
v_gaps := array_append(v_gaps, dname || ': no completed scan in the last 7 days.');
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
END $function$;
REVOKE EXECUTE ON FUNCTION public.monitoring_build_report(uuid, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.monitoring_build_report(uuid, boolean) TO service_role;
