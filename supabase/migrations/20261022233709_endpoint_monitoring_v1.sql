/*
# Endpoint monitoring, scheduled scans and incidents

Adds a server-side monitor that runs every 5 minutes via pg_cron, independently of
whether anyone has the website open.

1. Modified tables
- `endpoint_devices`: new `scan_schedule` (off | daily | weekly), `next_scan_at`,
  `last_monitored_at` (last time the server monitor evaluated this device).
2. New tables
- `endpoint_incidents`: one row per incident (threat, agent offline, protection disabled,
  stale signatures, missed scheduled scans, failed job). Fields: kind, dedupe_key, severity,
  title, detail, status (new | investigating | awaiting_approval | remediation_in_progress |
  resolved | unresolved), auto_managed, timestamps, resolution.
- `endpoint_monitor_runs`: one row per monitor execution with counts and any error.
3. Functions
- `endpoint_monitor_tick()`: expires stale jobs, fails hung jobs, queues due scheduled scans
  (paid plans only), opens/updates/auto-resolves incidents, writes in-app notifications.
4. Scheduling
- pg_cron job `blackveil-endpoint-monitor` every 5 minutes.
5. Security
- RLS on both new tables. Owners can SELECT their incidents; runs table is server-only.
- All incident writes go through service_role (edge function) or the monitor function.
- Monitor function EXECUTE revoked from PUBLIC, anon, authenticated.

Notes
1. Nothing is deleted or renamed; all changes are additive.
2. Monitoring here is periodic (5 min) plus agent check-ins, not continuous kernel-level monitoring.
*/

CREATE EXTENSION IF NOT EXISTS pg_cron;

ALTER TABLE endpoint_devices ADD COLUMN IF NOT EXISTS scan_schedule text NOT NULL DEFAULT 'off';
ALTER TABLE endpoint_devices ADD COLUMN IF NOT EXISTS next_scan_at timestamptz;
ALTER TABLE endpoint_devices ADD COLUMN IF NOT EXISTS last_monitored_at timestamptz;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'endpoint_devices_scan_schedule_check') THEN
    ALTER TABLE endpoint_devices ADD CONSTRAINT endpoint_devices_scan_schedule_check CHECK (scan_schedule IN ('off','daily','weekly'));
  END IF;
END $$;
GRANT SELECT (scan_schedule, next_scan_at, last_monitored_at) ON endpoint_devices TO authenticated;

CREATE TABLE IF NOT EXISTS endpoint_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id uuid REFERENCES endpoint_devices(id) ON DELETE CASCADE,
  threat_id uuid REFERENCES endpoint_threats(id) ON DELETE SET NULL,
  job_id uuid REFERENCES endpoint_jobs(id) ON DELETE SET NULL,
  kind text NOT NULL CHECK (kind IN ('threat','agent_offline','protection_disabled','signatures_stale','scan_overdue','job_failed')),
  dedupe_key text NOT NULL,
  severity text NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  title text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','investigating','awaiting_approval','remediation_in_progress','resolved','unresolved')),
  auto_managed boolean NOT NULL DEFAULT true,
  opened_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolution text
);
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_incidents_open_key ON endpoint_incidents(user_id, dedupe_key) WHERE status <> 'resolved';
CREATE INDEX IF NOT EXISTS endpoint_incidents_user_idx ON endpoint_incidents(user_id, opened_at DESC);
CREATE INDEX IF NOT EXISTS endpoint_incidents_key_idx ON endpoint_incidents(dedupe_key);

ALTER TABLE endpoint_incidents ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON endpoint_incidents TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpoint_incidents TO service_role;
DROP POLICY IF EXISTS "select_own_incidents" ON endpoint_incidents;
CREATE POLICY "select_own_incidents" ON endpoint_incidents FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS endpoint_monitor_runs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  devices_checked int NOT NULL DEFAULT 0,
  scans_queued int NOT NULL DEFAULT 0,
  jobs_closed int NOT NULL DEFAULT 0,
  incidents_opened int NOT NULL DEFAULT 0,
  incidents_resolved int NOT NULL DEFAULT 0,
  error text
);
ALTER TABLE endpoint_monitor_runs ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE ON endpoint_monitor_runs TO service_role;

CREATE OR REPLACE FUNCTION endpoint_safe_ts(v text) RETURNS timestamptz
LANGUAGE plpgsql IMMUTABLE SET search_path = public, pg_temp AS $$
BEGIN
  RETURN v::timestamptz;
EXCEPTION WHEN others THEN
  RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_safe_ts(text) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION endpoint_open_incident(
  p_user uuid, p_device uuid, p_threat uuid, p_job uuid, p_kind text, p_key text,
  p_severity text, p_title text, p_detail jsonb, p_status text, p_once boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE inserted uuid;
BEGIN
  IF p_once AND EXISTS (SELECT 1 FROM endpoint_incidents WHERE user_id = p_user AND dedupe_key = p_key) THEN
    RETURN false;
  END IF;
  INSERT INTO endpoint_incidents (user_id, device_id, threat_id, job_id, kind, dedupe_key, severity, title, detail, status)
  VALUES (p_user, p_device, p_threat, p_job, p_kind, p_key, p_severity, p_title, p_detail, p_status)
  ON CONFLICT (user_id, dedupe_key) WHERE status <> 'resolved' DO NOTHING
  RETURNING id INTO inserted;
  IF inserted IS NULL THEN RETURN false; END IF;
  INSERT INTO endpoint_audit (user_id, device_id, job_id, actor, action, outcome, detail)
  VALUES (p_user, p_device, p_job, 'system', 'incident_opened', p_status, jsonb_build_object('incident', inserted, 'kind', p_kind, 'title', p_title));
  INSERT INTO notifications (user_id, kind, title, body, link)
  VALUES (p_user, 'system', p_title, coalesce(p_detail->>'summary', 'Open Malware Remediation to review.'), 'malware');
  RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_open_incident(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,boolean) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION endpoint_close_incident(p_user uuid, p_key text, p_resolution text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE n int;
BEGIN
  WITH closed AS (
    UPDATE endpoint_incidents SET status = 'resolved', resolved_at = now(), updated_at = now(), resolution = p_resolution
    WHERE user_id = p_user AND dedupe_key = p_key AND status <> 'resolved'
    RETURNING id, device_id
  ), logged AS (
    INSERT INTO endpoint_audit (user_id, device_id, actor, action, outcome, detail)
    SELECT p_user, device_id, 'system', 'incident_resolved', 'resolved', jsonb_build_object('incident', id, 'resolution', p_resolution) FROM closed
    RETURNING 1
  )
  SELECT count(*) INTO n FROM logged;
  RETURN n;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_close_incident(uuid,text,text) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION endpoint_monitor_tick() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  run_id bigint;
  d record; t record; j record;
  n int;
  v_devices int := 0; v_scans int := 0; v_jobs int := 0; v_opened int := 0; v_resolved int := 0;
  scope text; sig_ts timestamptz; online boolean; target text; overdue_after interval;
BEGIN
  INSERT INTO endpoint_monitor_runs DEFAULT VALUES RETURNING id INTO run_id;
  BEGIN
    WITH x AS (
      UPDATE endpoint_jobs SET status = 'expired', completed_at = now(), error = 'The agent did not pick up this job before it expired'
      WHERE status IN ('queued','pending_approval') AND expires_at < now() RETURNING 1
    ) SELECT count(*) INTO n FROM x;
    v_jobs := v_jobs + n;

    WITH x AS (
      UPDATE endpoint_jobs SET status = 'failed', completed_at = now(), error = 'The agent stopped responding during this job'
      WHERE status = 'dispatched' AND dispatched_at < now() - make_interval(mins => 30 + (CASE kind
        WHEN 'scan' THEN (CASE params->>'scanType' WHEN 'full' THEN 480 WHEN 'custom' THEN 90 ELSE 45 END)
        WHEN 'verify' THEN 60 WHEN 'remediate' THEN 20 ELSE 10 END))
      RETURNING 1
    ) SELECT count(*) INTO n FROM x;
    v_jobs := v_jobs + n;

    FOR d IN
      SELECT dv.*, (
        EXISTS (SELECT 1 FROM subscriptions s WHERE s.user_id = dv.user_id AND s.plan IN ('malware_removal','pro','elite') AND s.status IN ('active','trialing'))
        OR EXISTS (SELECT 1 FROM auth.users u WHERE u.id = dv.user_id AND u.raw_app_meta_data->>'role' = 'admin')
      ) AS paid
      FROM endpoint_devices dv WHERE dv.revoked_at IS NULL
    LOOP
      v_devices := v_devices + 1;
      online := d.last_seen_at IS NOT NULL AND d.last_seen_at > now() - interval '30 minutes';
      overdue_after := (CASE d.scan_schedule WHEN 'daily' THEN interval '2 days' ELSE interval '14 days' END);

      IF d.paid AND d.scan_schedule <> 'off' AND coalesce(d.next_scan_at, now()) <= now()
         AND NOT EXISTS (SELECT 1 FROM endpoint_jobs WHERE device_id = d.id AND status IN ('queued','dispatched','pending_approval')) THEN
        scope := (CASE WHEN 'quick' = ANY(d.allowed_scopes) THEN 'quick' WHEN 'full' = ANY(d.allowed_scopes) THEN 'full' ELSE NULL END);
        IF scope IS NOT NULL THEN
          INSERT INTO endpoint_jobs (device_id, user_id, kind, params, status, requested_by, approved_by, approved_at, expires_at)
          VALUES (d.id, d.user_id, 'scan', jsonb_build_object('scanType', scope, 'scheduled', true), 'queued', d.user_id, d.user_id, now(), now() + interval '6 hours');
          INSERT INTO endpoint_audit (user_id, device_id, actor, action, outcome, detail)
          VALUES (d.user_id, d.id, 'system', 'scheduled_scan', 'queued', jsonb_build_object('scanType', scope, 'schedule', d.scan_schedule));
          v_scans := v_scans + 1;
        END IF;
        UPDATE endpoint_devices SET next_scan_at = now() + (CASE d.scan_schedule WHEN 'daily' THEN interval '1 day' ELSE interval '7 days' END) WHERE id = d.id;
      END IF;

      target := 'offline:' || d.id;
      IF NOT online AND coalesce(d.last_seen_at, d.created_at) < now() - interval '30 minutes' THEN
        IF endpoint_open_incident(d.user_id, d.id, NULL, NULL, 'agent_offline', target, 'medium',
             'Agent offline: ' || d.name,
             jsonb_build_object('summary', 'The Blackveil agent on ' || d.name || ' has not checked in for over 30 minutes. This device is not being scanned.', 'last_seen_at', d.last_seen_at),
             'new', false) THEN v_opened := v_opened + 1; END IF;
      ELSE
        v_resolved := v_resolved + endpoint_close_incident(d.user_id, target, 'Agent reconnected');
      END IF;

      target := 'protection:' || d.id;
      IF online AND (d.engine_status->>'antivirusEnabled' = 'false' OR d.engine_status->>'realTimeProtection' = 'false') THEN
        IF endpoint_open_incident(d.user_id, d.id, NULL, NULL, 'protection_disabled', target, 'high',
             'Microsoft Defender protection is off on ' || d.name,
             jsonb_build_object('summary', 'Antivirus or real-time protection is disabled. Turn it back on in Windows Security.', 'engine', d.engine_status),
             'new', false) THEN v_opened := v_opened + 1; END IF;
      ELSIF online THEN
        v_resolved := v_resolved + endpoint_close_incident(d.user_id, target, 'Protection re-enabled');
      END IF;

      target := 'signatures:' || d.id;
      sig_ts := endpoint_safe_ts(d.engine_status->>'signatureUpdated');
      IF online AND sig_ts IS NOT NULL AND sig_ts < now() - interval '3 days' THEN
        IF endpoint_open_incident(d.user_id, d.id, NULL, NULL, 'signatures_stale', target, 'medium',
             'Outdated malware definitions on ' || d.name,
             jsonb_build_object('summary', 'Microsoft Defender definitions are more than 3 days old. Run Windows Update or start a scan to refresh them.', 'signature_updated', sig_ts),
             'new', false) THEN v_opened := v_opened + 1; END IF;
      ELSIF online AND sig_ts IS NOT NULL THEN
        v_resolved := v_resolved + endpoint_close_incident(d.user_id, target, 'Definitions updated');
      END IF;

      target := 'overdue:' || d.id;
      IF d.scan_schedule <> 'off' AND coalesce(d.last_scan_at, d.created_at) < now() - overdue_after THEN
        IF endpoint_open_incident(d.user_id, d.id, NULL, NULL, 'scan_overdue', target, 'medium',
             'Scheduled scans missed on ' || d.name,
             jsonb_build_object('summary', 'No scan has completed within the schedule. The agent may have been offline.', 'last_scan_at', d.last_scan_at),
             'new', false) THEN v_opened := v_opened + 1; END IF;
      ELSE
        v_resolved := v_resolved + endpoint_close_incident(d.user_id, target, 'Scan completed');
      END IF;

      UPDATE endpoint_devices SET last_monitored_at = now() WHERE id = d.id;
    END LOOP;

    FOR j IN
      SELECT ej.id, ej.user_id, ej.device_id, ej.kind, ej.status, ej.error, dv.name
      FROM endpoint_jobs ej JOIN endpoint_devices dv ON dv.id = ej.device_id
      WHERE ej.status IN ('failed','expired') AND ej.completed_at > now() - interval '2 days'
    LOOP
      IF endpoint_open_incident(j.user_id, j.device_id, NULL, j.id, 'job_failed', 'job:' || j.id,
           (CASE WHEN j.kind IN ('remediate','verify') THEN 'high' ELSE 'low' END),
           initcap(j.kind) || ' ' || j.status || ' on ' || j.name,
           jsonb_build_object('summary', coalesce(j.error, 'The job did not complete.'), 'job_kind', j.kind),
           'new', true) THEN v_opened := v_opened + 1; END IF;
    END LOOP;

    FOR t IN
      SELECT th.*, dv.name AS device_name FROM endpoint_threats th JOIN endpoint_devices dv ON dv.id = th.device_id
      WHERE th.status IN ('detected','awaiting_approval','quarantined','removed','failed')
    LOOP
      IF endpoint_open_incident(t.user_id, t.device_id, t.id, NULL, 'threat', 'threat:' || t.id || ':' || t.times_seen,
           (CASE WHEN t.severity IN ('critical','high','medium','low') THEN t.severity ELSE 'medium' END),
           'Threat detected on ' || t.device_name || ': ' || t.name,
           jsonb_build_object('summary', 'Microsoft Defender reported ' || t.name || '. Review the evidence and approve remediation.'),
           (CASE t.status WHEN 'awaiting_approval' THEN 'awaiting_approval' WHEN 'failed' THEN 'unresolved'
             WHEN 'detected' THEN 'new' ELSE 'remediation_in_progress' END),
           true) THEN v_opened := v_opened + 1; END IF;
    END LOOP;

    WITH mapped AS (
      SELECT i.id, th.status AS tstatus,
        (CASE th.status
          WHEN 'awaiting_approval' THEN 'awaiting_approval'
          WHEN 'quarantined' THEN 'remediation_in_progress'
          WHEN 'removed' THEN 'remediation_in_progress'
          WHEN 'failed' THEN 'unresolved'
          WHEN 'verified_clean' THEN 'resolved'
          WHEN 'restored' THEN 'resolved'
          ELSE i.status END) AS next_status
      FROM endpoint_incidents i JOIN endpoint_threats th ON th.id = i.threat_id
      WHERE i.kind = 'threat' AND i.status <> 'resolved'
    )
    UPDATE endpoint_incidents i SET
      status = m.next_status,
      resolved_at = (CASE WHEN m.next_status = 'resolved' THEN now() ELSE NULL END),
      resolution = (CASE m.tstatus WHEN 'verified_clean' THEN 'Verified remediated' WHEN 'restored' THEN 'Restored by user as a false positive' ELSE i.resolution END),
      updated_at = now()
    FROM mapped m
    WHERE i.id = m.id AND i.status IS DISTINCT FROM m.next_status;

    UPDATE endpoint_monitor_runs SET finished_at = now(), devices_checked = v_devices, scans_queued = v_scans,
      jobs_closed = v_jobs, incidents_opened = v_opened, incidents_resolved = v_resolved WHERE id = run_id;
  EXCEPTION WHEN others THEN
    UPDATE endpoint_monitor_runs SET finished_at = now(), error = left(SQLERRM, 300) WHERE id = run_id;
  END;
END $$;
REVOKE EXECUTE ON FUNCTION endpoint_monitor_tick() FROM PUBLIC, anon, authenticated;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'blackveil-endpoint-monitor') THEN
    PERFORM cron.unschedule('blackveil-endpoint-monitor');
  END IF;
  PERFORM cron.schedule('blackveil-endpoint-monitor', '*/5 * * * *', 'select public.endpoint_monitor_tick()');
END $$;
