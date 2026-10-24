/*
# Push notifications for security alerts (replaces text-message alerts)

Plain English: Blackveil can now send phone/desktop push notifications for high-priority
security incidents and the daily report. Text-message (SMS) alerts are retired; existing
phone numbers are kept but no longer used.

1. New tables
- `push_subscriptions`: one row per browser/device a user enabled push on.
  - id, user_id (owner), endpoint (push service URL, unique), p256dh + auth_secret (browser
    encryption keys), device_label, created_at, last_success_at, failure_count.
2. Modified tables
- `monitoring_settings.push_alerts` (boolean, default false).
- `alert_deliveries`: channel may now be 'push'; new `link` (in-app path opened on tap) and
  `dedupe_key` (unique per user+channel) to block duplicate notifications.
- `monitoring_settings.sms_alerts` set to false for everyone; queued SMS marked failed.
3. Functions
- `monitoring_queue_alert` no longer queues SMS; queues push for high/critical incidents
  (respecting the user's minimum level) and for daily reports, de-duplicated and capped at
  10 incident pushes per user per hour.
4. Security
- RLS on `push_subscriptions`; users may only SELECT non-secret columns of their own rows.
  All writes go through the authenticated `monitoring` server function (service_role).
- service_role may INSERT into `internal_config` so the server can store its generated
  VAPID signing key. Clients still have no access to `internal_config`.

Notes
1. No data deleted; phone/sms columns are left in place.
*/

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint text NOT NULL UNIQUE CHECK (endpoint LIKE 'https://%' AND length(endpoint) <= 1024),
  p256dh text NOT NULL CHECK (length(p256dh) BETWEEN 80 AND 100),
  auth_secret text NOT NULL CHECK (length(auth_secret) BETWEEN 16 AND 32),
  device_label text NOT NULL DEFAULT 'Browser' CHECK (length(device_label) <= 60),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_success_at timestamptz,
  failure_count int NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS push_subscriptions_user_idx ON push_subscriptions(user_id);
ALTER TABLE push_subscriptions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON push_subscriptions FROM anon, authenticated;
GRANT SELECT (id, user_id, device_label, created_at, last_success_at) ON push_subscriptions TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON push_subscriptions TO service_role;
DROP POLICY IF EXISTS "select_own_push_subscriptions" ON push_subscriptions;
CREATE POLICY "select_own_push_subscriptions" ON push_subscriptions FOR SELECT TO authenticated USING (auth.uid() = user_id);

ALTER TABLE monitoring_settings ADD COLUMN IF NOT EXISTS push_alerts boolean NOT NULL DEFAULT false;
UPDATE monitoring_settings SET sms_alerts = false WHERE sms_alerts;

ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_channel_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_channel_check CHECK (channel IN ('email','sms','push'));
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS link text;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS dedupe_key text;
CREATE UNIQUE INDEX IF NOT EXISTS alert_deliveries_dedupe_idx ON alert_deliveries(user_id, channel, dedupe_key) WHERE dedupe_key IS NOT NULL;
UPDATE alert_deliveries SET status = 'failed', error = 'Text alerts were retired' WHERE channel = 'sms' AND status IN ('pending','sending');

GRANT INSERT ON internal_config TO service_role;

CREATE OR REPLACE FUNCTION monitoring_queue_alert(p_user uuid, p_kind text, p_subject text, p_body text, p_sms text, p_severity text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE s monitoring_settings%ROWTYPE; rank_in int; rank_min int; v_recent int;
BEGIN
  SELECT * INTO s FROM monitoring_settings WHERE user_id = p_user;
  IF NOT FOUND OR NOT s.enabled OR NOT monitoring_has_plan(p_user) THEN RETURN; END IF;
  rank_in := array_position(ARRAY['low','medium','high','critical'], p_severity);
  IF p_severity IS NOT NULL THEN
    rank_min := array_position(ARRAY['low','medium','high','critical'], s.min_severity);
    IF coalesce(rank_in, 2) < coalesce(rank_min, 2) THEN RETURN; END IF;
  END IF;
  IF s.email_alerts THEN
    INSERT INTO alert_deliveries (user_id, channel, kind, subject, body) VALUES (p_user, 'email', p_kind, p_subject, p_body);
  END IF;
  IF s.push_alerts AND EXISTS (SELECT 1 FROM push_subscriptions WHERE user_id = p_user)
     AND (p_kind = 'daily_report' OR coalesce(rank_in, 0) >= 3) THEN
    SELECT count(*) INTO v_recent FROM alert_deliveries
      WHERE user_id = p_user AND channel = 'push' AND kind = 'incident' AND created_at > now() - interval '1 hour';
    IF p_kind <> 'incident' OR v_recent < 10 THEN
      INSERT INTO alert_deliveries (user_id, channel, kind, subject, body, link, dedupe_key)
      VALUES (p_user, 'push', p_kind, left(p_subject, 120), left(p_sms, 180),
              CASE WHEN p_kind = 'daily_report' THEN '/?open=reports' ELSE '/?open=incidents' END,
              p_kind || ':' || md5(p_subject || coalesce(p_sms, '')) || ':' ||
                CASE WHEN p_kind = 'daily_report' THEN to_char(now(), 'YYYYMMDD') ELSE to_char(now(), 'YYYYMMDDHH24') END)
      ON CONFLICT (user_id, channel, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING;
    END IF;
  END IF;
END $$;
REVOKE EXECUTE ON FUNCTION monitoring_queue_alert(uuid,text,text,text,text,text) FROM PUBLIC, anon, authenticated;