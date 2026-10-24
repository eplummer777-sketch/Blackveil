/*
  # Daily report push: exactly one per user per day

  The daily report push dedupe key previously included a hash of the report text,
  so a regenerated report with different numbers could push twice on the same day.
  The key is now just the date for daily reports. Incident behaviour is unchanged.
*/
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
              CASE WHEN p_kind = 'daily_report' THEN 'daily_report:' || to_char(now() AT TIME ZONE 'UTC', 'YYYYMMDD')
                   ELSE p_kind || ':' || md5(p_subject || coalesce(p_sms, '')) || ':' || to_char(now(), 'YYYYMMDDHH24') END)
      ON CONFLICT (user_id, channel, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING;
    END IF;
  END IF;
END $$;
REVOKE EXECUTE ON FUNCTION monitoring_queue_alert(uuid,text,text,text,text,text) FROM PUBLIC, anon, authenticated;
