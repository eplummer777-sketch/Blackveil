/*
# Blackveil Sentinel - honeypot management, events, health checks, policy actions

## Summary
Adds the data model for Blackveil Sentinel, the premium honeypot module. Users can
deploy isolated decoy services (simulated in this prototype), see recorded attacker
interactions, verify decoy health, and route any response action through a human
approval queue. All writes go through server-side functions; the browser can only
read its own rows and annotate investigations.

## 1. New Tables
### honeypots
- id, user_id (owner, defaults to auth.uid())
- name, decoy_type (ssh | http_admin | database | smb_share | iot_telnet)
- provider (simulator | isolated_test | cloud), environment (simulated | isolated_test | cloud)
- is_simulated (bool) - true for every simulator-backed decoy
- exposure (internal_only | public) - public is forbidden for simulator decoys
- status (deploying | active | degraded | failed | retiring | retired)
- provider_ref, config (jsonb), last_health_status (unknown | healthy | unhealthy)
- last_health_check_at, verified_at, retired_at, created_at, updated_at
### honeypot_health_checks
- id, honeypot_id, user_id, status (healthy | unhealthy), checks (jsonb), latency_ms, checked_at
### honeypot_events
- id, honeypot_id, user_id, provider, is_simulated, event_type, severity, protocol
- source_ip, source_port, source_label, summary, evidence (jsonb, sanitized - never passwords)
- mitre_technique, investigation_status (new | investigating | resolved | false_positive)
- investigation_notes, ai_analysis (jsonb), analyzed_at, occurred_at, created_at
### policy_actions
- id, user_id, honeypot_id, event_id, action_type, target, rationale
- proposed_by (analyst_ai | user), risk_level (low | medium | high), affects_real_systems
- status (pending_approval | approved | rejected | executed_simulated | blocked_by_policy)
- policy_reason, decided_by, decided_at, decision_note, created_at

## 2. Security
- RLS enabled on every table. Owners (and admins via app_metadata.role) can SELECT.
- authenticated gets SELECT only, plus column-limited UPDATE of investigation_status and
  investigation_notes on honeypot_events. All other writes are server-only (service_role).
- Constraints guarantee: a honeypot can never be 'active' without a passed health check;
  simulator decoys can never be public; simulator events are always flagged simulated.

## 3. Notes
1. No real passwords or files are ever stored - evidence is sanitized server-side.
2. No data is deleted or altered in existing tables.
*/

CREATE TABLE IF NOT EXISTS public.honeypots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  decoy_type text NOT NULL CHECK (decoy_type IN ('ssh','http_admin','database','smb_share','iot_telnet')),
  provider text NOT NULL DEFAULT 'simulator' CHECK (provider IN ('simulator','isolated_test','cloud')),
  environment text NOT NULL DEFAULT 'simulated' CHECK (environment IN ('simulated','isolated_test','cloud')),
  is_simulated boolean NOT NULL DEFAULT true,
  exposure text NOT NULL DEFAULT 'internal_only' CHECK (exposure IN ('internal_only','public')),
  status text NOT NULL DEFAULT 'deploying' CHECK (status IN ('deploying','active','degraded','failed','retiring','retired')),
  provider_ref text,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_health_status text NOT NULL DEFAULT 'unknown' CHECK (last_health_status IN ('unknown','healthy','unhealthy')),
  last_health_check_at timestamptz,
  verified_at timestamptz,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT honeypots_active_requires_verified_health
    CHECK (status <> 'active' OR (verified_at IS NOT NULL AND last_health_status = 'healthy')),
  CONSTRAINT honeypots_simulator_never_public
    CHECK (provider <> 'simulator' OR exposure = 'internal_only'),
  CONSTRAINT honeypots_simulator_is_simulated
    CHECK (provider <> 'simulator' OR is_simulated)
);

CREATE INDEX IF NOT EXISTS honeypots_user_status_idx ON public.honeypots (user_id, status);

CREATE TABLE IF NOT EXISTS public.honeypot_health_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  honeypot_id uuid NOT NULL REFERENCES public.honeypots(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('healthy','unhealthy')),
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  latency_ms integer,
  checked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS honeypot_health_checks_hp_idx ON public.honeypot_health_checks (honeypot_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS honeypot_health_checks_user_idx ON public.honeypot_health_checks (user_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS public.honeypot_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  honeypot_id uuid NOT NULL REFERENCES public.honeypots(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('simulator','isolated_test','cloud')),
  is_simulated boolean NOT NULL,
  event_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  protocol text,
  source_ip text,
  source_port integer,
  source_label text,
  summary text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  mitre_technique text,
  investigation_status text NOT NULL DEFAULT 'new' CHECK (investigation_status IN ('new','investigating','resolved','false_positive')),
  investigation_notes text CHECK (investigation_notes IS NULL OR char_length(investigation_notes) <= 4000),
  ai_analysis jsonb,
  analyzed_at timestamptz,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT honeypot_events_simulator_flagged CHECK (provider <> 'simulator' OR is_simulated)
);

CREATE INDEX IF NOT EXISTS honeypot_events_user_idx ON public.honeypot_events (user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS honeypot_events_hp_idx ON public.honeypot_events (honeypot_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS public.policy_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  honeypot_id uuid REFERENCES public.honeypots(id) ON DELETE SET NULL,
  event_id uuid REFERENCES public.honeypot_events(id) ON DELETE SET NULL,
  action_type text NOT NULL CHECK (action_type IN ('add_watchlist','notify_team','escalate_incident','block_source_ip','isolate_host','expose_publicly')),
  target text,
  rationale text NOT NULL CHECK (char_length(rationale) <= 2000),
  proposed_by text NOT NULL CHECK (proposed_by IN ('analyst_ai','user')),
  risk_level text NOT NULL CHECK (risk_level IN ('low','medium','high')),
  affects_real_systems boolean NOT NULL,
  status text NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval','approved','rejected','executed_simulated','blocked_by_policy')),
  policy_reason text,
  decided_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  decided_at timestamptz,
  decision_note text CHECK (decision_note IS NULL OR char_length(decision_note) <= 1000),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS policy_actions_user_idx ON public.policy_actions (user_id, status, created_at DESC);

DROP TRIGGER IF EXISTS honeypots_touch_updated_at ON public.honeypots;
CREATE TRIGGER honeypots_touch_updated_at BEFORE UPDATE ON public.honeypots
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

ALTER TABLE public.honeypots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeypot_health_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeypot_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.policy_actions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.honeypots, public.honeypot_health_checks, public.honeypot_events, public.policy_actions FROM anon, authenticated;
GRANT SELECT ON public.honeypots, public.honeypot_health_checks, public.honeypot_events, public.policy_actions TO authenticated;
GRANT UPDATE (investigation_status, investigation_notes) ON public.honeypot_events TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.honeypots, public.honeypot_health_checks, public.honeypot_events, public.policy_actions TO service_role;

DROP POLICY IF EXISTS "select_own_honeypots" ON public.honeypots;
CREATE POLICY "select_own_honeypots" ON public.honeypots FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_health_checks" ON public.honeypot_health_checks;
CREATE POLICY "select_own_health_checks" ON public.honeypot_health_checks FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "select_own_honeypot_events" ON public.honeypot_events;
CREATE POLICY "select_own_honeypot_events" ON public.honeypot_events FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "update_own_honeypot_events" ON public.honeypot_events;
CREATE POLICY "update_own_honeypot_events" ON public.honeypot_events FOR UPDATE TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "select_own_policy_actions" ON public.policy_actions;
CREATE POLICY "select_own_policy_actions" ON public.policy_actions FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
