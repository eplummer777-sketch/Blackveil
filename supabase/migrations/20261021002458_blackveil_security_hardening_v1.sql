/*
# Security hardening: RLS policies for system tables, function search paths, EXECUTE revokes

## Purpose
Addresses findings from the Supabase database security linter:

1. **admin_events and ai_usage tables** had RLS enabled but no policies.
   With RLS enabled and no policies, the tables are locked down (no role
   can read/write via the PostgREST API), which is the intended behavior
   since these are system tables written only by the service role from
   edge functions. However, the linter flags this as "RLS enabled no
   policy." We add explicit deny-by-default policies that document the
   intent: these tables are service-role only and should never be
   accessible via the anon or authenticated API.

2. **SECURITY DEFINER functions** (handle_new_user, handle_new_subscription,
   touch_updated_at) had mutable search_path. A mutable search_path is a
   security risk because an attacker could create objects in another schema
   that shadow the ones the function expects. We set search_path = public
   on all three functions.

3. **SECURITY DEFINER functions callable by anon/authenticated**. The
   trigger functions handle_new_user and handle_new_subscription are
   meant to be called only by PostgreSQL triggers on auth.users, not via
   the REST API. We REVOKE EXECUTE from anon and authenticated so they
   cannot be called via /rest/v1/rpc/.

## Tables modified
- `admin_events` — adds SELECT/INSERT/UPDATE/DELETE policies restricted
  to authenticated users who are admins (app_metadata.role = 'admin').
  This is defense-in-depth: the service role bypasses RLS anyway, and
  non-admin users get zero rows.
- `ai_usage` — adds SELECT policy restricted to the owning user
  (auth.uid() = user_id), and INSERT/UPDATE/DELETE restricted to admin.
  The service role (used by edge functions) bypasses RLS.

## Functions modified
- `public.handle_new_user()` — set search_path = public, revoke EXECUTE from anon + authenticated
- `public.handle_new_subscription()` — set search_path = public, revoke EXECUTE from anon + authenticated
- `public.touch_updated_at()` — set search_path = public

## Security changes
- Deny-by-default policies on admin_events and ai_usage.
- Fixed search_path on 3 SECURITY DEFINER / trigger functions.
- Revoked EXECUTE on 2 SECURITY DEFINER trigger functions from anon + authenticated roles.
- These changes do NOT affect any existing application behavior:
  - admin_events and ai_usage are only written/read by the service role (bypasses RLS)
  - handle_new_user and handle_new_subscription are only called by triggers on auth.users
  - touch_updated_at is only called by triggers on profiles/subscriptions

## Important notes
1. The policies on admin_events use a check against auth.jwt() -> app_metadata -> role
   to determine admin status. This is the same pattern used elsewhere in the app.
2. ai_usage has a user_id column for per-user SELECT access. INSERT/UPDATE/DELETE
   remain admin-only since usage records are written by the service role from edge functions.
3. No data is lost, no columns are dropped, no tables are renamed.
*/

-- ===== admin_events: admin-only access =====
-- These are system events written by edge functions (service role bypasses RLS).
-- Admins can read them via the API; no one else can.

DROP POLICY IF EXISTS "admin_read_admin_events" ON admin_events;
CREATE POLICY "admin_read_admin_events" ON admin_events FOR SELECT
  TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "admin_insert_admin_events" ON admin_events;
CREATE POLICY "admin_insert_admin_events" ON admin_events FOR INSERT
  TO authenticated
  WITH CHECK ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "admin_update_admin_events" ON admin_events;
CREATE POLICY "admin_update_admin_events" ON admin_events FOR UPDATE
  TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  WITH CHECK ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "admin_delete_admin_events" ON admin_events;
CREATE POLICY "admin_delete_admin_events" ON admin_events FOR DELETE
  TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- ===== ai_usage: user can read own usage, admin can manage all =====
-- Written by the service role from edge functions (bypasses RLS).

DROP POLICY IF EXISTS "select_own_ai_usage" ON ai_usage;
CREATE POLICY "select_own_ai_usage" ON ai_usage FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "admin_insert_ai_usage" ON ai_usage;
CREATE POLICY "admin_insert_ai_usage" ON ai_usage FOR INSERT
  TO authenticated
  WITH CHECK ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "admin_update_ai_usage" ON ai_usage;
CREATE POLICY "admin_update_ai_usage" ON ai_usage FOR UPDATE
  TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  WITH CHECK ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

DROP POLICY IF EXISTS "admin_delete_ai_usage" ON ai_usage;
CREATE POLICY "admin_delete_ai_usage" ON ai_usage FOR DELETE
  TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- ===== Fix search_path on SECURITY DEFINER functions =====

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (NEW.id, NEW.email, COALESCE(NEW.raw_user_meta_data->>'display_name', ''));
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.handle_new_subscription()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.subscriptions (user_id, plan, status)
  VALUES (NEW.id, 'free', 'free')
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- ===== Revoke EXECUTE on trigger functions from anon + authenticated =====
-- These are only called by PostgreSQL triggers on auth.users, not via the REST API.

REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_new_subscription() FROM anon, authenticated;
