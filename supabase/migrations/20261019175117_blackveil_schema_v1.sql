/*
# BLACKVEIL AI — Core Schema (v1)

## Purpose
Multi-tenant cybersecurity platform: customers sign in, run authorized website
security assessments, chat with an AI security assistant, and download reports.
Administrators manage users and monitor service health. Strict per-customer data
isolation is enforced by row-level security using auth.uid().

## New Tables
1. `profiles` — one row per auth user; holds display name, role (customer|admin),
   company, and timestamps. Role is stored in raw_app_meta_data (server-side) and
   mirrored here for convenience; the authoritative check uses auth.jwt().
2. `assessments` — a website security assessment run by a user. Fields: target
   domain, status (pending|running|completed|failed), summary counts by severity,
   overall status, ownership/authorization confirmation, timestamps.
3. `findings` — individual findings belonging to an assessment. Severity
   (critical|high|medium|low|info), check id, title, evidence, remediation,
   verified (bool) vs inferred.
4. `chat_threads` — AI assistant conversation threads per user.
5. `chat_messages` — messages in a thread (role: user|assistant), content,
   flagged-uncertain marker.
6. `audit_logs` — important user actions (login, assessment started, account
   deletion, etc.). User-scoped; admins see all.
7. `admin_events` — service-level events (AI usage, errors, rate limits). For admin
   monitoring. Written by edge functions via service role.
8. `ai_usage` — per-request AI usage accounting (tokens, model, cost estimate)
   for cost controls and monitoring.

## Security
- RLS enabled on every table.
- Customer tables (assessments, findings, chat_threads, chat_messages, audit_logs,
  profiles) are owner-scoped: auth.uid() = user_id.
- admin_events and ai_usage are NOT directly writable/readable by anon or
  authenticated; they are written by edge functions using the service role key
  and read by admins via a SECURITY DEFINER function (added in a later migration
  if needed). For now they are locked down (no policies = no anon access).
- profiles.role has a default of 'customer' and a CHECK constraint.
- No plaintext passwords (Supabase Auth handles credentials).
- Owner columns default to auth.uid() so client inserts without user_id succeed.

## Notes
- The first registered user is NEVER automatically an admin. Admin provisioning is
  a manual operator action performed via SQL / Supabase dashboard by setting
  raw_app_meta_data.role = 'admin' on a chosen user. This is documented in the
  app's admin guide.
- No destructive operations; idempotent via IF NOT EXISTS.
*/

-- ---------- profiles ----------
CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  display_name text,
  company text,
  role text NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_profile" ON public.profiles;
CREATE POLICY "select_own_profile" ON public.profiles
  FOR SELECT TO authenticated USING (auth.uid() = id);

DROP POLICY IF EXISTS "update_own_profile" ON public.profiles;
CREATE POLICY "update_own_profile" ON public.profiles
  FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "insert_own_profile" ON public.profiles;
CREATE POLICY "insert_own_profile" ON public.profiles
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);

-- ---------- assessments ----------
CREATE TABLE IF NOT EXISTS public.assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  target text NOT NULL,
  authorization_confirmed boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
  overall_status text,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.assessments ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_assessments" ON public.assessments;
CREATE POLICY "select_own_assessments" ON public.assessments
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_assessments" ON public.assessments;
CREATE POLICY "insert_own_assessments" ON public.assessments
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_assessments" ON public.assessments;
CREATE POLICY "update_own_assessments" ON public.assessments
  FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_assessments" ON public.assessments;
CREATE POLICY "delete_own_assessments" ON public.assessments
  FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS assessments_user_created_idx
  ON public.assessments (user_id, created_at DESC);

-- ---------- findings ----------
CREATE TABLE IF NOT EXISTS public.findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES public.assessments(id) ON DELETE CASCADE,
  check_id text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  description text,
  evidence text,
  remediation text,
  verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_findings" ON public.findings;
CREATE POLICY "select_own_findings" ON public.findings
  FOR SELECT TO authenticated USING (
    EXISTS (SELECT 1 FROM public.assessments a
            WHERE a.id = findings.assessment_id AND a.user_id = auth.uid())
  );

DROP POLICY IF EXISTS "insert_own_findings" ON public.findings;
CREATE POLICY "insert_own_findings" ON public.findings
  FOR INSERT TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM public.assessments a
            WHERE a.id = findings.assessment_id AND a.user_id = auth.uid())
  );

DROP POLICY IF EXISTS "update_own_findings" ON public.findings;
CREATE POLICY "update_own_findings" ON public.findings
  FOR UPDATE TO authenticated USING (
    EXISTS (SELECT 1 FROM public.assessments a
            WHERE a.id = findings.assessment_id AND a.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM public.assessments a
            WHERE a.id = findings.assessment_id AND a.user_id = auth.uid())
  );

DROP POLICY IF EXISTS "delete_own_findings" ON public.findings;
CREATE POLICY "delete_own_findings" ON public.findings
  FOR DELETE TO authenticated USING (
    EXISTS (SELECT 1 FROM public.assessments a
            WHERE a.id = findings.assessment_id AND a.user_id = auth.uid())
  );

CREATE INDEX IF NOT EXISTS findings_assessment_idx
  ON public.findings (assessment_id);

-- ---------- chat_threads ----------
CREATE TABLE IF NOT EXISTS public.chat_threads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'New conversation',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.chat_threads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_threads" ON public.chat_threads;
CREATE POLICY "select_own_threads" ON public.chat_threads
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_threads" ON public.chat_threads;
CREATE POLICY "insert_own_threads" ON public.chat_threads
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_threads" ON public.chat_threads;
CREATE POLICY "update_own_threads" ON public.chat_threads
  FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_threads" ON public.chat_threads;
CREATE POLICY "delete_own_threads" ON public.chat_threads
  FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- ---------- chat_messages ----------
CREATE TABLE IF NOT EXISTS public.chat_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  thread_id uuid NOT NULL REFERENCES public.chat_threads(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('user','assistant')),
  content text NOT NULL,
  uncertain boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_messages" ON public.chat_messages;
CREATE POLICY "select_own_messages" ON public.chat_messages
  FOR SELECT TO authenticated USING (
    EXISTS (SELECT 1 FROM public.chat_threads t
            WHERE t.id = chat_messages.thread_id AND t.user_id = auth.uid())
  );

DROP POLICY IF EXISTS "insert_own_messages" ON public.chat_messages;
CREATE POLICY "insert_own_messages" ON public.chat_messages
  FOR INSERT TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM public.chat_threads t
            WHERE t.id = chat_messages.thread_id AND t.user_id = auth.uid())
  );

DROP POLICY IF EXISTS "delete_own_messages" ON public.chat_messages;
CREATE POLICY "delete_own_messages" ON public.chat_messages
  FOR DELETE TO authenticated USING (
    EXISTS (SELECT 1 FROM public.chat_threads t
            WHERE t.id = chat_messages.thread_id AND t.user_id = auth.uid())
  );

CREATE INDEX IF NOT EXISTS chat_messages_thread_idx
  ON public.chat_messages (thread_id, created_at);

-- ---------- audit_logs ----------
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_audit" ON public.audit_logs;
CREATE POLICY "select_own_audit" ON public.audit_logs
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_audit" ON public.audit_logs;
CREATE POLICY "insert_own_audit" ON public.audit_logs
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS audit_user_created_idx
  ON public.audit_logs (user_id, created_at DESC);

-- ---------- admin_events ----------
-- Written by edge functions using the service role key (bypasses RLS).
-- No anon/authenticated policies => not accessible from the client.
CREATE TABLE IF NOT EXISTS public.admin_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL,
  detail jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.admin_events ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS admin_events_created_idx
  ON public.admin_events (created_at DESC);

-- ---------- ai_usage ----------
-- Written by edge functions using service role key.
CREATE TABLE IF NOT EXISTS public.ai_usage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid,
  feature text NOT NULL,
  model text,
  input_tokens integer DEFAULT 0,
  output_tokens integer DEFAULT 0,
  cost_usd numeric(10,6) DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.ai_usage ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS ai_usage_created_idx
  ON public.ai_usage (created_at DESC);

-- ---------- updated_at trigger for profiles ----------
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS profiles_touch ON public.profiles;
CREATE TRIGGER profiles_touch BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

-- ---------- auto-create profile on signup ----------
-- A profile row is created automatically when a new auth user is inserted.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (NEW.id, NEW.email, COALESCE(NEW.raw_user_meta_data->>'display_name', ''));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
