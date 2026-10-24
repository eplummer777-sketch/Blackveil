/*
# BLACKVEIL AI — Subscriptions & Malware Removal Guide feature

## Purpose
Add a $5/month subscription that gates the premium Malware Removal Guide.
Stripe is not yet configured, so this migration sets up the data layer only.
Once Stripe is connected, the `stripe_customer_id` and `stripe_subscription_id`
columns will be populated by a checkout edge function.

## New Tables
1. `subscriptions` — one row per user. Tracks plan ('free' | 'malware_removal'),
   status ('active' | 'canceled' | 'past_due' | 'trialing'), Stripe IDs for later
   wiring, and timestamps. Owner-scoped via auth.uid().
2. `malware_removal_progress` — per-user progress through the malware removal
   checklist steps. So users can resume where they left off. Owner-scoped.

## Security
- RLS enabled on both tables.
- Owner-scoped CRUD via auth.uid() = user_id.
- user_id defaults to auth.uid() so client inserts succeed.

## Notes
- No destructive operations; idempotent via IF NOT EXISTS.
- This does NOT charge any customer. Subscriptions are recorded in the DB; actual
  billing requires the operator to configure the Stripe secret key and deploy a
  checkout edge function (documented in the app).
*/

-- ---------- subscriptions ----------
CREATE TABLE IF NOT EXISTS public.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  plan text NOT NULL DEFAULT 'free' CHECK (plan IN ('free','malware_removal')),
  status text NOT NULL DEFAULT 'free' CHECK (status IN ('free','active','canceled','past_due','trialing')),
  stripe_customer_id text,
  stripe_subscription_id text,
  current_period_end timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id)
);
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_subscriptions" ON public.subscriptions;
CREATE POLICY "select_own_subscriptions" ON public.subscriptions
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_subscriptions" ON public.subscriptions;
CREATE POLICY "insert_own_subscriptions" ON public.subscriptions
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_subscriptions" ON public.subscriptions;
CREATE POLICY "update_own_subscriptions" ON public.subscriptions
  FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- ---------- malware_removal_progress ----------
CREATE TABLE IF NOT EXISTS public.malware_removal_progress (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  step_id text NOT NULL,
  completed boolean NOT NULL DEFAULT false,
  completed_at timestamptz,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, step_id)
);
ALTER TABLE public.malware_removal_progress ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_mrp" ON public.malware_removal_progress;
CREATE POLICY "select_own_mrp" ON public.malware_removal_progress
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "upsert_own_mrp" ON public.malware_removal_progress;
CREATE POLICY "upsert_own_mrp" ON public.malware_removal_progress
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_mrp" ON public.malware_removal_progress;
CREATE POLICY "update_own_mrp" ON public.malware_removal_progress
  FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_mrp" ON public.malware_removal_progress;
CREATE POLICY "delete_own_mrp" ON public.malware_removal_progress
  FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- ---------- auto-create free subscription on signup ----------
CREATE OR REPLACE FUNCTION public.handle_new_subscription()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO public.subscriptions (user_id, plan, status)
  VALUES (NEW.id, 'free', 'free')
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_sub_created ON auth.users;
CREATE TRIGGER on_auth_user_sub_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_subscription();

-- ---------- updated_at trigger for subscriptions ----------
DROP TRIGGER IF EXISTS subscriptions_touch ON public.subscriptions;
CREATE TRIGGER subscriptions_touch BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

DROP TRIGGER IF EXISTS mrp_touch ON public.malware_removal_progress;
CREATE TRIGGER mrp_touch BEFORE UPDATE ON public.malware_removal_progress
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
