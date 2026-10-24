/*
# Subscription table security hardening — prevent client-side plan bypass

## Problem
The `subscriptions` table grants `UPDATE` on ALL columns to the `authenticated`
role, with an RLS policy that only checks row ownership (`auth.uid() = user_id`).
This means any logged-in user can directly update their own `plan` and `status`
columns to `'elite'` and `'active'` — granting themselves paid access without
paying through Stripe. The `WITH CHECK` clause only verifies ownership, not the
values being written.

## Fix
1. Revoke ALL privileges on `subscriptions` from the `anon` role (defense-in-depth;
   no anon policy exists, but the grant was unnecessary).
2. Revoke `UPDATE` from the `authenticated` role on the entire table.
3. Grant `UPDATE` only on the `updated_at` column to `authenticated` (the
   `touch_updated_at` trigger needs this for the row-level trigger to work).
   All security-sensitive columns (`plan`, `status`, `stripe_customer_id`,
   `stripe_subscription_id`, `current_period_end`) are now writable ONLY by
   `service_role` — which is used exclusively by the Stripe webhook edge function.
4. Keep `SELECT` and `INSERT` for `authenticated` so users can read their own
   subscription and the auto-create trigger still works.

## Security impact
- `service_role` (used by stripe-webhook edge function) retains full access and
  bypasses RLS, so webhook-driven updates continue to work.
- Client-side `supabase.from('subscriptions').update({ plan: 'elite' })` will
  now fail with a column-level permission error.
- The existing `update_own_subscriptions` RLS policy remains in place but is now
  effectively limited to the `updated_at` column by the column-level grant.

## No data loss
- No columns are dropped, renamed, or type-changed.
- No rows are deleted or modified.
- Existing subscription data is fully preserved.
*/

-- 1. Remove all anon access (defense-in-depth — no anon policy exists)
REVOKE ALL ON public.subscriptions FROM anon;

-- 2. Remove broad UPDATE from authenticated
REVOKE UPDATE ON public.subscriptions FROM authenticated;

-- 3. Grant minimal UPDATE only on updated_at (needed by the touch_updated_at trigger)
GRANT UPDATE (updated_at) ON public.subscriptions TO authenticated;

-- 4. Keep SELECT and INSERT for authenticated (already present, re-grant for clarity)
GRANT SELECT ON public.subscriptions TO authenticated;
GRANT INSERT ON public.subscriptions TO authenticated;

-- 5. Ensure service_role retains full access (it bypasses RLS but needs the grant)
GRANT SELECT, INSERT, UPDATE, DELETE ON public.subscriptions TO service_role;
