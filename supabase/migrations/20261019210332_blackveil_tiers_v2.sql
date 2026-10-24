/*
# BLACKVEIL AI — Three-tier subscription plans

## Purpose
Expand the existing single $5/month "malware_removal" plan into three paid tiers,
each with a different monthly AI message allowance and feature set. This is the
data-layer change that supports the new pricing UI and tiered quota enforcement.

## Plans
1. `free`            — $0,   20 AI messages / day, no malware removal guide.
2. `malware_removal` — $5/mo, 100 AI messages / month, malware removal guide. (existing tier, unchanged identity)
3. `pro`             — $10/mo, 1000 AI messages / month, malware removal guide + "extra benefits" (priority assessments, advanced reports).
4. `elite`           — $25/mo, UNLIMITED AI messages, malware removal guide + everything in Pro + "exclusive security protection" (priority AI, exclusive threat advisories).

## Schema changes
- `subscriptions.plan` CHECK constraint relaxed to include `pro` and `elite`.
- No new tables. No columns renamed or dropped. No data loss.
- Existing `malware_removal` subscribers keep their plan exactly as-is.

## Security
- No RLS policy changes — the existing owner-scoped policies on `subscriptions`
  continue to govern access. Plan values are written only by the Stripe webhook
  edge function using the service role key (server-side, not client-writable).

## Notes
- Idempotent: uses DROP/CREATE for the CHECK constraint swap and IF NOT EXISTS
  where applicable. Safe to re-run if the migration appears to time out.
- This migration does NOT charge customers. Billing is handled by Stripe via
  the existing stripe-checkout / stripe-webhook edge functions, which are being
  updated separately to create the three recurring prices.
*/

-- ---------- expand plan constraint ----------
-- The existing CHECK constraint name may vary; drop the known one and re-add.
ALTER TABLE public.subscriptions DROP CONSTRAINT IF EXISTS subscriptions_plan_check;
ALTER TABLE public.subscriptions DROP CONSTRAINT IF EXISTS subscriptions_status_check;

ALTER TABLE public.subscriptions
  ADD CONSTRAINT subscriptions_plan_check
  CHECK (plan IN ('free','malware_removal','pro','elite'));

ALTER TABLE public.subscriptions
  ADD CONSTRAINT subscriptions_status_check
  CHECK (status IN ('free','active','canceled','past_due','trialing'));
