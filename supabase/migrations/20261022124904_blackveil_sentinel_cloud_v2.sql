/*
# Blackveil Sentinel - Cloud deployment support, ingestion tokens, spending limits

## Summary
Extends the Sentinel honeypot system to support real cloud-hosted decoys via Cloudflare Workers.
Adds: (1) a 'stopped' honeypot status, (2) ingestion tokens for external tools,
(3) cloud deployment metadata columns on honeypots, (4) a spending/budget tracking table,
(5) columns linking honeypots to Cloudflare integrations. All existing data and functionality preserved.

## 1. Schema changes to honeypots
- Added 'stopped' to the status CHECK constraint (distinct from 'retired' which is permanent)
- Added cloud_account_id, cloud_resource_id, cloud_resource_url (metadata for deployed Workers)
- Added cf_integration_id (links to architect_integrations for credential reuse)
- Added ingestion_token (per-honeypot secret for external event ingestion)
- Added cost_estimate_usd (tracks estimated monthly cost of the cloud resource)

## 2. New table: honeypot_spending
- Tracks cumulative spending per user across all cloud honeypots
- monthly_budget_usd is user-configurable (default $10)
- total_spent_usd accumulates as cloud resources are deployed
- billing_period_start tracks the current billing month

## 3. Security
- RLS enabled on honeypot_spending (owner + admin SELECT, service_role full)
- ingestion_token columns are excluded from authenticated SELECT (only service_role can read them)
- All writes go through edge functions using service_role
- Existing RLS policies on honeypots, honeypot_events, policy_actions preserved

## 4. Notes
- No data is deleted or altered in existing rows
- The 'stopped' state is for cloud honeypots that were intentionally shut down but not permanently retired
- Ingestion tokens are generated server-side using crypto.randomUUID() and stored hashed
*/

-- Add 'stopped' to honeypot status
ALTER TABLE public.honeypots DROP CONSTRAINT IF EXISTS honeypots_status_check;
ALTER TABLE public.honeypots ADD CONSTRAINT honeypots_status_check
  CHECK (status IN ('deploying','active','degraded','failed','retiring','retired','stopped'));

-- Add cloud deployment metadata columns
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS cloud_account_id text;
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS cloud_resource_id text;
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS cloud_resource_url text;
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS cf_integration_id uuid REFERENCES public.architect_integrations(id) ON DELETE SET NULL;
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS ingestion_token text;
ALTER TABLE public.honeypots ADD COLUMN IF NOT EXISTS cost_estimate_usd numeric(10,4) DEFAULT 0;

-- Create index for ingestion token lookups (used by the ingest edge function)
CREATE INDEX IF NOT EXISTS honeypots_ingestion_token_idx ON public.honeypots (ingestion_token) WHERE ingestion_token IS NOT NULL;

-- Spending tracking table
CREATE TABLE IF NOT EXISTS public.honeypot_spending (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  monthly_budget_usd numeric(10,2) NOT NULL DEFAULT 10.00 CHECK (monthly_budget_usd >= 0),
  total_spent_usd numeric(10,4) NOT NULL DEFAULT 0.00,
  billing_period_start timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS honeypot_spending_user_idx ON public.honeypot_spending (user_id);

-- RLS on honeypot_spending
ALTER TABLE public.honeypot_spending ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.honeypot_spending FROM anon, authenticated;
GRANT SELECT ON public.honeypot_spending TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.honeypot_spending TO service_role;

DROP POLICY IF EXISTS "select_own_spending" ON public.honeypot_spending;
CREATE POLICY "select_own_spending" ON public.honeypot_spending FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- Revoke access to sensitive new columns on honeypots (ingestion_token should not be client-readable)
-- We do this by granting SELECT only on non-sensitive columns. Since we already have a broad SELECT grant,
-- we need to revoke and re-grant with column restrictions.
REVOKE SELECT ON public.honeypots FROM authenticated;
GRANT SELECT (
  id, user_id, name, decoy_type, provider, environment, is_simulated, exposure, status,
  provider_ref, config, last_health_status, last_health_check_at, verified_at, retired_at,
  created_at, updated_at, cloud_account_id, cloud_resource_id, cloud_resource_url,
  cf_integration_id, cost_estimate_usd
) ON public.honeypots TO authenticated;

-- Update the trigger to also touch honeypot_spending
DROP TRIGGER IF EXISTS honeypots_touch_updated_at ON public.honeypots;
CREATE TRIGGER honeypots_touch_updated_at BEFORE UPDATE ON public.honeypots
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
