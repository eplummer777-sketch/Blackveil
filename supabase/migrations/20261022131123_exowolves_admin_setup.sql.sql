/*
# Set up ExoWolves admin account with full access

## Purpose
Grant the existing user eplummer777@gmail.com (ExoWolves) admin privileges
and full subscription access (Elite plan) at no cost.

## Changes
1. Update the user's password.
2. Set raw_app_meta_data role to 'admin' so the frontend recognizes them as admin.
3. Set their subscription to elite/active so all features are unlocked.

## Security
- This is an admin-level operation using service role privileges.
- The subscription update bypasses RLS (service role) which is correct —
  only the server should set subscription status, not the client.
- No existing data is lost; only this one user's metadata and subscription
  are modified.
*/

-- 1. Update password for the user
UPDATE auth.users
SET encrypted_password = crypt('lukeviet1', gen_salt('bf'))
WHERE email = 'eplummer777@gmail.com';

-- 2. Set admin role in app metadata
UPDATE auth.users
SET raw_app_meta_data = COALESCE(raw_app_meta_data, '{}'::jsonb) || '{"role": "admin"}'::jsonb
WHERE email = 'eplummer777@gmail.com';

-- 3. Set subscription to elite/active (using service role bypasses RLS)
UPDATE public.subscriptions
SET plan = 'elite', status = 'active', updated_at = now()
WHERE user_id = 'fa04e79f-046c-434e-ab64-d8f221123639';
