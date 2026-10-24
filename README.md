# BLACKVEIL AI — Sentinel and Architect

Sentinel is the active-defense module of BLACKVEIL AI. It manages isolated honeypot decoys, records interactions, explains them with an AI analyst, and routes every response action through a human approval queue. It is available on the Pro (3 decoys) and Elite (10 decoys) plans; admins get 25.

## Setup

1. Install dependencies: `npm install`
2. Supabase credentials are read from `.env` (`VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`).
3. Database tables (`honeypots`, `honeypot_health_checks`, `honeypot_events`, `policy_actions`) are created by the `sentinel_honeypots_v1` migration.
4. Edge functions: `sentinel-manager` (deploy, health check, retire, simulate, propose, decide) and `threat-analyst` (AI explanations). Both require a signed-in user.
5. Optional: set the `OPENAI_API_KEY` edge function secret for higher-quality analysis. Without it, the analyst uses a fallback model and finally a rule-based explanation.
6. Run tests: `npm test` — covers the simulator (documentation-only IPs, secret redaction, severity escalation, isolation, health fault) and the policy engine (blocked actions, human-only decisions, high-risk justification).

## Safety model

- **Isolation**: the simulator runs in-process with no sockets. A DB constraint forbids public simulator decoys; `expose_publicly` is always blocked by policy.
- **No real secrets**: `sanitizeEvidence` replaces any password/token/key/cookie/session field with `[never captured]` before storage.
- **Verified health**: `status = 'active'` requires a passing health check and `verified_at` (DB constraint + server flow + UI badge).
- **AI cannot act**: analyst suggestions only create `pending_approval` rows; only a human owner or admin can decide. High-risk approvals require a written note.
- **Simulated vs real**: every decoy and event carries `is_simulated`; simulated rows are forced to `true` by constraint and shown with an amber "Simulated" badge.
- **Audit**: every operation writes to `audit_logs`. Clients have read-only access; all writes go through edge functions.

## Adding a real provider

Implement the `HoneypotProvider` interface in `supabase/functions/sentinel-manager/types.ts` (`deploy`, `healthCheck`, `retire`) and register it in `providers.ts`. A real provider must run decoys in a segmented network with no route to production, block egress except to a write-only log collector, strip secrets at capture time, report real health checks, and leave all block/isolate execution behind the existing approval queue.

# Architect

Architect is an AI security builder available on every plan (projects per 30 days: free 2, malware_removal 3, pro 25, elite 100, admin 100). Users describe what they want to protect, answer follow-up questions, and receive a plan plus concrete artifacts (Nginx/Apache headers, UFW, sshd, fail2ban, PowerShell, cloud JSON policies, checklists).

## Setup

- Tables: `architect_projects`, `architect_changes`, `architect_tests`, `architect_events` (migration `architect_v1`). Clients have SELECT only; all writes go through the `architect` edge function.
- AI: uses `OPENAI_API_KEY` (gpt-4o-mini) if set, otherwise the Pollinations fallback, otherwise deterministic safe templates. No other external services are required.
- Tests: `npm test` runs `tests/architect.test.ts` (sandbox, lifecycle, AI output filtering, URL validation).

## Lifecycle and safety model

`proposed -> tested | test_failed -> approved -> deployed -> verified`, plus `rejected` and `rolled_back`.

- **No execution**: the AI only produces text. There is no code path that connects to or runs commands on user systems.
- **Sandbox**: static analysis only (syntax, destructive/remote-exec patterns, embedded secrets, lockout risks, wildcard IAM). Nothing is executed and no network is used.
- **Honest statuses**: DB CHECK constraints require a passing test before `tested`/`approved`, an approver before `approved`/`deployed`/`verified`, and a deploy method + timestamp before `deployed`. Today the only method is `manual_self_reported` (shown as "Applied by you").
- **Verification**: only for HTTP header changes — one read-only GET to the user's public HTTPS site (private hosts rejected, max 4 redirects). Other types stay at "Applied by you".
- **Approval**: human owner only, risk acknowledgement required, written reason for high risk.
- **Audit**: every step is logged to `architect_events` and `audit_logs`.

## Adding integrations

Implement `IntegrationProvider` in `supabase/functions/architect/types.ts` (`canDeploy`, `deploy`, `rollback`) and record `deployed_method = 'integration'`. Integrations must use explicitly authorized, scoped credentials, keep the approval gate, and only set `verified` from a real post-deploy check.

# Cloudflare integration

The first real Architect integration. Users connect a Cloudflare API token scoped to a single zone, and Architect reads the zone's security settings, identifies gaps, proposes specific changes, and applies them through the official Cloudflare API after explicit human approval.

## Setup

- Tables: `architect_integrations`, `architect_integration_secrets`, `architect_cf_settings_snapshots`, `architect_cf_proposals` (migration `architect_cloudflare_v1`).
- Edge function: `cloudflare-architect` (connect, read_settings, analyze, approve, reject, apply, verify, rollback, enable_write, disconnect).
- Tokens are encrypted at rest with AES-GCM. The `architect_integration_secrets` table has NO SELECT grant to authenticated — only the service role can read them.
- No additional secrets are required. Token encryption uses a key derived from the server environment.

## What it does

- Reads 10 supported security settings from the Cloudflare API: SSL/TLS mode, Always Use HTTPS, Automatic HTTPS Rewrites, Min TLS Version, TLS 1.3, Security Level, Browser Integrity Check, Privacy Pass, HSTS, and Server-Side Exclude.
- Identifies gaps by comparing current values against recommended values.
- Proposes specific changes with explanations, risks, and rollback instructions.
- Applies changes only after explicit user approval (risk acknowledgement required; high-risk changes need a written reason).
- After applying, re-reads the setting from Cloudflare to verify it took effect.
- Supports automatic rollback to the previous value via the API.

## Safety model

- **Read-only first**: connections start in read-only mode. Write mode must be explicitly enabled after reviewing the recommendations.
- **Least-privilege tokens**: users create scoped Cloudflare API tokens with Zone:Read and optionally Zone Settings:Edit. Architect never asks for global tokens.
- **Allowlisted settings only**: only the 10 settings in the catalog can be read or written. DNS, page rules, firewall rules, and workers are never touched.
- **Never disables protections**: the analysis engine only proposes enabling or strengthening settings, never disabling them.
- **Honest statuses**: DB CHECK constraints prevent `applied` without approval, `verified` without an applied timestamp and a verification result, `failed` without an error message. A setting is only marked `verified` when a live re-read confirms the value matches.
- **Audit**: every action (connect, read, analyze, approve, reject, apply, verify, rollback, enable_write, disconnect) is logged to `audit_logs`.
- **No DNS changes**: the integration never reads or writes DNS records.

# Assessment & Remediation Engine

A unified security assessment and remediation system that inspects an authorized website with safe, non-intrusive HTTP checks and optionally reads the connected Cloudflare zone's security settings. It identifies real weaknesses, prioritizes them by severity, proposes specific fixes, applies approved fixes through the Cloudflare API, and verifies each fix by re-reading the setting.

## Setup

- Tables: `remediation_assessments`, `remediation_findings`, `remediation_audit` (migration `remediation_engine_v1`).
- Edge function: `assessment-engine` (run_assessment, approve_fix, reject_fix, apply_fix, verify_fix, get_assessment).
- Optionally links to an existing Cloudflare integration from the Architect tab. If no integration is connected, only HTTP checks run.
- Tests: `tests/assessment-engine.test.ts` covers SSRF protection, Cloudflare gap detection, fix lifecycle validation, verification logic, rate limiting, and severity mapping.

## What it does

1. **Assess**: runs safe HTTP probes (HTTPS reachability, security headers, HTTP-to-HTTPS redirect, server banner leak, DNS resolution, security.txt) and reads all 10 supported Cloudflare zone settings if connected. Findings are clearly labeled as confirmed (verified=true) or informational.
2. **Prioritize**: assigns each finding a severity (critical, high, medium, low, info), explains the evidence, describes the impact in plain English, and recommends a specific remediation.
3. **Generate fixes**: for each Cloudflare finding with a gap, generates a fix proposal with current value, proposed value, risks, and rollback instructions. HTTP findings get manual remediation advice. Only allowlisted Cloudflare API settings can be changed.
4. **Apply fixes**: requires explicit user approval (risk acknowledgement required, written reason for high-risk). Uses the secure backend with encrypted Cloudflare credentials. Saves the previous value for rollback. Prevents duplicate actions and handles API failures safely.
5. **Verify**: after applying, re-reads the setting from Cloudflare and compares it to the expected value. Shows VERIFIED, FAILED, or NOT VERIFIED based on actual evidence. Never claims the website is fully secure.

## Dashboard

The Assessment Engine page shows:
- Findings grouped by severity.
- Recommended fixes with current and proposed values.
- Pending approvals count.
- Changes successfully applied and verified.
- Verification results (actual vs expected values).
- A complete audit history for each assessment.

## Security requirements

- **Credentials on the server**: Cloudflare API tokens are encrypted at rest and only accessible via the service role. The browser never sees them.
- **Authentication required**: every edge function call verifies the user's JWT.
- **Authorization check**: users must confirm they own or have permission to assess the target domain.
- **SSRF protection**: private IPs, loopback, cloud metadata endpoints, and localhost are blocked. Redirects are re-validated after each hop.
- **Rate limiting**: max 10 assessments per user per hour.
- **No DNS changes**: the engine never reads or writes DNS records.
- **No intrusive testing**: no exploit-based or penetration-testing techniques are used. All checks are read-only HTTP probes.
- **Audit trail**: every action is logged to `remediation_audit` and `audit_logs`.


