import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { requireEnv } from "../_lib/env.ts";
import { getProvider, getCloudProvider } from "./providers.ts";
import { generateEvents, sanitizeEvidence } from "./simulator.ts";
import { decideAction, evaluateProposal, isActionType, type ActionStatus } from "./policy.ts";
import { DECOY_TYPES, type DecoyType, type HoneypotSpec, type ProviderId } from "./types.ts";

const PLAN_HONEYPOT_LIMITS: Record<string, number> = { pro: 3, elite: 10 };
const ADMIN_LIMIT = 25;
const DEFAULT_MONTHLY_BUDGET = 10.00;
const CLOUD_DECOY_COST_USD = 0.50; // estimated monthly cost per Worker

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Cloudflare token encryption (reused from cloudflare-architect)

async function deriveKey(): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(requireEnv("CF_ENCRYPTION_KEY")), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("blackveil-cf-salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function decryptToken(encrypted: string, iv: string): Promise<string> {
  const key = await deriveKey();
  const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, ciphertext);
  return new TextDecoder().decode(dec);
}

interface HoneypotRow {
  id: string;
  user_id: string;
  name: string;
  decoy_type: DecoyType;
  provider: ProviderId;
  environment: "simulated" | "isolated_test" | "cloud";
  exposure: "internal_only" | "public";
  status: string;
  provider_ref: string | null;
  config: Record<string, unknown>;
  last_health_status: string;
  cf_integration_id: string | null;
  ingestion_token: string | null;
  cost_estimate_usd: number;
  cloud_resource_id: string | null;
  cloud_resource_url: string | null;
}

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function toSpec(row: HoneypotRow): HoneypotSpec {
  return { id: row.id, name: row.name, decoyType: row.decoy_type, exposure: row.exposure, config: row.config ?? {} };
}

function randomSeed(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0];
}

async function audit(svc: SupabaseClient, userId: string, action: string, detail: Record<string, unknown>) {
  await svc.from("audit_logs").insert({ user_id: userId, action, detail });
}

async function loadOwnedHoneypot(svc: SupabaseClient, id: unknown, userId: string, admin: boolean): Promise<HoneypotRow> {
  if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) throw new HttpError(400, "Invalid honeypot id.");
  const { data, error } = await svc.from("honeypots").select("*").eq("id", id).maybeSingle();
  if (error) throw new HttpError(500, "Could not load honeypot.");
  if (!data || (data.user_id !== userId && !admin)) throw new HttpError(404, "Honeypot not found.");
  return data as HoneypotRow;
}

async function runHealthCheck(svc: SupabaseClient, row: HoneypotRow, cloudCreds?: { apiToken: string; accountId: string; ingestUrl: string }) {
  const provider = getProvider(row.provider, cloudCreds);
  const result = await provider.healthCheck(toSpec(row), row.provider_ref ?? "");
  const now = new Date().toISOString();

  await svc.from("honeypot_health_checks").insert({
    honeypot_id: row.id,
    user_id: row.user_id,
    status: result.healthy ? "healthy" : "unhealthy",
    checks: result.checks,
    latency_ms: result.latencyMs,
  });

  const update = result.healthy
    ? { status: "active", last_health_status: "healthy", last_health_check_at: now, verified_at: now }
    : {
      status: row.status === "deploying" ? "failed" : "degraded",
      last_health_status: "unhealthy",
      last_health_check_at: now,
    };
  const { data, error } = await svc.from("honeypots").update(update).eq("id", row.id).select("*").maybeSingle();
  if (error || !data) throw new HttpError(500, "Health check ran but the result could not be saved.");
  return { honeypot: data, health: result };
}

// --- Spending management ---

async function ensureSpendingRecord(svc: SupabaseClient, userId: string) {
  const { data } = await svc.from("honeypot_spending").select("*").eq("user_id", userId).maybeSingle();
  if (!data) {
    await svc.from("honeypot_spending").insert({
      user_id: userId,
      monthly_budget_usd: DEFAULT_MONTHLY_BUDGET,
      total_spent_usd: 0,
    });
  }
}

async function checkBudget(svc: SupabaseClient, userId: string): Promise<void> {
  await ensureSpendingRecord(svc, userId);
  const { data } = await svc.from("honeypot_spending").select("monthly_budget_usd, total_spent_usd").eq("user_id", userId).maybeSingle();
  if (!data) return;
  const remaining = Number(data.monthly_budget_usd) - Number(data.total_spent_usd);
  if (remaining < CLOUD_DECOY_COST_USD) {
    throw new HttpError(403, `Cloud deployment would exceed your monthly budget of $${data.monthly_budget_usd}. Current spend: $${data.total_spent_usd}. Increase your budget in Settings or retire a cloud decoy.`);
  }
}

async function addSpending(svc: SupabaseClient, userId: string, amount: number) {
  await ensureSpendingRecord(svc, userId);
  const { data } = await svc.from("honeypot_spending").select("total_spent_usd").eq("user_id", userId).maybeSingle();
  if (data) {
    const newTotal = Number(data.total_spent_usd) + amount;
    await svc.from("honeypot_spending").update({ total_spent_usd: newTotal, updated_at: new Date().toISOString() }).eq("user_id", userId);
  }
}

async function subtractSpending(svc: SupabaseClient, userId: string, amount: number) {
  await ensureSpendingRecord(svc, userId);
  const { data } = await svc.from("honeypot_spending").select("total_spent_usd").eq("user_id", userId).maybeSingle();
  if (data) {
    const newTotal = Math.max(0, Number(data.total_spent_usd) - amount);
    await svc.from("honeypot_spending").update({ total_spent_usd: newTotal, updated_at: new Date().toISOString() }).eq("user_id", userId);
  }
}

// --- Cloudflare credential loading ---

async function loadCloudflareCreds(svc: SupabaseClient, integrationId: string): Promise<{ apiToken: string; accountId: string; ingestUrl: string }> {
  if (!UUID.test(integrationId)) throw new HttpError(400, "Invalid integration id.");

  const { data: integration, error: integError } = await svc.from("architect_integrations")
    .select("id, user_id, status, mode, account_id, zone_name").eq("id", integrationId).maybeSingle();
  if (integError || !integration) throw new HttpError(404, "Cloudflare integration not found. Connect one in Architect first.");
  if (integration.status !== "connected") throw new HttpError(403, "This Cloudflare integration is not active. Reconnect it in Architect.");
  if (integration.mode !== "write") throw new HttpError(403, "Cloud deployment requires write mode. Enable write mode on your Cloudflare integration in Architect.");

  const { data: secret, error: secretError } = await svc.from("architect_integration_secrets")
    .select("encrypted_token, iv").eq("integration_id", integrationId).maybeSingle();
  if (secretError || !secret) throw new HttpError(404, "No stored credentials for this integration. Reconnect it in Architect.");

  const apiToken = await decryptToken(secret.encrypted_token as string, secret.iv as string);
  const accountId = integration.account_id;
  if (!accountId) throw new HttpError(400, "This integration has no account ID. Reconnect it in Architect.");

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const ingestUrl = `${supabaseUrl}/functions/v1/sentinel-ingest`;

  return { apiToken, accountId, ingestUrl };
}

// --- Deploy handlers ---

async function handleDeploy(svc: SupabaseClient, userId: string, limit: number, admin: boolean, body: Record<string, unknown>) {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const decoyType = body.decoy_type as DecoyType;
  if (name.length < 1 || name.length > 80) throw new HttpError(400, "Name must be between 1 and 80 characters.");
  if (!DECOY_TYPES.includes(decoyType)) throw new HttpError(400, "Unknown decoy type.");
  if (body.exposure !== undefined && body.exposure !== "internal_only") {
    throw new HttpError(403, "Public exposure requires a separate approval. Deploy as internal-only first.");
  }

  const providerType: ProviderId = body.provider === "cloud" ? "cloud" : "simulator";

  // Count existing non-retired honeypots
  const { count } = await svc.from("honeypots").select("id", { count: "exact", head: true })
    .eq("user_id", userId).neq("status", "retired");
  if ((count ?? 0) >= limit) throw new HttpError(403, `Your plan allows ${limit} honeypots at once. Retire or stop one first.`);

  let cloudCreds: { apiToken: string; accountId: string; ingestUrl: string } | undefined;
  let cfIntegrationId: string | null = null;
  let costEstimate = 0;

  if (providerType === "cloud") {
    // Cloud deployment requires a Cloudflare integration and budget
    const integrationId = typeof body.cf_integration_id === "string" ? body.cf_integration_id : null;
    if (!integrationId) {
      throw new HttpError(400, "Cloud deployment requires a Cloudflare integration. Connect one in Architect first.");
    }
    // Verify the integration belongs to this user
    const { data: integ } = await svc.from("architect_integrations").select("user_id").eq("id", integrationId).maybeSingle();
    if (!integ || (integ.user_id !== userId && !admin)) {
      throw new HttpError(404, "Cloudflare integration not found.");
    }

    cloudCreds = await loadCloudflareCreds(svc, integrationId);
    cfIntegrationId = integrationId;
    costEstimate = CLOUD_DECOY_COST_USD;

    // Check spending budget
    await checkBudget(svc, userId);
  }

  // Create the honeypot record
  const insertRow: Record<string, unknown> = {
    user_id: userId,
    name,
    decoy_type: decoyType,
    provider: providerType,
    environment: providerType === "cloud" ? "cloud" : "simulated",
    is_simulated: providerType === "simulator",
    exposure: "internal_only",
    status: "deploying",
    config: providerType === "simulator" ? { inject_health_fault: body.inject_health_fault === true } : {},
    cf_integration_id: cfIntegrationId,
    cost_estimate_usd: costEstimate,
  };

  const { data: created, error } = await svc.from("honeypots").insert(insertRow).select("*").maybeSingle();
  if (error || !created) throw new HttpError(500, "Could not create the honeypot record.");

  const row = created as HoneypotRow;

  try {
    const provider = getProvider(row.provider, cloudCreds);
    const deployed = await provider.deploy(toSpec(row));
    row.provider_ref = deployed.providerRef;

    const updateFields: Record<string, unknown> = { provider_ref: deployed.providerRef };

    // Store cloud metadata
    if (providerType === "cloud") {
      const cloudDeployed = deployed as DeployResult & { resourceId: string; resourceUrl: string; ingestionToken: string };
      updateFields.cloud_resource_id = cloudDeployed.resourceId;
      updateFields.cloud_resource_url = cloudDeployed.resourceUrl;
      updateFields.ingestion_token = cloudDeployed.ingestionToken;

      // Track spending
      await addSpending(svc, userId, CLOUD_DECOY_COST_USD);
    }

    await svc.from("honeypots").update(updateFields).eq("id", row.id);
  } catch (e) {
    await svc.from("honeypots").update({ status: "failed", last_health_status: "unhealthy" }).eq("id", row.id);
    await audit(svc, userId, "sentinel_deploy_failed", { honeypot_id: row.id, provider: providerType, reason: (e as Error).message });
    throw new HttpError(502, "Deployment failed: " + (e as Error).message);
  }

  // Reload the row to get the updated fields
  const { data: updatedRow } = await svc.from("honeypots").select("*").eq("id", row.id).maybeSingle();
  const fullRow = (updatedRow ?? row) as HoneypotRow;

  const result = await runHealthCheck(svc, fullRow, cloudCreds);
  await audit(svc, userId, "sentinel_honeypot_deployed", {
    honeypot_id: row.id, decoy_type: decoyType, provider: providerType, verified: result.health.healthy,
  });
  return result;
}

async function handleSimulate(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  const count = Math.max(1, Math.min(25, Number(body.count) || 5));
  let targets: HoneypotRow[];
  if (body.honeypot_id) {
    targets = [await loadOwnedHoneypot(svc, body.honeypot_id, userId, admin)];
  } else {
    const { data } = await svc.from("honeypots").select("*").eq("user_id", userId).eq("status", "active");
    targets = (data as HoneypotRow[]) ?? [];
  }
  const verified = targets.filter((t) => t.status === "active" && t.last_health_status === "healthy" && t.provider === "simulator");
  if (verified.length === 0) {
    throw new HttpError(409, "No verified simulated honeypots. Deploy one and pass a health check first. Cloud honeypots receive real events automatically.");
  }

  const rows = verified.flatMap((hp) =>
    generateEvents(hp.decoy_type, Math.ceil(count / verified.length), randomSeed()).map((e) => ({
      honeypot_id: hp.id,
      user_id: hp.user_id,
      provider: "simulator",
      is_simulated: true,
      event_type: e.eventType,
      severity: e.severity,
      protocol: e.protocol,
      source_ip: e.sourceIp,
      source_port: e.sourcePort,
      source_label: e.sourceLabel,
      summary: e.summary,
      evidence: sanitizeEvidence(e.evidence),
      mitre_technique: e.mitreTechnique,
      occurred_at: e.occurredAt,
    }))
  );

  const { error } = await svc.from("honeypot_events").insert(rows);
  if (error) throw new HttpError(500, "Could not record simulated events.");

  const serious = rows.filter((r) => r.severity === "critical" || r.severity === "high");
  if (serious.length > 0) {
    await svc.from("notifications").insert({
      user_id: userId,
      kind: "security_alert",
      title: `[Simulated] ${serious.length} high-severity honeypot event${serious.length > 1 ? "s" : ""}`,
      body: "Generated by the Sentinel simulator. No real system was involved.",
      link: "sentinel",
    });
  }
  await audit(svc, userId, "sentinel_simulation_run", { events: rows.length, honeypots: verified.map((v) => v.id) });
  return { inserted: rows.length, high_severity: serious.length };
}

async function handlePropose(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  if (!isActionType(body.action_type)) throw new HttpError(400, "Unknown action type.");
  const rationale = typeof body.rationale === "string" ? body.rationale.trim().slice(0, 2000) : "";
  if (rationale.length < 5) throw new HttpError(400, "Please describe why this action is needed.");
  const target = typeof body.target === "string" && body.target.trim() ? body.target.trim().slice(0, 120) : null;
  const proposedBy = body.proposed_by === "analyst_ai" ? "analyst_ai" : "user";

  let honeypotId: string | null = null;
  let eventId: string | null = null;
  if (body.event_id) {
    const { data: ev } = await svc.from("honeypot_events").select("id, user_id, honeypot_id").eq("id", String(body.event_id)).maybeSingle();
    if (!ev || (ev.user_id !== userId && !admin)) throw new HttpError(404, "Event not found.");
    eventId = ev.id;
    honeypotId = ev.honeypot_id;
  }

  const verdict = evaluateProposal({ actionType: body.action_type, target, proposedBy });
  const { data, error } = await svc.from("policy_actions").insert({
    user_id: userId,
    honeypot_id: honeypotId,
    event_id: eventId,
    action_type: body.action_type,
    target,
    rationale,
    proposed_by: proposedBy,
    risk_level: verdict.risk,
    affects_real_systems: verdict.affectsRealSystems,
    status: verdict.status,
    policy_reason: verdict.reason,
  }).select("*").maybeSingle();
  if (error || !data) throw new HttpError(500, "Could not record the proposed action.");

  await audit(svc, userId, "sentinel_action_proposed", {
    action_id: data.id, action_type: body.action_type, status: verdict.status, proposed_by: proposedBy,
  });
  return { action: data };
}

async function handleDecide(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  const decision = body.decision === "approve" ? "approve" : body.decision === "reject" ? "reject" : null;
  if (!decision) throw new HttpError(400, "Decision must be approve or reject.");
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 1000) : null;

  const { data: action } = await svc.from("policy_actions").select("*").eq("id", String(body.action_id ?? "")).maybeSingle();
  if (!action || (action.user_id !== userId && !admin)) throw new HttpError(404, "Action not found.");

  let environment: "simulated" | "isolated_test" | "cloud" = "simulated";
  if (action.honeypot_id) {
    const { data: hp } = await svc.from("honeypots").select("environment").eq("id", action.honeypot_id).maybeSingle();
    if (hp) environment = hp.environment;
  }

  const result = decideAction({
    currentStatus: action.status as ActionStatus,
    decision,
    deciderKind: "human",
    deciderIsOwner: action.user_id === userId,
    deciderIsAdmin: admin,
    risk: action.risk_level,
    note,
    environment,
  });
  if (!result.ok) throw new HttpError(400, result.error);

  const { data: updated, error } = await svc.from("policy_actions").update({
    status: result.status,
    decided_by: userId,
    decided_at: new Date().toISOString(),
    decision_note: note,
  }).eq("id", action.id).eq("status", "pending_approval").select("*").maybeSingle();
  if (error) throw new HttpError(500, "Could not save the decision.");
  if (!updated) throw new HttpError(409, "This action was already decided.");

  await audit(svc, action.user_id, "sentinel_action_decided", {
    action_id: action.id, decision, status: result.status, decided_by: userId,
  });
  return { action: updated, execution_note: result.executionNote };
}

// --- Stop / Start / Retire for cloud honeypots ---

async function handleStop(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  const row = await loadOwnedHoneypot(svc, body.honeypot_id, userId, admin);
  if (row.provider !== "cloud") throw new HttpError(400, "Only cloud honeypots can be stopped.");
  if (row.status === "stopped") throw new HttpError(409, "This honeypot is already stopped.");
  if (row.status === "retired") throw new HttpError(409, "This honeypot has been retired.");
  if (!row.cf_integration_id) throw new HttpError(400, "No Cloudflare integration linked to this honeypot.");

  const creds = await loadCloudflareCreds(svc, row.cf_integration_id);
  const provider = getCloudProvider(creds.apiToken, creds.accountId, creds.ingestUrl);
  await provider.stop(row.provider_ref ?? "");

  const { data } = await svc.from("honeypots").update({
    status: "stopped", verified_at: null, last_health_status: "unknown",
  }).eq("id", row.id).select("*").maybeSingle();

  await subtractSpending(svc, userId, CLOUD_DECOY_COST_USD);
  await audit(svc, userId, "sentinel_honeypot_stopped", { honeypot_id: row.id });
  return { honeypot: data };
}

async function handleStart(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  const row = await loadOwnedHoneypot(svc, body.honeypot_id, userId, admin);
  if (row.provider !== "cloud") throw new HttpError(400, "Only cloud honeypots can be started.");
  if (row.status !== "stopped") throw new HttpError(409, "Only stopped honeypots can be started.");
  if (!row.cf_integration_id) throw new HttpError(400, "No Cloudflare integration linked to this honeypot.");

  const creds = await loadCloudflareCreds(svc, row.cf_integration_id);
  const provider = getCloudProvider(creds.apiToken, creds.accountId, creds.ingestUrl);
  await provider.start(row.provider_ref ?? "");

  // Re-check budget before re-enabling
  await checkBudget(svc, userId);

  // Re-run health check
  const { data } = await svc.from("honeypots").update({ status: "deploying" }).eq("id", row.id).select("*").maybeSingle();
  const updatedRow = (data ?? row) as HoneypotRow;
  const result = await runHealthCheck(svc, updatedRow, creds);

  await addSpending(svc, userId, CLOUD_DECOY_COST_USD);
  await audit(svc, userId, "sentinel_honeypot_started", { honeypot_id: row.id, healthy: result.health.healthy });
  return result;
}

async function handleRetire(svc: SupabaseClient, userId: string, admin: boolean, body: Record<string, unknown>) {
  const row = await loadOwnedHoneypot(svc, body.honeypot_id, userId, admin);
  if (row.status === "retired") throw new HttpError(409, "Already retired.");

  let cloudCreds: { apiToken: string; accountId: string; ingestUrl: string } | undefined;
  if (row.provider === "cloud" && row.cf_integration_id) {
    cloudCreds = await loadCloudflareCreds(svc, row.cf_integration_id);
  }

  await getProvider(row.provider, cloudCreds).retire(row.provider_ref ?? "");
  const { data } = await svc.from("honeypots").update({
    status: "retired", retired_at: new Date().toISOString(), verified_at: null, last_health_status: "unknown",
  }).eq("id", row.id).select("*").maybeSingle();

  if (row.provider === "cloud" && row.cost_estimate_usd > 0) {
    await subtractSpending(svc, userId, Number(row.cost_estimate_usd));
  }

  await audit(svc, userId, "sentinel_honeypot_retired", { honeypot_id: row.id, provider: row.provider });
  return { honeypot: data };
}

// --- Budget management ---

async function handleSetBudget(svc: SupabaseClient, userId: string, body: Record<string, unknown>) {
  const budget = Number(body.monthly_budget_usd);
  if (isNaN(budget) || budget < 0 || budget > 1000) {
    throw new HttpError(400, "Budget must be between $0 and $1000.");
  }
  await ensureSpendingRecord(svc, userId);
  const { data, error } = await svc.from("honeypot_spending").update({
    monthly_budget_usd: budget, updated_at: new Date().toISOString(),
  }).eq("user_id", userId).select("*").maybeSingle();
  if (error) throw new HttpError(500, "Could not update budget.");
  await audit(svc, userId, "sentinel_budget_updated", { monthly_budget_usd: budget });
  return { spending: data };
}

async function handleGetSpending(svc: SupabaseClient, userId: string) {
  await ensureSpendingRecord(svc, userId);
  const { data } = await svc.from("honeypot_spending").select("*").eq("user_id", userId).maybeSingle();
  return { spending: data };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user, error: authError } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(authError ?? "Unauthorized", 401);

    const svc = getServiceClient();
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";

    const { data: sub } = await svc.from("subscriptions").select("plan, status").eq("user_id", user.id).maybeSingle();
    const activePlan = sub && (sub.status === "active" || sub.status === "trialing") ? String(sub.plan) : "free";
    const limit = admin ? ADMIN_LIMIT : PLAN_HONEYPOT_LIMITS[activePlan];
    if (!limit) return errorResponse("Sentinel requires a Pro or Elite subscription.", 403);

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid request body.", 400);
    }

    switch (body.action) {
      case "deploy":
        return json(await handleDeploy(svc, user.id, limit, admin, body));
      case "health_check": {
        const row = await loadOwnedHoneypot(svc, body.honeypot_id, user.id, admin);
        if (row.status === "retired") throw new HttpError(409, "This honeypot has been retired.");
        let cloudCreds: { apiToken: string; accountId: string; ingestUrl: string } | undefined;
        if (row.provider === "cloud" && row.cf_integration_id) {
          cloudCreds = await loadCloudflareCreds(svc, row.cf_integration_id);
        }
        const result = await runHealthCheck(svc, row, cloudCreds);
        await audit(svc, user.id, "sentinel_health_check", { honeypot_id: row.id, healthy: result.health.healthy });
        return json(result);
      }
      case "retire":
        return json(await handleRetire(svc, user.id, admin, body));
      case "stop":
        return json(await handleStop(svc, user.id, admin, body));
      case "start":
        return json(await handleStart(svc, user.id, admin, body));
      case "simulate":
        return json(await handleSimulate(svc, user.id, admin, body));
      case "propose_action":
        return json(await handlePropose(svc, user.id, admin, body));
      case "decide_action":
        return json(await handleDecide(svc, user.id, admin, body));
      case "set_budget":
        return json(await handleSetBudget(svc, user.id, body));
      case "get_spending":
        return json(await handleGetSpending(svc, user.id));
      default:
        return errorResponse("Unknown action.", 400);
    }
  } catch (e) {
    if (e instanceof HttpError) return errorResponse(e.message, e.status);
    console.error("sentinel-manager error", e);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});

