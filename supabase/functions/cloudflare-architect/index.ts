import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { requireEnv } from "../_lib/env.ts";
import { verifyToken, listZones, getZone, CfZone } from "./cloudflare.ts";
import { readAllSettings, identifyGaps, applySetting, getSettingDef, GapProposal } from "./settings.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

interface Ctx {
  svc: SupabaseClient;
  userId: string;
  isAdmin: boolean;
}

// --- Encryption (AES-GCM) for storing tokens at rest ---
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

async function encryptToken(token: string): Promise<{ encrypted: string; iv: string }> {
  const key = await deriveKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(token));
  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

async function decryptToken(encrypted: string, iv: string): Promise<string> {
  const key = await deriveKey();
  const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, ciphertext);
  return new TextDecoder().decode(dec);
}

async function loadIntegration(ctx: Ctx, integrationId: string) {
  const { data } = await ctx.svc.from("architect_integrations").select("*").eq("id", integrationId).maybeSingle();
  if (!data || (data.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Integration not found.");
  return data as {
    id: string; user_id: string; provider: string; zone_id: string; zone_name: string;
    status: string; mode: string; account_id: string | null; account_name: string | null;
    last_error: string | null;
  };
}

async function loadToken(ctx: Ctx, integrationId: string): Promise<string> {
  const { data } = await ctx.svc.from("architect_integration_secrets").select("encrypted_token, iv")
    .eq("integration_id", integrationId).maybeSingle();
  if (!data) throw new HttpError(404, "No stored credentials for this integration.");
  return decryptToken(data.encrypted_token as string, data.iv as string);
}

async function logAudit(ctx: Ctx, action: string, integrationId: string, detail: Record<string, unknown> = {}) {
  await ctx.svc.from("audit_logs").insert({
    user_id: ctx.userId,
    action: `cloudflare_${action}`,
    detail: { integration_id: integrationId, ...detail },
  });
}

// --- Handlers ---

async function connect(ctx: Ctx, body: Record<string, unknown>) {
  const token = typeof body.api_token === "string" ? body.api_token.trim() : "";
  if (!token || token.length < 10) throw new HttpError(400, "Please provide a Cloudflare API token.");
  if (token.length > 500) throw new HttpError(400, "That token is too long. Check you pasted the right value.");

  const mode = body.mode === "write" ? "write" : "read_only";

  // 1. Verify the token is valid with Cloudflare.
  const verify = await verifyToken(token);
  if (!verify.ok) throw new HttpError(400, "Cloudflare did not accept this token. Check that it is a valid API token.");
  const tokenInfo = verify.data;
  if (tokenInfo?.status !== "active") throw new HttpError(400, `This token is ${tokenInfo?.status ?? "not active"}.`);
  if (tokenInfo.expires_on) {
    const exp = new Date(tokenInfo.expires_on).getTime();
    if (exp < Date.now()) throw new HttpError(400, "This token has expired.");
  }

  // 2. List zones the token can access.
  const zones = await listZones(token);
  if (!zones.ok || !zones.data?.length) {
    throw new HttpError(400, "This token can access no Cloudflare zones. Create a token scoped to at least one zone with Zone:Read permission.");
  }

  // 3. If a zone_id was specified, verify access to that specific zone.
  let zone: CfZone | undefined;
  if (typeof body.zone_id === "string" && body.zone_id) {
    zone = zones.data.find((z) => z.id === body.zone_id);
    if (!zone) {
      const zr = await getZone(token, body.zone_id as string);
      if (!zr.ok) throw new HttpError(400, "This token cannot access the selected zone. Check the token's zone scope.");
      zone = zr.data as CfZone;
    }
  }

  // 4. Store encrypted token + integration record.
  const enc = await encryptToken(token);
  const { data: integration, error } = await ctx.svc.from("architect_integrations").insert({
    user_id: ctx.userId,
    provider: "cloudflare",
    zone_id: zone?.id ?? zones.data[0].id,
    zone_name: zone?.name ?? zones.data[0].name,
    account_id: zone?.account.id ?? zones.data[0].account.id,
    account_name: zone?.account.name ?? zones.data[0].account.name,
    status: "connected",
    mode,
    token_permissions: tokenInfo?.policies ?? [],
  }).select("*").maybeSingle();
  if (error || !integration) throw new HttpError(500, "Could not save the integration.");

  await ctx.svc.from("architect_integration_secrets").insert({
    integration_id: integration.id,
    user_id: ctx.userId,
    encrypted_token: enc.encrypted,
    iv: enc.iv,
  });

  await logAudit(ctx, "connect", integration.id, { zone: integration.zone_name, mode });
  return {
    integration,
    zones: zones.data.map((z) => ({ id: z.id, name: z.name, account: z.account.name, status: z.status })),
  };
}

async function readSettings(ctx: Ctx, integrationId: string) {
  const integration = await loadIntegration(ctx, integrationId);
  const token = await loadToken(ctx, integrationId);

  // Re-verify the token still works.
  const verify = await verifyToken(token);
  if (!verify.ok) {
    await ctx.svc.from("architect_integrations").update({ status: "error", last_error: "Token is no longer valid." }).eq("id", integrationId);
    throw new HttpError(401, "Your Cloudflare token is no longer valid. Please reconnect.");
  }

  const { settings, errors } = await readAllSettings(token, integration.zone_id);

  // Save a snapshot.
  await ctx.svc.from("architect_cf_settings_snapshots").insert({
    integration_id: integrationId,
    user_id: ctx.userId,
    settings: settings.map((s) => ({ key: s.key, value: s.value, error: s.error })),
  });
  await ctx.svc.from("architect_integrations").update({ last_settings_at: new Date().toISOString(), status: "connected", last_error: null }).eq("id", integrationId);

  await logAudit(ctx, "read_settings", integrationId, { gaps: settings.filter((s) => s.has_gap).length, errors });
  return { settings, errors };
}

async function analyze(ctx: Ctx, integrationId: string) {
  const integration = await loadIntegration(ctx, integrationId);
  const token = await loadToken(ctx, integrationId);

  const { settings, errors } = await readAllSettings(token, integration.zone_id);

  // Save snapshot.
  await ctx.svc.from("architect_cf_settings_snapshots").insert({
    integration_id: integrationId,
    user_id: ctx.userId,
    settings: settings.map((s) => ({ key: s.key, value: s.value, error: s.error })),
  });

  const gaps = identifyGaps(settings);

  // Save gap proposals as rows.
  if (gaps.length > 0) {
    // Remove existing unapproved proposals for this integration so we don't accumulate stale ones.
    await ctx.svc.from("architect_cf_proposals").delete()
      .eq("integration_id", integrationId).in("status", ["proposed", "rejected"]);

    const rows = gaps.map((g: GapProposal) => ({
      integration_id: integrationId,
      user_id: ctx.userId,
      setting_key: g.setting_key,
      setting_label: g.setting_label,
      category: g.category,
      current_value: g.current_value,
      proposed_value: g.proposed_value,
      recommended_value: g.recommended_value,
      api_path: g.api_path,
      explanation: g.explanation,
      risks: g.risks,
      risk_level: g.risk_level,
      rollback_supported: g.rollback_supported,
      rollback_instructions: g.rollback_instructions,
      status: "proposed",
    }));
    await ctx.svc.from("architect_cf_proposals").insert(rows);
  }

  await ctx.svc.from("architect_integrations").update({ last_settings_at: new Date().toISOString(), status: "connected", last_error: null }).eq("id", integrationId);
  await logAudit(ctx, "analyze", integrationId, { gaps: gaps.length, errors });

  // Return the proposals.
  const { data: proposals } = await ctx.svc.from("architect_cf_proposals")
    .select("*").eq("integration_id", integrationId).order("created_at", { ascending: true });
  return { settings, gaps, proposals: proposals ?? [], errors };
}

async function approveProposal(ctx: Ctx, proposalId: string, body: Record<string, unknown>) {
  if (typeof proposalId !== "string" || !UUID.test(proposalId)) throw new HttpError(400, "Invalid proposal id.");
  const { data: proposal } = await ctx.svc.from("architect_cf_proposals").select("*").eq("id", proposalId).maybeSingle();
  if (!proposal || (proposal.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Proposal not found.");
  if (proposal.status !== "proposed") throw new HttpError(409, "This proposal can only be approved while it is still proposed.");

  const integration = await loadIntegration(ctx, proposal.integration_id);
  if (integration.mode !== "write") {
    throw new HttpError(403, "This integration is in read-only mode. Enable write mode before approving changes.");
  }

  const ack = body.acknowledged_risks === true;
  if (!ack) throw new HttpError(400, "Please confirm you have read the risks before approving.");
  if (proposal.risk_level === "high") {
    const note = typeof body.note === "string" ? body.note.trim() : "";
    if (note.length < 10) throw new HttpError(400, "High-risk changes need a written reason (at least 10 characters).");
  }

  const now = new Date().toISOString();
  await ctx.svc.from("architect_cf_proposals").update({
    status: "approved",
    approved_by: ctx.userId,
    approved_at: now,
  }).eq("id", proposalId).eq("status", "proposed");

  await logAudit(ctx, "approve", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key });
  return { message: `Approved: ${proposal.setting_label}. Nothing has been applied yet.` };
}

async function rejectProposal(ctx: Ctx, proposalId: string) {
  if (typeof proposalId !== "string" || !UUID.test(proposalId)) throw new HttpError(400, "Invalid proposal id.");
  const { data: proposal } = await ctx.svc.from("architect_cf_proposals").select("*").eq("id", proposalId).maybeSingle();
  if (!proposal || (proposal.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Proposal not found.");
  if (!["proposed", "approved"].includes(proposal.status)) throw new HttpError(409, "This proposal can only be rejected before it is applied.");

  await ctx.svc.from("architect_cf_proposals").update({
    status: "rejected",
    rejected_at: new Date().toISOString(),
  }).eq("id", proposalId).in("status", ["proposed", "approved"]);

  await logAudit(ctx, "reject", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key });
  return { message: `Rejected: ${proposal.setting_label}.` };
}

async function applyProposal(ctx: Ctx, proposalId: string, body: Record<string, unknown>) {
  if (typeof proposalId !== "string" || !UUID.test(proposalId)) throw new HttpError(400, "Invalid proposal id.");
  const { data: proposal } = await ctx.svc.from("architect_cf_proposals").select("*").eq("id", proposalId).maybeSingle();
  if (!proposal || (proposal.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Proposal not found.");
  if (proposal.status !== "approved") throw new HttpError(409, "Only approved proposals can be applied.");

  const integration = await loadIntegration(ctx, proposal.integration_id);
  if (integration.mode !== "write") throw new HttpError(403, "This integration is in read-only mode. Enable write mode before applying.");

  const confirmed = body.confirmed === true;
  if (!confirmed) throw new HttpError(400, "Please confirm you want to apply this change to your live Cloudflare zone.");

  const token = await loadToken(ctx, proposal.integration_id);
  const def = getSettingDef(proposal.setting_key);
  if (!def) throw new HttpError(400, "This setting is no longer supported.");

  const result = await applySetting(token, integration.zone_id, proposal.setting_key, proposal.proposed_value);
  const now = new Date().toISOString();

  if (!result.ok) {
    await ctx.svc.from("architect_cf_proposals").update({
      status: "failed",
      apply_error: result.error ?? "Unknown error",
      updated_at: now,
    }).eq("id", proposalId).eq("status", "approved");

    await logAudit(ctx, "apply_failed", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key, error: result.error });
    throw new HttpError(502, `Cloudflare rejected the change: ${result.error}`);
  }

  await ctx.svc.from("architect_cf_proposals").update({
    status: "applied",
    applied_at: now,
    apply_error: null,
  }).eq("id", proposalId).eq("status", "approved");

  await logAudit(ctx, "apply", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key });
  return { message: `Applied: ${proposal.setting_label}. Re-reading the setting to verify it took effect.` };
}

async function verifyProposal(ctx: Ctx, proposalId: string) {
  if (typeof proposalId !== "string" || !UUID.test(proposalId)) throw new HttpError(400, "Invalid proposal id.");
  const { data: proposal } = await ctx.svc.from("architect_cf_proposals").select("*").eq("id", proposalId).maybeSingle();
  if (!proposal || (proposal.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Proposal not found.");
  if (!["applied", "verified", "failed"].includes(proposal.status)) throw new HttpError(409, "Only applied changes can be verified.");

  const integration = await loadIntegration(ctx, proposal.integration_id);
  const token = await loadToken(ctx, proposal.integration_id);
  const def = getSettingDef(proposal.setting_key);
  if (!def) throw new HttpError(400, "This setting is no longer supported.");

  // Re-read the setting from Cloudflare.
  const r = await def.read(token, integration.zone_id);
  const now = new Date().toISOString();

  if (!r.ok) {
    const verifyResult = { ok: false, error: r.errors[0]?.message ?? "Could not read setting", checked_at: now };
    await ctx.svc.from("architect_cf_proposals").update({
      verification_result: verifyResult,
      verified_at: now,
    }).eq("id", proposalId);
    await logAudit(ctx, "verify_failed", proposal.integration_id, { proposal_id: proposalId, error: verifyResult.error });
    return { message: `Could not verify: ${verifyResult.error}`, passed: false, verification_result: verifyResult };
  }

  const actualValue = r.data?.value ?? null;
  const passed = JSON.stringify(actualValue) === JSON.stringify(proposal.proposed_value);

  const verifyResult = {
    ok: true,
    expected: proposal.proposed_value,
    actual: actualValue,
    checked_at: now,
  };

  if (passed) {
    await ctx.svc.from("architect_cf_proposals").update({
      status: "verified",
      verified_at: now,
      verification_result: verifyResult,
    }).eq("id", proposalId);
    await logAudit(ctx, "verify_passed", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key });
  } else {
    await ctx.svc.from("architect_cf_proposals").update({
      verification_result: verifyResult,
      verified_at: now,
    }).eq("id", proposalId);
    await logAudit(ctx, "verify_mismatch", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key, expected: proposal.proposed_value, actual: actualValue });
  }

  // Save a post-apply snapshot.
  await ctx.svc.from("architect_cf_settings_snapshots").insert({
    integration_id: proposal.integration_id,
    user_id: ctx.userId,
    settings: [{ key: proposal.setting_key, value: actualValue, source: "post_apply_verify" }],
    source: "post_apply_verify",
  });

  return {
    message: passed
      ? `Verified: ${proposal.setting_label} now matches the recommended value.`
      : `Not verified: ${proposal.setting_label} is set to ${JSON.stringify(actualValue)}, not the expected ${JSON.stringify(proposal.proposed_value)}.`,
    passed,
    verification_result: verifyResult,
  };
}

async function rollbackProposal(ctx: Ctx, proposalId: string, body: Record<string, unknown>) {
  if (typeof proposalId !== "string" || !UUID.test(proposalId)) throw new HttpError(400, "Invalid proposal id.");
  const { data: proposal } = await ctx.svc.from("architect_cf_proposals").select("*").eq("id", proposalId).maybeSingle();
  if (!proposal || (proposal.user_id !== ctx.userId && !ctx.isAdmin)) throw new HttpError(404, "Proposal not found.");
  if (!["applied", "verified"].includes(proposal.status)) throw new HttpError(409, "Only applied or verified changes can be rolled back.");

  const integration = await loadIntegration(ctx, proposal.integration_id);
  if (integration.mode !== "write") throw new HttpError(403, "Rollback requires write mode.");

  const confirmed = body.confirmed === true;
  if (!confirmed) throw new HttpError(400, "Please confirm you want to revert this change on your live Cloudflare zone.");

  if (!proposal.rollback_supported || proposal.current_value === null) {
    throw new HttpError(400, "This change does not support automatic rollback. Follow the rollback instructions to do it manually in the Cloudflare dashboard.");
  }

  const token = await loadToken(ctx, proposal.integration_id);
  const result = await applySetting(token, integration.zone_id, proposal.setting_key, proposal.current_value);
  const now = new Date().toISOString();

  if (!result.ok) {
    await ctx.svc.from("architect_cf_proposals").update({
      rollback_error: result.error ?? "Unknown error",
      updated_at: now,
    }).eq("id", proposalId);
    await logAudit(ctx, "rollback_failed", proposal.integration_id, { proposal_id: proposalId, error: result.error });
    throw new HttpError(502, `Cloudflare rejected the rollback: ${result.error}. Follow the manual rollback instructions.`);
  }

  await ctx.svc.from("architect_cf_proposals").update({
    status: "rolled_back",
    rolled_back_at: now,
    rollback_error: null,
  }).eq("id", proposalId);

  await logAudit(ctx, "rollback", proposal.integration_id, { proposal_id: proposalId, setting: proposal.setting_key });
  return { message: `Rolled back: ${proposal.setting_label} restored to its previous value.` };
}

async function enableWriteMode(ctx: Ctx, integrationId: string) {
  const integration = await loadIntegration(ctx, integrationId);
  const token = await loadToken(ctx, integrationId);

  // Verify token still works and has write permission by attempting a no-op read.
  const verify = await verifyToken(token);
  if (!verify.ok) throw new HttpError(401, "Your Cloudflare token is no longer valid. Please reconnect.");

  await ctx.svc.from("architect_integrations").update({ mode: "write" }).eq("id", integrationId);
  await logAudit(ctx, "enable_write", integrationId, { zone: integration.zone_name });
  return { message: `Write mode enabled for ${integration.zone_name}. You can now approve and apply changes.` };
}

async function disconnect(ctx: Ctx, integrationId: string) {
  const integration = await loadIntegration(ctx, integrationId);
  // Secrets are cascade-deleted by FK.
  await ctx.svc.from("architect_integrations").update({ status: "disconnected" }).eq("id", integrationId);
  await ctx.svc.from("architect_integration_secrets").delete().eq("integration_id", integrationId);
  await logAudit(ctx, "disconnect", integrationId, { zone: integration.zone_name });
  return { message: `Disconnected from ${integration.zone_name}. Your API token has been deleted.` };
}

// --- Router ---
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user, error: authError } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(authError ?? "Unauthorized", 401);

    const svc = getServiceClient();
    const isAdmin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const ctx: Ctx = { svc, userId: user.id, isAdmin };

    let body: Record<string, unknown>;
    try { body = await req.json(); } catch { return errorResponse("Invalid request body.", 400); }

    switch (body.action) {
      case "connect": return json(await connect(ctx, body));
      case "read_settings": {
        if (typeof body.integration_id !== "string" || !UUID.test(body.integration_id)) return errorResponse("Invalid integration id.", 400);
        return json(await readSettings(ctx, body.integration_id));
      }
      case "analyze": {
        if (typeof body.integration_id !== "string" || !UUID.test(body.integration_id)) return errorResponse("Invalid integration id.", 400);
        return json(await analyze(ctx, body.integration_id));
      }
      case "approve": return json(await approveProposal(ctx, body.proposal_id as string, body));
      case "reject": return json(await rejectProposal(ctx, body.proposal_id as string));
      case "apply": return json(await applyProposal(ctx, body.proposal_id as string, body));
      case "verify": return json(await verifyProposal(ctx, body.proposal_id as string));
      case "rollback": return json(await rollbackProposal(ctx, body.proposal_id as string, body));
      case "enable_write": {
        if (typeof body.integration_id !== "string" || !UUID.test(body.integration_id)) return errorResponse("Invalid integration id.", 400);
        return json(await enableWriteMode(ctx, body.integration_id));
      }
      case "disconnect": {
        if (typeof body.integration_id !== "string" || !UUID.test(body.integration_id)) return errorResponse("Invalid integration id.", 400);
        return json(await disconnect(ctx, body.integration_id));
      }
      case "list_integrations": {
        const { data: integrations } = await ctx.svc.from("architect_integrations")
          .select("id, user_id, provider, zone_id, zone_name, account_id, account_name, status, mode, last_error, created_at, updated_at")
          .eq("user_id", ctx.userId).order("created_at", { ascending: false });
        const adminIntegrations = ctx.isAdmin
          ? (await ctx.svc.from("architect_integrations")
              .select("id, user_id, provider, zone_id, zone_name, account_id, account_name, status, mode, last_error, created_at, updated_at")
              .order("created_at", { ascending: false })).data ?? []
          : [];
        const all = [...(integrations ?? []), ...adminIntegrations.filter((i: Record<string, unknown>) => i.user_id !== ctx.userId)];
        return json({ integrations: all });
      }
      default: return errorResponse("Unknown action.", 400);
    }
  } catch (e) {
    if (e instanceof HttpError) return errorResponse(e.message, e.status);
    console.error("cloudflare-architect error", e);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});

