import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { resolvePublic } from "../_lib/net.ts";
import { hasElite } from "../_lib/elite.ts";
import { keyHint, validateApiKey, validateInstanceName, validateInstanceUrl } from "./validate.ts";
import { decryptSecret, encryptSecret } from "./secrets.ts";
import { checkInstance } from "./health.ts";
import { getProvider, validateLimits } from "./provider.ts";

type Svc = ReturnType<typeof getServiceClient>;

const MAX_INSTANCES = 5;
const TEST_COOLDOWN_MS = 10_000;
const PUBLIC_COLUMNS = "id, name, base_url, api_key_hint, provider, status, zap_version, last_checked_at, last_ok_at, connected_since, last_error, consecutive_failures, created_at, updated_at";

const master = () => Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

async function audit(svc: Svc, userId: string, action: string, detail: Record<string, unknown>) {
  await svc.from("pob_audit").insert({ user_id: userId, action, detail, target_id: null });
}

async function loadOwned(svc: Svc, userId: string, id: unknown) {
  if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) return null;
  const { data } = await svc.from("zap_instances").select(`${PUBLIC_COLUMNS}, user_id, api_key_ciphertext`).eq("id", id).eq("user_id", userId).maybeSingle();
  return data;
}

// deno-lint-ignore no-explicit-any
async function runTest(svc: Svc, row: any) {
  const now = new Date().toISOString();
  let result;
  try {
    const key = await decryptSecret(row.api_key_ciphertext, master(), row.user_id);
    result = await checkInstance(row.base_url, key, { resolvePublic });
  } catch (err) {
    console.error("zap instance key decrypt failed", err instanceof Error ? err.name : "error");
    result = { status: "unhealthy" as const, version: null, error: "The saved API key could not be read. Enter the key again.", checks: [] };
  }
  const ok = result.status === "connected";
  const patch = {
    status: result.status, last_checked_at: now, last_error: result.error, updated_at: now,
    zap_version: result.version ?? row.zap_version,
    consecutive_failures: ok ? 0 : (row.consecutive_failures ?? 0) + 1,
    ...(ok ? { last_ok_at: now, connected_since: row.status === "connected" && row.connected_since ? row.connected_since : now } : { connected_since: null }),
  };
  const { data } = await svc.from("zap_instances").update(patch).eq("id", row.id).select(PUBLIC_COLUMNS).single();
  return { instance: data, checks: result.checks };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "POST") return errorResponse("Method not allowed", 405);
    const { user } = await getAuthenticatedUser(req);
    if (!user) return errorResponse("Unauthorized", 401);
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const svc = getServiceClient();
    if (!(await hasElite(svc, user.id, admin))) return errorResponse("ZAP scanner management is included with the Elite plan.", 402);
    const body = await req.json().catch(() => ({}));

    switch (String(body.action ?? "")) {
      case "list": {
        const { data, error } = await svc.from("zap_instances").select(PUBLIC_COLUMNS).eq("user_id", user.id).order("created_at");
        if (error) return errorResponse("Could not load scanners.", 500);
        return json({ instances: data ?? [] });
      }
      case "create": {
        const name = validateInstanceName(body.name);
        if ("error" in name) return errorResponse(name.error, 400);
        const url = validateInstanceUrl(body.base_url);
        if ("error" in url) return errorResponse(url.error, 400);
        const key = validateApiKey(body.api_key);
        if ("error" in key) return errorResponse(key.error, 400);
        const { count } = await svc.from("zap_instances").select("id", { count: "exact", head: true }).eq("user_id", user.id);
        if ((count ?? 0) >= MAX_INSTANCES) return errorResponse(`You can connect up to ${MAX_INSTANCES} scanners.`, 429);
        const { data: row, error } = await svc.from("zap_instances").insert({
          user_id: user.id, name: name.value, base_url: url.value,
          api_key_ciphertext: await encryptSecret(key.value, master(), user.id), api_key_hint: keyHint(key.value),
        }).select(`${PUBLIC_COLUMNS}, user_id, api_key_ciphertext`).single();
        if (error || !row) return errorResponse(error?.code === "23505" ? "You already have a scanner with that name." : "Could not save the scanner.", 409);
        await audit(svc, user.id, "zap_instance_created", { name: row.name, host: new URL(row.base_url).hostname });
        return json(await runTest(svc, row));
      }
      case "update": {
        const row = await loadOwned(svc, user.id, body.id);
        if (!row) return errorResponse("Scanner not found", 404);
        const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
        if (body.name !== undefined) {
          const n = validateInstanceName(body.name);
          if ("error" in n) return errorResponse(n.error, 400);
          patch.name = n.value;
        }
        if (body.base_url !== undefined) {
          const u = validateInstanceUrl(body.base_url);
          if ("error" in u) return errorResponse(u.error, 400);
          patch.base_url = u.value;
        }
        if (typeof body.api_key === "string" && body.api_key.trim()) {
          const k = validateApiKey(body.api_key);
          if ("error" in k) return errorResponse(k.error, 400);
          patch.api_key_ciphertext = await encryptSecret(k.value, master(), user.id);
          patch.api_key_hint = keyHint(k.value);
        }
        const connectionChanged = "base_url" in patch || "api_key_ciphertext" in patch;
        if (connectionChanged) Object.assign(patch, { status: "configured", connected_since: null, last_error: null, zap_version: null });
        const { data: updated, error } = await svc.from("zap_instances").update(patch).eq("id", row.id).eq("user_id", user.id)
          .select(`${PUBLIC_COLUMNS}, user_id, api_key_ciphertext`).single();
        if (error || !updated) return errorResponse(error?.code === "23505" ? "You already have a scanner with that name." : "Could not update the scanner.", 409);
        await audit(svc, user.id, "zap_instance_updated", { name: updated.name, fields: Object.keys(patch).filter((k) => k !== "api_key_ciphertext" && k !== "updated_at") });
        if (connectionChanged) return json(await runTest(svc, updated));
        const { api_key_ciphertext: _c, user_id: _u, ...pub } = updated;
        return json({ instance: pub, checks: [] });
      }
      case "test": {
        const row = await loadOwned(svc, user.id, body.id);
        if (!row) return errorResponse("Scanner not found", 404);
        if (row.last_checked_at && Date.now() - new Date(row.last_checked_at).getTime() < TEST_COOLDOWN_MS) {
          return errorResponse("This scanner was just checked. Wait a few seconds and try again.", 429);
        }
        return json(await runTest(svc, row));
      }
      case "remove": {
        const row = await loadOwned(svc, user.id, body.id);
        if (!row) return errorResponse("Scanner not found", 404);
        const { error } = await svc.from("zap_instances").delete().eq("id", row.id).eq("user_id", user.id);
        if (error) return errorResponse("Could not remove the scanner.", 500);
        await audit(svc, user.id, "zap_instance_removed", { name: row.name });
        return json({ ok: true });
      }
      case "provider_status": {
        const p = getProvider();
        return json({ provider: p.id, configured: p.configured });
      }
      case "provision": {
        const limits = validateLimits(body.limits);
        if ("error" in limits) return errorResponse(limits.error, 400);
        const result = await getProvider().create(user.id, limits.value);
        if (!result.ok) return errorResponse(result.error, 501);
        return errorResponse("Provisioning is not available.", 501);
      }
      case "restart": {
        const row = await loadOwned(svc, user.id, body.id);
        if (!row) return errorResponse("Scanner not found", 404);
        if (row.provider === "manual") return errorResponse("This scanner runs on your own server. Restart ZAP there, then press Test.", 409);
        const r = await getProvider().restart(row.id);
        return r.ok ? json({ ok: true }) : errorResponse(r.error ?? "Restart failed.", 501);
      }
      default:
        return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("zap-instances error", err instanceof Error ? err.message : "error");
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
