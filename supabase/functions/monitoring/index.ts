import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { channelStatus, sendEmail } from "../_lib/alerts.ts";
import { getVapidKeys, isAllowedPushEndpoint, isValidSubscriptionKeys, pushToUser } from "../_lib/webpush.ts";

const SEVERITIES = ["critical", "high", "medium", "low"];
const TESTS_PER_HOUR = 3;
const REPORTS_PER_HOUR = 5;
const PUSH_TESTS_PER_HOUR = 5;
const MAX_PUSH_DEVICES = 10;

async function hasPlan(svc: SupabaseClient, userId: string, isAdmin: boolean) {
  if (isAdmin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && ["pro", "elite"].includes(data.plan) && ["active", "trialing"].includes(data.status);
}

async function saveSettings(svc: SupabaseClient, userId: string, body: Record<string, unknown>) {
  const { data: current } = await svc.from("monitoring_settings").select("*").eq("user_id", userId).maybeSingle();
  const bool = (k: string, d: boolean) => (typeof body[k] === "boolean" ? body[k] as boolean : (current?.[k] ?? d));
  const enabled = bool("enabled", false);
  const minSeverity = body.min_severity ?? current?.min_severity ?? "medium";
  if (!SEVERITIES.includes(minSeverity as string)) return errorResponse("Invalid alert level", 400);
  const hour = body.report_hour_utc ?? current?.report_hour_utc ?? 13;
  if (!Number.isInteger(hour) || (hour as number) < 0 || (hour as number) > 23) return errorResponse("Invalid report time", 400);

  const row = {
    user_id: userId, enabled, email_alerts: bool("email_alerts", true),
    min_severity: minSeverity, daily_report: bool("daily_report", true), report_hour_utc: hour,
    enabled_at: enabled ? (current?.enabled ? current.enabled_at : new Date().toISOString()) : null,
    updated_at: new Date().toISOString(),
  };
  const { error } = await svc.from("monitoring_settings").upsert(row, { onConflict: "user_id" });
  if (error) return errorResponse("Could not save settings", 500);
  if (current?.enabled !== enabled) {
    await svc.from("endpoint_audit").insert({ user_id: userId, actor: "user", action: enabled ? "monitoring_enabled" : "monitoring_disabled", outcome: "succeeded", detail: {} });
  }
  return json({ ok: true });
}

async function sendTest(svc: SupabaseClient, userId: string, email: string | undefined) {
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("alert_deliveries").select("id", { count: "exact", head: true })
    .eq("user_id", userId).eq("channel", "email").eq("kind", "test").gte("created_at", since);
  if ((count ?? 0) >= TESTS_PER_HOUR) return errorResponse("Test limit reached. Try again in an hour.", 429);
  if (!email) return errorResponse("Your account has no email address", 400);

  const subject = "Blackveil Security test alert";
  const text = "This is a test alert from Blackveil Security. If you received it, security alerts will reach you on this channel.";
  const result = await sendEmail(email, subject, text);
  const status = result.ok ? "sent" : result.notConfigured ? "not_configured" : "failed";
  await svc.from("alert_deliveries").insert({
    user_id: userId, channel: "email", kind: "test", subject, body: text, status, attempts: 1,
    error: result.ok ? null : result.error, provider_id: result.ok ? result.providerId : null,
    sent_at: result.ok ? new Date().toISOString() : null,
  });
  if (!result.ok) return errorResponse(result.notConfigured ? "Email delivery has not been set up for Blackveil yet" : result.error, result.notConfigured ? 503 : 502);
  return json({ ok: true });
}

function deviceLabel(ua: string): string {
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
    : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "Device";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  return `${os} - ${browser}`;
}

async function pushSubscribe(svc: SupabaseClient, userId: string, body: Record<string, unknown>, ua: string) {
  const sub = body.subscription as { endpoint?: unknown; keys?: { p256dh?: unknown; auth?: unknown } } | undefined;
  if (!sub || !isAllowedPushEndpoint(sub.endpoint) || !isValidSubscriptionKeys(sub.keys?.p256dh, sub.keys?.auth)) {
    return errorResponse("This browser returned an invalid push subscription", 400);
  }
  const { count } = await svc.from("push_subscriptions").select("id", { count: "exact", head: true })
    .eq("user_id", userId).neq("endpoint", sub.endpoint);
  if ((count ?? 0) >= MAX_PUSH_DEVICES) return errorResponse(`You can have push turned on for up to ${MAX_PUSH_DEVICES} devices. Remove one first.`, 400);
  const { data: row, error } = await svc.from("push_subscriptions").upsert({
    user_id: userId, endpoint: sub.endpoint, p256dh: sub.keys!.p256dh, auth_secret: sub.keys!.auth,
    device_label: deviceLabel(ua), failure_count: 0,
  }, { onConflict: "endpoint" }).select("id").single();
  if (error || !row) return errorResponse("Could not save this device", 500);
  const { error: sErr } = await svc.from("monitoring_settings").upsert({ user_id: userId, push_alerts: true, updated_at: new Date().toISOString() }, { onConflict: "user_id" });
  if (sErr) return errorResponse("Could not save settings", 500);
  await svc.from("endpoint_audit").insert({ user_id: userId, actor: "user", action: "push_device_added", outcome: "succeeded", detail: { device: deviceLabel(ua) } });
  return json({ ok: true, id: row.id });
}

async function pushUnsubscribe(svc: SupabaseClient, userId: string, body: Record<string, unknown>) {
  let q = svc.from("push_subscriptions").delete().eq("user_id", userId);
  if (body.all !== true) {
    if (typeof body.id === "string" && /^[0-9a-f-]{36}$/i.test(body.id)) q = q.eq("id", body.id);
    else if (typeof body.endpoint === "string") q = q.eq("endpoint", body.endpoint);
    else return errorResponse("Choose a device to remove", 400);
  }
  const { data, error } = await q.select("id");
  if (error) return errorResponse("Could not remove the device", 500);
  const { count } = await svc.from("push_subscriptions").select("id", { count: "exact", head: true }).eq("user_id", userId);
  if (!count) await svc.from("monitoring_settings").update({ push_alerts: false }).eq("user_id", userId);
  await svc.from("endpoint_audit").insert({ user_id: userId, actor: "user", action: "push_device_removed", outcome: "succeeded", detail: { removed: data?.length ?? 0 } });
  return json({ ok: true, removed: data?.length ?? 0, remaining: count ?? 0 });
}

async function pushTest(svc: SupabaseClient, userId: string, body: Record<string, unknown>) {
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("alert_deliveries").select("id", { count: "exact", head: true })
    .eq("user_id", userId).eq("channel", "push").eq("kind", "test").gte("created_at", since);
  if ((count ?? 0) >= PUSH_TESTS_PER_HOUR) return errorResponse("Test limit reached. Try again in an hour.", 429);
  const endpoint = typeof body.endpoint === "string" ? body.endpoint : undefined;
  const subject = "Blackveil test notification";
  const text = "Push notifications are working. Urgent security alerts will appear here.";
  const id = crypto.randomUUID();
  const receipt = typeof body.nonce === "string" && /^[0-9a-f-]{36}$/i.test(body.nonce) ? body.nonce : id;
  const r = await pushToUser(svc, userId, { title: subject, body: text, url: "/?open=alerts", tag: "blackveil-test", id: receipt }, "high", endpoint);
  if (r.devices === 0) return errorResponse(endpoint ? "This device is not registered for push. Turn push notifications off and on again." : r.error, 400);
  await svc.from("alert_deliveries").insert({
    id, user_id: userId, channel: "push", kind: "test", subject, body: text, link: "/?open=alerts", attempts: 1,
    status: r.sent > 0 ? "sent" : "failed", error: r.sent > 0 ? null : r.error,
    provider_id: `${r.sent}/${r.devices} devices`, sent_at: r.sent > 0 ? new Date().toISOString() : null,
  });
  if (r.sent === 0) return errorResponse(r.removed > 0 ? "This device's push registration had expired and was removed. Turn push notifications on again." : r.error, 502);
  return json({ ok: true, id, sent: r.sent, devices: r.devices });
}

async function reportNow(svc: SupabaseClient, userId: string) {
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await svc.from("monitoring_reports").select("id", { count: "exact", head: true })
    .eq("user_id", userId).gte("created_at", since);
  if ((count ?? 0) >= REPORTS_PER_HOUR) return errorResponse("Report limit reached. Try again later.", 429);
  const { data, error } = await svc.rpc("monitoring_build_report", { p_user: userId, p_deliver: false });
  if (error || typeof data !== "string") return errorResponse("Could not build the report", 500);
  return json({ reportId: data });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);
  try {
    const { user, error } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(error ?? "Unauthorized", 401);
    let body: Record<string, unknown>;
    try { body = await req.json(); } catch { return errorResponse("Invalid request body", 400); }
    const svc = getServiceClient();
    const isAdmin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const eligible = await hasPlan(svc, user.id, isAdmin);
    if (body.action === "status") {
      return json({ eligible, channels: channelStatus(), pushKey: eligible ? (await getVapidKeys(svc)).publicKey : null });
    }
    if (!eligible) return errorResponse("24/7 monitoring is included with the Pro and Elite plans", 403);
    switch (body.action) {
      case "save": return await saveSettings(svc, user.id, body);
      case "test": return await sendTest(svc, user.id, user.email);
      case "push_subscribe": return await pushSubscribe(svc, user.id, body, req.headers.get("user-agent") ?? "");
      case "push_unsubscribe": return await pushUnsubscribe(svc, user.id, body);
      case "push_test": return await pushTest(svc, user.id, body);
      case "report_now": return await reportNow(svc, user.id);
      default: return errorResponse("Unknown action", 400);
    }
  } catch (err) {
    console.error("monitoring error", err instanceof Error ? err.message : "unknown");
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
