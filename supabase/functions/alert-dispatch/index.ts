import { getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { MAX_ATTEMPTS, nextAttemptDelayMs, sendEmail, type SendResult } from "../_lib/alerts.ts";
import { pushToUser } from "../_lib/webpush.ts";

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);
  try {
    const svc = getServiceClient();
    const { data: cfg } = await svc.from("internal_config").select("value").eq("key", "dispatch_secret").maybeSingle();
    if (!cfg || !safeEqual(req.headers.get("x-dispatch-secret") ?? "", cfg.value)) return errorResponse("Unauthorized", 401);

    const { data: batch, error } = await svc.rpc("claim_alert_deliveries", { p_limit: 25 });
    if (error) return errorResponse("Could not claim deliveries", 500);
    const rows = (batch ?? []) as { id: string; user_id: string; channel: string; kind: string; subject: string; body: string; link: string | null; attempts: number }[];

    const counts = { sent: 0, failed: 0, retry: 0, not_configured: 0 };
    for (const row of rows) {
      let result: SendResult;
      if (row.channel === "email") {
        const { data: u } = await svc.auth.admin.getUserById(row.user_id);
        const email = u?.user?.email;
        result = email ? await sendEmail(email, row.subject, row.body)
          : { ok: false, notConfigured: false, error: "Account has no email address", retryable: false };
      } else if (row.channel === "push") {
        const daily = row.kind === "daily_report";
        const r = await pushToUser(svc, row.user_id, {
          title: row.subject, body: row.body, url: row.link ?? "/", tag: daily ? "blackveil-daily" : `blackveil-${row.id}`, id: row.id,
        }, daily ? "normal" : "high");
        result = r.sent > 0 ? { ok: true, providerId: `${r.sent}/${r.devices} devices` }
          : { ok: false, notConfigured: false, error: r.error, retryable: r.retryable };
      } else {
        result = { ok: false, notConfigured: false, error: "Text alerts were retired", retryable: false };
      }
      const now = new Date();
      if (result.ok) {
        counts.sent++;
        await svc.from("alert_deliveries").update({ status: "sent", sent_at: now.toISOString(), provider_id: result.providerId, error: null }).eq("id", row.id);
      } else if (result.notConfigured) {
        counts.not_configured++;
        await svc.from("alert_deliveries").update({ status: "not_configured", error: result.error }).eq("id", row.id);
      } else if (result.retryable && row.attempts < MAX_ATTEMPTS) {
        counts.retry++;
        await svc.from("alert_deliveries").update({
          status: "pending", error: result.error, next_attempt_at: new Date(now.getTime() + nextAttemptDelayMs(row.attempts)).toISOString(),
        }).eq("id", row.id);
      } else {
        counts.failed++;
        await svc.from("alert_deliveries").update({ status: "failed", error: result.error }).eq("id", row.id);
      }
    }
    return json({ processed: rows.length, ...counts });
  } catch (err) {
    console.error("alert-dispatch error", err instanceof Error ? err.message : "unknown");
    return errorResponse("Dispatch failed", 500);
  }
});
