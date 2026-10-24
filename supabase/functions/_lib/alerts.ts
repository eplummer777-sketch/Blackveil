export type Channel = "email" | "push";
export type SendResult =
  | { ok: true; providerId: string | null }
  | { ok: false; notConfigured: boolean; error: string; retryable: boolean };

export function channelStatus() {
  return {
    email: !!((Deno.env.get("RESEND_API_KEY") ?? "").trim() && (Deno.env.get("ALERT_FROM_EMAIL") ?? "").trim()),
    push: true,
  };
}

const retryableStatus = (s: number) => s === 429 || s >= 500;

export async function sendEmail(to: string, subject: string, text: string): Promise<SendResult> {
  const key = (Deno.env.get("RESEND_API_KEY") ?? "").trim();
  const from = (Deno.env.get("ALERT_FROM_EMAIL") ?? "").trim();
  if (!key || !from) return { ok: false, notConfigured: true, error: "Email delivery is not configured", retryable: false };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: [to], subject: subject.slice(0, 200), text }),
      signal: AbortSignal.timeout(15_000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const reason = typeof data?.message === "string" ? `: ${data.message.replace(/re_[A-Za-z0-9_]+/g, "[redacted]").slice(0, 200)}` : "";
      return { ok: false, notConfigured: false, error: `Email provider error ${res.status}${reason}`, retryable: retryableStatus(res.status) };
    }
    return { ok: true, providerId: typeof data?.id === "string" ? data.id : null };
  } catch {
    return { ok: false, notConfigured: false, error: "Email provider unreachable", retryable: true };
  }
}

export const MAX_ATTEMPTS = 4;

export function nextAttemptDelayMs(attempts: number): number {
  return Math.min(60, 2 ** attempts) * 60_000;
}
