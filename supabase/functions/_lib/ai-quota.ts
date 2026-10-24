import type { SupabaseClient, User } from "npm:@supabase/supabase-js@2.57.4";

export type Plan = "free" | "malware_removal" | "pro" | "elite";

interface QuotaConfig {
  limit: number; // 0 = unlimited
  window: "daily" | "monthly";
}

const PLAN_QUOTAS: Record<Plan, QuotaConfig> = {
  free: { limit: 20, window: "daily" },
  malware_removal: { limit: 100, window: "monthly" },
  pro: { limit: 1000, window: "monthly" },
  elite: { limit: 0, window: "monthly" },
};

export const PLAN_LABEL: Record<Plan, string> = {
  free: "Free",
  malware_removal: "Malware Removal",
  pro: "Pro",
  elite: "Elite",
};

function planFromSub(row: { plan: string | null; status: string | null } | null): Plan {
  if (!row || (row.status !== "active" && row.status !== "trialing")) return "free";
  if (row.plan === "malware_removal" || row.plan === "pro" || row.plan === "elite") return row.plan;
  return "free";
}

export interface QuotaState {
  plan: Plan;
  limit: number;
  window: "daily" | "monthly";
  used: number;
  remaining: number; // -1 = unlimited
}

export async function resolveQuota(svc: SupabaseClient, user: User): Promise<QuotaState> {
  const isAdminUser = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
  let plan: Plan = "elite";
  if (!isAdminUser) {
    const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", user.id).maybeSingle();
    plan = planFromSub(data as { plan: string | null; status: string | null } | null);
  }
  const { limit, window } = PLAN_QUOTAS[plan];
  if (limit === 0) return { plan, limit, window, used: 0, remaining: -1 };

  const ms = window === "daily" ? 24 * 60 * 60_000 : 30 * 24 * 60 * 60_000;
  const { count } = await svc
    .from("ai_usage")
    .select("*", { count: "exact", head: true })
    .eq("user_id", user.id)
    .eq("feature", "assistant")
    .gte("created_at", new Date(Date.now() - ms).toISOString());
  const used = count ?? 0;
  return { plan, limit, window, used, remaining: Math.max(0, limit - used) };
}

export function quotaMessage(q: QuotaState): string {
  return "You've used all " + q.limit + " AI uses for this " + q.window + " cycle on the " +
    PLAN_LABEL[q.plan] + " plan. " +
    (q.plan === "free"
      ? "Upgrade to a paid plan for a much higher monthly allowance."
      : "Upgrade to a higher tier for more, or wait for your cycle to reset.");
}
