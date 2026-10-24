import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";

export async function hasElite(svc: SupabaseClient, userId: string, admin: boolean): Promise<boolean> {
  if (admin) return true;
  const { data } = await svc.from("subscriptions").select("plan, status").eq("user_id", userId).maybeSingle();
  return !!data && data.plan === "elite" && (data.status === "active" || data.status === "trialing");
}
