import { createClient, SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";

export function getSupabaseClient(req: Request): SupabaseClient {
  const authHeader = req.headers.get("Authorization") ?? "";
  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  return createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
  });
}

export function getServiceClient(): SupabaseClient {
  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  return createClient(supabaseUrl, serviceRoleKey);
}

export async function getAuthenticatedUser(req: Request) {
  const client = getSupabaseClient(req);
  const {
    data: { user },
    error,
  } = await client.auth.getUser();
  if (error || !user) {
    return { user: null, client, error: error?.message ?? "Unauthorized" };
  }
  return { user, client, error: null };
}

export async function isAdmin(req: Request): Promise<boolean> {
  const { user } = await getAuthenticatedUser(req);
  if (!user) return false;
  const role = (user.app_metadata as Record<string, unknown> | undefined)?.role;
  return role === "admin";
}
