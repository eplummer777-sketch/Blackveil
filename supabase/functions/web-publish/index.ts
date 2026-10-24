import { getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";

const SLUG = /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "GET") return errorResponse("Method not allowed.", 405);
    const slug = new URL(req.url).searchParams.get("slug") ?? "";
    if (!SLUG.test(slug)) return errorResponse("Site not found.", 404);
    const { data, error } = await getServiceClient().from("wb_publications")
      .select("title, entry, pages, published_at").eq("slug", slug).maybeSingle();
    if (error) return errorResponse("This site could not be loaded right now.", 500);
    if (!data) return errorResponse("Site not found.", 404);
    return json(data);
  } catch {
    return errorResponse("This site could not be loaded right now.", 500);
  }
});
