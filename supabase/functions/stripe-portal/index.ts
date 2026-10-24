import Stripe from "npm:stripe@14.25.0";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { getFrontendUrl } from "../_lib/env.ts";
import { isLiveKey } from "../_lib/stripe-plans.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  const { user, error } = await getAuthenticatedUser(req);
  if (!user) return errorResponse(error ?? "Unauthorized", 401);

  const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
  if (!stripeKey) {
    return errorResponse("Payments are not yet configured.", 503);
  }
  if (!isLiveKey(stripeKey)) {
    return errorResponse("Billing management is temporarily unavailable. Please try again later.", 503);
  }
  let frontendUrl: string;
  try {
    frontendUrl = getFrontendUrl();
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    return errorResponse("Payments are not yet configured.", 503);
  }

  const serviceClient = getServiceClient();
  const stripe = new Stripe(stripeKey, { apiVersion: "2024-06-20" });

  const { data: sub } = await serviceClient
    .from("subscriptions")
    .select("stripe_customer_id")
    .eq("user_id", user.id)
    .maybeSingle();

  const customerId = sub?.stripe_customer_id;
  if (!customerId) {
    return errorResponse(
      "No billing account found. Subscribe to a plan first.",
      404
    );
  }

  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: frontendUrl + "/?checkout=returned",
    });
    return json({ url: session.url }, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return errorResponse("Could not open billing portal. " + msg, 500);
  }
});
