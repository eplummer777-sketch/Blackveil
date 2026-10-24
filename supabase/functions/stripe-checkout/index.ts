import Stripe from "npm:stripe@14.25.0";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { getFrontendUrl } from "../_lib/env.ts";
import { isLiveKey, PRICE_BY_PLAN, type PaidPlan } from "../_lib/stripe-plans.ts";

// Customers saved during test mode do not exist in live mode.
async function isUsableCustomer(stripe: Stripe, id: string): Promise<boolean> {
  try {
    const c = await stripe.customers.retrieve(id);
    return !("deleted" in c && c.deleted);
  } catch (err) {
    if ((err as { code?: string }).code === "resource_missing") return false;
    throw err;
  }
}

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
    await getServiceClient().from("admin_events").insert({ kind: "stripe_test_mode_blocked", detail: { user_id: user.id } });
    return errorResponse("Payments are temporarily unavailable. Please try again later.", 503);
  }
  let frontendUrl: string;
  try {
    frontendUrl = getFrontendUrl();
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    return errorResponse("Payments are not yet configured.", 503);
  }

  let body: { tier?: string } = {};
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid request body", 400);
  }
  const tierKey = typeof body.tier === "string" ? body.tier : "";
  if (!(tierKey in PRICE_BY_PLAN)) {
    return errorResponse(
      "Missing or invalid tier. Expected one of: malware_removal, pro, elite.",
      400
    );
  }
  const tier = { plan: tierKey as PaidPlan, priceId: PRICE_BY_PLAN[tierKey as PaidPlan] };

  const serviceClient = getServiceClient();
  const stripe = new Stripe(stripeKey, { apiVersion: "2024-06-20" });

  const { data: sub } = await serviceClient
    .from("subscriptions")
    .select("id, stripe_customer_id")
    .eq("user_id", user.id)
    .maybeSingle();

  let customerId = sub?.stripe_customer_id ?? null;
  if (customerId && !(await isUsableCustomer(stripe, customerId))) customerId = null;
  if (!customerId) {
    const customer = await stripe.customers.create({
      email: user.email ?? undefined,
      metadata: { supabase_uid: user.id },
    });
    customerId = customer.id;
    if (sub) {
      await serviceClient
        .from("subscriptions")
        .update({ stripe_customer_id: customerId })
        .eq("id", sub.id);
    } else {
      await serviceClient
        .from("subscriptions")
        .insert({
          user_id: user.id,
          plan: "free",
          status: "free",
          stripe_customer_id: customerId,
        });
    }
  }

  const existing = await stripe.subscriptions.list({ customer: customerId, status: "all", limit: 20 });
  if (existing.data.some((s) => ["active", "trialing", "past_due", "unpaid"].includes(s.status))) {
    return errorResponse("You already have an active plan. To change plans, contact support or cancel your current plan under Manage billing in Settings.", 409);
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: tier.priceId, quantity: 1 }],
      success_url: frontendUrl + "/?checkout=success",
      cancel_url: frontendUrl + "/?checkout=canceled",
      metadata: { supabase_uid: user.id, plan: tier.plan },
      subscription_data: {
        metadata: { supabase_uid: user.id, plan: tier.plan },
      },
    });
    if (!session.livemode) throw new Error("Checkout was not created in live mode");

    await serviceClient.from("audit_logs").insert({
      user_id: user.id,
      action: "checkout_session_created",
      detail: { session_id: session.id, tier: tier.plan },
    });

    return json({ url: session.url }, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    await serviceClient.from("admin_events").insert({
      kind: "stripe_checkout_error",
      detail: { user_id: user.id, error: msg, tier: tier.plan },
    });
    return errorResponse("Could not start checkout. " + msg, 500);
  }
});
