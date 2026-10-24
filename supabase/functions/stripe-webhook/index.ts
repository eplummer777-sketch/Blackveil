import Stripe from "npm:stripe@14.25.0";
import { corsHeaders, json } from "../_lib/cors.ts";
import { getServiceClient } from "../_lib/auth.ts";
import { planForPrice } from "../_lib/stripe-plans.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
  const webhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
  if (!stripeKey || !webhookSecret) {
    return json({ error: "Webhook not configured" }, 500);
  }

  const stripe = new Stripe(stripeKey, { apiVersion: "2024-06-20" });
  const serviceClient = getServiceClient();

  const sig = req.headers.get("stripe-signature");
  if (!sig) return json({ error: "Missing signature" }, 400);

  const rawBody = await req.text();
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(rawBody, sig, webhookSecret);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    await serviceClient.from("admin_events").insert({
      kind: "stripe_webhook_signature_error",
      detail: { error: msg },
    });
    return json({ error: "Invalid signature: " + msg }, 400);
  }

  if (!event.livemode) {
    await serviceClient.from("admin_events").insert({
      kind: "stripe_test_event_ignored",
      detail: { type: event.type, id: event.id },
    });
    return json({ received: true, ignored: "test mode event" }, 200);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const uid = session.metadata?.supabase_uid;
        if (uid) {
          await serviceClient.from("audit_logs").insert({
            user_id: uid,
            action: "checkout_completed",
            detail: { session_id: session.id },
          });
        }
        break;
      }
      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.resumed": {
        const subObj = event.data.object as Stripe.Subscription;
        const uid = await resolveUserId(serviceClient, subObj);
        if (!uid) {
          await serviceClient.from("admin_events").insert({
            kind: "stripe_webhook_no_uid",
            detail: {
              subscription_id: subObj.id,
              metadata: subObj.metadata,
              customer: subObj.customer,
              event_type: event.type,
            },
          });
          break;
        }
        const status = mapSubStatus(subObj.status);
        const plan = planForPrice(subObj.items?.data?.[0]?.price?.id) ?? mapPlan(subObj.metadata?.plan);
        await upsertSubscription(serviceClient, uid, {
          plan,
          status,
          stripe_subscription_id: subObj.id,
          stripe_customer_id: typeof subObj.customer === "string" ? subObj.customer : null,
          current_period_end: subObj.current_period_end
            ? new Date(subObj.current_period_end * 1000).toISOString()
            : null,
        });
        await serviceClient.from("audit_logs").insert({
          user_id: uid,
          action: "subscription_" + event.type.split(".").pop(),
          detail: { subscription_id: subObj.id, status: subObj.status, plan },
        });
        break;
      }
      case "customer.subscription.deleted": {
        const subObj = event.data.object as Stripe.Subscription;
        const uid = await resolveUserId(serviceClient, subObj);
        if (!uid) break;
        const { data: current } = await serviceClient
          .from("subscriptions").select("stripe_subscription_id").eq("user_id", uid).maybeSingle();
        if (current?.stripe_subscription_id && current.stripe_subscription_id !== subObj.id) break;
        await upsertSubscription(serviceClient, uid, {
          plan: "free",
          status: "canceled",
          stripe_subscription_id: subObj.id,
          current_period_end: null,
        });
        await serviceClient.from("audit_logs").insert({
          user_id: uid,
          action: "subscription_canceled",
          detail: { subscription_id: subObj.id },
        });
        break;
      }
      case "invoice.paid": {
        const invoice = event.data.object as Stripe.Invoice;
        const uid = invoice.subscription_details?.metadata?.supabase_uid;
        if (uid) {
          await serviceClient.from("admin_events").insert({
            kind: "stripe_invoice_paid",
            detail: { user_id: uid, amount: invoice.amount_paid, currency: invoice.currency },
          });
        }
        break;
      }
      default:
        await serviceClient.from("admin_events").insert({
          kind: "stripe_webhook_unhandled",
          detail: { type: event.type },
        });
    }
    return json({ received: true }, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    await serviceClient.from("admin_events").insert({
      kind: "stripe_webhook_error",
      detail: { type: event.type, error: msg },
    });
    return json({ error: "Webhook handler failed" }, 500);
  }
});

/**
 * Resolve the Supabase user ID from a Stripe subscription object.
 * Tries subscription metadata first, then falls back to looking up
 * the subscriptions table by stripe_customer_id.
 */
async function resolveUserId(
  serviceClient: ReturnType<typeof getServiceClient>,
  subObj: Stripe.Subscription
): Promise<string | null> {
  const metaUid = subObj.metadata?.supabase_uid;
  if (metaUid) return metaUid;

  const customerId = typeof subObj.customer === "string" ? subObj.customer : null;
  if (!customerId) return null;

  const { data } = await serviceClient
    .from("subscriptions")
    .select("user_id")
    .eq("stripe_customer_id", customerId)
    .maybeSingle();
  return data?.user_id ?? null;
}

/**
 * Insert or update the subscription row for a user.
 * If no row exists yet (new user, first checkout), insert one.
 * If a row exists, update it.
 */
async function upsertSubscription(
  serviceClient: ReturnType<typeof getServiceClient>,
  userId: string,
  fields: {
    plan: string;
    status: string;
    stripe_subscription_id?: string;
    stripe_customer_id?: string | null;
    current_period_end: string | null;
  }
): Promise<void> {
  const { data: existing } = await serviceClient
    .from("subscriptions")
    .select("id")
    .eq("user_id", userId)
    .maybeSingle();

  const { error } = existing
    ? await serviceClient.from("subscriptions").update(fields).eq("user_id", userId)
    : await serviceClient.from("subscriptions").insert({ user_id: userId, ...fields });
  // Throwing makes the webhook return 500 so Stripe retries the event.
  if (error) throw new Error("Saving subscription failed: " + error.message);
}

function mapSubStatus(s: Stripe.Subscription.Status): string {
  if (s === "active") return "active";
  if (s === "trialing") return "trialing";
  if (s === "past_due") return "past_due";
  if (s === "canceled") return "canceled";
  if (s === "unpaid") return "past_due";
  return "free";
}

function mapPlan(p: string | undefined): "malware_removal" | "pro" | "elite" {
  if (p === "pro") return "pro";
  if (p === "elite") return "elite";
  if (p === "malware_removal") return "malware_removal";
  return "malware_removal";
}
