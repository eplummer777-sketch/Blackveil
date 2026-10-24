import { createClient } from "npm:@supabase/supabase-js@2.57.4";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";

// RFC 5737 documentation ranges — reused from simulator to reject fake IPs in real events
const SIMULATED_SOURCE_RANGES = ["192.0.2.", "198.51.100.", "203.0.113."];
function isSimulatedSourceIp(ip: string): boolean {
  return SIMULATED_SOURCE_RANGES.some((p) => ip.startsWith(p));
}

/**
 * Sentinel event ingestion endpoint.
 *
 * Accepts events from deployed Cloudflare Worker honeypots.
 * Authentication is via a per-honeypot ingestion token (not a user JWT),
 * because the Worker cannot hold user credentials.
 *
 * The token is validated against the honeypots table. Events are sanitized
 * and inserted with is_simulated = false and provider = "cloud".
 *
 * This endpoint is public (verify_jwt = false) but every request must carry
 * a valid ingestion token. Without it, the request is rejected.
 */

interface IngestEvent {
  honeypot_id: string;
  decoy_type: string;
  event_type: string;
  severity: string;
  summary: string;
  evidence: Record<string, unknown>;
  protocol: string | null;
  source_ip: string | null;
  source_label: string | null;
  occurred_at: string;
}

const SENSITIVE_KEY = /pass(word)?|secret|token|api[_-]?key|private[_-]?key|cookie|session|credential/i;
const MAX_STRING = 300;

function sanitizeEvidence(input: unknown, depth = 0): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input) || depth > 3) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>).slice(0, 25)) {
    if (SENSITIVE_KEY.test(key)) {
      out[key] = "[never captured]";
      continue;
    }
    if (typeof value === "string") out[key] = value.slice(0, MAX_STRING);
    else if (typeof value === "number" || typeof value === "boolean" || value === null) out[key] = value;
    else if (Array.isArray(value)) {
      out[key] = value.slice(0, 20).map((v) =>
        typeof v === "string" ? v.slice(0, MAX_STRING) : typeof v === "number" || typeof v === "boolean" ? v : null
      );
    } else if (typeof value === "object") out[key] = sanitizeEvidence(value, depth + 1);
  }
  return out;
}

const VALID_SEVERITY = new Set(["critical", "high", "medium", "low", "info"]);

const DECOY_MITRE: Record<string, string | null> = {
  ssh: "T1110.001",
  http_admin: "T1190",
  database: "T1110.001",
  smb_share: "T1135",
  iot_telnet: "T1110.001",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const token = req.headers.get("X-Honeypot-Token");
    if (!token || token.length < 10) return errorResponse("Missing or invalid ingestion token.", 401);

    let body: IngestEvent;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid request body.", 400);
    }

    if (!body || typeof body.honeypot_id !== "string") {
      return errorResponse("Missing honeypot_id.", 400);
    }
    if (!body.event_type || typeof body.event_type !== "string") {
      return errorResponse("Missing event_type.", 400);
    }
    if (!body.summary || typeof body.summary !== "string") {
      return errorResponse("Missing summary.", 400);
    }

    const severity = VALID_SEVERITY.has(body.severity) ? body.severity : "info";

    // Use service role to look up the honeypot by ingestion token
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const svc = createClient(supabaseUrl, serviceRoleKey);

    // Look up honeypot by ingestion token
    const { data: honeypot, error: lookupError } = await svc
      .from("honeypots")
      .select("id, user_id, status, provider, decoy_type, ingestion_token")
      .eq("ingestion_token", token)
      .eq("id", body.honeypot_id)
      .maybeSingle();

    if (lookupError || !honeypot) {
      return errorResponse("Invalid ingestion token or honeypot not found.", 401);
    }

    // Only accept events for active cloud honeypots
    if (honeypot.provider !== "cloud") {
      return errorResponse("This honeypot is not a cloud-deployed decoy.", 403);
    }
    if (honeypot.status !== "active") {
      return errorResponse("This honeypot is not currently active.", 409);
    }

    // Reject simulated source IPs coming from a cloud honeypot (safety check)
    const sourceIp = body.source_ip ?? null;
    if (sourceIp && isSimulatedSourceIp(sourceIp)) {
      return errorResponse("Invalid source address for a cloud honeypot event.", 400);
    }

    // Determine MITRE technique
    const mitreTechnique = DECOY_MITRE[honeypot.decoy_type] ?? null;

    // Sanitize and insert the event
    const eventRow = {
      honeypot_id: honeypot.id,
      user_id: honeypot.user_id,
      provider: "cloud",
      is_simulated: false,
      event_type: body.event_type.slice(0, 100),
      severity,
      protocol: body.protocol?.slice(0, 30) ?? null,
      source_ip: sourceIp?.slice(0, 64) ?? null,
      source_port: null,
      source_label: body.source_label?.slice(0, 120) ?? null,
      summary: body.summary.slice(0, 500),
      evidence: sanitizeEvidence(body.evidence),
      mitre_technique: mitreTechnique,
      occurred_at: body.occurred_at || new Date().toISOString(),
    };

    const { error: insertError } = await svc.from("honeypot_events").insert(eventRow);
    if (insertError) {
      console.error("sentinel-ingest insert error", insertError);
      return errorResponse("Could not record the event.", 500);
    }

    // Notify on high-severity real events
    if (severity === "critical" || severity === "high") {
      await svc.from("notifications").insert({
        user_id: honeypot.user_id,
        kind: "security_alert",
        title: `${severity.toUpperCase()} honeypot event on ${honeypot.decoy_type} decoy`,
        body: body.summary.slice(0, 200),
        link: "sentinel",
      });
    }

    // Audit log
    await svc.from("audit_logs").insert({
      user_id: honeypot.user_id,
      action: "sentinel_event_ingested",
      detail: {
        honeypot_id: honeypot.id,
        event_type: body.event_type,
        severity,
        source_ip: sourceIp,
      },
    });

    return json({ ok: true });
  } catch (e) {
    console.error("sentinel-ingest error", e);
    return errorResponse("Could not process the event.", 500);
  }
});
