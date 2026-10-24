const BASE = "https://api.hostedscan.com/v1";
const TIMEOUT_MS = 20_000;

export class HsError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const isConfigured = () => !!Deno.env.get("HOSTEDSCAN_API_KEY")?.trim();

function friendly(status: number, apiMsg: string): string {
  switch (status) {
    case 400: return apiMsg ? `HostedScan rejected the request: ${apiMsg}` : "HostedScan rejected the request.";
    case 401: return "HostedScan rejected the API key. Check that HOSTEDSCAN_API_KEY is correct and still active.";
    case 403: return "This feature is not enabled on the connected HostedScan plan.";
    case 404: return "HostedScan could not find that scan or result.";
    case 429: return "HostedScan's rate limit was reached. Wait a minute and try again.";
    default: return status >= 500 ? "HostedScan is having problems right now. Try again shortly." : `HostedScan returned an unexpected error (${status}).`;
  }
}

export async function hs<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const key = Deno.env.get("HOSTEDSCAN_API_KEY")?.trim();
  if (!key) throw new HsError(503, "HostedScan is not connected yet. An administrator needs to add the HOSTEDSCAN_API_KEY secret.");
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method: init.method ?? "GET",
      headers: { "X-HOSTEDSCAN-API-KEY": key, Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}) },
      body: init.body ? JSON.stringify(init.body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    const timeout = err instanceof DOMException && err.name === "TimeoutError";
    console.error("hostedscan network error", path.split("?")[0], timeout ? "timeout" : "fetch_failed");
    throw new HsError(502, timeout ? "HostedScan did not respond in time." : "Could not reach HostedScan.");
  }
  const body = await res.json().catch(() => null) as Record<string, unknown> | null;
  if (!res.ok) {
    // eslint-disable-next-line no-control-regex
    const apiMsg = typeof body?.error === "string" ? body.error.replace(/[\u0000-\u001f]/g, " ").slice(0, 300) : "";
    console.error("hostedscan api error", res.status, path.split("?")[0], typeof body?.ref === "string" ? body.ref : "");
    throw new HsError(res.status, friendly(res.status, apiMsg));
  }
  if (!body || typeof body !== "object") throw new HsError(502, "HostedScan returned an unreadable response.");
  return body as T;
}

export interface HsScan {
  id: string;
  type: string;
  state: string;
  progress: number;
  risks?: { new_open?: { risk_id?: string }[]; still_open?: { risk_id?: string }[] };
  skipped_targets?: { target_id?: string; skipped_reason?: string }[];
}

export interface HsRisk {
  id: string;
  status?: string;
  target?: string;
  risk_definition?: { title?: string; threat_level?: string; cvss?: string | null; description?: string; solution?: string; references?: string[]; additional_info?: Record<string, unknown> };
}
