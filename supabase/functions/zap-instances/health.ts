import { createZap, ZapError } from "../_lib/zapclient.ts";

export type InstanceStatus = "connected" | "disconnected" | "unhealthy";
export type Check = { name: string; ok: boolean; detail: string };
export interface HealthResult { status: InstanceStatus; version: string | null; error: string | null; checks: Check[] }

type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export interface HealthDeps {
  resolvePublic: (host: string) => Promise<unknown>;
  fetchImpl?: FetchFn;
  sleep?: (ms: number) => Promise<void>;
  timeoutMs?: number;
  retries?: number;
}

const VERSION_RE = /^(\d+\.\d+(\.\d+)?|D-\d{4}-\d{2}-\d{2}|dev\b)/i;

function withRetry(fetchImpl: FetchFn, retries: number, sleep: (ms: number) => Promise<void>): FetchFn {
  return async (url, init) => {
    for (let attempt = 0; ; attempt++) {
      try {
        return await fetchImpl(url, init);
      } catch (err) {
        if (attempt >= retries) throw err;
        await sleep(500 * (attempt + 1));
      }
    }
  };
}

export async function checkInstance(baseUrl: string, apiKey: string, deps: HealthDeps): Promise<HealthResult> {
  const checks: Check[] = [];
  const timeoutMs = deps.timeoutMs ?? 10_000;
  const fetchImpl = withRetry(deps.fetchImpl ?? fetch, deps.retries ?? 1, deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))));
  const fail = (status: InstanceStatus, error: string): HealthResult => ({ status, version: null, error, checks });

  const host = new URL(baseUrl).hostname;
  try {
    await deps.resolvePublic(host);
    checks.push({ name: "Address is public", ok: true, detail: "Resolves only to public internet addresses" });
  } catch {
    checks.push({ name: "Address is public", ok: false, detail: "Does not resolve, or resolves to a private/internal address" });
    return fail("unhealthy", "This address does not resolve to a public server, so Blackveil will not connect to it.");
  }

  let anon: Response;
  try {
    anon = await fetchImpl(`${baseUrl}/JSON/core/view/version/`, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    checks.push({ name: "Server reachable", ok: true, detail: `Answered with HTTP ${anon.status}` });
  } catch {
    checks.push({ name: "Server reachable", ok: false, detail: "No answer (offline, wrong port, firewall, or still starting)" });
    return fail("disconnected", "The scanner did not answer. It may be offline, still starting, or blocked by a firewall.");
  }

  const text = await anon.text().catch(() => "");
  let body: Record<string, unknown> | null = null;
  try { body = JSON.parse(text); } catch { /* not json */ }
  const rejected = anon.status === 401 || anon.status === 403 || body?.code === "bad_api_key" || body?.code === "no_access";
  if (anon.status >= 300 && anon.status < 400) {
    checks.push({ name: "Responds like the ZAP API", ok: false, detail: `Redirects (HTTP ${anon.status}); redirects are never followed` });
    return fail("unhealthy", "The address redirects instead of answering. Point it directly at the ZAP API.");
  }
  if (!rejected && typeof body?.version !== "string") {
    checks.push({ name: "Responds like the ZAP API", ok: false, detail: `Unexpected answer (HTTP ${anon.status}, ${body ? "JSON" : "not JSON"})` });
    return fail("unhealthy", "Something answered at this address, but it is not the ZAP API.");
  }
  checks.push({ name: "Responds like the ZAP API", ok: true, detail: "ZAP API detected" });
  if (!rejected) {
    checks.push({ name: "Requires an API key", ok: false, detail: "Answered without a key" });
    return fail("unhealthy", "This ZAP accepts requests without an API key, so anyone could control it. Enable api.key before connecting.");
  }
  checks.push({ name: "Requires an API key", ok: true, detail: "Requests without a key are refused" });

  try {
    const v = String((await createZap(baseUrl, apiKey, fetchImpl, timeoutMs).call("core", "view", "version")).version ?? "");
    if (!VERSION_RE.test(v)) {
      checks.push({ name: "Accepts the saved key", ok: false, detail: "Answered, but without a valid ZAP version" });
      return fail("unhealthy", "The scanner answered with an unexpected version value.");
    }
    checks.push({ name: "Accepts the saved key", ok: true, detail: `ZAP ${v}` });
    return { status: "connected", version: v, error: null, checks };
  } catch (err) {
    const auth = err instanceof ZapError && err.kind === "auth";
    checks.push({ name: "Accepts the saved key", ok: false, detail: auth ? "Key rejected" : "Request failed" });
    if (auth) return fail("unhealthy", "ZAP rejected the saved API key. Update the key to match the scanner.");
    return fail("disconnected", "The scanner stopped answering during the check.");
  }
}
