import { isBlockedIp } from "../_lib/net.ts";
import { createZap, validateZapBaseUrl, ZapError } from "../_lib/zapclient.ts";

type Check = { name: string; ok: boolean; detail: string };

const TIMEOUT_MS = 10_000;

async function probe(root: string, key: string | null) {
  try {
    const resp = await fetch(`${root}/JSON/core/view/version/`, {
      headers: key ? { "X-ZAP-API-Key": key } : {}, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await resp.text().catch(() => "");
    let body: Record<string, unknown> | null = null;
    try { body = JSON.parse(text); } catch { /* not json */ }
    const title = /<title[^>]*>([^<]{0,80})/i.exec(text)?.[1]?.replace(/[^\w .:/-]/g, "").trim();
    const fingerprint = [
      `type ${(resp.headers.get("content-type") ?? "none").split(";")[0]}`,
      resp.headers.get("server") ? `server ${resp.headers.get("server")!.slice(0, 40)}` : "",
      title ? `page title "${title}"` : "",
      body ? `JSON keys ${Object.keys(body).slice(0, 5).join(",")}` : "",
      resp.headers.get("set-cookie") ? "sets a cookie" : "",
      resp.headers.get("location") ? `redirects to ${resp.headers.get("location")!.replace(/[?#].*/, "").slice(0, 120)}` : "",
    ].filter(Boolean).join(", ");
    const location = resp.headers.get("location");
    const selfRedirect = !!location && new URL(location, resp.url || `${root}/`).href === `${root}/JSON/core/view/version/`;
    return { reached: true, status: resp.status, body, fingerprint, selfRedirect };
  } catch (err) {
    return { reached: false, status: 0, body: null, timeout: err instanceof DOMException && err.name === "TimeoutError" };
  }
}

function describeShape(raw: string | undefined): string {
  if (!raw) return "The value is empty.";
  const hints: string[] = [`Length ${raw.length}.`];
  if (raw !== raw.trim()) hints.push("Has leading or trailing spaces or line breaks.");
  const t = raw.trim();
  if (/^["'`]|["'`]$/.test(t)) hints.push("Wrapped in quote characters; remove them.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(t.replace(/^["'`]/, ""))) hints.push("Does not start with https:// (or http://).");
  if (/\s/.test(t)) hints.push("Contains spaces.");
  if (/^[a-z]+=/i.test(t)) hints.push("Looks like it includes a variable name (NAME=value); store only the address.");
  return hints.join(" ");
}

const isZapReject = (p: Awaited<ReturnType<typeof probe>>) =>
  p.status === 401 || p.status === 403 || p.body?.code === "bad_api_key" || p.body?.code === "no_access";

export async function runDiagnostics(rawUrl: string | undefined, apiKey: string | undefined) {
  try {
    const url = validateZapBaseUrl(rawUrl);
    return await probeAll(rawUrl!, url, apiKey, [{ name: "ZAP address is valid", ok: true, detail: `Scheme ${url.protocol.replace(":", "")}` }], []);
  } catch (err) {
    const first: Check = { name: "ZAP address is valid", ok: false, detail: `${err instanceof ZapError ? err.message : "Invalid"}. ${describeShape(rawUrl)}` };
    const t = (rawUrl ?? "").trim();
    if (!t || /^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /[\s"'`]/.test(t)) return { ok: false, checks: [first], blockers: ["ZAP_API_URL is missing or invalid."] };
    for (const scheme of ["https", "http"]) {
      let candidate: URL;
      try { candidate = validateZapBaseUrl(`${scheme}://${t}`); } catch { continue; }
      const p = await probe(candidate.toString().replace(/\/+$/, ""), null);
      if (!p.reached) continue;
      const blocker = `ZAP_API_URL is missing its prefix. ZAP answered when ${scheme}:// was added in front, so update the secret to start with ${scheme}://.`;
      const res = await probeAll(`${scheme}://${t}`, candidate, apiKey, [first, { name: `Retried with ${scheme}:// added (diagnostic only)`, ok: true, detail: "Server answered; results below use this address" }], [blocker]);
      return { ...res, ok: false, suggested_scheme: scheme };
    }
    let host = "", port = "";
    try { const u = new URL(`http://${t}`); host = u.hostname; port = u.port; } catch { /* unparseable */ }
    const ipLit = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    let ips: string[] = ipLit ? [host] : [];
    if (!ipLit && host) { try { ips = await Deno.resolveDns(host, "A"); } catch { ips = []; } }
    const extra: Check[] = [
      { name: "Host part resolves", ok: ips.length > 0, detail: !host ? "Could not read a host name" : ips.length ? `${ipLit ? "IP address" : "Hostname"}; ${ips.some(isBlockedIp) ? "PRIVATE/internal address, not reachable from the cloud backend" : "public address"}` : "Hostname does not resolve in DNS" },
      { name: "Port", ok: true, detail: port ? `Explicit port ${port}` : "No port given (defaults 443/80)" },
    ];
    return { ok: false, checks: [first, ...extra, { name: "Retried with https:// and http:// added", ok: false, detail: "Neither address answered (connection refused, timed out, or TLS failed)" }], blockers: ["ZAP_API_URL is missing its https:// prefix, and the server did not answer with either prefix."] };
  }
}

async function probeAll(rawUrl: string, url: URL, apiKey: string | undefined, checks: Check[], blockers: string[]) {
  checks.push({ name: "ZAP_API_KEY is set", ok: !!apiKey, detail: apiKey ? `Set (${apiKey.length} characters)` : "Missing" });
  if (url.protocol !== "https:") blockers.push("ZAP_API_URL uses plain http. The API key travels unencrypted; put ZAP behind HTTPS.");

  let ips: string[] = [];
  const isIpLiteral = /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname);
  if (isIpLiteral) ips = [url.hostname];
  else {
    try { ips = await Deno.resolveDns(url.hostname, "A"); } catch { ips = []; }
  }
  const dnsOk = ips.length > 0;
  checks.push({ name: "ZAP host resolves", ok: dnsOk, detail: dnsOk ? `${ips.length} IPv4 address(es)${ips.some(isBlockedIp) ? ", includes a private address" : ""}` : "No IPv4 address found" });
  if (!dnsOk) return { ok: false, checks, blockers: [...blockers, "The ZAP hostname does not resolve."] };

  const root = url.toString().replace(/\/+$/, "");
  const anon = await probe(root, null);
  checks.push({ name: "ZAP server reachable", ok: anon.reached, detail: anon.reached ? `Answered with HTTP ${anon.status}` : anon.timeout ? "Timed out after 10s" : "Connection failed (offline, wrong port, or firewall)" });
  if (!anon.reached) return { ok: false, checks, blockers: [...blockers, "The ZAP server could not be reached from the app's backend."] };

  const looksZap = isZapReject(anon) || typeof anon.body?.version === "string";
  checks.push({ name: "Responds like the ZAP API (daemon/API mode)", ok: looksZap, detail: looksZap ? "ZAP JSON API detected" : `Unexpected response (HTTP ${anon.status}; ${anon.fingerprint}). The address may point at a proxy, web page, or hosting placeholder instead of the ZAP API` });
  if (!looksZap) {
    const path = url.pathname.replace(/\/+$/, "");
    checks.push({ name: "Address has no extra path", ok: !path, detail: path ? `Includes a path (${path.length} characters); use only the server root, e.g. https://zap.example.com` : "Root address" });
    if (apiKey) {
      const keyed = await probe(root, apiKey);
      const keyedZap = typeof keyed.body?.version === "string";
      checks.push({ name: "ZAP API answers with the configured key", ok: keyedZap, detail: keyedZap ? "ZAP JSON API detected" : `No (HTTP ${keyed.status}; ${keyed.fingerprint ?? "no answer"})` });
    }
    if (anon.selfRedirect) {
      checks.push({ name: "No redirect loop", ok: false, detail: "The address redirects to itself, so requests never reach ZAP" });
      blockers.push("The ZAP address is stuck in a redirect loop. In the hosting service, set the container port to 8080 and turn off any HTTP-to-HTTPS redirect on the container itself (the host already provides HTTPS).");
    } else blockers.push("The ZAP address reaches a server, but it is not the ZAP API. Point it at the ZAP daemon's port (8080 by default) through HTTPS.");
    return { ok: false, version: null, mode: null, checks, blockers };
  }
  const keyEnforced = isZapReject(anon);
  checks.push({ name: "Rejects requests without an API key", ok: keyEnforced, detail: keyEnforced ? "Unauthenticated requests are refused" : "ZAP answered without a key" });
  if (looksZap && !keyEnforced) blockers.push("ZAP accepts API calls without a key. Anyone who finds the address could control it. Set -config api.key=... and remove api.disablekey=true.");

  const bogus = await probe(root, `invalid-${crypto.randomUUID()}`);
  const wrongRejected = isZapReject(bogus);
  checks.push({ name: "Rejects a wrong API key", ok: wrongRejected, detail: wrongRejected ? "Wrong key refused" : "A wrong key was accepted" });
  if (looksZap && !wrongRejected) blockers.push("ZAP accepted a made-up API key, so key protection is not active.");

  let version: string | null = null;
  let mode: string | null = null;
  if (apiKey && looksZap) {
    try {
      const zap = createZap(rawUrl, apiKey, fetch, TIMEOUT_MS);
      version = String((await zap.call("core", "view", "version")).version ?? "unknown");
      checks.push({ name: "Accepts the configured API key", ok: true, detail: `ZAP ${version}` });
      mode = String((await zap.call("core", "view", "mode")).mode ?? "unknown");
      const modeOk = mode === "standard" || mode === "attack";
      checks.push({ name: "ZAP mode allows active scanning", ok: modeOk, detail: `Mode: ${mode}${modeOk ? "" : " (active scans need standard or attack mode)"}` });
      for (const [comp, view, label] of [["spider", "optionMaxDuration", "Spider"], ["ascan", "optionThreadPerHost", "Active scanner"], ["pscan", "recordsToScan", "Passive scanner"]] as const) {
        try {
          await zap.call(comp, "view", view);
          checks.push({ name: `${label} API available`, ok: true, detail: "Available" });
        } catch (e) {
          checks.push({ name: `${label} API available`, ok: false, detail: e instanceof ZapError ? e.message : "Unavailable" });
        }
      }
      const [maj, min] = version.split(".").map((n) => Number(n));
      if (Number.isFinite(maj) && (maj < 2 || (maj === 2 && min < 12))) checks.push({ name: "ZAP version supports API file uploads", ok: false, detail: "Uploaded OpenAPI files need ZAP 2.12 or newer" });
    } catch (e) {
      checks.push({ name: "Accepts the configured API key", ok: false, detail: e instanceof ZapError ? (e.kind === "auth" ? "ZAP rejected ZAP_API_KEY" : e.message) : "Failed" });
      blockers.push("The configured ZAP_API_KEY was not accepted.");
    }
  }
  const ok = checks.every((c) => c.ok) && blockers.length === 0;
  return { ok, version, mode, checks, blockers };
}
