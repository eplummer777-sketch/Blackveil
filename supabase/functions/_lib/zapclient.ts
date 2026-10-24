export type ZapErrorKind = "unconfigured" | "unreachable" | "auth" | "api";

export class ZapError extends Error {
  kind: ZapErrorKind;
  constructor(message: string, kind: ZapErrorKind) {
    super(message);
    this.kind = kind;
  }
}

export type ZapParams = Record<string, string | number | boolean>;

export interface ZapApi {
  call(component: string, type: "view" | "action", name: string, params?: ZapParams): Promise<Record<string, unknown>>;
  upload(fileName: string, contents: string): Promise<string>;
}

type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export function validateZapBaseUrl(raw: string | undefined): URL {
  if (!raw) throw new ZapError("ZAP_API_URL is not set", "unconfigured");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ZapError("ZAP_API_URL is not a valid URL", "unconfigured");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new ZapError("ZAP_API_URL must use http or https", "unconfigured");
  if (u.username || u.password) throw new ZapError("ZAP_API_URL must not contain credentials", "unconfigured");
  return u;
}

export function createZap(baseUrl: string | undefined, apiKey: string | undefined, fetchImpl: FetchFn = fetch, timeoutMs = 15000): ZapApi {
  const base = validateZapBaseUrl(baseUrl);
  if (!apiKey) throw new ZapError("ZAP_API_KEY is not set", "unconfigured");
  const root = base.toString().replace(/\/+$/, "");

  async function send(url: string, init: RequestInit): Promise<Record<string, unknown>> {
    let resp: Response;
    try {
      resp = await fetchImpl(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      throw new ZapError("ZAP did not respond (offline, wrong address or blocked by a firewall)", "unreachable");
    }
    if (resp.status === 401 || resp.status === 403) throw new ZapError("ZAP rejected the API key", "auth");
    const text = await resp.text().catch(() => "");
    let body: Record<string, unknown> = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      throw new ZapError(`The ZAP address answered, but not like a ZAP API (HTTP ${resp.status}). Check ZAP_API_URL.`, "unreachable");
    }
    const code = typeof body.code === "string" ? body.code : "";
    if (code === "bad_api_key") throw new ZapError("ZAP rejected the API key", "auth");
    if (!resp.ok || code) {
      const msg = typeof body.message === "string" ? body.message : `HTTP ${resp.status}`;
      throw new ZapError(`ZAP API error: ${msg.slice(0, 200)}`, "api");
    }
    return body;
  }

  return {
    call(component, type, name, params = {}) {
      const qs = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
      return send(`${root}/JSON/${component}/${type}/${name}/${qs ? `?${qs}` : ""}`, { method: "GET", headers: { "X-ZAP-API-Key": apiKey } });
    },
    async upload(fileName, contents) {
      const form = new FormData();
      form.append("fileName", fileName);
      form.append("fileContents", new Blob([contents], { type: "application/json" }), fileName);
      const body = await send(`${root}/OTHER/core/other/fileUpload/`, { method: "POST", headers: { "X-ZAP-API-Key": apiKey }, body: form });
      const path = Object.values(body).find((v) => typeof v === "string" && v.length > 0);
      if (typeof path !== "string") throw new ZapError("ZAP file upload is not supported by this ZAP version (needs 2.12+)", "api");
      return path;
    },
  };
}
