// Read-only verification: a single GET to the user's own public HTTPS site to confirm headers are live.

const PRIVATE = /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|::$|fc|fd|fe80:)/i;

export interface VerificationResult {
  ok: boolean;
  checked_url: string;
  http_status: number | null;
  present: string[];
  missing: string[];
  checked_at: string;
  error?: string;
}

async function hostIsPublic(hostname: string): Promise<boolean> {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || /^[\d.]+$/.test(h) || h.includes(":")) return false;
  const addrs: string[] = [];
  for (const type of ["A", "AAAA"] as const) {
    try {
      addrs.push(...(await Deno.resolveDns(h, type)));
    } catch {
      /* missing record type */
    }
  }
  return addrs.length > 0 && addrs.every((a) => !PRIVATE.test(a));
}

export async function verifyHeaders(url: string, expect: string[]): Promise<VerificationResult> {
  const base = { present: [] as string[], missing: expect, checked_at: new Date().toISOString(), http_status: null };
  let current: URL;
  try {
    current = new URL(url);
  } catch {
    return { ...base, ok: false, checked_url: url, error: "Invalid website address." };
  }
  for (let hop = 0; hop < 4; hop++) {
    if (current.protocol !== "https:" || !(await hostIsPublic(current.hostname))) {
      return { ...base, ok: false, checked_url: current.toString(), error: "Only public https:// websites can be verified." };
    }
    let resp: Response;
    try {
      resp = await fetch(current, {
        redirect: "manual",
        headers: { "User-Agent": "Blackveil-Architect-Verifier/1.0 (+header check)" },
        signal: AbortSignal.timeout(8000),
      });
    } catch {
      return { ...base, ok: false, checked_url: current.toString(), error: "The website could not be reached." };
    }
    const loc = resp.headers.get("location");
    if (resp.status >= 300 && resp.status < 400 && loc) {
      await resp.body?.cancel();
      try {
        current = new URL(loc, current);
      } catch {
        return { ...base, ok: false, checked_url: current.toString(), error: "The website returned an invalid redirect." };
      }
      continue;
    }
    await resp.body?.cancel();
    const present = expect.filter((h) => resp.headers.has(h));
    return {
      ok: true, checked_url: current.toString(), http_status: resp.status, present,
      missing: expect.filter((h) => !present.includes(h)), checked_at: base.checked_at,
    };
  }
  return { ...base, ok: false, checked_url: current.toString(), error: "Too many redirects." };
}
