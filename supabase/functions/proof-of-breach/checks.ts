import { safeFetch, ScopeError, resolvePublic } from "../_lib/net.ts";
import type { SafeResponse, Scope } from "../_lib/net.ts";
import { probeTls } from "../_lib/tls.ts";
import { daysRemaining, type X509Cert } from "../_lib/x509.ts";

export type Result = "passed" | "failed" | "partial" | "incomplete" | "not_performed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Validation = "detected" | "suspected" | "validated" | "unresolved";

export interface Fix {
  why: string;
  steps: string[];
  snippets: { label: string; code: string }[];
  side_effects: string;
  rollback: string;
}

export interface Outcome {
  result: Result;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  validation: Validation;
  affected_asset: string;
  summary: string;
  evidence: Record<string, unknown>;
  operation: string;
}

export interface Ctx {
  scope: Scope;
  home: () => Promise<SafeResponse>;
}

export interface CheckDef {
  key: string;
  title: string;
  category: string;
  fix: Fix;
  run: (ctx: Ctx) => Promise<Outcome>;
}

export const TOOL = "Blackveil HTTP Probe";
export const TOOL_VERSION = "1.0.0";

export function pickHeaders(h: Headers, names: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of names) {
    const v = h.get(n);
    if (v !== null) out[n] = v.slice(0, 300);
  }
  return out;
}

const o = (p: Partial<Outcome> & Pick<Outcome, "result" | "summary" | "operation" | "affected_asset">): Outcome => ({
  severity: "info", confidence: "high", validation: "detected", evidence: {}, ...p,
});

export function errorOutcome(err: unknown, operation: string, asset: string): Outcome {
  const msg = err instanceof Error ? err.message : String(err);
  const isScope = err instanceof ScopeError;
  const aborted = err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError");
  return o({
    result: isScope ? "not_performed" : "incomplete",
    validation: "unresolved",
    confidence: "low",
    summary: isScope ? `Blocked by scope rules: ${msg}` : aborted ? "Stopped before finishing (time limit or stop requested)." : `Could not finish: ${msg.slice(0, 160)}`,
    operation,
    affected_asset: asset,
  });
}

function base(host: string, path = "/"): string {
  const p = path.startsWith("/") ? path : "/" + path;
  return `https://${host}${p}`;
}

const headerFix = (name: string, value: string, why: string, side: string): Fix => ({
  why,
  steps: [`Add the ${name} response header on every HTML response.`, "Deploy, then press Verify the fix."],
  snippets: [
    { label: "Nginx", code: `add_header ${name} "${value}" always;` },
    { label: "Apache", code: `Header always set ${name} "${value}"` },
    { label: "Netlify _headers", code: `/*\n  ${name}: ${value}` },
    { label: "Cloudflare Transform Rule", code: `Set static response header: ${name} = ${value}` },
  ],
  side_effects: side,
  rollback: `Remove the ${name} line and redeploy.`,
});

function hasDirective(csp: string, d: string): string | null {
  const part = csp.split(";").map((s) => s.trim()).find((s) => s.toLowerCase().startsWith(d + " ") || s.toLowerCase() === d);
  return part ?? null;
}

export const CHECKS: CheckDef[] = [
  {
    key: "https_tls",
    title: "HTTPS with a valid certificate",
    category: "transport",
    fix: {
      why: "Without a valid certificate, visitors see warnings and traffic can be intercepted.",
      steps: ["Issue a certificate (e.g. Let's Encrypt or your host's free TLS).", "Make sure the full chain is served.", "Renew automatically."],
      snippets: [{ label: "Certbot", code: "certbot --nginx -d example.com -d www.example.com" }],
      side_effects: "None for visitors; brief reload of the web server.",
      rollback: "Restore the previous certificate files and reload.",
    },
    run: async ({ scope }) => {
      const op = `GET ${base(scope.host)} (TLS handshake, no redirects followed)`;
      try {
        const r = await safeFetch(base(scope.host), scope, { followRedirects: false, method: "HEAD" });
        return o({ result: "passed", summary: `TLS handshake succeeded and the certificate was accepted (HTTP ${r.status}).`, operation: op, affected_asset: base(scope.host), evidence: { status: r.status } });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "";
        if (/certificate|tls|ssl|handshake/i.test(msg)) {
          return o({ result: "failed", severity: "high", validation: "validated", summary: "The TLS handshake was rejected: the certificate is invalid, expired or mismatched.", operation: op, affected_asset: base(scope.host), evidence: { error: msg.slice(0, 200) } });
        }
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "http_redirect",
    title: "HTTP redirects to HTTPS",
    category: "transport",
    fix: {
      why: "Visitors who type the address without https:// otherwise browse unencrypted.",
      steps: ["Permanently redirect every http:// request to https://."],
      snippets: [
        { label: "Nginx", code: "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}" },
        { label: "Cloudflare", code: "SSL/TLS > Edge Certificates > Always Use HTTPS = On" },
      ],
      side_effects: "Clients that can't use HTTPS (very old devices) won't load the site.",
      rollback: "Remove the redirect block.",
    },
    run: async ({ scope }) => {
      const url = `http://${scope.host}/`;
      const op = `GET ${url} (no redirects followed)`;
      try {
        const r = await safeFetch(url, scope, { followRedirects: false, method: "HEAD" });
        const loc = r.headers.get("location") ?? "";
        if (r.status >= 300 && r.status < 400 && loc.startsWith("https://")) {
          return o({ result: "passed", summary: `Plain HTTP answered ${r.status} redirecting to HTTPS.`, operation: op, affected_asset: url, evidence: { status: r.status, location: loc.slice(0, 200) } });
        }
        return o({ result: "failed", severity: "medium", validation: "validated", summary: `Plain HTTP answered ${r.status} without redirecting to HTTPS.`, operation: op, affected_asset: url, evidence: { status: r.status, location: loc.slice(0, 200) || null } });
      } catch (err) {
        return errorOutcome(err, op, url);
      }
    },
  },
  {
    key: "hsts",
    title: "Strict-Transport-Security (HSTS)",
    category: "headers",
    fix: headerFix("Strict-Transport-Security", "max-age=31536000; includeSubDomains", "HSTS tells browsers to always use HTTPS, blocking downgrade attacks on public Wi-Fi.", "Once set, browsers refuse plain HTTP for the max-age period. Make sure every subdomain supports HTTPS before adding includeSubDomains."),
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and inspect Strict-Transport-Security header`;
      try {
        const r = await home();
        const v = r.headers.get("strict-transport-security");
        const ev = { final_url: r.url, header: v };
        if (!v) return o({ result: "failed", severity: "medium", validation: "validated", summary: "No HSTS header is sent, so browsers may connect over HTTP first.", operation: op, affected_asset: r.url, evidence: ev });
        const age = Number(v.match(/max-age=(\d+)/i)?.[1] ?? 0);
        if (age < 15552000) return o({ result: "partial", severity: "low", validation: "validated", summary: `HSTS is present but max-age is short (${age}s; at least 6 months recommended).`, operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: "passed", summary: `HSTS is enabled with max-age ${age}s.`, operation: op, affected_asset: r.url, evidence: ev });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "csp",
    title: "Content-Security-Policy",
    category: "headers",
    fix: headerFix("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'", "A CSP limits which scripts can run, reducing the impact of cross-site scripting.", "A strict policy can block third-party scripts, fonts or analytics. Start with Content-Security-Policy-Report-Only to test first."),
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and parse Content-Security-Policy`;
      try {
        const r = await home();
        const csp = r.headers.get("content-security-policy");
        const ro = r.headers.get("content-security-policy-report-only");
        const ev = { final_url: r.url, csp: csp?.slice(0, 300) ?? null, report_only: ro ? ro.slice(0, 120) : null };
        if (!csp) {
          return o({ result: "failed", severity: ro ? "low" : "medium", validation: "validated", summary: ro ? "Only a report-only CSP is set; it does not block anything." : "No Content-Security-Policy header. This does not prove a script-injection flaw exists, but removes a key safety net.", operation: op, affected_asset: r.url, evidence: ev });
        }
        const script = hasDirective(csp, "script-src") ?? hasDirective(csp, "default-src") ?? "";
        if (!script) return o({ result: "partial", severity: "low", validation: "validated", summary: "CSP is set but has no script-src or default-src, so scripts are unrestricted.", operation: op, affected_asset: r.url, evidence: ev });
        if (/'unsafe-inline'|'unsafe-eval'|\*(\s|$)/.test(script)) return o({ result: "partial", severity: "low", validation: "validated", summary: "CSP allows inline/eval or wildcard scripts, which weakens its protection.", operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: "passed", summary: "A CSP restricting script sources is in place.", operation: op, affected_asset: r.url, evidence: ev });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "framing",
    title: "Clickjacking protection",
    category: "headers",
    fix: headerFix("X-Frame-Options", "SAMEORIGIN", "Stops other sites from embedding your pages invisibly to trick users into clicking.", "Legitimate embeds of your site on other domains will stop working."),
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and inspect X-Frame-Options / frame-ancestors`;
      try {
        const r = await home();
        const xfo = r.headers.get("x-frame-options");
        const fa = hasDirective(r.headers.get("content-security-policy") ?? "", "frame-ancestors");
        const ev = { final_url: r.url, x_frame_options: xfo, frame_ancestors: fa };
        if (xfo || fa) return o({ result: "passed", summary: "Framing is restricted.", operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: "failed", severity: "low", validation: "validated", summary: "No X-Frame-Options or frame-ancestors, so pages can be embedded by any site.", operation: op, affected_asset: r.url, evidence: ev });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "nosniff_referrer",
    title: "Content-type sniffing and referrer policy",
    category: "headers",
    fix: {
      ...headerFix("X-Content-Type-Options", "nosniff", "Prevents browsers from guessing file types, and stops full URLs leaking to other sites.", "Rarely any; files served with a wrong content type may stop loading."),
      snippets: [
        { label: "Nginx", code: 'add_header X-Content-Type-Options "nosniff" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;' },
        { label: "Apache", code: 'Header always set X-Content-Type-Options "nosniff"\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"' },
      ],
    },
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and inspect X-Content-Type-Options, Referrer-Policy`;
      try {
        const r = await home();
        const ev = pickHeaders(r.headers, ["x-content-type-options", "referrer-policy"]);
        const missing = ["x-content-type-options", "referrer-policy"].filter((h) => !ev[h]);
        if (missing.length === 0) return o({ result: "passed", summary: "Both headers are set.", operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: missing.length === 2 ? "failed" : "partial", severity: "low", validation: "validated", summary: `Missing: ${missing.join(", ")}.`, operation: op, affected_asset: r.url, evidence: { ...ev, missing } });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "cookies",
    title: "Cookie security attributes",
    category: "cookies",
    fix: {
      why: "Cookies without Secure/HttpOnly/SameSite can be stolen over HTTP, read by injected scripts, or sent in cross-site requests.",
      steps: ["Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies in your framework's cookie settings."],
      snippets: [
        { label: "Express", code: "app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }))" },
        { label: "PHP", code: "session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Lax']);" },
      ],
      side_effects: "HttpOnly cookies can no longer be read by your own JavaScript; SameSite=Strict can log users out when arriving from links.",
      rollback: "Revert the cookie options in config.",
    },
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and inspect Set-Cookie attributes (values discarded)`;
      try {
        const r = await home();
        if (r.setCookies.length === 0) return o({ result: "passed", summary: "The homepage sets no cookies, so there is nothing to weaken here. Logged-in areas were not tested.", confidence: "medium", operation: op, affected_asset: r.url, evidence: { cookies: [] } });
        const cookies = r.setCookies.slice(0, 10).map((c) => ({
          name: c.split("=")[0].trim().slice(0, 60),
          secure: /;\s*secure/i.test(c),
          httponly: /;\s*httponly/i.test(c),
          samesite: c.match(/;\s*samesite=(\w+)/i)?.[1] ?? null,
        }));
        const weak = cookies.filter((c) => !c.secure || !c.httponly || !c.samesite);
        if (weak.length === 0) return o({ result: "passed", summary: `${cookies.length} cookie(s) all set Secure, HttpOnly and SameSite.`, operation: op, affected_asset: r.url, evidence: { cookies } });
        const sessionLike = weak.some((c) => /sess|auth|token|sid|login/i.test(c.name));
        return o({ result: "failed", severity: sessionLike ? "medium" : "low", validation: "validated", summary: `${weak.length} cookie(s) are missing security flags${sessionLike ? ", including what looks like a session cookie" : ""}.`, operation: op, affected_asset: r.url, evidence: { cookies } });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "banner",
    title: "Software version disclosure",
    category: "exposure",
    fix: {
      why: "Version numbers help attackers pick known exploits. A banner alone does not prove the software is exploitable.",
      steps: ["Hide version details from Server and X-Powered-By headers.", "Keep the software itself updated."],
      snippets: [
        { label: "Nginx", code: "server_tokens off;" },
        { label: "Apache", code: "ServerTokens Prod\nServerSignature Off" },
        { label: "PHP", code: "expose_php = Off" },
        { label: "Express", code: "app.disable('x-powered-by')" },
      ],
      side_effects: "None.",
      rollback: "Revert the setting.",
    },
    run: async ({ scope, home }) => {
      const op = `GET ${base(scope.host)} and inspect Server, X-Powered-By, X-AspNet-Version`;
      try {
        const r = await home();
        const ev = pickHeaders(r.headers, ["server", "x-powered-by", "x-aspnet-version", "x-generator"]);
        const versioned = Object.entries(ev).filter(([, v]) => /\d+\.\d+/.test(v));
        if (versioned.length === 0) return o({ result: "passed", summary: "No software version numbers are exposed in headers.", operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: "failed", severity: "low", validation: "detected", confidence: "high", summary: `Headers reveal software versions (${versioned.map(([k]) => k).join(", ")}). This is information disclosure only; no exploit was attempted.`, operation: op, affected_asset: r.url, evidence: ev });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "git_exposed",
    title: "Exposed source control (.git)",
    category: "exposure",
    fix: {
      why: "A public .git folder can let anyone download your full source code and any secrets committed to it.",
      steps: ["Block access to /.git on the web server.", "Remove the .git folder from the deployed web root.", "Rotate any secrets that were ever committed."],
      snippets: [
        { label: "Nginx", code: "location ~ /\\.git { deny all; return 404; }" },
        { label: "Apache", code: 'RedirectMatch 404 /\\.git' },
      ],
      side_effects: "None for visitors.",
      rollback: "Remove the deny rule.",
    },
    run: async ({ scope }) => {
      const url = base(scope.host, "/.git/HEAD");
      const op = `GET ${url} and match the first line against /^ref: refs\\// (content not stored)`;
      try {
        const r = await safeFetch(url, scope, { followRedirects: false, maxBody: 256 });
        const hit = r.status === 200 && /^ref: refs\//.test(r.body.trim());
        if (hit) return o({ result: "failed", severity: "high", validation: "validated", summary: "/.git/HEAD is publicly readable and contains a real git reference. The repository is likely downloadable.", operation: op, affected_asset: url, evidence: { status: r.status, matched: "ref: refs/…" } });
        return o({ result: "passed", summary: `/.git/HEAD is not exposed (HTTP ${r.status}).`, operation: op, affected_asset: url, evidence: { status: r.status } });
      } catch (err) {
        return errorOutcome(err, op, url);
      }
    },
  },
  {
    key: "env_exposed",
    title: "Exposed environment file (.env)",
    category: "exposure",
    fix: {
      why: "A public .env file usually contains database passwords and API keys.",
      steps: ["Move .env outside the web root or block it.", "Rotate every credential that was in the file."],
      snippets: [
        { label: "Nginx", code: "location ~ /\\.env { deny all; return 404; }" },
        { label: "Apache", code: '<Files ".env">\n  Require all denied\n</Files>' },
      ],
      side_effects: "None for visitors.",
      rollback: "Remove the deny rule.",
    },
    run: async ({ scope }) => {
      const url = base(scope.host, "/.env");
      const op = `GET ${url} and test for KEY=value lines (content discarded, never stored)`;
      try {
        const r = await safeFetch(url, scope, { followRedirects: false, maxBody: 2048 });
        const html = /<html|<!doctype/i.test(r.body);
        const lines = r.body.split("\n").filter((l) => /^[A-Z][A-Z0-9_]{2,}=/.test(l.trim())).length;
        if (r.status === 200 && !html && lines >= 2) return o({ result: "failed", severity: "critical", validation: "validated", summary: `/.env is publicly downloadable and contains ${lines} configuration line(s). Values were not stored by Blackveil.`, operation: op, affected_asset: url, evidence: { status: r.status, config_lines_matched: lines } });
        return o({ result: "passed", summary: `/.env is not exposed (HTTP ${r.status}).`, operation: op, affected_asset: url, evidence: { status: r.status } });
      } catch (err) {
        return errorOutcome(err, op, url);
      }
    },
  },
  {
    key: "admin_panels",
    title: "Publicly reachable admin interfaces",
    category: "exposure",
    fix: {
      why: "Admin logins open to the internet attract password-guessing attacks.",
      steps: ["Restrict admin paths by IP allowlist, VPN or an access gateway (e.g. Cloudflare Access).", "Enforce multi-factor authentication."],
      snippets: [{ label: "Nginx", code: "location /admin {\n  allow 203.0.113.10;\n  deny all;\n}" }],
      side_effects: "Admins outside the allowlist need VPN or gateway access.",
      rollback: "Remove the allow/deny rules.",
    },
    run: async ({ scope }) => {
      const paths = ["/admin", "/wp-admin/", "/phpmyadmin/", "/administrator/"];
      const op = `GET ${paths.join(", ")} (no redirects followed, look for a login form)`;
      const found: { path: string; status: number }[] = [];
      try {
        for (const p of paths) {
          if (scope.signal.aborted) throw new DOMException("aborted", "AbortError");
          const r = await safeFetch(base(scope.host, p), scope, { followRedirects: false, maxBody: 16384 });
          if (r.status === 200 && /type=["']?password/i.test(r.body)) found.push({ path: p, status: r.status });
        }
        if (found.length === 0) return o({ result: "passed", summary: "No common admin login pages were reachable.", confidence: "medium", operation: op, affected_asset: base(scope.host), evidence: { checked: paths } });
        return o({ result: "failed", severity: "medium", validation: "validated", summary: `Admin login form reachable at ${found.map((f) => f.path).join(", ")}. No login attempts were made.`, operation: op, affected_asset: base(scope.host, found[0].path), evidence: { found } });
      } catch (err) {
        return errorOutcome(err, op, base(scope.host));
      }
    },
  },
  {
    key: "cors",
    title: "CORS origin reflection",
    category: "cors",
    fix: {
      why: "If any website can make credentialed requests and read the response, a malicious page can read a logged-in user's data.",
      steps: ["Only allow specific trusted origins.", "Never combine a reflected origin with Access-Control-Allow-Credentials: true."],
      snippets: [{ label: "Express (cors)", code: "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))" }],
      side_effects: "Front-ends on other domains not in the list will be blocked.",
      rollback: "Restore the previous CORS config.",
    },
    run: async ({ scope }) => {
      const probe = "https://blackveil-cors-probe.invalid";
      const url = base(scope.host);
      const op = `GET ${url} with header Origin: ${probe}`;
      try {
        const r = await safeFetch(url, scope, { headers: { Origin: probe }, maxBody: 1024 });
        const ev = pickHeaders(r.headers, ["access-control-allow-origin", "access-control-allow-credentials"]);
        const reflected = ev["access-control-allow-origin"] === probe;
        const creds = ev["access-control-allow-credentials"] === "true";
        if (reflected && creds) return o({ result: "failed", severity: "high", validation: "validated", summary: "The server echoed an arbitrary origin and allowed credentials. Any website could read authenticated responses.", operation: op, affected_asset: r.url, evidence: ev });
        if (reflected || ev["access-control-allow-origin"] === "*") return o({ result: "partial", severity: "low", validation: "validated", summary: "Any origin may read public responses (no credentials). Usually fine for public content.", operation: op, affected_asset: r.url, evidence: ev });
        return o({ result: "passed", summary: "Arbitrary origins are not trusted.", operation: op, affected_asset: r.url, evidence: ev });
      } catch (err) {
        return errorOutcome(err, op, url);
      }
    },
  },
  {
    key: "tls_config",
    title: "TLS certificate and configuration audit",
    category: "transport",
    fix: {
      why: "Weak protocols, weak cipher suites, soon-expiring or expired certificates let attackers decrypt or interfere with the connection.",
      steps: ["Enable TLS 1.2 and 1.3 and disable SSL/TLS 1.0/1.1.", "Prefer modern AEAD cipher suites (AES-GCM / ChaCha20-Poly1305).", "Renew certificates well before expiry and serve the full chain."],
      snippets: [
        { label: "Nginx", code: "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;\nssl_prefer_server_ciphers off;" },
        { label: "Cloudflare", code: "SSL/TLS > Edge Certificates > Minimum TLS Version = 1.2" },
      ],
      side_effects: "Very old legacy clients (pre-2015) will no longer connect.",
      rollback: "Re-enable the previous protocol/cipher settings.",
    },
    run: async ({ scope }) => {
      const op = `Open a TLS connection to ${scope.host}:443 and inspect the certificate chain, version and cipher suite (no data sent)`;
      const asset = `${scope.host}:443`;
      try {
        await resolvePublic(scope.host);
        const ev = await probeTls(scope.host, 443, { signal: scope.signal });

        if (!ev.reachable) {
          return o({ result: ev.error?.includes("Stopped") ? "incomplete" : "incomplete", severity: "high", validation: "unresolved", confidence: "low", summary: `Could not complete the TLS audit: ${ev.error ?? "no response"}.`, operation: op, affected_asset: asset, evidence: ev });
        }

        const cert = ev.serverCert;
        const days = cert ? daysRemaining(cert.notAfter) : null;
        const legacyVersion = ev.protocolVersion && /TLS 1\.[01]\b|SSL/.test(ev.protocolVersion);
        const badCipher = ev.cipherSuite && /CBC|RC4|3DES|SHA\b/i.test(ev.cipherSuiteName) && !/GCM|POLY1305/.test(ev.cipherSuiteName);
        const nearExpiry = days !== null && days < 30;
        const expired = days !== null && days < 0;
        const chainTooShort = ev.certificateChain.length === 1;
        const sans = cert?.subjectAltNames ?? [];

        const problems: string[] = [];
        if (expired) problems.push("certificate expired");
        else if (nearExpiry) problems.push(`certificate expires in ${days} days`);
        if (legacyVersion) problems.push(`only negotiated ${ev.protocolVersion}`);
        if (badCipher) problems.push(`negotiated weak cipher ${ev.cipherSuiteName}`);
        if (chainTooShort) problems.push("only one certificate in the chain (missing intermediate)");

        if (expired) {
          return o({ result: "failed", severity: "high", validation: "validated", summary: `The certificate expired ${Math.abs(days!)} days ago.`, operation: op, affected_asset: asset, evidence: { ...certEvidence(cert), protocol: ev.protocolVersion, cipher: ev.cipherSuiteName, chainLength: ev.certificateChain.length, sanCount: sans.length } });
        }
        if (problems.length) {
          return o({ result: "failed", severity: nearExpiry ? "medium" : legacyVersion || badCipher ? "medium" : "low", validation: "validated", summary: `TLS issues found: ${problems.join("; ")}.`, operation: op, affected_asset: asset, evidence: { ...certEvidence(cert), protocol: ev.protocolVersion, cipher: ev.cipherSuiteName, chainLength: ev.certificateChain.length, sanCount: sans.length, problems } });
        }
        return o({ result: "passed", summary: `TLS ${ev.protocolVersion} with a valid certificate (${days} days left) and strong cipher ${ev.cipherSuiteName}.`, operation: op, affected_asset: asset, evidence: { ...certEvidence(cert), protocol: ev.protocolVersion, cipher: ev.cipherSuiteName, chainLength: ev.certificateChain.length, sanCount: sans.length } });
      } catch (err) {
        return errorOutcome(err, op, asset);
      }
    },
  },
];

function certEvidence(cert: X509Cert | null): Record<string, unknown> {
  if (!cert) return { cert: null };
  return {
    cert: {
      subject: cert.subject.slice(0, 200),
      issuer: cert.issuer.slice(0, 200),
      notAfter: `${cert.notAfter.year}-${String(cert.notAfter.month).padStart(2, "0")}-${String(cert.notAfter.day).padStart(2, "0")}`,
    },
  };
}

const SEV_WEIGHT: Record<Severity, number> = { critical: 35, high: 20, medium: 9, low: 3, info: 0 };
const VAL_FACTOR: Record<Validation, number> = { validated: 1, detected: 0.8, suspected: 0.5, unresolved: 0.3 };

export function computeScore(rows: { result: Result; severity: Severity; validation: Validation }[]) {
  let score = 100;
  const counts = { passed: 0, failed: 0, partial: 0, validated: 0, suspected: 0, incomplete: 0, not_performed: 0, total: rows.length };
  for (const r of rows) {
    if (r.result === "passed") counts.passed++;
    else if (r.result === "incomplete") { counts.incomplete++; score -= 3; }
    else if (r.result === "not_performed") { counts.not_performed++; score -= 3; }
    else {
      if (r.result === "failed") counts.failed++; else counts.partial++;
      if (r.validation === "validated") counts.validated++;
      if (r.validation === "suspected" || r.validation === "detected") counts.suspected++;
      const w = SEV_WEIGHT[r.severity] * VAL_FACTOR[r.validation] * (r.result === "partial" ? 0.5 : 1);
      score -= w;
    }
  }
  return { score: Math.max(0, Math.min(95, Math.round(score))), counts };
}
