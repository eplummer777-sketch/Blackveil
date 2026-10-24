export interface PageResponse {
  url: string;
  status: number;
  headers: Headers;
  setCookies: string[];
  body: string;
}

export interface RawAlert {
  pluginId: string;
  alert: string;
  risk: "High" | "Medium" | "Low" | "Informational";
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  other: string;
  cweid: string;
  wascid: string;
  sourceid: string;
  url: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
}

type Rule = Omit<RawAlert, "url" | "method" | "param" | "attack" | "evidence" | "other" | "sourceid">;

const R: Record<string, Rule> = {
  csp: { pluginId: "10038", alert: "Content Security Policy (CSP) Header Not Set", risk: "Medium", confidence: "High", cweid: "693", wascid: "15",
    description: "The page does not send a Content-Security-Policy header, so the browser cannot restrict which scripts, styles and frames may load. This makes cross-site scripting and data injection easier to exploit.",
    solution: "Send a Content-Security-Policy header that allows only trusted sources, for example default-src 'self'.", reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" },
  frame: { pluginId: "10020", alert: "Missing Anti-clickjacking Header", risk: "Medium", confidence: "Medium", cweid: "1021", wascid: "15",
    description: "The response does not protect against clickjacking with X-Frame-Options or a CSP frame-ancestors directive.",
    solution: "Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive.", reference: "https://owasp.org/www-community/attacks/Clickjacking" },
  nosniff: { pluginId: "10021", alert: "X-Content-Type-Options Header Missing", risk: "Low", confidence: "Medium", cweid: "693", wascid: "15",
    description: "Without X-Content-Type-Options: nosniff, older browsers may guess the content type and render responses as something other than declared.",
    solution: "Send X-Content-Type-Options: nosniff on all responses.", reference: "https://owasp.org/www-project-secure-headers/" },
  hsts: { pluginId: "10035", alert: "Strict-Transport-Security Header Not Set", risk: "Low", confidence: "High", cweid: "319", wascid: "15",
    description: "The HTTPS response does not send HTTP Strict Transport Security, so browsers may still connect over plain HTTP where traffic can be intercepted.",
    solution: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.", reference: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html" },
  httponly: { pluginId: "10010", alert: "Cookie No HttpOnly Flag", risk: "Low", confidence: "Medium", cweid: "1004", wascid: "13",
    description: "A cookie was set without the HttpOnly flag, so page scripts can read it. If an attacker injects script, the cookie can be stolen.",
    solution: "Set the HttpOnly flag on cookies that scripts do not need to read, especially session cookies.", reference: "https://owasp.org/www-community/HttpOnly" },
  secure: { pluginId: "10011", alert: "Cookie Without Secure Flag", risk: "Low", confidence: "Medium", cweid: "614", wascid: "13",
    description: "A cookie was set without the Secure flag, so it can be sent over unencrypted HTTP connections.",
    solution: "Set the Secure flag on all cookies served over HTTPS.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  samesite: { pluginId: "10054", alert: "Cookie without SameSite Attribute", risk: "Low", confidence: "Medium", cweid: "1275", wascid: "13",
    description: "A cookie was set without a SameSite attribute, which helps protect against cross-site request forgery.",
    solution: "Set SameSite=Lax or SameSite=Strict on cookies.", reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite" },
  server: { pluginId: "10036", alert: "Server Leaks Version Information via \"Server\" Header", risk: "Low", confidence: "High", cweid: "497", wascid: "13",
    description: "The Server header reveals the software version, helping attackers find known vulnerabilities for that exact version.",
    solution: "Configure the web server to omit or genericise the Server header.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  powered: { pluginId: "10037", alert: "Server Leaks Information via \"X-Powered-By\" Header", risk: "Low", confidence: "Medium", cweid: "497", wascid: "13",
    description: "The X-Powered-By header reveals the framework or language behind the site.",
    solution: "Disable the X-Powered-By header in the framework or web server.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  permissions: { pluginId: "10063", alert: "Permissions Policy Header Not Set", risk: "Low", confidence: "Medium", cweid: "693", wascid: "15",
    description: "No Permissions-Policy header restricts which browser features (camera, microphone, geolocation) the page and its frames may use.",
    solution: "Send a Permissions-Policy header that disables features the site does not use.", reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy" },
  cors: { pluginId: "10098", alert: "Cross-Domain Misconfiguration", risk: "Medium", confidence: "Medium", cweid: "264", wascid: "14",
    description: "The response allows any website to read it (Access-Control-Allow-Origin: *). If the content is not truly public, other sites can read it from a visitor's browser.",
    solution: "Only allow specific trusted origins, or remove the CORS header from responses that are not meant to be shared.", reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" },
  csrf: { pluginId: "10202", alert: "Absence of Anti-CSRF Tokens", risk: "Medium", confidence: "Low", cweid: "352", wascid: "9",
    description: "A form that submits with POST has no visible anti-CSRF token, so another site may be able to submit it on behalf of a signed-in visitor.",
    solution: "Add a unique, unpredictable token to every state-changing form and verify it on the server, and use SameSite cookies.", reference: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  sri: { pluginId: "90003", alert: "Sub Resource Integrity Attribute Missing", risk: "Low", confidence: "High", cweid: "345", wascid: "15",
    description: "A script from another domain is loaded without an integrity attribute. If that domain is compromised, the modified script runs on your site.",
    solution: "Add integrity and crossorigin attributes to third-party scripts, or host them yourself.", reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity" },
  mixed: { pluginId: "10040", alert: "Secure Pages Include Mixed Content", risk: "Medium", confidence: "Medium", cweid: "311", wascid: "4",
    description: "An HTTPS page loads a resource over plain HTTP, which can be intercepted or modified in transit.",
    solution: "Load every resource over HTTPS.", reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content" },
  errors: { pluginId: "90022", alert: "Application Error Disclosure", risk: "Low", confidence: "Medium", cweid: "209", wascid: "13",
    description: "The page contains an error message or stack trace that may reveal internal file paths, code or software versions.",
    solution: "Show generic error pages to visitors and log details on the server only.", reference: "https://owasp.org/www-community/Improper_Error_Handling" },
  urlsecret: { pluginId: "10024", alert: "Information Disclosure - Sensitive Information in URL", risk: "Informational", confidence: "Medium", cweid: "200", wascid: "13",
    description: "A link includes a parameter that looks like a password, token or key. URLs end up in logs, browser history and Referer headers.",
    solution: "Never put secrets in URLs; send them in request bodies or headers.", reference: "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url" },
  plainhttp: { pluginId: "10106", alert: "HTTP Only Site", risk: "Medium", confidence: "Medium", cweid: "311", wascid: "4",
    description: "The page is served over plain HTTP and does not redirect to HTTPS, so traffic can be read and modified in transit.",
    solution: "Serve the site over HTTPS and redirect all HTTP requests to HTTPS.", reference: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html" },
  env: { pluginId: "40034", alert: "Exposed Environment File (.env)", risk: "High", confidence: "High", cweid: "538", wascid: "13",
    description: "A .env file is publicly downloadable. These files usually contain database passwords, API keys and other secrets.",
    solution: "Remove the file from the public web root, block dotfiles in the web server, and rotate every secret it contained.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  git: { pluginId: "41", alert: "Source Code Disclosure - Git Repository", risk: "High", confidence: "High", cweid: "541", wascid: "34",
    description: "The .git folder is publicly reachable, which can allow the full source code and its history (including old secrets) to be downloaded.",
    solution: "Remove the .git folder from the deployed site and block access to dotfiles.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  dsstore: { pluginId: "40036", alert: "Exposed .DS_Store File", risk: "Low", confidence: "High", cweid: "538", wascid: "13",
    description: "A macOS .DS_Store file is publicly reachable and lists file and folder names on the server.",
    solution: "Delete .DS_Store files from the deployment and block dotfiles.", reference: "https://owasp.org/www-project-web-security-testing-guide/" },
  status: { pluginId: "40035", alert: "Server Status Page Exposed", risk: "Medium", confidence: "High", cweid: "200", wascid: "13",
    description: "A web server status page is public and reveals visitor addresses, requested URLs and server internals.",
    solution: "Restrict the status page to administrators or disable it.", reference: "https://httpd.apache.org/docs/current/mod/mod_status.html" },
};

function hit(rule: Rule, url: string, extra: Partial<RawAlert> = {}): RawAlert {
  return { ...rule, url, method: "GET", param: "", attack: "", evidence: "", other: "", sourceid: "3", ...extra };
}

const isHtml = (r: PageResponse) => /text\/html|application\/xhtml/i.test(r.headers.get("content-type") ?? "");

const ERROR_RE = /(Traceback \(most recent call last\)|Fatal error: .{0,80} on line \d+|at [\w$.]+\([\w/\\.-]+\.(?:java|js|ts|cs):\d+|Microsoft OLE DB Provider|You have an error in your SQL syntax|Warning: (?:mysql|pg)_\w+\(|System\.\w+Exception)/;

export function passiveChecks(r: PageResponse): RawAlert[] {
  const out: RawAlert[] = [];
  const h = (n: string) => r.headers.get(n);
  const https = r.url.startsWith("https:");
  const html = isHtml(r);
  if (html && r.status < 400) {
    const csp = h("content-security-policy");
    if (!csp) out.push(hit(R.csp, r.url));
    if (!h("x-frame-options") && !/frame-ancestors/i.test(csp ?? "")) out.push(hit(R.frame, r.url, { param: "x-frame-options" }));
    if (!h("permissions-policy")) out.push(hit(R.permissions, r.url));
    if (!https) out.push(hit(R.plainhttp, r.url));
  }
  if (!/nosniff/i.test(h("x-content-type-options") ?? "")) out.push(hit(R.nosniff, r.url, { param: "x-content-type-options" }));
  if (https && !h("strict-transport-security")) out.push(hit(R.hsts, r.url));
  const server = h("server") ?? "";
  if (/\d/.test(server)) out.push(hit(R.server, r.url, { evidence: server.slice(0, 120) }));
  const powered = h("x-powered-by");
  if (powered) out.push(hit(R.powered, r.url, { evidence: powered.slice(0, 120) }));
  if (h("access-control-allow-origin")?.trim() === "*") out.push(hit(R.cors, r.url, { evidence: "Access-Control-Allow-Origin: *" }));

  for (const c of r.setCookies) {
    const name = c.split("=")[0]?.trim().slice(0, 80) ?? "";
    const attrs = c.toLowerCase();
    if (!/;\s*httponly/.test(attrs)) out.push(hit(R.httponly, r.url, { param: name, evidence: `Set-Cookie: ${name}` }));
    if (https && !/;\s*secure/.test(attrs)) out.push(hit(R.secure, r.url, { param: name, evidence: `Set-Cookie: ${name}` }));
    if (!/;\s*samesite=/.test(attrs)) out.push(hit(R.samesite, r.url, { param: name, evidence: `Set-Cookie: ${name}` }));
  }

  if (!html) return out;
  const origin = new URL(r.url).origin;
  for (const m of r.body.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)) {
    const tag = m[0].slice(0, m[0].indexOf(">") + 1);
    if (!/method\s*=\s*["']?post/i.test(tag)) continue;
    if (/<input[^>]+name\s*=\s*["']?[\w-]*(csrf|xsrf|token|nonce|authenticity)/i.test(m[1])) continue;
    out.push(hit(R.csrf, r.url, { evidence: tag.slice(0, 300) }));
  }
  for (const m of r.body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
    let src: URL;
    try { src = new URL(m[1], r.url); } catch { continue; }
    if (https && src.protocol === "http:") out.push(hit(R.mixed, r.url, { evidence: m[0].slice(0, 300) }));
    else if (src.origin !== origin && !/\bintegrity\s*=/i.test(m[0])) out.push(hit(R.sri, r.url, { evidence: m[0].slice(0, 300) }));
  }
  if (https) {
    const m = r.body.match(/<(?:link|img|iframe)\b[^>]*(?:src|href)\s*=\s*["']http:\/\/[^"']+["'][^>]*>/i);
    if (m) out.push(hit(R.mixed, r.url, { evidence: m[0].slice(0, 300) }));
  }
  const err = r.body.match(ERROR_RE);
  if (err) out.push(hit(R.errors, r.url, { evidence: err[0].slice(0, 200) }));
  const secret = r.body.match(/href\s*=\s*["'][^"']*[?&](password|passwd|token|api_?key|secret|session_?id)=[^"'&]{3,}/i);
  if (secret) out.push(hit(R.urlsecret, r.url, { param: secret[1] }));
  return out;
}

export const DISCOVERY_PATHS = ["/.env", "/.git/HEAD", "/.DS_Store", "/server-status"];

export function discoveryCheck(path: string, r: PageResponse): RawAlert | null {
  if (r.status !== 200) return null;
  const extra = { sourceid: "1", attack: path };
  if (path === "/.env" && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(r.body) && !isHtml(r)) return hit(R.env, r.url, { ...extra, evidence: "File contains KEY=value lines" });
  if (path === "/.git/HEAD" && /^ref: refs\//.test(r.body)) return hit(R.git, r.url, { ...extra, evidence: r.body.slice(0, 60).trim() });
  if (path === "/.DS_Store" && r.body.slice(4, 8) === "Bud1") return hit(R.dsstore, r.url, { ...extra, evidence: "Bud1 file signature" });
  if (path === "/server-status" && /Apache Server Status/i.test(r.body)) return hit(R.status, r.url, { ...extra, evidence: "Apache Server Status" });
  return null;
}

export function extractLinks(r: PageResponse): string[] {
  if (!isHtml(r)) return [];
  const out = new Set<string>();
  for (const m of r.body.matchAll(/<(?:a|link|area|form|iframe)\b[^>]*\b(?:href|action|src)\s*=\s*["']([^"'#]+)/gi)) {
    try {
      const u = new URL(m[1].trim(), r.url);
      if (u.protocol !== "http:" && u.protocol !== "https:") continue;
      if (/\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|mp3|pdf|zip)$/i.test(u.pathname)) continue;
      u.hash = "";
      out.add(u.toString());
    } catch { /* invalid link */ }
  }
  return [...out];
}

export function openApiPaths(spec: unknown, base: string): string[] {
  if (!spec || typeof spec !== "object") return [];
  const paths = (spec as { paths?: Record<string, Record<string, unknown>> }).paths ?? {};
  const out: string[] = [];
  for (const [p, ops] of Object.entries(paths)) {
    if (p.includes("{") || !ops || typeof ops !== "object" || !("get" in ops)) continue;
    try { out.push(new URL(p.replace(/^\/?/, ""), base.endsWith("/") ? base : `${base}/`).toString()); } catch { /* skip */ }
  }
  return out;
}
