// Safe HTTP security checks — non-intrusive, read-only probes against public HTTPS sites.
// Reuses the SSRF protection pattern from the existing website-assessment function.

const PRIVATE_IP_REGEX =
  /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1|fe80:|fc00:|fd00:|100\.64\.)/i;

const BLOCKED_HOSTS = [
  "169.254.169.254", "metadata.google.internal", "169.254.169.253",
  "0.0.0.0", "localhost", "metadata",
];

function blockSsrf(hostname: string): string | null {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTS.includes(h)) return "Blocked cloud metadata / loopback host.";
  if (isPrivateOrLoopback(h)) return "Blocked private / loopback destination.";
  return null;
}

function isPrivateOrLoopback(host: string): boolean {
  return PRIVATE_IP_REGEX.test(host);
}

export function normalizeTarget(input: string): { host: string; url: string } | null {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  if (!/^https?:\/\//.test(s)) s = "https://" + s;
  try {
    const u = new URL(s);
    if (!u.hostname) return null;
    if (u.username || u.password) return null;
    const blocked = blockSsrf(u.hostname);
    if (blocked) return null;
    return { host: u.hostname, url: u.toString() };
  } catch {
    return null;
  }
}

async function fetchWithTimeout(url: string, ms = 8000): Promise<Response> {
  return fetch(url, {
    redirect: "manual",
    headers: { "User-Agent": "Blackveil-Remediation-Engine/1.0 (+authorized)" },
    signal: AbortSignal.timeout(ms),
  });
}

async function safeFetchFinal(url: string): Promise<{ resp: Response | null; finalUrl: string; note?: string }> {
  let current = url;
  for (let i = 0; i < 4; i++) {
    let resp: Response;
    try {
      resp = await fetchWithTimeout(current);
    } catch {
      return { resp: null, finalUrl: current, note: "Request failed or timed out." };
    }
    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get("location");
      if (!loc) return { resp, finalUrl: current, note: "Redirect without Location header." };
      let next: URL;
      try { next = new URL(loc, current); } catch { return { resp, finalUrl: current, note: "Invalid redirect Location." }; }
      const blocked = blockSsrf(next.hostname);
      if (blocked) return { resp: null, finalUrl: current, note: blocked };
      current = next.toString();
      continue;
    }
    return { resp, finalUrl: current };
  }
  return { resp: null, finalUrl: current, note: "Too many redirects." };
}

export interface HttpFinding {
  check_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  source: "http";
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  verified: boolean;
}

export interface CheckResult {
  check_id: string;
  status: "completed" | "skipped" | "failed";
  note?: string;
}

export async function runHttpChecks(host: string): Promise<{ findings: HttpFinding[]; checks: CheckResult[] }> {
  const findings: HttpFinding[] = [];
  const checks: CheckResult[] = [];

  // 1. HTTPS reachability
  const httpsResp = await safeFetchFinal(`https://${host}/`);
  if (!httpsResp.resp) {
    checks.push({ check_id: "https_reachable", status: "failed", note: httpsResp.note });
    findings.push({
      check_id: "https_reachable",
      title: "HTTPS not reachable",
      severity: "high",
      category: "Transport",
      source: "http",
      description: "The site did not respond over HTTPS within the timeout.",
      evidence: httpsResp.note ?? "No response received.",
      impact: "Visitors cannot access your site securely. Without HTTPS, all traffic including passwords and session cookies is sent in plaintext and can be intercepted.",
      remediation: "Obtain a TLS certificate (e.g. from Let's Encrypt) and configure your web server to serve HTTPS on port 443.",
      verified: true,
    });
  } else {
    checks.push({ check_id: "https_reachable", status: "completed" });
    findings.push({
      check_id: "https_reachable",
      title: "HTTPS is reachable",
      severity: "info",
      category: "Transport",
      source: "http",
      description: "The site responded over HTTPS successfully.",
      evidence: `HTTPS request returned status ${httpsResp.resp.status}.`,
      impact: "HTTPS is working. Visitors can connect securely.",
      remediation: "Continue to monitor certificate expiry and renewal.",
      verified: true,
    });

    // 2. Security headers
    const headerChecks: { id: string; header: string; title: string; severity: "high" | "medium" | "low"; impact: string; remediation: string; validate?: (v: string) => boolean }[] = [
      {
        id: "strict_transport_security",
        header: "strict-transport-security",
        title: "HSTS header missing or weak",
        severity: "medium",
        impact: "Without HSTS, browsers may downgrade to HTTP on subsequent visits, exposing users to man-in-the-middle attacks.",
        remediation: "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains' on all HTTPS responses. If using Cloudflare, enable HSTS in the SSL/TLS Edge Certificates settings.",
        validate: (v) => /max-age\s*=\s*\d{5,}/i.test(v),
      },
      {
        id: "x_content_type_options",
        header: "x-content-type-options",
        title: "X-Content-Type-Options missing",
        severity: "low",
        impact: "Without nosniff, browsers may guess MIME types, potentially executing uploaded files as scripts.",
        remediation: "Send 'X-Content-Type-Options: nosniff' on all responses.",
        validate: (v) => /nosniff/i.test(v),
      },
      {
        id: "x_frame_options",
        header: "x-frame-options",
        title: "Clickjacking protection missing",
        severity: "medium",
        impact: "Your site can be embedded in an invisible iframe on a malicious site, tricking users into clicking hidden elements.",
        remediation: "Set 'X-Frame-Options: DENY' or use Content-Security-Policy: frame-ancestors 'none'.",
        validate: (v) => /^(deny|sameorigin)/i.test(v),
      },
      {
        id: "content_security_policy",
        header: "content-security-policy",
        title: "Content-Security-Policy missing",
        severity: "high",
        impact: "Without CSP, any injected script can execute freely, making XSS attacks much more dangerous.",
        remediation: "Define a strict Content-Security-Policy. Start with 'default-src 'self'' and add specific directives for scripts, styles, and images.",
      },
      {
        id: "referrer_policy",
        header: "referrer-policy",
        title: "Referrer-Policy missing",
        severity: "low",
        impact: "The full URL may be leaked to third-party sites via the Referer header, potentially exposing sensitive path parameters.",
        remediation: "Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
      },
      {
        id: "permissions_policy",
        header: "permissions-policy",
        title: "Permissions-Policy missing",
        severity: "low",
        impact: "Browser features like camera, microphone, and geolocation are not restricted, allowing third-party embeds to access them.",
        remediation: "Send a Permissions-Policy restricting sensitive features (e.g. 'geolocation=(), microphone=(), camera=()').",
      },
    ];

    for (const h of headerChecks) {
      const value = httpsResp.resp.headers.get(h.header);
      if (!value || (h.validate && !h.validate(value))) {
        findings.push({
          check_id: h.id,
          title: h.title,
          severity: h.severity,
          category: "Headers",
          source: "http",
          description: `The ${h.header} response header was missing or did not meet the recommended value.`,
          evidence: value ? `Received: ${value}` : "Header not present in response.",
          impact: h.impact,
          remediation: h.remediation,
          verified: true,
        });
      }
    }
    checks.push({ check_id: "security_headers", status: "completed" });

    // 3. Server banner
    const server = httpsResp.resp.headers.get("server") ?? "";
    const xPower = httpsResp.resp.headers.get("x-powered-by") ?? "";
    const leaks: string[] = [];
    if (server) leaks.push(`Server: ${server}`);
    if (xPower) leaks.push(`X-Powered-By: ${xPower}`);
    if (leaks.length) {
      findings.push({
        check_id: "server_banner",
        title: "Server software version disclosed",
        severity: "low",
        category: "Information disclosure",
        source: "http",
        description: "The server advertises software and possibly version information.",
        evidence: leaks.join(" | "),
        impact: "Attackers can use this information to identify known vulnerabilities in your specific server software version.",
        remediation: "Suppress the Server and X-Powered-By headers in your web server configuration.",
        verified: true,
      });
    }
    checks.push({ check_id: "server_banner", status: "completed" });
  }

  // 4. HTTP -> HTTPS redirect
  const httpResp = await safeFetchFinal(`http://${host}/`);
  if (!httpResp.resp) {
    checks.push({ check_id: "http_redirect", status: "skipped", note: "No HTTP response." });
  } else {
    checks.push({ check_id: "http_redirect", status: "completed" });
    if (!httpResp.finalUrl.startsWith("https://")) {
      findings.push({
        check_id: "http_redirect",
        title: "HTTP does not redirect to HTTPS",
        severity: "medium",
        category: "Transport",
        source: "http",
        description: "Requests over plain HTTP were not redirected to HTTPS.",
        evidence: `HTTP request final URL: ${httpResp.finalUrl} (status ${httpResp.resp.status}).`,
        impact: "Visitors who type your domain without https:// will browse over an unencrypted connection, exposing their data.",
        remediation: "Configure your web server or CDN to 301 redirect all HTTP traffic to HTTPS. If using Cloudflare, enable 'Always Use HTTPS'.",
        verified: true,
      });
    } else {
      findings.push({
        check_id: "http_redirect",
        title: "HTTP redirects to HTTPS",
        severity: "info",
        category: "Transport",
        source: "http",
        description: "Plain HTTP traffic was redirected to HTTPS.",
        evidence: `Final URL after redirect: ${httpResp.finalUrl}`,
        impact: "Visitors are automatically redirected to the secure connection.",
        remediation: "Maintain the redirect and consider enabling HSTS preload.",
        verified: true,
      });
    }
  }

  // 5. DNS resolution
  try {
    const records = await Deno.resolveDns(host, "A");
    checks.push({ check_id: "dns_a", status: "completed", note: `${records.length} A record(s).` });
    if (records.length === 0) {
      findings.push({
        check_id: "dns_a",
        title: "No A records found",
        severity: "medium",
        category: "DNS",
        source: "http",
        description: "The domain has no A records configured.",
        evidence: "DNS query returned zero A records.",
        impact: "The domain is not reachable. Visitors cannot access your site.",
        remediation: "Create an A record pointing to your web server's public IP address.",
        verified: true,
      });
    }
  } catch {
    checks.push({ check_id: "dns_a", status: "skipped", note: "DNS resolution unavailable." });
  }

  // 6. Well-known security.txt
  const secTxtResp = await safeFetchFinal(`https://${host}/.well-known/security.txt`);
  if (secTxtResp.resp) {
    checks.push({ check_id: "security_txt", status: "completed" });
    if (secTxtResp.resp.status !== 200) {
      findings.push({
        check_id: "security_txt",
        title: "security.txt missing",
        severity: "low",
        category: "Information disclosure",
        source: "http",
        description: "No security.txt file was found at the standard location.",
        evidence: `GET /.well-known/security.txt -> ${secTxtResp.resp.status}`,
        impact: "Security researchers cannot find a contact channel to report vulnerabilities responsibly.",
        remediation: "Publish /.well-known/security.txt with a contact address and expiry date.",
        verified: true,
      });
    }
  } else {
    checks.push({ check_id: "security_txt", status: "skipped", note: "No response." });
  }

  return { findings, checks };
}
