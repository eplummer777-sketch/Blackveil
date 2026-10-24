import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";

// ---------- Types ----------
interface Finding {
  check_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence: string;
  remediation: string;
  verified: boolean;
}

interface CheckResult {
  check_id: string;
  status: "completed" | "skipped" | "failed";
  note?: string;
}

// ---------- SSRF protection ----------
const PRIVATE_IP_REGEX =
  /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1|fe80:|fc00:|fd00:|100\.64\.)/i;

function isPrivateOrLoopback(host: string): boolean {
  return PRIVATE_IP_REGEX.test(host);
}

const BLOCKED_HOSTS = [
  "169.254.169.254", // AWS / GCP metadata
  "metadata.google.internal",
  "169.254.169.253",
  "0.0.0.0",
  "localhost",
  "metadata",
];

function blockSsrf(hostname: string): string | null {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTS.includes(h)) return "Blocked cloud metadata / loopback host.";
  if (isPrivateOrLoopback(h)) return "Blocked private / loopback destination.";
  // No raw IP scans to public cloud metadata ranges; allow public IPs/domains.
  if (/^[0-9.]+$/.test(h) && PRIVATE_IP_REGEX.test(h + ".")) {
    return "Blocked private IP range.";
  }
  return null;
}

function normalizeTarget(input: string): { host: string; url: string } | null {
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

async function fetchWithTimeout(url: string, opts: RequestInit = {}, ms = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    // follow: manual so we do not blindly chase redirects into private space
    const r = await fetch(url, {
      ...opts,
      redirect: "manual",
      signal: ctrl.signal,
    });
    return r;
  } finally {
    clearTimeout(t);
  }
}

async function safeFetchFinal(url: string): Promise<{ resp: Response | null; finalUrl: string; note?: string }> {
  let current = url;
  for (let i = 0; i < 4; i++) {
    let resp: Response;
    try {
      resp = await fetchWithTimeout(current, {
        headers: { "User-Agent": "Blackveil-AI-Security-Assessment/1.0 (+authorized)" },
      });
    } catch {
      return { resp: null, finalUrl: current, note: "Request failed or timed out." };
    }
    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get("location");
      if (!loc) return { resp, finalUrl: current, note: "Redirect without Location header." };
      let next: URL;
      try {
        next = new URL(loc, current);
      } catch {
        return { resp, finalUrl: current, note: "Invalid redirect Location." };
      }
      const blocked = blockSsrf(next.hostname);
      if (blocked) return { resp: null, finalUrl: current, note: blocked };
      current = next.toString();
      continue;
    }
    return { resp, finalUrl: current };
  }
  return { resp: null, finalUrl: current, note: "Too many redirects." };
}

// ---------- Checks ----------
async function checkTlsAndHttps(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const url = "https://" + host + "/";
  const { resp, note } = await safeFetchFinal(url);

  if (!resp) {
    checks.push({ check_id: "https_reachable", status: "failed", note });
    findings.push({
      check_id: "https_reachable",
      title: "HTTPS not reachable",
      severity: "high",
      description: "The site did not respond over HTTPS within the timeout.",
      evidence: note ?? "No response received.",
      remediation:
        "Ensure TLS/443 is served and reachable. If HTTPS is not configured, obtain a certificate (e.g. Let's Encrypt) and redirect HTTP to HTTPS.",
      verified: true,
    });
    return { findings, checks };
  }

  checks.push({ check_id: "https_reachable", status: "completed" });

  // TLS cert validity via the response (we cannot read cert details from fetch,
  // but we can confirm the TLS handshake succeeded and the cert chain was trusted).
  findings.push({
    check_id: "tls_handshake",
    title: "TLS handshake succeeded",
    severity: "info",
    description:
      "The server completed a TLS handshake and presented a certificate chain that was trusted by the runtime.",
    evidence: `HTTPS request to ${url} returned status ${resp.status}.`,
    remediation: "Continue to monitor certificate expiry and renewal.",
    verified: true,
  });
  checks.push({ check_id: "tls_handshake", status: "completed" });

  return { findings, checks };
}

async function checkSecurityHeaders(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const url = "https://" + host + "/";
  const { resp, note } = await safeFetchFinal(url);
  if (!resp) {
    checks.push({ check_id: "security_headers", status: "skipped", note: note ?? "No response." });
    return { findings, checks };
  }
  checks.push({ check_id: "security_headers", status: "completed" });

  const headerChecks: {
    id: string;
    header: string;
    title: string;
    severity: "medium" | "low" | "high";
    remediation: string;
    validate?: (v: string) => boolean;
  }[] = [
    {
      id: "strict_transport_security",
      header: "strict-transport-security",
      title: "Strict-Transport-Security (HSTS) missing or weak",
      severity: "medium",
      remediation:
        "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' on all HTTPS responses.",
      validate: (v) => /max-age\s*=\s*\d{5,}/i.test(v),
    },
    {
      id: "x_content_type_options",
      header: "x-content-type-options",
      title: "X-Content-Type-Options missing",
      severity: "low",
      remediation: "Send 'X-Content-Type-Options: nosniff'.",
      validate: (v) => /nosniff/i.test(v),
    },
    {
      id: "x_frame_options",
      header: "x-frame-options",
      title: "Click-jacking protection missing (X-Frame-Options / CSP frame-ancestors)",
      severity: "medium",
      remediation:
        "Set 'X-Frame-Options: DENY' or a 'Content-Security-Policy: frame-ancestors' directive.",
      validate: (v) => /^(deny|sameorigin)/i.test(v),
    },
    {
      id: "content_security_policy",
      header: "content-security-policy",
      title: "Content-Security-Policy missing",
      severity: "high",
      remediation:
        "Define a strict Content-Security-Policy limiting script/style/img/frame sources. Start with 'default-src 'self'' and refine.",
    },
    {
      id: "referrer_policy",
      header: "referrer-policy",
      title: "Referrer-Policy missing",
      severity: "low",
      remediation: "Send 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
    },
    {
      id: "permissions_policy",
      header: "permissions-policy",
      title: "Permissions-Policy missing",
      severity: "low",
      remediation:
        "Send a Permissions-Policy restricting sensitive browser features (e.g. camera, microphone, geolocation).",
    },
  ];

  for (const h of headerChecks) {
    const value = resp.headers.get(h.header);
    if (!value || (h.validate && !h.validate(value))) {
      findings.push({
        check_id: h.id,
        title: h.title,
        severity: h.severity,
        description: `The ${h.header} response header was missing or did not meet the recommended value.`,
        evidence: value ? `Received: ${value}` : "Header not present in response.",
        remediation: h.remediation,
        verified: true,
      });
    }
  }
  return { findings, checks };
}

async function checkHttpToHttpsRedirect(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const url = "http://" + host + "/";
  const { resp, finalUrl } = await safeFetchFinal(url);
  if (!resp) {
    checks.push({ check_id: "http_redirect", status: "skipped", note: "No HTTP response." });
    return { findings, checks };
  }
  checks.push({ check_id: "http_redirect", status: "completed" });
  const finalIsHttps = finalUrl.startsWith("https://");
  if (!finalIsHttps) {
    findings.push({
      check_id: "http_redirect",
      title: "HTTP does not redirect to HTTPS",
      severity: "medium",
      description: "Requests over plain HTTP were not redirected to HTTPS.",
      evidence: `HTTP request final URL: ${finalUrl} (status ${resp.status}).`,
      remediation: "Configure your web server to 301 redirect all HTTP traffic to HTTPS.",
      verified: true,
    });
  } else {
    findings.push({
      check_id: "http_redirect",
      title: "HTTP redirects to HTTPS",
      severity: "info",
      description: "Plain HTTP traffic was redirected to HTTPS.",
      evidence: `Final URL after redirect: ${finalUrl}`,
      remediation: "Maintain the redirect and consider HSTS preload.",
      verified: true,
    });
  }
  return { findings, checks };
}

async function checkDnsBasic(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  try {
    // Use Deno.resolveDns if available; otherwise mark skipped.
    // @ts-ignore - resolveDns exists in Deno runtime
    const records = await Deno.resolveDns(host, "A");
    checks.push({ check_id: "dns_a", status: "completed", note: `${records.length} A record(s).` });
    findings.push({
      check_id: "dns_a",
      title: "DNS A records resolved",
      severity: "info",
      description: `The domain resolved to ${records.length} A record(s).`,
      evidence: `A records: ${records.join(", ") || "(none)"}`,
      remediation: "Keep DNS records tight and remove stale entries.",
      verified: true,
    });
    if (records.length === 0) {
      findings.push({
        check_id: "dns_a",
        title: "No A records found",
        severity: "medium",
        description: "The domain has no A records configured.",
        evidence: "DNS query returned zero A records.",
        remediation: "Create an A record pointing to your web server's public IP.",
        verified: true,
      });
    }
  } catch {
    checks.push({ check_id: "dns_a", status: "skipped", note: "DNS resolution unavailable." });
  }
  return { findings, checks };
}

async function checkServerSignature(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const url = "https://" + host + "/";
  const { resp } = await safeFetchFinal(url);
  if (!resp) {
    checks.push({ check_id: "server_banner", status: "skipped", note: "No response." });
    return { findings, checks };
  }
  checks.push({ check_id: "server_banner", status: "completed" });
  const server = resp.headers.get("server") ?? "";
  const xPower = resp.headers.get("x-powered-by") ?? "";
  const leaks: string[] = [];
  if (server) leaks.push(`Server: ${server}`);
  if (xPower) leaks.push(`X-Powered-By: ${xPower}`);
  if (leaks.length) {
    findings.push({
      check_id: "server_banner",
      title: "Server software version disclosed",
      severity: "low",
      description:
        "The server advertises software and possibly version information, which can help attackers target known vulnerabilities.",
      evidence: leaks.join(" | "),
      remediation:
        "Suppress the Server and X-Powered-By headers or replace them with non-revealing values in your web server config.",
      verified: true,
    });
  }
  return { findings, checks };
}

async function checkWellKnownSecurity(host: string): Promise<{ findings: Finding[]; checks: CheckResult[] }> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const paths = [
    { id: "security_txt", path: "/.well-known/security.txt", severity: "low" as const,
      title: "security.txt missing",
      desc: "No security.txt found. This file helps researchers report vulnerabilities responsibly.",
      rem: "Publish /.well-known/security.txt with a contact address and expiry." },
    { id: "robots_txt", path: "/robots.txt", severity: "info" as const,
      title: "robots.txt present",
      desc: "robots.txt was found. Review it for sensitive paths you may be inadvertently exposing.",
      rem: "Ensure robots.txt does not list private admin or backup paths." },
  ];

  for (const p of paths) {
    const { resp } = await safeFetchFinal("https://" + host + p.path);
    if (!resp) {
      checks.push({ check_id: p.id, status: "skipped", note: "No response." });
      continue;
    }
    if (p.id === "security_txt" && resp.status === 200) {
      findings.push({
        check_id: p.id,
        title: "security.txt published",
        severity: "info",
        description: "A security.txt file was reachable.",
        evidence: `GET ${p.path} -> ${resp.status}`,
        remediation: p.rem,
        verified: true,
      });
    } else if (p.id === "security_txt") {
      findings.push({
        check_id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.desc,
        evidence: `GET ${p.path} -> ${resp.status}`,
        remediation: p.rem,
        verified: true,
      });
    } else if (p.id === "robots_txt" && resp.status === 200) {
      findings.push({
        check_id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.desc,
        evidence: `GET ${p.path} -> ${resp.status}`,
        remediation: p.rem,
        verified: true,
      });
    }
    checks.push({ check_id: p.id, status: "completed" });
  }
  return { findings, checks };
}

function computeOverall(findings: Finding[]): { status: string; summary: Record<string, number> } {
  const summary: Record<string, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of findings) summary[f.severity]++;
  let status = "Good";
  if (summary.critical > 0) status = "Critical";
  else if (summary.high > 0) status = "Needs attention";
  else if (summary.medium > 0) status = "Fair";
  return { status, summary };
}

// ---------- Handler ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  const { user, client, error } = await getAuthenticatedUser(req);
  if (!user) return errorResponse(error ?? "Unauthorized", 401);

  let body: { target?: string; authorization_confirmed?: boolean };
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON", 400);
  }

  const target = (body.target ?? "").trim();
  const authorized = !!body.authorization_confirmed;
  if (!target) return errorResponse("Target is required", 400);
  if (!authorized) {
    return errorResponse(
      "You must confirm you own or have explicit permission to assess this target.",
      400
    );
  }

  const parsed = normalizeTarget(target);
  if (!parsed) {
    return errorResponse(
      "Invalid or blocked target. Use a public domain you own. Private, loopback, and metadata destinations are blocked.",
      400
    );
  }

  const serviceClient = getServiceClient();

  // Plan-aware rate limits: free=6/hour, malware_removal=12/hour, pro=30/hour, elite=unlimited
  const userRole = (user.app_metadata as Record<string, unknown> | undefined)?.role;
  const isAdminUser = userRole === "admin";
  const { data: subRow } = await serviceClient
    .from("subscriptions")
    .select("plan, status")
    .eq("user_id", user.id)
    .maybeSingle();
  const subActive = subRow && (subRow.status === "active" || subRow.status === "trialing");
  const subPlan = subActive ? subRow.plan : "free";
  const rateLimit = isAdminUser || subPlan === "elite" ? 0
    : subPlan === "pro" ? 30
    : subPlan === "malware_removal" ? 12
    : 6;

  if (rateLimit > 0) {
    const since = new Date(Date.now() - 3_600_000).toISOString();
    const { count } = await serviceClient
      .from("assessments")
      .select("*", { count: "exact", head: true })
      .eq("user_id", user.id)
      .gte("created_at", since);
    if ((count ?? 0) >= rateLimit) {
      return errorResponse(`Assessment rate limit reached (${rateLimit}/hour). Upgrade for more assessments.`, 429);
    }
  }

  // Create assessment record
  const { data: assessment, error: aErr } = await client
    .from("assessments")
    .insert({
      user_id: user.id,
      target: parsed.host,
      authorization_confirmed: true,
      status: "running",
      started_at: new Date().toISOString(),
    })
    .select("id")
    .single();
  if (aErr || !assessment) return errorResponse("Could not start assessment", 500);

  const assessmentId = assessment.id;

  try {
    const allFindings: Finding[] = [];
    const allChecks: CheckResult[] = [];

    const fns = [
      () => checkTlsAndHttps(parsed.host),
      () => checkHttpToHttpsRedirect(parsed.host),
      () => checkSecurityHeaders(parsed.host),
      () => checkServerSignature(parsed.host),
      () => checkWellKnownSecurity(parsed.host),
      () => checkDnsBasic(parsed.host),
    ];

    for (const fn of fns) {
      try {
        const r = await fn();
        allFindings.push(...r.findings);
        allChecks.push(...r.checks);
      } catch {
        allChecks.push({ check_id: "unknown", status: "failed", note: "Check threw an error." });
      }
    }

    const { status, summary } = computeOverall(allFindings);

    // Save findings
    if (allFindings.length) {
      const rows = allFindings.map((f) => ({
        assessment_id: assessmentId,
        check_id: f.check_id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence,
        remediation: f.remediation,
        verified: f.verified,
      }));
      const { error: fErr } = await serviceClient.from("findings").insert(rows);
      if (fErr) {
        await serviceClient.from("admin_events").insert({
          kind: "assessment_save_error",
          detail: { assessment_id: assessmentId, error: fErr.message },
        });
      }
    }

    const { error: updErr } = await serviceClient
      .from("assessments")
      .update({
        status: "completed",
        overall_status: status,
        summary: { ...summary, checks: allChecks, info_count: summary.info },
        completed_at: new Date().toISOString(),
      })
      .eq("id", assessmentId);
    if (updErr) {
      await serviceClient.from("admin_events").insert({
        kind: "assessment_update_error",
        detail: { assessment_id: assessmentId, error: updErr.message },
      });
    }

    await serviceClient.from("audit_logs").insert({
      user_id: user.id,
      action: "assessment_completed",
      detail: { assessment_id: assessmentId, target: parsed.host, findings: allFindings.length },
    });

    return json({
      assessmentId,
      target: parsed.host,
      status: "completed",
      overall_status: status,
      summary,
      checks: allChecks,
      findings: allFindings,
    }, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    await serviceClient.from("assessments").update({
      status: "failed",
      error: msg,
      completed_at: new Date().toISOString(),
    }).eq("id", assessmentId);
    await serviceClient.from("admin_events").insert({
      kind: "assessment_failed",
      detail: { assessment_id: assessmentId, error: msg },
    });
    return json({ assessmentId, status: "failed", error: msg }, 200);
  }
});
