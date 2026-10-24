import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";

// Link scanner — suspicious URL / phishing detection with SSRF protection

// ---------- Types ----------
interface RiskIndicator {
  id: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
}

interface ScanResult {
  verdict: "low_risk" | "suspicious" | "high_risk" | "unable_to_determine";
  risk_score: number;
  indicators: RiskIndicator[];
  recommendations: string[];
  target_url: string | null;
  target_host: string | null;
  details: Record<string, unknown>;
}

// ---------- SSRF protection ----------
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

// ---------- URL parsing & validation ----------
function extractUrl(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // If input looks like a URL (has a scheme or starts with a domain-like pattern)
  let candidate = trimmed;
  if (!/^https?:\/\//i.test(candidate)) {
    // Check if it looks like a domain (something.tld)
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(candidate)) {
      candidate = "https://" + candidate;
    } else {
      return null;
    }
  }

  try {
    const u = new URL(candidate);
    if (!u.hostname) return null;
    if (u.username || u.password) return null;
    const blocked = blockSsrf(u.hostname);
    if (blocked) return null;
    return u.toString();
  } catch {
    return null;
  }
}

function extractUrlsFromText(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"')\]]+|www\.[a-z0-9.-]+\.[a-z]{2,}[^\s<>"')\]]*/gi;
  const matches = text.match(urlRegex) ?? [];
  const urls: string[] = [];
  for (const m of matches) {
    let url = m;
    if (url.startsWith("www.")) url = "https://" + url;
    try {
      const u = new URL(url);
      if (u.hostname && !blockSsrf(u.hostname)) {
        urls.push(u.toString());
      }
    } catch { /* skip invalid */ }
  }
  return urls;
}

// ---------- Phishing heuristics ----------
const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "click", "link", "work", "country", "kim", "rest"];

const LEGIT_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];

const URL_SHORTENER_DOMAINS = new Set(LEGIT_SHORTENERS);

// Known safe/legitimate domains that should not trigger heuristics as easily
const WELL_KNOWN_DOMAINS = new Set([
  "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
  "facebook.com", "twitter.com", "linkedin.com", "youtube.com", "wikipedia.org",
  "reddit.com", "stackoverflow.com", "stackoverflow.com",
]);

function isWellKnownDomain(host: string): boolean {
  const bare = host.replace(/^www\./, "");
  for (const d of WELL_KNOWN_DOMAINS) {
    if (bare === d || bare.endsWith("." + d)) return true;
  }
  return false;
}

function analyzeUrlHeuristics(urlStr: string): RiskIndicator[] {
  const indicators: RiskIndicator[] = [];
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    return indicators;
  }

  const host = url.hostname.toLowerCase();
  const bareHost = host.replace(/^www\./, "");
  const tld = bareHost.split(".").pop() ?? "";
  const path = url.pathname + url.search;
  const fullUrl = urlStr;

  // 1. IP address instead of domain name
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    indicators.push({
      id: "ip_host",
      label: "Uses a raw IP address instead of a domain name",
      severity: "high",
      detail: `The URL points directly to ${host}. Legitimate websites almost always use a domain name. This is a common phishing tactic.`,
    });
  }

  // 2. Suspicious TLD
  if (SUSPICIOUS_TLDS.includes(tld)) {
    indicators.push({
      id: "suspicious_tld",
      label: `Uses a high-risk TLD (.${tld})`,
      severity: "medium",
      detail: `The .${tld} top-level domain is frequently abused for phishing and malware distribution. Exercise extra caution.`,
    });
  }

  // 3. Excessive subdomains (brand spoofing)
  const subdomainParts = bareHost.split(".");
  const subdomainCount = subdomainParts.length - 2;
  if (subdomainCount > 3) {
    indicators.push({
      id: "deep_subdomain",
      label: "Unusually deep subdomain structure",
      severity: "medium",
      detail: `The domain has ${subdomainCount} subdomain levels. Attackers use this to hide a fake domain inside a legitimate-looking hierarchy.`,
    });
  }

  // 4. Brand name in subdomain but different root domain
  const knownBrands = ["google", "apple", "microsoft", "amazon", "facebook", "paypal", "netflix", "instagram", "twitter", "linkedin", "bank", "chase", "wellsfargo", "citi", "amex"];
  for (const brand of knownBrands) {
    if (host.includes(brand) && !isWellKnownDomain(host)) {
      const rootDomain = subdomainParts.slice(-2).join(".");
      if (!rootDomain.startsWith(brand)) {
        indicators.push({
          id: "brand_spoofing",
          label: `Brand name "${brand}" used in a non-official domain`,
          severity: "high",
          detail: `The URL contains "${brand}" but the root domain is "${rootDomain}", not the official ${brand}.com. This is a classic phishing pattern.`,
        });
        break;
      }
    }
  }

  // 5. Hyphen abuse in domain
  const hyphenCount = (bareHost.match(/-/g) ?? []).length;
  if (hyphenCount >= 2) {
    indicators.push({
      id: "hyphen_abuse",
      label: "Domain contains multiple hyphens",
      severity: "low",
      detail: `The domain has ${hyphenCount} hyphens. Attackers use hyphens to mimic legitimate domains (e.g. "secure-paypal-login.com").`,
    });
  }

  // 6. URL shortener
  if (URL_SHORTENER_DOMAINS.has(bareHost)) {
    indicators.push({
      id: "url_shortener",
      label: "URL shortener detected",
      severity: "medium",
      detail: `This is a shortened URL from ${bareHost}. Shortened links hide the real destination and are frequently used in phishing. Expand the link before trusting it.`,
    });
  }

  // 7. Embedded credentials (user:pass@)
  if (url.username || url.password) {
    indicators.push({
      id: "embedded_credentials",
      label: "URL contains embedded credentials",
      severity: "critical",
      detail: "The URL includes a username and/or password before the @ sign. This is a strong phishing signal designed to obscure the real domain.",
    });
  }

  // 8. Non-standard port
  if (url.port && !["80", "443"].includes(url.port)) {
    indicators.push({
      id: "nonstandard_port",
      label: `Non-standard port :${url.port}`,
      severity: "low",
      detail: `The URL uses port ${url.port} instead of the standard 80 (HTTP) or 443 (HTTPS). This can indicate a non-standard or malicious service.`,
    });
  }

  // 9. HTTPS vs HTTP
  if (url.protocol === "http:") {
    indicators.push({
      id: "no_https",
      label: "Uses HTTP, not HTTPS",
      severity: "medium",
      detail: "The URL uses unencrypted HTTP. Modern legitimate websites use HTTPS. Data sent over HTTP can be intercepted.",
    });
  }

  // 10. Excessive URL length
  if (fullUrl.length > 200) {
    indicators.push({
      id: "excessive_length",
      label: "Unusually long URL",
      severity: "low",
      detail: `The URL is ${fullUrl.length} characters long. Excessively long URLs can hide redirects or encode malicious payloads.`,
    });
  }

  // 11. @ symbol in path (deceptive)
  if (fullUrl.includes("@") && !url.username && !url.password) {
    indicators.push({
      id: "at_symbol_deception",
      label: "@ symbol in URL",
      severity: "medium",
      detail: "The @ symbol in a URL can be used to deceive users about the actual destination domain.",
    });
  }

  // 12. Data URI
  if (fullUrl.startsWith("data:")) {
    indicators.push({
      id: "data_uri",
      label: "Data URI scheme",
      severity: "high",
      detail: "Data URIs can embed malicious content directly. Do not trust data: URLs from untrusted sources.",
    });
  }

  // 13. Redirect parameter
  const redirectParams = ["redirect", "redirect_to", "redirect_url", "return_url", "returnurl", "next", "url", "goto", "dest", "destination"];
  const searchParams = url.searchParams;
  for (const param of redirectParams) {
    const val = searchParams.get(param);
    if (val) {
      try {
        const redirectUrl = new URL(val, url.origin);
        if (redirectUrl.hostname !== host) {
          indicators.push({
            id: "open_redirect_param",
            label: `Redirect parameter "${param}" points to a different domain`,
            severity: "high",
            detail: `The parameter "${param}=${val}" redirects to ${redirectUrl.hostname}, which differs from ${host}. Open redirects are abused in phishing chains.`,
          });
          break;
        }
      } catch { /* not a URL, ignore */ }
    }
  }

  // 14. Punycode / IDN homograph
  if (host.includes("xn--")) {
    indicators.push({
      id: "punycode_domain",
      label: "Punycode (internationalized) domain",
      severity: "medium",
      detail: "This domain uses Punycode to display non-ASCII characters. Attackers use this for homograph attacks (e.g. аpple.com vs apple.com). Verify the domain visually.",
    });
  }

  // 15. Login/auth keywords in path on non-well-known domain
  const loginKeywords = ["login", "signin", "sign-in", "account", "verify", "secure", "update", "confirm", "password", "wallet", "recover"];
  const pathLower = url.pathname.toLowerCase();
  if (!isWellKnownDomain(host)) {
    const matched = loginKeywords.filter((k) => pathLower.includes(k));
    if (matched.length >= 2) {
      indicators.push({
        id: "login_form_keywords",
        label: "Multiple login/verify keywords in path",
        severity: "medium",
        detail: `The path contains: ${matched.join(", ")}. Phishing pages often stack these keywords to appear legitimate.`,
      });
    }
  }

  return indicators;
}

// ---------- Network checks ----------
async function fetchWithTimeout(url: string, opts: RequestInit = {}, ms = 6000): Promise<Response | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, redirect: "manual", signal: ctrl.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function checkRedirectChain(urlStr: string): Promise<{ indicators: RiskIndicator[]; finalUrl: string; chain: string[]; note?: string }> {
  const indicators: RiskIndicator[] = [];
  const chain: string[] = [urlStr];
  let current = urlStr;

  for (let i = 0; i < 5; i++) {
    const resp = await fetchWithTimeout(current, {
      headers: { "User-Agent": "Blackveil-LinkScanner/1.0 (+security-check)" },
    });
    if (!resp) break;

    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get("location");
      if (!loc) break;
      let next: URL;
      try {
        next = new URL(loc, current);
      } catch {
        break;
      }
      const blocked = blockSsrf(next.hostname);
      if (blocked) {
        indicators.push({
          id: "redirect_to_blocked",
          label: "Redirect targets a blocked internal address",
          severity: "critical",
          detail: blocked,
        });
        break;
      }
      chain.push(next.toString());
      current = next.toString();
      continue;
    }
    break;
  }

  // Check if the final domain differs from the original
  if (chain.length > 1) {
    try {
      const origHost = new URL(urlStr).hostname;
      const finalHost = new URL(current).hostname;
      if (origHost !== finalHost) {
        indicators.push({
          id: "cross_domain_redirect",
          label: `Redirects from ${origHost} to ${finalHost}`,
          severity: "medium",
          detail: `The URL redirects through ${chain.length} hop(s) to a different domain. Redirect chains are used to hide the true destination.`,
        });
      }
    } catch { /* ignore */ }

    if (chain.length > 3) {
      indicators.push({
        id: "long_redirect_chain",
        label: `Long redirect chain (${chain.length} hops)`,
        severity: "low",
        detail: "Multiple redirects can be used to obscure the final destination or evade security scanners.",
      });
    }
  }

  return { indicators, finalUrl: current, chain };
}

async function checkHttpsAndTls(urlStr: string): Promise<{ indicators: RiskIndicator[]; details: Record<string, unknown> }> {
  const indicators: RiskIndicator[] = [];
  const details: Record<string, unknown> = {};

  try {
    const u = new URL(urlStr);
    if (u.protocol === "https:") {
      const resp = await fetchWithTimeout(urlStr, {
        headers: { "User-Agent": "Blackveil-LinkScanner/1.0 (+security-check)" },
      });
      if (resp) {
        details["https_reachable"] = true;
        details["http_status"] = resp.status;
        const hsts = resp.headers.get("strict-transport-security");
        if (hsts) details["hsts"] = hsts;
      } else {
        details["https_reachable"] = false;
        indicators.push({
          id: "https_unreachable",
          label: "HTTPS endpoint did not respond",
          severity: "medium",
          detail: "The server did not respond to HTTPS requests within the timeout. The site may be down or misconfigured.",
        });
      }
    }
  } catch { /* ignore */ }

  return { indicators, details };
}

// ---------- Scoring ----------
function scoreFromIndicators(indicators: RiskIndicator[]): number {
  let score = 0;
  for (const ind of indicators) {
    switch (ind.severity) {
      case "critical": score += 35; break;
      case "high": score += 20; break;
      case "medium": score += 10; break;
      case "low": score += 4; break;
      case "info": score += 0; break;
    }
  }
  return Math.min(100, score);
}

function verdictFromScore(score: number, indicators: RiskIndicator[]): "low_risk" | "suspicious" | "high_risk" | "unable_to_determine" {
  const hasCritical = indicators.some((i) => i.severity === "critical");
  if (hasCritical || score >= 50) return "high_risk";
  if (score >= 15) return "suspicious";
  return "low_risk";
}

function recommendationsFor(verdict: string, indicators: RiskIndicator[]): string[] {
  const recs: string[] = [];
  const ids = new Set(indicators.map((i) => i.id));

  if (verdict === "high_risk") {
    recs.push("Do not visit this URL. Do not enter any personal information or credentials.");
    recs.push("If you received this link in a message or email, report it as phishing and delete it.");
    recs.push("If you already clicked it or entered information, change your password for the relevant service immediately and enable MFA.");
  } else if (verdict === "suspicious") {
    recs.push("Treat this URL with caution. Do not enter credentials or personal information.");
    recs.push("If you know the legitimate organization, navigate to their website directly by typing the known address instead of clicking this link.");
    recs.push("Check the URL carefully for misspellings or unusual characters before proceeding.");
  } else if (verdict === "low_risk") {
    recs.push("No significant risk indicators were detected. This does not guarantee the site is safe — always stay alert.");
    recs.push("Continue to verify the site is the one you intend to visit before entering sensitive information.");
  } else {
    recs.push("This URL could not be fully analyzed. Exercise caution and verify the destination manually.");
  }

  if (ids.has("url_shortener")) {
    recs.push("Expand the shortened URL using a link expander service before clicking, or ask the sender for the full destination.");
  }
  if (ids.has("brand_spoofing")) {
    recs.push("Verify the domain spelling character-by-character. Phishing domains often differ by one letter from the real one.");
  }
  if (ids.has("no_https")) {
    recs.push("Never enter credentials on a non-HTTPS page. The connection is unencrypted and can be intercepted.");
  }

  return recs;
}

// ---------- Main scan ----------
async function scanUrl(input: string, scanType: "url" | "message" | "qr"): Promise<ScanResult> {
  const targetUrl = extractUrl(input);
  if (!targetUrl) {
    return {
      verdict: "unable_to_determine",
      risk_score: 0,
      indicators: [{
        id: "invalid_url",
        label: "Could not parse a valid URL",
        severity: "info",
        detail: "The input did not contain a recognizable, public URL.",
      }],
      recommendations: ["Provide a full URL including the protocol (e.g. https://example.com) or a domain name."],
      target_url: null,
      target_host: null,
      details: { input },
    };
  }

  const url = new URL(targetUrl);
  const host = url.hostname;

  // 1. Static heuristics
  const staticIndicators = analyzeUrlHeuristics(targetUrl);

  // 2. Redirect chain analysis
  const { indicators: redirectIndicators, finalUrl, chain } = await checkRedirectChain(targetUrl);

  // 3. HTTPS/TLS check
  const { indicators: httpsIndicators, details: httpsDetails } = await checkHttpsAndTls(targetUrl);

  // 4. DNS resolution
  let dnsInfo: Record<string, unknown> = {};
  try {
    // @ts-ignore - Deno.resolveDns is available at runtime
    const aRecords = await Deno.resolveDns(host, "A");
    dnsInfo["a_records"] = aRecords;
  } catch {
    dnsInfo["a_records"] = [];
    dnsInfo["dns_error"] = "Could not resolve DNS A records.";
  }

  const allIndicators = [...staticIndicators, ...redirectIndicators, ...httpsIndicators];
  // Deduplicate by id (keep highest severity)
  const seen = new Map<string, RiskIndicator>();
  for (const ind of allIndicators) {
    const existing = seen.get(ind.id);
    if (!existing) {
      seen.set(ind.id, ind);
    } else {
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      if (severityOrder.indexOf(ind.severity) < severityOrder.indexOf(existing.severity)) {
        seen.set(ind.id, ind);
      }
    }
  }
  const deduped = Array.from(seen.values());

  const riskScore = scoreFromIndicators(deduped);
  const verdict = verdictFromScore(riskScore, deduped);
  const recommendations = recommendationsFor(verdict, deduped);

  return {
    verdict,
    risk_score: riskScore,
    indicators: deduped,
    recommendations,
    target_url: targetUrl,
    target_host: host,
    details: {
      ...httpsDetails,
      redirect_chain: chain,
      final_url: finalUrl,
      dns: dnsInfo,
    },
  };
}

async function scanMessage(text: string): Promise<ScanResult> {
  const urls = extractUrlsFromText(text);
  if (urls.length === 0) {
    // Heuristics on the message text itself
    const indicators: RiskIndicator[] = [];
    const lower = text.toLowerCase();

    const urgencyPatterns = ["urgent", "immediately", "act now", "expires", "final notice", "last warning", "within 24 hours", "account suspended", "verify now", "confirm your account"];
    const matchedUrgency = urgencyPatterns.filter((p) => lower.includes(p));
    if (matchedUrgency.length >= 2) {
      indicators.push({
        id: "urgency_pressure",
        label: "Creates false urgency",
        severity: "high",
        detail: `The message uses pressure phrases: ${matchedUrgency.join(", ")}. Scammers create urgency so you act before thinking.`,
      });
    }

    const requestPatterns = ["password", "otp", "code", "pin", "social security", "credit card", "bank account", "wire", "gift card", "bitcoin", "crypto"];
    const matchedRequests = requestPatterns.filter((p) => lower.includes(p));
    if (matchedRequests.length >= 1) {
      indicators.push({
        id: "credential_request",
        label: "Requests sensitive information",
        severity: "high",
        detail: `The message asks for: ${matchedRequests.join(", ")}. Legitimate organizations never ask for passwords, OTPs, or gift cards.`,
      });
    }

    if (/dear (valued |customer|user|sir|madam|client)/i.test(text)) {
      indicators.push({
        id: "generic_greeting",
        label: "Uses a generic greeting",
        severity: "low",
        detail: "Messages that say 'Dear Customer' instead of your name are often mass-sent phishing attempts.",
      });
    }

    if (/you have won|lottery|prize|inheritance|beneficiary|transfer of funds/i.test(text)) {
      indicators.push({
        id: "too_good_to_be_true",
        label: "Too-good-to-be-true offer",
        severity: "high",
        detail: "Messages about unexpected prizes, lottery wins, or inheritance are advance-fee scams. Do not respond or send money.",
      });
    }

    const riskScore = scoreFromIndicators(indicators);
    const verdict = verdictFromScore(riskScore, indicators);
    return {
      verdict,
      risk_score: riskScore,
      indicators,
      recommendations: recommendationsFor(verdict, indicators),
      target_url: null,
      target_host: null,
      details: { message_length: text.length, urls_found: 0 },
    };
  }

  // If URLs found, scan each and aggregate
  let maxScore = 0;
  let worstVerdict: ScanResult["verdict"] = "low_risk";
  let worstIndicators: RiskIndicator[] = [];
  let worstUrl: string | null = null;
  let worstHost: string | null = null;

  for (const u of urls.slice(0, 5)) {
    const result = await scanUrl(u, "message");
    if (result.risk_score > maxScore) {
      maxScore = result.risk_score;
      worstVerdict = result.verdict;
      worstIndicators = result.indicators;
      worstUrl = result.target_url;
      worstHost = result.target_host;
    }
  }

  // Add message-level indicators
  const lower = text.toLowerCase();
  const urgencyPatterns = ["urgent", "immediately", "act now", "expires", "final notice", "verify now"];
  const matchedUrgency = urgencyPatterns.filter((p) => lower.includes(p));
  if (matchedUrgency.length >= 2) {
    worstIndicators.push({
      id: "urgency_pressure",
      label: "Message creates false urgency",
      severity: "high",
      detail: `The message uses pressure phrases: ${matchedUrgency.join(", ")}. Combined with a suspicious link, this is a strong phishing signal.`,
    });
    maxScore = Math.min(100, maxScore + 15);
  }

  const verdict = verdictFromScore(maxScore, worstIndicators);
  return {
    verdict,
    risk_score: maxScore,
    indicators: worstIndicators,
    recommendations: recommendationsFor(verdict, worstIndicators),
    target_url: worstUrl,
    target_host: worstHost,
    details: { urls_found: urls.length, scanned_urls: urls.slice(0, 5) },
  };
}

// ---------- Handler ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  const { user, client, error } = await getAuthenticatedUser(req);
  if (!user) return errorResponse(error ?? "Unauthorized", 401);

  let body: { input?: string; scan_type?: "url" | "message" | "qr" };
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON", 400);
  }

  const input = (body.input ?? "").trim();
  const scanType = body.scan_type ?? "url";
  if (!input) return errorResponse("Input is required", 400);
  if (input.length > 10000) return errorResponse("Input too long (max 10000 chars)", 413);

  // Rate limit: max 20 scans per user per hour
  const serviceClient = getServiceClient();
  const since = new Date(Date.now() - 3_600_000).toISOString();
  const { count } = await serviceClient
    .from("link_scans")
    .select("*", { count: "exact", head: true })
    .eq("user_id", user.id)
    .gte("created_at", since);
  if ((count ?? 0) >= 20) {
    return errorResponse("Scan rate limit reached (20/hour). Try again later.", 429);
  }

  // Run the scan
  let result: ScanResult;
  try {
    result = scanType === "url" || scanType === "qr"
      ? await scanUrl(input, scanType)
      : await scanMessage(input);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return errorResponse("Scan failed: " + msg, 500);
  }

  // Persist the scan result
  const { error: insertErr } = await client.from("link_scans").insert({
    user_id: user.id,
    input,
    target_url: result.target_url,
    target_host: result.target_host,
    verdict: result.verdict,
    risk_score: result.risk_score,
    indicators: result.indicators,
    recommendations: result.recommendations,
    details: result.details,
    scan_type: scanType,
  });

  if (insertErr) {
    await serviceClient.from("admin_events").insert({
      kind: "link_scan_save_error",
      detail: { user_id: user.id, error: insertErr.message },
    });
  }

  // Create a notification for high-risk findings
  if (result.verdict === "high_risk") {
    await serviceClient.from("notifications").insert({
      user_id: user.id,
      kind: "security_alert",
      title: "High-risk link detected",
      body: `A link you scanned was flagged as high risk (score: ${result.risk_score}/100). Review the findings in your scan history.`,
      link: "tools",
    });
  }

  await serviceClient.from("audit_logs").insert({
    user_id: user.id,
    action: "link_scan_completed",
    detail: { verdict: result.verdict, score: result.risk_score, scan_type: scanType },
  });

  return json(result, 200);
});
