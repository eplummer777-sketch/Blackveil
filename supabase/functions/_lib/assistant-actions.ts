import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import type { Plan } from "./ai-quota.ts";

export type ActionKind =
  | "scan_device" | "remove_threats" | "verify_device" | "set_scan_schedule"
  | "scan_link" | "assess_website" | "apply_cloudflare_fix"
  | "pob_quick_scan" | "pentest_scan" | "network_scan" | "send_report_now" | "open_page";

export const PAGES: Record<string, string> = {
  dashboard: "Dashboard", reports: "Reports", assessments: "Assessments", "assessment-engine": "Assessment Engine",
  "proof-of-breach": "Proof-of-Breach AI", "network-scan": "Network Scan", pentest: "Penetration Test",
  sentinel: "Sentinel", architect: "Architect", device: "Device", malware: "Malware Removal",
  tools: "Security Tools", settings: "Account & alerts", limitations: "Limitations",
};

interface Target { id: string; hostname: string }

interface Device {
  id: string; name: string; os: string; allowed_scopes: string[]; allowed_paths: string[];
  last_seen_at: string | null; scan_schedule: string | null;
}
interface Threat { id: string; device_id: string; name: string; severity: string; status: string }
interface CfProposal {
  id: string; setting_label: string; proposed_value: unknown; risk_level: string; status: string; zone_name: string | null;
}

export interface ActionContext {
  paid: boolean; devices: Device[]; threats: Threat[]; cfProposals: CfProposal[]; targets: Target[]; recent: string[];
}

export interface ValidAction { kind: ActionKind; params: Record<string, unknown>; summary: string }

const ONLINE_MS = 2 * 60_000;
const SCHEDULES = ["off", "daily", "weekly"];
const ACTION_BLOCK = /```blackveil-action\s*([\s\S]*?)```/g;
export const MAX_ACTIONS_PER_REPLY = 3;

export async function loadActionContext(svc: SupabaseClient, userId: string, plan: Plan): Promise<ActionContext> {
  const paid = plan !== "free";
  const now = new Date().toISOString();
  const weekAgo = new Date(Date.now() - 7 * 86400_000).toISOString();
  const [devRes, thrRes, intRes, tgtRes, asRes, pobRes, penRes, netRes, hpRes] = await Promise.all([
    paid
      ? svc.from("endpoint_devices").select("id, name, os, allowed_scopes, allowed_paths, last_seen_at, scan_schedule")
        .eq("user_id", userId).is("revoked_at", null).order("created_at").limit(10)
      : Promise.resolve({ data: [] }),
    paid
      ? svc.from("endpoint_threats").select("id, device_id, name, severity, status")
        .eq("user_id", userId).in("status", ["detected", "awaiting_approval"]).limit(20)
      : Promise.resolve({ data: [] }),
    svc.from("architect_integrations").select("id, zone_name").eq("user_id", userId).eq("mode", "write"),
    svc.from("pob_targets").select("id, hostname, expires_at").eq("user_id", userId).eq("status", "verified").limit(10),
    svc.from("assessments").select("target, status, overall_status, created_at").eq("user_id", userId).order("created_at", { ascending: false }).limit(3),
    svc.from("pob_scans").select("hostname, status, score, counts, started_at").eq("user_id", userId).order("started_at", { ascending: false }).limit(2),
    svc.from("pentest_scans").select("hostname, mode, status, score, counts, started_at").eq("user_id", userId).order("started_at", { ascending: false }).limit(2),
    svc.from("nmap_scans").select("target_input, status, summary, created_at").eq("user_id", userId).order("created_at", { ascending: false }).limit(2),
    svc.from("honeypot_events").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("occurred_at", weekAgo),
  ]);

  const day = (s: string | null) => (s ? s.slice(0, 10) : "?");
  const brief = (v: unknown) => (v ? JSON.stringify(v).slice(0, 160) : "");
  const recent = [
    ...((asRes.data ?? []) as { target: string; status: string; overall_status: string | null; created_at: string }[])
      .map((a) => `- Website assessment ${a.target} on ${day(a.created_at)}: ${a.status}${a.overall_status ? `, ${a.overall_status}` : ""}`),
    ...((pobRes.data ?? []) as { hostname: string; status: string; score: number | null; counts: unknown; started_at: string }[])
      .map((s) => `- Proof-of-Breach test ${s.hostname} on ${day(s.started_at)}: ${s.status}, score ${s.score ?? "n/a"} ${brief(s.counts)}`),
    ...((penRes.data ?? []) as { hostname: string; mode: string; status: string; score: number | null; counts: unknown; started_at: string }[])
      .map((s) => `- Penetration test (${s.mode}) ${s.hostname} on ${day(s.started_at)}: ${s.status}, score ${s.score ?? "n/a"} ${brief(s.counts)}`),
    ...((netRes.data ?? []) as { target_input: string; status: string; summary: unknown; created_at: string }[])
      .map((s) => `- Network scan ${s.target_input} on ${day(s.created_at)}: ${s.status} ${brief(s.summary)}`),
    `- Sentinel honeypot events in the last 7 days: ${hpRes.count ?? 0}`,
  ];
  const targets = ((tgtRes.data ?? []) as (Target & { expires_at: string | null })[])
    .filter((t) => !t.expires_at || t.expires_at > now)
    .map(({ id, hostname }) => ({ id, hostname }));

  const integrations = (intRes.data ?? []) as { id: string; zone_name: string | null }[];
  let cfProposals: CfProposal[] = [];
  if (integrations.length) {
    const { data } = await svc.from("architect_cf_proposals")
      .select("id, integration_id, setting_label, proposed_value, risk_level, status")
      .eq("user_id", userId).in("integration_id", integrations.map((i) => i.id))
      .in("status", ["proposed", "approved"]).in("risk_level", ["low", "medium"]).limit(10);
    cfProposals = ((data ?? []) as (Omit<CfProposal, "zone_name"> & { integration_id: string })[]).map((p) => ({
      ...p, zone_name: integrations.find((i) => i.id === p.integration_id)?.zone_name ?? null,
    }));
  }

  return {
    paid,
    devices: (devRes.data ?? []) as Device[],
    threats: (thrRes.data ?? []) as Threat[],
    cfProposals,
    targets,
    recent,
  };
}

const online = (d: Device) => !!d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() < ONLINE_MS;

export function actionPrompt(ctx: ActionContext): string {
  const devices = ctx.devices.length
    ? ctx.devices.map((d) =>
      `- device_id=${d.id} name="${d.name}" os=${d.os} ${online(d) ? "ONLINE" : "OFFLINE"} allowed_scans=${d.allowed_scopes.join("/") || "none"} schedule=${d.scan_schedule ?? "off"}`
    ).join("\n")
    : ctx.paid ? "- none enrolled (user can enroll one on the Devices page)" : "- device protection requires a paid plan";
  const threats = ctx.threats.length
    ? ctx.threats.map((t) => `- threat_id=${t.id} device_id=${t.device_id} "${t.name}" severity=${t.severity}`).join("\n")
    : "- none open";
  const cf = ctx.cfProposals.length
    ? ctx.cfProposals.map((p) =>
      `- proposal_id=${p.id} "${p.setting_label}" -> ${JSON.stringify(p.proposed_value)} risk=${p.risk_level} zone=${p.zone_name ?? "?"}`
    ).join("\n")
    : "- none (user can connect Cloudflare with write access and run an analysis on the Architect page)";
  const targets = ctx.targets.length
    ? ctx.targets.map((t) => `- target_id=${t.id} hostname=${t.hostname}`).join("\n")
    : "- none (user must add and verify ownership of a domain on the Proof-of-Breach AI page first)";

  return [
    "",
    "ACTIONS YOU CAN PROPOSE:",
    "You can propose actions that the platform runs for the user ONLY after they press Confirm on a",
    "card shown under your reply. Never claim an action has already run. Never propose an action the",
    "user did not ask for or would not clearly benefit from. Use only IDs from USER ENVIRONMENT.",
    "To propose, put one fenced block per action at the very END of your reply (max 3), e.g.:",
    "```blackveil-action",
    '{"kind":"scan_device","device_id":"<id>","scan_type":"quick"}',
    "```",
    "Kinds and fields:",
    "- scan_device {device_id, scan_type: quick|full} (scan type must be in allowed_scans; device must be ONLINE)",
    "- remove_threats {device_id, threat_ids: [...]} (quarantines detected threats; reversible from the Devices page)",
    "- verify_device {device_id} (re-checks a device after cleanup)",
    "- set_scan_schedule {device_id, schedule: off|daily|weekly}",
    "- scan_link {url} (safety check of a suspicious link)",
    "- assess_website {domain} (only for a site the user says they own or are authorized to test)",
    "- apply_cloudflare_fix {proposal_id} (applies a reviewed Cloudflare protection to the live zone)",
    "- pob_quick_scan {target_id} (Proof-of-Breach quick test of a verified target; Elite plan)",
    "- pentest_scan {target_id, mode: baseline|active} (penetration test of a verified target; default baseline; Elite plan)",
    "- network_scan {target_id, profile: native_quick|native_standard} (open port discovery on a verified target; Elite plan)",
    "- send_report_now {} (emails the user their security monitoring report now)",
    `- open_page {page} (takes the user to a page; page is one of: ${Object.keys(PAGES).join(", ")})`,
    "Prefer an action over instructions whenever one fits the request. If the user asks for something",
    "no action covers, explain the exact steps and offer open_page for the right page.",
    "In your text, briefly say what each proposed action will do and ask the user to review and confirm it.",
    "If something is not possible (offline device, no plan, nothing connected), explain how to enable it instead.",
    "",
    "USER ENVIRONMENT:",
    "Devices:", devices,
    "Open threats:", threats,
    "Cloudflare protections ready to apply:", cf,
    "Verified targets (for pob_quick_scan, pentest_scan, network_scan):", targets,
    "Recent results (use these to answer questions about the user's security):", ...ctx.recent,
  ].join("\n");
}

export function extractActions(content: string): { clean: string; raw: unknown[] } {
  const raw: unknown[] = [];
  const clean = content.replace(ACTION_BLOCK, (_m, body: string) => {
    try { raw.push(JSON.parse(body.trim())); } catch { /* ignore malformed proposal */ }
    return "";
  }).replace(/```blackveil-action[\s\S]*$/, "").trim();
  return { clean, raw };
}

function parseHost(input: unknown): { url: string; host: string } | null {
  if (typeof input !== "string") return null;
  const v = input.trim();
  if (!v || v.length > 2048) return null;
  try {
    const u = new URL(/^https?:\/\//i.test(v) ? v : "https://" + v);
    if (!u.hostname.includes(".")) return null;
    return { url: u.toString(), host: u.hostname };
  } catch {
    return null;
  }
}

export function validateAction(raw: unknown, ctx: ActionContext): ValidAction | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const device = ctx.devices.find((d) => d.id === r.device_id);

  switch (r.kind) {
    case "scan_device": {
      const type = r.scan_type;
      if (!device || (type !== "quick" && type !== "full") || !device.allowed_scopes.includes(type)) return null;
      return { kind: "scan_device", params: { device_id: device.id, scan_type: type }, summary: `Run a ${type} scan on "${device.name}"` };
    }
    case "remove_threats": {
      if (!device || !Array.isArray(r.threat_ids)) return null;
      const picked = ctx.threats.filter((t) => t.device_id === device.id && (r.threat_ids as unknown[]).includes(t.id)).slice(0, 20);
      if (!picked.length) return null;
      return {
        kind: "remove_threats",
        params: { device_id: device.id, threat_ids: picked.map((t) => t.id) },
        summary: `Quarantine ${picked.length} threat${picked.length > 1 ? "s" : ""} on "${device.name}": ${picked.map((t) => t.name).join(", ")}`,
      };
    }
    case "verify_device":
      if (!device) return null;
      return { kind: "verify_device", params: { device_id: device.id }, summary: `Re-check "${device.name}" to confirm it is clean` };
    case "set_scan_schedule": {
      const s = r.schedule;
      if (!device || typeof s !== "string" || !SCHEDULES.includes(s)) return null;
      if (s !== "off" && !device.allowed_scopes.some((x) => x === "quick" || x === "full")) return null;
      return {
        kind: "set_scan_schedule",
        params: { device_id: device.id, schedule: s },
        summary: s === "off" ? `Turn off automatic scans on "${device.name}"` : `Scan "${device.name}" automatically ${s}`,
      };
    }
    case "scan_link": {
      const p = parseHost(r.url);
      if (!p) return null;
      return { kind: "scan_link", params: { url: p.url }, summary: `Check whether ${p.host} is safe to open` };
    }
    case "assess_website": {
      const p = parseHost(r.domain);
      if (!p) return null;
      return {
        kind: "assess_website",
        params: { domain: p.host },
        summary: `Run a security assessment of ${p.host} (you confirm you own it or are authorized to test it)`,
      };
    }
    case "apply_cloudflare_fix": {
      const prop = ctx.cfProposals.find((p) => p.id === r.proposal_id);
      if (!prop) return null;
      return {
        kind: "apply_cloudflare_fix",
        params: { proposal_id: prop.id },
        summary: `Apply Cloudflare protection "${prop.setting_label}" (set to ${JSON.stringify(prop.proposed_value)}) on ${prop.zone_name ?? "your zone"}`,
      };
    }
    case "pob_quick_scan":
    case "pentest_scan":
    case "network_scan": {
      const t = ctx.targets.find((x) => x.id === r.target_id);
      if (!t) return null;
      if (r.kind === "pob_quick_scan") {
        return { kind: "pob_quick_scan", params: { target_id: t.id }, summary: `Run a Proof-of-Breach quick test on ${t.hostname}` };
      }
      if (r.kind === "pentest_scan") {
        const mode = r.mode === "active" ? "active" : "baseline";
        return {
          kind: "pentest_scan",
          params: { target_id: t.id, mode },
          summary: `Run a ${mode} penetration test on ${t.hostname} (you confirm you are authorized to test it)`,
        };
      }
      const profile = r.profile === "native_standard" ? "native_standard" : "native_quick";
      return {
        kind: "network_scan",
        params: { target_id: t.id, profile },
        summary: `Run a ${profile === "native_quick" ? "quick" : "standard"} network discovery scan on ${t.hostname} (you confirm you are authorized to scan it)`,
      };
    }
    case "send_report_now":
      return { kind: "send_report_now", params: {}, summary: "Email your security monitoring report now" };
    case "open_page": {
      if (typeof r.page !== "string" || !PAGES[r.page]) return null;
      return { kind: "open_page", params: { page: r.page }, summary: `Open the ${PAGES[r.page]} page` };
    }
    default:
      return null;
  }
}
