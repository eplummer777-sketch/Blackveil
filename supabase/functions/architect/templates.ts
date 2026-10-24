import type { GeneratedChange, GeneratedPlan, Question } from "./types.ts";

export type Answers = Record<string, string | string[]>;

export const SYSTEM_OPTIONS = [
  "Windows computer", "Mac", "Linux server", "Website or web app", "Home Wi-Fi / router",
  "Cloud account (AWS, Azure, Google Cloud)", "Phones or tablets", "Online accounts (email, banking, social)",
];

export const BASE_QUESTIONS: Question[] = [
  {
    id: "technical_level", type: "single", why: "So instructions match how comfortable you are with technical steps.",
    question: "How comfortable are you with technical setup?",
    options: ["I'm not technical", "I can follow step-by-step instructions", "I manage servers or write code"],
  },
  {
    id: "systems", type: "multi", why: "Each system needs different protections.",
    question: "What do you want to protect?", options: SYSTEM_OPTIONS,
  },
  {
    id: "goals", type: "multi", why: "Lets the plan focus on what matters most to you.",
    question: "What are your main security goals?",
    options: ["Stop account takeovers", "Protect my website", "Lock down remote access", "Prevent malware", "Protect sensitive data", "Meet a compliance requirement"],
  },
  {
    id: "web_server", type: "single", why: "Configuration files differ by web server.",
    question: "If you run a website, what serves it?",
    options: ["Nginx", "Apache", "Hosted platform (Shopify, Wix, Vercel, etc.)", "Not sure", "I don't have a website"],
  },
  {
    id: "website_url", type: "text", why: "Optional. Used only to check that header changes are live after you apply them.",
    question: "Your website address (optional)", options: [],
  },
];

export const FALLBACK_EXTRA_QUESTIONS: Question[] = [
  {
    id: "ai_remote_access", type: "single", why: "Remote access settings can lock you out if done wrong.",
    question: "How do you connect to your servers?",
    options: ["SSH with a key", "SSH with a password", "Remote desktop", "I don't connect remotely", "Not sure"],
  },
  {
    id: "ai_users", type: "single", why: "Shared systems need stricter account controls.",
    question: "How many people use these systems?",
    options: ["Just me", "Family or a small team (2-10)", "An organization (10+)"],
  },
];

const list = (v: string | string[] | undefined): string[] => (Array.isArray(v) ? v : v ? [v] : []);

export function normalizeUrl(input: unknown): string | null {
  if (typeof input !== "string" || !input.trim()) return null;
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  try {
    const u = new URL(s);
    if (u.protocol !== "https:" || u.username || u.password || !u.hostname.includes(".")) return null;
    return u.origin + "/";
  } catch {
    return null;
  }
}

const SECURITY_HEADERS: [string, string][] = [
  ["Strict-Transport-Security", "max-age=31536000; includeSubDomains"],
  ["X-Content-Type-Options", "nosniff"],
  ["X-Frame-Options", "SAMEORIGIN"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
];

function headerChange(server: string, url: string | null): GeneratedChange {
  const verification = url ? { type: "http_headers" as const, url, expect_headers: SECURITY_HEADERS.map(([h]) => h) } : null;
  const base = {
    category: "website", risks: [
      "Strict-Transport-Security tells browsers to only use HTTPS for a year. Only apply it if HTTPS already works on every page and subdomain.",
      "X-Frame-Options SAMEORIGIN stops other sites from embedding your pages, which can break legitimate embeds.",
    ],
    risk_level: "medium" as const, rollback_supported: true, verification,
  };
  if (server === "Nginx") {
    return {
      ...base, title: "Add browser security headers (Nginx)", target_system: "Nginx web server", artifact_type: "nginx_conf",
      filename: "security-headers.conf",
      content: [
        "# Include inside your server { } block: include /etc/nginx/snippets/security-headers.conf;",
        ...SECURITY_HEADERS.map(([h, v]) => `add_header ${h} "${v}" always;`),
        "server_tokens off;",
      ].join("\n"),
      explanation: "Adds headers that tell browsers to block common attacks such as clickjacking and content sniffing, and hides the Nginx version number.",
      rollback_instructions: "Remove the include line from your server block, run `sudo nginx -t` to check the config, then `sudo systemctl reload nginx`.",
    };
  }
  if (server === "Apache") {
    return {
      ...base, title: "Add browser security headers (Apache)", target_system: "Apache web server", artifact_type: "apache_conf",
      filename: "security-headers.conf",
      content: [
        "# Requires mod_headers: sudo a2enmod headers",
        "<IfModule mod_headers.c>",
        ...SECURITY_HEADERS.map(([h, v]) => `  Header always set ${h} "${v}"`),
        "</IfModule>",
        "ServerTokens Prod",
        "ServerSignature Off",
      ].join("\n"),
      explanation: "Adds headers that tell browsers to block common attacks and hides the Apache version number.",
      rollback_instructions: "Disable the file with `sudo a2disconf security-headers`, run `sudo apachectl configtest`, then `sudo systemctl reload apache2`.",
    };
  }
  return {
    ...base, title: "Add browser security headers", target_system: "Website hosting platform", artifact_type: "http_headers",
    filename: "security-headers.txt",
    content: SECURITY_HEADERS.map(([h, v]) => `${h}: ${v}`).join("\n"),
    explanation: "The list of response headers to add in your hosting platform's headers or security settings. They tell browsers to block common attacks.",
    rollback_instructions: "Remove these headers from your hosting platform's header settings and redeploy.",
  };
}

const SSHD_CHANGE: GeneratedChange = {
  title: "Harden SSH remote access", category: "remote_access", target_system: "Linux server (OpenSSH)", artifact_type: "sshd_config",
  filename: "99-blackveil-hardening.conf",
  content: [
    "# Place in /etc/ssh/sshd_config.d/ then test with: sudo sshd -t",
    "PermitRootLogin no",
    "PasswordAuthentication no",
    "PubkeyAuthentication yes",
    "PermitEmptyPasswords no",
    "KbdInteractiveAuthentication no",
    "MaxAuthTries 3",
    "LoginGraceTime 30",
    "X11Forwarding no",
    "ClientAliveInterval 300",
    "ClientAliveCountMax 2",
  ].join("\n"),
  explanation: "Blocks direct root login and password guessing by requiring SSH keys, and limits failed attempts.",
  risks: [
    "If your SSH key is not set up, disabling passwords will lock you out. Keep your current session open and test a new login before closing it.",
    "Automation that logs in as root will stop working.",
  ],
  risk_level: "high", rollback_supported: true,
  rollback_instructions: "Delete /etc/ssh/sshd_config.d/99-blackveil-hardening.conf, run `sudo sshd -t`, then `sudo systemctl reload ssh` (or sshd).",
  verification: null,
};

const UFW_CHANGE: GeneratedChange = {
  title: "Turn on a default-deny firewall", category: "network", target_system: "Linux server (UFW)", artifact_type: "ufw_rules",
  filename: "firewall-rules.sh",
  content: [
    "# Run these one at a time. SSH is allowed first so you are not locked out.",
    "sudo ufw default deny incoming",
    "sudo ufw default allow outgoing",
    "sudo ufw limit OpenSSH",
    "sudo ufw allow 80/tcp",
    "sudo ufw allow 443/tcp",
    "sudo ufw enable",
  ].join("\n"),
  explanation: "Blocks every incoming connection except SSH (rate-limited) and web traffic.",
  risks: [
    "Services on other ports (databases, admin panels, game servers) will become unreachable until you add a rule for them.",
    "If SSH runs on a non-standard port, change the OpenSSH rule first or you may lose access.",
  ],
  risk_level: "high", rollback_supported: true,
  rollback_instructions: "Run `sudo ufw status numbered` to review, then `sudo ufw delete <number>` for specific rules. To remove the policy entirely, run `sudo ufw reset` from a console session.",
  verification: null,
};

const FAIL2BAN_CHANGE: GeneratedChange = {
  title: "Ban repeated failed logins", category: "remote_access", target_system: "Linux server (fail2ban)", artifact_type: "fail2ban_jail",
  filename: "jail.local",
  content: ["[DEFAULT]", "bantime = 1h", "findtime = 10m", "maxretry = 5", "", "[sshd]", "enabled = true"].join("\n"),
  explanation: "Temporarily blocks addresses that fail to log in five times within ten minutes.",
  risks: ["You can ban yourself by mistyping a password repeatedly. Add your own address to ignoreip if it is fixed."],
  risk_level: "low", rollback_supported: true,
  rollback_instructions: "Delete /etc/fail2ban/jail.local and run `sudo systemctl restart fail2ban`. Unban an address with `sudo fail2ban-client set sshd unbanip <address>`.",
  verification: null,
};

const WINDOWS_SCRIPT: GeneratedChange = {
  title: "Check and enable Windows built-in protection", category: "endpoint", target_system: "Windows 10/11", artifact_type: "powershell_script",
  filename: "windows-protection.ps1",
  content: [
    "# Run in PowerShell as Administrator. Shows current status, then turns protections on.",
    "Get-NetFirewallProfile | Select-Object Name, Enabled",
    "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
    "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureLastUpdated",
    "Set-MpPreference -DisableRealtimeMonitoring $false",
    "Update-MpSignature",
  ].join("\n"),
  explanation: "Shows whether Windows Firewall and Microsoft Defender are on, then turns them on and updates virus definitions.",
  risks: ["If you use a different antivirus product, Defender may stay in passive mode. That is expected."],
  risk_level: "low", rollback_supported: true,
  rollback_instructions: "Firewall and Defender settings can be changed back in Windows Security. Turning protection off is not recommended.",
  verification: null,
};

function checklist(title: string, target: string, filename: string, steps: string[], explanation: string): GeneratedChange {
  return {
    title, category: "procedure", target_system: target, artifact_type: "checklist", filename,
    content: steps.map((s, i) => `${i + 1}. ${s}`).join("\n"), explanation,
    risks: ["Write down recovery codes before turning on two-step verification so you do not get locked out."],
    risk_level: "low", rollback_supported: false, rollback_instructions: "These are manual settings and can be changed back in each device or account's settings.",
    verification: null,
  };
}

const ACCOUNTS_CHECKLIST = checklist("Secure your online accounts", "Online accounts", "accounts-checklist.md", [
  "Install a password manager and let it generate a unique password for every account.",
  "Turn on two-step verification (an authenticator app, not SMS where possible) for email first, then banking and social media.",
  "Save the recovery codes for each account somewhere offline.",
  "Review signed-in devices in each account and sign out anything you don't recognize.",
  "Check haveibeenpwned.com for your email and change any passwords from breached sites.",
], "Your email account is the key to resetting every other password, so this protects everything else.");

const MAC_CHECKLIST = checklist("Turn on Mac built-in protection", "macOS", "mac-checklist.md", [
  "System Settings > Privacy & Security > FileVault: turn on and store the recovery key safely.",
  "System Settings > Network > Firewall: turn on.",
  "System Settings > General > Software Update: enable automatic updates.",
  "Only install apps from the App Store or identified developers.",
], "Encrypts your disk so a lost Mac does not expose your files, and blocks unwanted incoming connections.");

const ROUTER_CHECKLIST = checklist("Lock down your home Wi-Fi router", "Home router", "router-checklist.md", [
  "Log in to the router's admin page and change the default admin password.",
  "Update the router firmware.",
  "Use WPA3 (or WPA2-AES) with a long Wi-Fi password.",
  "Turn off WPS and remote administration.",
  "Put smart-home devices on a separate guest network.",
], "Most home router compromises use default passwords or old firmware.");

const PHONE_CHECKLIST = checklist("Secure your phones and tablets", "iOS / Android", "phone-checklist.md", [
  "Use a 6+ digit passcode and enable Face ID / fingerprint.",
  "Turn on automatic system and app updates.",
  "Enable Find My (iPhone) or Find My Device (Android) with remote wipe.",
  "Review app permissions for location, camera, and microphone.",
], "Protects your data if a device is lost and limits what apps can access.");

const CLOUD_MFA_POLICY: GeneratedChange = {
  title: "Require MFA for cloud console access (AWS)", category: "cloud", target_system: "AWS IAM", artifact_type: "json_policy",
  filename: "require-mfa-policy.json",
  content: JSON.stringify({
    Version: "2012-10-17",
    Statement: [{
      Sid: "DenyAllExceptMfaSetupWithoutMFA", Effect: "Deny",
      NotAction: ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:GetUser", "iam:ListMFADevices", "iam:ListVirtualMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"],
      Resource: "*",
      Condition: { BoolIfExists: { "aws:MultiFactorAuthPresent": "false" } },
    }],
  }, null, 2),
  explanation: "Blocks almost everything for users who signed in without multi-factor authentication, except setting up MFA itself.",
  risks: ["Attach to a test user first. Applied to everyone at once, users without MFA (and some automation using access keys) will be blocked."],
  risk_level: "high", rollback_supported: true,
  rollback_instructions: "In the IAM console, detach the policy from the users or groups it was attached to.",
  verification: null,
};

export function buildTemplatePlan(description: string, answers: Answers): GeneratedPlan {
  const systems = list(answers.systems);
  const server = typeof answers.web_server === "string" ? answers.web_server : "Not sure";
  const url = normalizeUrl(answers.website_url);
  const changes: GeneratedChange[] = [];

  if (systems.includes("Website or web app") || (server !== "I don't have a website" && server !== "Not sure")) changes.push(headerChange(server, url));
  if (systems.includes("Linux server")) changes.push(SSHD_CHANGE, UFW_CHANGE, FAIL2BAN_CHANGE);
  if (systems.includes("Windows computer")) changes.push(WINDOWS_SCRIPT);
  if (systems.includes("Cloud account (AWS, Azure, Google Cloud)")) changes.push(CLOUD_MFA_POLICY);
  if (systems.includes("Mac")) changes.push(MAC_CHECKLIST);
  if (systems.includes("Home Wi-Fi / router")) changes.push(ROUTER_CHECKLIST);
  if (systems.includes("Phones or tablets")) changes.push(PHONE_CHECKLIST);
  if (systems.includes("Online accounts (email, banking, social)") || changes.length === 0) changes.push(ACCOUNTS_CHECKLIST);

  const selected = changes.slice(0, 6);
  return {
    plan: {
      title: "Your security plan",
      summary: `A starting plan based on your answers for: "${description.slice(0, 140)}${description.length > 140 ? "..." : ""}". Apply the low-risk items first, then the higher-risk ones once you've read their risks.`,
      steps: selected.map((c) => ({ title: c.title, detail: c.explanation })),
      not_covered: [
        "This plan does not provide complete protection for any device or system.",
        "It does not include monitoring, backups or incident response.",
        ...(changes.length > selected.length ? ["Some systems were left out to keep the plan focused. Create another project for them."] : []),
      ],
      assumptions: ["Built from Blackveil's standard templates because the AI service was unavailable."],
    },
    changes: selected,
  };
}
