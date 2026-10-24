export const ARTIFACT_TYPES = [
  "nginx_conf", "apache_conf", "http_headers", "ufw_rules", "sshd_config",
  "fail2ban_jail", "json_policy", "bash_script", "powershell_script", "checklist",
] as const;
export type ArtifactType = typeof ARTIFACT_TYPES[number];

export type ChangeStatus =
  | "proposed" | "test_failed" | "tested" | "approved" | "deployed" | "verified" | "rejected" | "rolled_back";

export type RiskLevel = "low" | "medium" | "high";

export interface Question {
  id: string;
  question: string;
  why: string;
  type: "single" | "multi" | "text";
  options: string[];
}

export interface PlanStep {
  title: string;
  detail: string;
}

export interface Plan {
  title: string;
  summary: string;
  steps: PlanStep[];
  not_covered: string[];
  assumptions: string[];
}

export interface VerificationSpec {
  type: "http_headers";
  url: string;
  expect_headers: string[];
}

export interface GeneratedChange {
  title: string;
  category: string;
  target_system: string;
  artifact_type: ArtifactType;
  filename: string;
  content: string;
  explanation: string;
  risks: string[];
  risk_level: RiskLevel;
  rollback_supported: boolean;
  rollback_instructions: string;
  verification: VerificationSpec | null;
}

export interface GeneratedPlan {
  plan: Plan;
  changes: GeneratedChange[];
}

export interface SandboxCheck {
  id: string;
  label: string;
  level: "pass" | "warning" | "error";
  detail: string;
}

export interface SandboxResult {
  passed: boolean;
  checks: SandboxCheck[];
  summary: string;
}

export interface IntegrationProvider {
  readonly id: string;
  readonly label: string;
  canDeploy(artifact: ArtifactType): boolean;
  deploy(change: GeneratedChange, credentials: unknown): Promise<{ reference: string }>;
  rollback(reference: string, credentials: unknown): Promise<void>;
}
