export type ActionType =
  | "add_watchlist" | "notify_team" | "escalate_incident"
  | "block_source_ip" | "isolate_host" | "expose_publicly";

export type ActionStatus = "pending_approval" | "approved" | "rejected" | "executed_simulated" | "blocked_by_policy";

interface ActionRule {
  risk: "low" | "medium" | "high";
  affectsRealSystems: boolean;
}

export const ACTION_RULES: Record<ActionType, ActionRule> = {
  add_watchlist: { risk: "low", affectsRealSystems: false },
  notify_team: { risk: "low", affectsRealSystems: false },
  escalate_incident: { risk: "medium", affectsRealSystems: false },
  block_source_ip: { risk: "high", affectsRealSystems: true },
  isolate_host: { risk: "high", affectsRealSystems: true },
  expose_publicly: { risk: "high", affectsRealSystems: true },
};

export function isActionType(v: unknown): v is ActionType {
  return typeof v === "string" && v in ACTION_RULES;
}

const INTERNAL_IP = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i;

export interface ProposalInput {
  actionType: ActionType;
  target: string | null;
  proposedBy: "analyst_ai" | "user";
}

export interface ProposalResult {
  status: Extract<ActionStatus, "pending_approval" | "blocked_by_policy">;
  risk: ActionRule["risk"];
  affectsRealSystems: boolean;
  reason: string;
}

/** Every proposal lands in the approval queue unless a hard rule forbids it outright. Nothing auto-executes. */
export function evaluateProposal(input: ProposalInput): ProposalResult {
  const rule = ACTION_RULES[input.actionType];
  const base = { risk: rule.risk, affectsRealSystems: rule.affectsRealSystems };

  if (input.actionType === "expose_publicly") {
    return { ...base, status: "blocked_by_policy", reason: "Public exposure of decoys is disabled in this prototype." };
  }
  if ((input.actionType === "block_source_ip" || input.actionType === "isolate_host") && !input.target) {
    return { ...base, status: "blocked_by_policy", reason: "A specific target is required for this action." };
  }
  if (input.actionType === "block_source_ip" && input.target && INTERNAL_IP.test(input.target)) {
    return { ...base, status: "blocked_by_policy", reason: "Blocking internal or private addresses could lock out legitimate users." };
  }
  return {
    ...base,
    status: "pending_approval",
    reason: input.proposedBy === "analyst_ai"
      ? "Recommended by the AI analyst. A human must review and approve before anything happens."
      : "Awaiting human approval.",
  };
}

export interface DecisionInput {
  currentStatus: ActionStatus;
  decision: "approve" | "reject";
  deciderKind: "human" | "ai";
  deciderIsOwner: boolean;
  deciderIsAdmin: boolean;
  risk: ActionRule["risk"];
  note: string | null;
  environment: "simulated" | "isolated_test" | "cloud";
}

export type DecisionResult =
  | { ok: true; status: ActionStatus; executionNote: string }
  | { ok: false; error: string };

export function decideAction(input: DecisionInput): DecisionResult {
  if (input.deciderKind !== "human") return { ok: false, error: "Only a human can approve or reject actions." };
  if (!input.deciderIsOwner && !input.deciderIsAdmin) return { ok: false, error: "You do not have permission to decide this action." };
  if (input.currentStatus !== "pending_approval") return { ok: false, error: "This action has already been decided." };

  if (input.decision === "reject") {
    return { ok: true, status: "rejected", executionNote: "Rejected. No changes were made." };
  }
  if (input.risk === "high" && (!input.note || input.note.trim().length < 10)) {
    return { ok: false, error: "High-risk approvals need a written justification (at least 10 characters)." };
  }
  if (input.environment === "simulated") {
    return {
      ok: true,
      status: "executed_simulated",
      executionNote: "Approved and recorded as a simulated execution. No real system, firewall, or device was changed.",
    };
  }
  return {
    ok: true,
    status: "approved",
    executionNote: "Approved. No automated executor is connected yet, so an operator must carry this out manually.",
  };
}
