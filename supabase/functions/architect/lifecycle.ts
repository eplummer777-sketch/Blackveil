import type { ChangeStatus, RiskLevel } from "./types.ts";

export type LifecycleAction = "test" | "approve" | "reject" | "mark_deployed" | "verify" | "mark_rolled_back";

export interface TransitionInput {
  action: LifecycleAction;
  status: ChangeStatus;
  actorKind: "human" | "ai";
  isOwner: boolean;
  riskLevel: RiskLevel;
  note: string | null;
  acknowledgedRisks: boolean;
  confirmed: boolean;
  verificationSupported: boolean;
}

export type TransitionResult = { ok: true } | { ok: false; error: string };

const FROM: Record<LifecycleAction, ChangeStatus[]> = {
  test: ["proposed", "test_failed", "tested"],
  approve: ["tested"],
  reject: ["proposed", "test_failed", "tested", "approved"],
  mark_deployed: ["approved"],
  verify: ["deployed", "verified"],
  mark_rolled_back: ["deployed", "verified"],
};

const STATUS_HINT: Partial<Record<LifecycleAction, string>> = {
  approve: "Only changes that passed the sandbox test can be approved.",
  mark_deployed: "A change must be approved before it can be marked as applied.",
  verify: "Only applied changes can be verified.",
  mark_rolled_back: "Only applied changes can be rolled back.",
};

export function canTransition(input: TransitionInput): TransitionResult {
  if (input.actorKind !== "human") return { ok: false, error: "Only a person can change the status of a proposed change." };
  if (!input.isOwner) return { ok: false, error: "Only the owner of this project can do that." };
  if (!FROM[input.action].includes(input.status)) {
    return { ok: false, error: STATUS_HINT[input.action] ?? `This action is not available while the change is ${input.status.replace("_", " ")}.` };
  }
  if (input.action === "approve") {
    if (!input.acknowledgedRisks) return { ok: false, error: "Please confirm you have read the risks before approving." };
    if (input.riskLevel === "high" && (!input.note || input.note.trim().length < 10)) {
      return { ok: false, error: "High-risk changes need a written reason (at least 10 characters)." };
    }
  }
  if (input.action === "mark_deployed" && !input.confirmed) {
    return { ok: false, error: "Confirm that you applied this change yourself." };
  }
  if (input.action === "mark_rolled_back" && !input.confirmed) {
    return { ok: false, error: "Confirm that you reverted this change yourself." };
  }
  if (input.action === "verify" && !input.verificationSupported) {
    return { ok: false, error: "Automatic verification is not available for this type of change yet." };
  }
  return { ok: true };
}
