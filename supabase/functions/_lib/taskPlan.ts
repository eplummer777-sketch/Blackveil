import type { CoverageRow, RequestAnalysis } from "./intent.ts";

// Requirement and step tracking for the Web Builder. Everything here is pure and deterministic:
// a requirement is only ever marked completed from real evidence (files that were actually
// applied), never because the model said so.

export type RequirementStatus = "pending" | "in_progress" | "completed" | "unresolved" | "failed";

export interface RequirementState {
  /** "R1", "R2", ... — the same ids the planner is given. */
  id: string;
  /** The requirement in the owner's words. */
  text: string;
  status: RequirementStatus;
  /** 1-based plan steps that claim to satisfy this requirement. */
  steps: number[];
  /** Files those steps are planned to change. */
  files: string[];
  /** What would count as done, taken from the request analysis. */
  acceptance: string[];
  /** Why it is unresolved or failed. */
  note?: string;
}

export type StepStatus = "pending" | "running" | "done" | "failed";

export interface PlanStep {
  /** 1-based, matching the numbers shown to the owner. */
  index: number;
  text: string;
  files: string[];
  /** Earlier steps this one builds on (always earlier indexes). */
  dependsOn: number[];
  requirements: string[];
  acceptance: string[];
  status: "pending" | "running" | "done" | "failed";
  /** How many times this step was attempted after a failure. */
  attempts: number;
  /** Why it failed, when it did. */
  note?: string;
}

export interface VerificationReport {
  /** Checks that really ran, in plain words. */
  performed: string[];
  /** Checks that failed. */
  failed: string[];
  /** Checks the app cannot perform at all. */
  notPerformed: string[];
}

/** Requirement text without its R-number prefix. */
const requirementText = (line: string): string => line.replace(/^R\d+:\s*/, "").trim();

/**
 * Builds the tracked requirement list from the analysis and the planner's coverage rows.
 * - a requirement the planner did not claim is `unresolved`;
 * - a requirement that never fitted in the prompt is `unresolved`, because the model never saw it;
 * - everything else starts `pending`.
 */
export function requirementStates(ra: RequestAnalysis, coverage: CoverageRow[], omitted: string[] = []): RequirementState[] {
  const byId = new Map<string, number[]>();
  for (const row of coverage) {
    const id = `R${/^r?\s*(\d+)\b/i.exec(row.requirement.trim())?.[1] ?? ""}`;
    if (!/^R\d+$/.test(id)) continue;
    const covered = row.covered_by.replace(/\s+/g, " ").trim();
    if (/^(none|no|not|not covered|uncovered|n\/a|-|—|)$/i.test(covered)) continue;
    const step = Number(/^(\d+)/.exec(covered)?.[1] ?? "");
    if (!Number.isFinite(step) || step < 1) continue;
    byId.set(id, [...(byId.get(id) ?? []), step]);
  }
  const dropped = new Set(omitted);
  return ra.requirements.map((raw, i) => {
    const id = `R${i + 1}`;
    const steps = byId.get(id) ?? [];
    const unresolved = dropped.has(id) || !steps.length;
    return {
      id,
      text: requirementText(raw),
      status: unresolved ? "unresolved" as const : "pending" as const,
      steps,
      files: [],
      acceptance: [`Done: ${requirementText(raw).replace(/[.!]+$/, "")}`],
      note: dropped.has(id)
        ? "It did not fit in the model's prompt, so the model never saw it."
        : steps.length ? undefined : "The plan did not say which step covers it.",
    };
  });
}

/** Files a plan step is expected to touch, per requirement. */
export function planSteps(plan: string[], batches: string[][], states: RequirementState[]): PlanStep[] {
  return batches.map((files, i) => {
    const index = i + 1;
    const mine = states.filter((s) => s.steps.includes(index));
    return {
      index,
      text: (plan[i] ?? `Step ${index}`).trim() || `Step ${index}`,
      files: [...files],
      dependsOn: index > 1 ? [index - 1] : [],
      requirements: mine.map((s) => s.id),
      acceptance: [...new Set(mine.flatMap((s) => s.acceptance))],
      status: "pending" as const,
      attempts: 0,
    };
  });
}

/** Attaches planned files to the requirements they are meant to satisfy. */
export function withRequirementFiles(states: RequirementState[], steps: PlanStep[]): RequirementState[] {
  return states.map((s) => {
    const files = [...new Set(steps.filter((st) => s.steps.includes(st.index)).flatMap((st) => st.files))];
    return files.length ? { ...s, files } : s;
  });
}

export function startStep(steps: PlanStep[], index: number): PlanStep[] {
  return steps.map((s) => (s.index === index ? { ...s, status: "running" as const } : s));
}

/** Marks a step done and moves its requirements to `in_progress` (nothing is applied yet). */
export function completeStep(steps: PlanStep[], states: RequirementState[], index: number): { steps: PlanStep[]; states: RequirementState[] } {
  const nextSteps = steps.map((s) => (s.index === index ? { ...s, status: "done" as const, note: undefined } : s));
  const nextStates = states.map((s) => (
    s.steps.includes(index) && (s.status === "pending" || s.status === "failed")
      ? { ...s, status: "in_progress" as const, note: undefined }
      : s
  ));
  return { steps: nextSteps, states: nextStates };
}

/** Marks a step failed without advancing past it. Requirements stay unfinished with a reason. */
export function failStep(steps: PlanStep[], states: RequirementState[], index: number, reason: string): { steps: PlanStep[]; states: RequirementState[] } {
  const nextSteps = steps.map((s) => (s.index === index
    ? { ...s, status: "failed" as const, attempts: s.attempts + 1, note: reason.slice(0, 500) }
    : s));
  const nextStates = states.map((s) => (s.steps.includes(index)
    ? { ...s, status: "failed" as const, note: `Step ${index} failed: ${reason.slice(0, 300)}` }
    : s));
  return { steps: nextSteps, states: nextStates };
}

/**
 * Marks requirements completed after the owner applies a change. A requirement is completed only
 * when every step that claims it succeeded and at least one of its files was really written.
 */
export function appliedRequirementStates(states: RequirementState[], steps: PlanStep[], appliedFiles: string[]): RequirementState[] {
  const applied = new Set(appliedFiles);
  const done = new Set(steps.filter((s) => s.status === "done").map((s) => s.index));
  return states.map((s) => {
    if (s.status === "unresolved") return s;
    const allStepsDone = s.steps.length > 0 && s.steps.every((n) => done.has(n));
    const wrote = s.files.some((f) => applied.has(f));
    if (allStepsDone && wrote) {
      return {
        ...s,
        status: "completed" as const,
        note: "Applied. Static checks only: nothing was rendered, run or tested in a browser.",
      };
    }
    return {
      ...s,
      status: "failed" as const,
      note: allStepsDone
        ? "Its steps finished but no file from this requirement was applied."
        : "Not every step that covers it finished, so it was not applied.",
    };
  });
}

export interface Progress {
  totalSteps: number;
  doneSteps: number;
  failedSteps: number;
  pendingSteps: number;
  requirementsTotal: number;
  requirementsCompleted: number;
  requirementsInProgress: number;
  requirementsPending: number;
  requirementsUnresolved: number;
  requirementsFailed: number;
}

export function progressOf(steps: PlanStep[], states: RequirementState[]): Progress {
  const count = (s: StepStatus) => steps.filter((x) => x.status === s).length;
  const rq = (s: RequirementStatus) => states.filter((x) => x.status === s).length;
  return {
    totalSteps: steps.length,
    doneSteps: count("done"),
    failedSteps: count("failed"),
    pendingSteps: steps.filter((x) => x.status === "pending" || x.status === "running").length,
    requirementsTotal: states.length,
    requirementsCompleted: rq("completed"),
    requirementsInProgress: rq("in_progress"),
    requirementsPending: rq("pending"),
    requirementsUnresolved: rq("unresolved"),
    requirementsFailed: rq("failed"),
  };
}

/** One line the chat can show, with no claim beyond what is tracked. */
export function progressLine(steps: PlanStep[], states: RequirementState[]): string {
  const p = progressOf(steps, states);
  if (!p.totalSteps && !p.requirementsTotal) return "";
  const stepPart = `${p.doneSteps}/${p.totalSteps} step(s) written${p.failedSteps ? `, ${p.failedSteps} failed` : ""}${p.pendingSteps ? `, ${p.pendingSteps} still to write` : ""}.`;
  if (!p.requirementsTotal) return stepPart;
  const bits = [
    p.requirementsCompleted ? `${p.requirementsCompleted} completed` : "",
    p.requirementsInProgress ? `${p.requirementsInProgress} in progress` : "",
    p.requirementsPending ? `${p.requirementsPending} pending` : "",
    p.requirementsUnresolved ? `${p.requirementsUnresolved} unresolved` : "",
    p.requirementsFailed ? `${p.requirementsFailed} failed` : "",
  ].filter(Boolean);
  return `${stepPart} Requirements: ${bits.join(", ") || "none tracked"}.`;
}

/** Requirement lines for the review drawer and the plan message. */
export function requirementLines(states: RequirementState[]): string[] {
  return states.map((s) => `${s.id}: ${s.text} — ${s.status}${s.note ? ` (${s.note})` : ""}`);
}

/**
 * Static verification of the finished proposal. Only lists what was actually computed here;
 * anything the app cannot do (rendering, behaviour) is listed as not performed.
 */
export function verificationReport(steps: PlanStep[], states: RequirementState[], checks: { name: string; ok: boolean; detail: string; warn?: boolean }[], changedFiles: string[]): VerificationReport {
  const performed: string[] = [];
  const failed: string[] = [];
  const notPerformed: string[] = [];

  const failing = checks.filter((c) => !c.ok && !c.warn);
  performed.push(`${checks.length} static check(s) ran on the proposed files (links and imports resolve, JSON parses, no empty files, no secret formats, brackets and tags balance).`);
  if (failing.length) failed.push(...failing.map((c) => `${c.name}: ${c.detail}`));
  else performed.push("All static checks on the proposed files passed.");

  const noFiles = steps.filter((s) => s.files.length === 0);
  if (noFiles.length) notPerformed.push(`Step(s) ${noFiles.map((s) => s.index).join(", ")} were planned without a named file, so their output could not be tied to a file here.`);
  performed.push(`${changedFiles.length} file(s) were actually proposed for change.`);
  performed.push(`${steps.filter((s) => s.status === "done").length}/${steps.length} plan step(s) produced changes without an error.`);

  notPerformed.push("Nothing was rendered in a browser, so layout and styling were not seen.");
  notPerformed.push("No behaviour was exercised (clicks, forms, scripts), so the features were not tested.");
  notPerformed.push("Nothing was built, installed, typechecked or run: there is no execution environment.");
  if (states.some((s) => s.status === "unresolved")) notPerformed.push("Requirements listed as unresolved were never planned for, so they are not verified at all.");
  return { performed, failed, notPerformed };
}
