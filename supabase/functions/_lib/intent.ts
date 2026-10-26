import type { ProjectIndex } from "./projectIndex.ts";
import type { FileMap } from "./webbuilder.ts";

export type Workflow = "ask" | "explain" | "plan" | "code" | "debug" | "review";
export const WORKFLOWS: Workflow[] = ["ask", "explain", "plan", "code", "debug", "review"];
export const EDITING_WORKFLOWS: Workflow[] = ["plan", "code", "debug"];

export interface ReportedError { message: string; file?: string; line?: number }

export interface RequestAnalysis {
  workflow: Workflow;
  chosen_by: "owner" | "auto";
  /** The owner's message exactly as it arrived, before any analysis. Never shortened. */
  original: string;
  /** One-line restatement of the outcome the owner asked for (derived, not the request itself). */
  goal: string;
  outcome: string;
  /** Every requirement found in the request, in the owner's order. Not capped. */
  requirements: string[];
  /** Every constraint found in the request. Not capped. */
  constraints: string[];
  /** Optional items, kept separately so they are not confused with requirements. Not capped. */
  optional: string[];
  /** Requirements the plan did not claim to cover, filled in after planning. */
  unresolved: string[];
  files: { path: string; reason: string }[];
  errors: ReportedError[];
  security: string[];
  conflicts: string[];
  questions: string[];
  assumptions: string[];
  complexity: { level: "simple" | "moderate" | "complex"; reasons: string[] };
  acceptance: string[];
}

const ACTION = /\b(add|make|change|create|remove|delete|fix|update|build|show|use|replace|move|rename|include|support|display|implement|let|allow|put|set|turn|style|redesign|convert|split|merge|link|connect|hide|swap|translate|resize|increase|decrease|improve)\b/i;
const CONSTRAINT = /\b(don'?t|do not|never|must not|mustn'?t|without|keep|preserve|only|must|avoid|leave)\b/i;
const OPTIONAL = /\b(if possible|optionally|optional|nice to have|maybe|could also|bonus|if you can|ideally)\b/i;
const SITEWIDE = /\b(every page|all pages|site-?wide|entire|whole (site|website|project)|across the (site|project)|theme|responsive|mobile|navigation|nav bar|global)\b/i;
const ERROR_LINE = /\b(?:Uncaught\s+)?([A-Z]\w*(?:Error|Exception))\b[:\s]+([^\n]{0,240})/g;
const FILE_LINE = /([\w./-]+\.(?:html?|css|scss|m?js|jsx|tsx?|json|sql))(?::(\d+))?(?::\d+)?/g;
const BUG_WORDS = /\b(not working|doesn'?t work|isn'?t working|broken|bug|crash(es|ed)?|fails?|failing|blank page|error|exception|undefined is not|cannot read|won'?t (load|show|work|open))\b/i;

const SECURITY: [RegExp, string][] = [
  [/\b(password|passcode|api[ -]?key|secret|token|credential)s?\b/i, "Touches credentials: keep real keys out of browser code and project files."],
  [/\b(login|log in|sign[ -]?in|sign[ -]?up|auth\w*|session|permission|admin|role)s?\b/i, "Touches sign-in or permissions: changes need your explicit confirmation before applying."],
  [/\b(payment|checkout|credit card|billing|stripe)\b/i, "Touches payments: never handle card numbers directly; use a payment provider."],
  [/\b(innerHTML|eval|document\.write|dangerouslySetInnerHTML)\b/, "Mentions code that can run untrusted input: escape user content instead."],
  [/\b(delete all|drop table|truncate|wipe|erase everything)\b/i, "Destructive operation: needs explicit confirmation and a checkpoint."],
  [/\b(scan|exploit|bypass|brute[ -]?force|phishing|keylogger)\b/i, "Security tooling: only passive, authorized, non-destructive features are allowed."],
];

const TOPIC_KINDS: [RegExp, string[], string][] = [
  [/\b(colou?rs?|fonts?|typography|theme|spacing|css|styles?|design|layout|dark mode|light mode|background|premium|look)\b/i, ["style"], "styling request"],
  [/\b(nav|navigation|menu|header|footer|pages?|links?|sections?|hero|headings?|title)\b/i, ["page"], "page structure"],
  [/\b(button|click|interactive|script|animation|toggle|modal|slider|carousel|form submit|validation)\b/i, ["script", "component"], "behaviour"],
  [/\b(database|table|migration|sql|row level|rls)\b/i, ["database"], "database"],
  [/\b(api|server|endpoint|backend|function)\b/i, ["backend"], "server code"],
];

const STOP = new Set("the and for with that this from your have will into make about page file code site website".split(" "));

// Every clause the owner wrote is kept. Prompt builders decide what fits the model's context window
// and report anything they leave out; this layer never drops a requirement on its own.
function clauses(prompt: string): string[] {
  return prompt
    .split(/\n+|(?<=[.!?])\s+|;\s+|\s+(?:and then|then|and also|also)\s+/i)
    .map((s) => s.replace(/^\s*(?:[-*•]|\d+[.)])\s*/, "").trim())
    .filter((s) => s.length > 2);
}

export function extractErrors(prompt: string): ReportedError[] {
  const out: ReportedError[] = [];
  for (const m of prompt.matchAll(ERROR_LINE)) out.push({ message: `${m[1]}: ${m[2].trim()}`.slice(0, 260) });
  const locs = [...prompt.matchAll(FILE_LINE)].filter((m) => m[2]);
  locs.forEach((m, i) => {
    const target = out[i] ?? out[out.length - 1];
    if (target && !target.file) { target.file = m[1].replace(/^\.?\//, ""); target.line = Number(m[2]); }
    else if (!target) out.push({ message: `Problem reported at ${m[1]}:${m[2]}`, file: m[1].replace(/^\.?\//, ""), line: Number(m[2]) });
  });
  return out.slice(0, 8);
}

export function chooseWorkflow(prompt: string, errors: ReportedError[]): Workflow {
  const p = prompt.trim().toLowerCase();
  if (errors.length || (BUG_WORDS.test(p) && !/^(what|how|why)\b/.test(p))) return "debug";
  if (/^(please )?(review|audit)\b|\b(review|audit) (my|the|this)\b|\bwhat'?s wrong with\b/.test(p)) return "review";
  if (/^(please )?(explain|walk me through)\b|^(how|what|why) (does|do|is|are)\b/.test(p)) return "explain";
  if (/^(please )?(plan|outline)\b|\b(roadmap|step[- ]by[- ]step plan|how should i|what steps)\b/.test(p)) return "plan";
  if (/^(hi|hello|hey|thanks|thank you)\b|\breply (with|exactly)\b|\bsay (hi|hello)\b/.test(p)) return "ask";
  if (ACTION.test(p) && !/\?\s*$/.test(p)) return "code";
  if (/^(can|could|would) you\b/.test(p) && ACTION.test(p)) return "code";
  return "ask";
}

function words(s: string): string[] {
  return (s.toLowerCase().match(/[a-z][a-z0-9-]{2,}/g) ?? []).filter((w) => !STOP.has(w));
}

export function relevantFiles(prompt: string, index: ProjectIndex, files: FileMap, errors: ReportedError[], max = 12): { path: string; reason: string }[] {
  const found = new Map<string, string>();
  const add = (p: string, reason: string) => { if (index.entries[p] && !found.has(p) && found.size < max) found.set(p, reason); };
  const lower = prompt.toLowerCase();
  for (const e of errors) {
    if (!e.file) continue;
    const hit = Object.keys(index.entries).find((p) => p === e.file || p.endsWith("/" + e.file) || e.file!.endsWith(p));
    if (hit) add(hit, `named in the error${e.line ? ` (line ${e.line})` : ""}`);
  }
  for (const p of Object.keys(index.entries)) {
    const base = p.split("/").pop()!.toLowerCase();
    const stem = base.replace(/\.\w+$/, "");
    if (lower.includes(p.toLowerCase()) || lower.includes(base)) add(p, "named in the request");
    else if (stem.length > 3 && stem !== "index" && new RegExp(`\\b${stem.replace(/[^a-z0-9]/g, ".")}\\b`).test(lower)) add(p, `matches "${stem}"`);
  }
  const ids = [...new Set([
    ...(prompt.match(/\b(?:[a-z]+[A-Z]\w*|[A-Z][a-z]+[A-Z]\w*|[a-z]\w*_\w+)\b/g) ?? []),
    ...[...prompt.matchAll(/(?:^|\s)([.#][a-z][\w-]{2,})/g)].map((m) => m[1]),
  ])].slice(0, 10);
  for (const id of ids) {
    const needle = id.replace(/^[.#]/, "");
    for (const [p, c] of Object.entries(files)) if (needle.length > 2 && c.includes(needle)) add(p, `contains "${needle}"`);
  }
  for (const [re, kinds, reason] of TOPIC_KINDS) {
    if (!re.test(prompt)) continue;
    for (const e of Object.values(index.entries)) if (kinds.includes(e.kind)) add(e.path, reason);
  }
  const terms = words(prompt);
  if (terms.length && found.size < max) {
    for (const e of Object.values(index.entries)) {
      const s = e.summary.toLowerCase();
      if (s && terms.some((t) => s.includes(t))) add(e.path, "summary matches the request");
    }
  }
  return [...found].map(([path, reason]) => ({ path, reason }));
}

function findConflicts(reqs: string[], cons: string[]): string[] {
  const out: string[] = [];
  const all = reqs.join(" ").toLowerCase();
  if (/\bdark (mode|theme|background)\b/.test(all) && /\blight (mode|theme|background)\b/.test(all) && !/\btoggle|switch|both\b/.test(all)) {
    out.push("The request asks for both a dark and a light look. Should it be one of them, or a toggle between both?");
  }
  for (const c of cons) {
    const m = /(?:don'?t|do not|never|without)\s+(?:change|changing|touch|touching|modify|modifying|edit|editing|remove|removing)\s+(?:the\s+|my\s+)?([\w-]{3,})/i.exec(c);
    if (!m) continue;
    const noun = m[1].toLowerCase();
    const clash = reqs.find((r) => r.toLowerCase().includes(noun) && /\b(change|remove|delete|replace|redesign|rename|move)\b/i.test(r));
    if (clash) out.push(`"${clash}" conflicts with "${c}". Which one should win?`);
  }
  return out.slice(0, 3);
}

export function analyzeRequest(prompt: string, index: ProjectIndex, files: FileMap, mode?: unknown): RequestAnalysis {
  const errors = extractErrors(prompt);
  const owner = typeof mode === "string" && (WORKFLOWS as string[]).includes(mode);
  const workflow = owner ? mode as Workflow : chooseWorkflow(prompt, errors);
  const parts = clauses(prompt);
  const optional = parts.filter((c) => OPTIONAL.test(c));
  const constraints = parts.filter((c) => !optional.includes(c) && CONSTRAINT.test(c));
  const requirements = parts.filter((c) => !optional.includes(c) && !constraints.includes(c) && (ACTION.test(c) || workflow === "debug"));
  const found = relevantFiles(prompt, index, files, errors);
  const security = SECURITY.filter(([re]) => re.test(prompt)).map(([, note]) => note);
  const conflicts = findConflicts(requirements, constraints);
  const vague = /^(please\s+)?(fix|change|update|improve|do|redo)\s+(it|this|that)\W*$/i.test(prompt.trim());
  const questions = [...conflicts];
  if (vague && !errors.length) questions.push("What exactly should change, and on which page or part of the site?");

  const reasons: string[] = [];
  let score = 0;
  if (requirements.length > 1) { score += requirements.length; reasons.push(`${requirements.length} separate requirements`); }
  if (SITEWIDE.test(prompt)) { score += 3; reasons.push("affects the whole site"); }
  if (found.length > 4) { score += 2; reasons.push(`${found.length} likely files`); }
  if (/\b(database|backend|server|api|auth)\b/i.test(prompt)) { score += 2; reasons.push("involves server or data code"); }
  if (/\bnew (page|feature|section)\b/i.test(prompt)) { score += 1; reasons.push("adds something new"); }
  if (security.length) { score += 1; reasons.push("security-sensitive"); }
  const level = score >= 6 ? "complex" : score >= 3 ? "moderate" : "simple";
  if (!reasons.length) reasons.push("single focused request");

  const assumptions: string[] = [];
  if (EDITING_WORKFLOWS.includes(workflow) && !found.length) assumptions.push("No file was named, so Blackveil AI picks files from the project map.");
  if (optional.length) assumptions.push("Optional items are only done if they fit into this change.");
  if (!owner) assumptions.push(`Treated as a "${workflow}" request. Pick a different mode if that is wrong.`);

  // Acceptance criteria are a derived checklist, so they may be summarised, but they are drawn from
  // every requirement and constraint, not the first few.
  const acceptance = EDITING_WORKFLOWS.includes(workflow) ? [
    ...requirements.map((r) => `Done: ${r.replace(/[.!]+$/, "")}`),
    ...constraints.map((c) => `Still true: ${c.replace(/[.!]+$/, "")}`),
    ...(workflow === "debug" ? ["The reported problem no longer occurs when you test it"] : []),
    "No existing link, import or page breaks",
  ] : [];

  const goal = (requirements[0] ?? parts[0] ?? prompt).replace(/\s+/g, " ").trim();

  return {
    workflow, chosen_by: owner ? "owner" : "auto",
    original: prompt,
    goal: goal.slice(0, 240),
    outcome: goal.slice(0, 240),
    requirements, constraints, optional,
    unresolved: [],
    files: found, errors, security, conflicts, questions, assumptions,
    complexity: { level, reasons },
    acceptance,
  };
}

export interface Cause { cause: string; evidence: string; likelihood: "high" | "medium" | "low" }

const RANK = { high: 0, medium: 1, low: 2 };

export function parseCauses(o: Record<string, unknown> | null): Cause[] {
  const raw = Array.isArray(o?.causes) ? o!.causes : [];
  return raw
    .map((c) => (c ?? {}) as Record<string, unknown>)
    .filter((c) => typeof c.cause === "string" && c.cause.trim())
    .map((c) => ({
      cause: (c.cause as string).trim().slice(0, 300),
      evidence: typeof c.evidence === "string" && c.evidence.trim() ? c.evidence.trim().slice(0, 300) : "no evidence given",
      likelihood: (c.likelihood === "high" || c.likelihood === "low" ? c.likelihood : "medium") as Cause["likelihood"],
    }))
    .map((c, i) => ({ c, i }))
    .sort((a, b) => RANK[a.c.likelihood] - RANK[b.c.likelihood] || a.i - b.i)
    .map(({ c }) => c)
    .slice(0, 5);
}

// Exact source lines around each reported location; the model ranks causes from these, not from memory.
export function errorEvidence(errors: ReportedError[], files: FileMap, radius = 6): { text: string; missing: string[] } {
  const parts: string[] = [];
  const missing: string[] = [];
  for (const e of errors) {
    if (!e.file || !e.line) continue;
    const path = Object.keys(files).find((p) => p === e.file || p.endsWith("/" + e.file));
    if (!path) { missing.push(e.file); continue; }
    const lines = files[path].split("\n");
    if (e.line > lines.length) { missing.push(`${e.file}:${e.line} (file has ${lines.length} lines)`); continue; }
    const from = Math.max(1, e.line - radius);
    const to = Math.min(lines.length, e.line + radius);
    const body = lines.slice(from - 1, to).map((l, i) => `${from + i === e.line ? ">" : " "}${String(from + i).padStart(4)} | ${l.slice(0, 200)}`).join("\n");
    parts.push(`${path} lines ${from}-${to} (reported: ${e.message}):\n${body}`);
  }
  return { text: parts.join("\n\n").slice(0, 3000), missing };
}

export interface Brief { text: string; omitted: string[]; tokens: number }

// Rough token estimate for a small on-device model reading code. Deliberately cautious
// (it slightly over-estimates) so the budgets stay on the safe side.
export const EST_CHARS_PER_TOKEN = 3.5;
export const estTokens = (text: string): number => Math.ceil(text.length / EST_CHARS_PER_TOKEN);

export interface PackSection { name: string; text: string; priority: number; keep?: boolean }
export interface PackedSections { text: string; included: string[]; omitted: string[]; tokens: number; overBudget: boolean }

// Packs prompt sections into a token budget without quietly losing anything:
// - `keep` sections are always included (the caller checks `overBudget`);
// - everything else that does not fit is named in `omitted`, so the app can say so.
export function packSections(sections: PackSection[], budgetTokens: number): PackedSections {
  const budget = Math.max(1, Math.floor(budgetTokens * EST_CHARS_PER_TOKEN));
  const present = sections.filter((s) => s.text.trim() !== "");
  const ranked = present
    .map((s, i) => ({ s, i }))
    .sort((a, b) => (Number(!!b.s.keep) - Number(!!a.s.keep)) || a.s.priority - b.s.priority || a.i - b.i);

  const kept = new Set<string>();
  let used = 0;
  for (const { s } of ranked) {
    const cost = (used ? 2 : 0) + s.text.length;
    if (s.keep || used + cost <= budget) { kept.add(s.name); used += cost; }
  }

  const included = present.filter((s) => kept.has(s.name));
  const text = included.map((s) => s.text).join("\n\n");
  return {
    text,
    included: included.map((s) => s.name),
    omitted: present.filter((s) => !kept.has(s.name)).map((s) => s.name),
    tokens: estTokens(text),
    overBudget: estTokens(text) > budgetTokens,
  };
}

// Requirements are numbered so the planner can report coverage by id instead of by guesswork.
export function requirementLines(a: RequestAnalysis): string[] {
  return a.requirements.map((r, i) => `R${i + 1}: ${r.replace(/^R\d+:\s*/, "")}`);
}

export interface CoverageRow { requirement: string; covered_by: string }

const NOT_COVERED = /^(none|no|not|not covered|uncovered|n\/a|-|—|)$/i;

export function parseCoverage(raw: unknown): CoverageRow[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((r) => (r ?? {}) as Record<string, unknown>)
    .filter((r) => typeof r.requirement === "string")
    .map((r) => ({
      requirement: String(r.requirement).trim(),
      covered_by: typeof r.covered_by === "string" ? r.covered_by.trim() : "",
    }));
}

const coverageId = (value: string): string => {
  const m = /^r?\s*(\d+)\b/i.exec(value.trim());
  return m ? m[1] : "";
};

// Requirements the plan did not claim to cover, matched by the R-number ids the planner was given.
// A requirement with no coverage row is reported as unconfirmed, never assumed done.
export function unresolvedRequirements(a: RequestAnalysis, coverage: CoverageRow[]): string[] {
  const byId = new Map<string, string>();
  for (const c of coverage) {
    const id = coverageId(c.requirement);
    if (id) byId.set(id, c.covered_by);
  }
  return requirementLines(a).filter((line) => {
    const id = coverageId(line);
    const by = (byId.get(id) ?? "").replace(/\s+/g, " ").trim();
    return NOT_COVERED.test(by);
  });
}

// Renders the request breakdown for the model. Blocks that do not fit the given token budget are
// listed in `omitted` instead of being cut mid-sentence, and they are reported to the owner.
// Requirement lines are packed one at a time, so a long list keeps as many whole requirements as fit
// and every requirement left out is named by its id (R7, R8, ...) rather than vanishing.
export function analysisBrief(a: RequestAnalysis, budgetTokens = 1_200): Brief {
  const budget = Math.max(200, Math.floor(budgetTokens * EST_CHARS_PER_TOKEN));
  const blocks: string[] = [];
  const omitted: string[] = [];
  let used = 0;
  const add = (text: string): boolean => {
    const cost = (blocks.length ? 2 : 0) + text.length;
    if (used + cost > budget) return false;
    blocks.push(text);
    used += cost;
    return true;
  };

  add([
    "REQUEST BREAKDOWN (prepared by the app from the owner's message; use it, but the owner's words win):",
    `Workflow: ${a.workflow}. Complexity: ${a.complexity.level} (${a.complexity.reasons.join(", ")}).`,
    `Goal: ${a.goal}`,
  ].join("\n"));

  if (a.requirements.length) {
    const lines = requirementLines(a);
    const head = "Requirements (complete list, numbered; every one must be covered or reported as not covered):";
    const kept: string[] = [];
    let cost = head.length;
    for (const line of lines) {
      const next = cost + 1 + line.length;
      if (used + 2 + next > budget) break;
      kept.push(line);
      cost = next;
    }
    if (kept.length) add(head + "\n" + kept.join("\n"));
    for (const line of lines.slice(kept.length)) omitted.push(line.split(":")[0]);
  }

  const block = (id: string, text: string) => { if (!add(text)) omitted.push(id); };
  if (a.constraints.length) block("constraints", "Constraints (must stay true):\n" + a.constraints.map((c, i) => `C${i + 1}: ${c}`).join("\n"));
  if (a.optional.length) block("optional", "Optional:\n" + a.optional.map((c, i) => `O${i + 1}: ${c}`).join("\n"));
  if (a.files.length) block("relevant files", `Likely relevant files: ${a.files.map((f) => `${f.path} (${f.reason})`).join("; ")}`);
  if (a.errors.length) {
    block("reported errors", "Errors reported:\n" + a.errors.map((e) => `${e.message}${e.file ? ` at ${e.file}${e.line ? `:${e.line}` : ""}` : ""}`).join("\n"));
  }
  if (a.security.length) block("security notes", "Security notes:\n" + a.security.join("\n"));
  if (a.acceptance.length) block("acceptance criteria", "Acceptance criteria:\n" + a.acceptance.map((c, i) => `${i + 1}. ${c}`).join("\n"));

  const joined = blocks.join("\n\n");
  return { text: joined, omitted, tokens: estTokens(joined) };
}

// The visible breakdown in the chat. It is not sent to the model, so it may be longer,
// but it still says what it left out rather than cutting quietly.
export function analysisSummary(a: RequestAnalysis, maxChars = 12_000): Brief {
  const blocks: { id: string; text: string }[] = [];
  const push = (id: string, text: string) => { if (text.trim()) blocks.push({ id, text }); };

  push("complexity", a.complexity.level !== "simple" ? `Request breakdown (${a.complexity.level}: ${a.complexity.reasons.join(", ")})` : "");
  push("goal", `Goal: ${a.goal}`);
  if (a.requirements.length) push("requirements", "Requirements:\n" + requirementLines(a).join("\n"));
  if (a.constraints.length) push("constraints", "Constraints:\n" + a.constraints.map((c, i) => `C${i + 1}: ${c}`).join("\n"));
  if (a.optional.length) push("optional", "Optional:\n" + a.optional.map((c, i) => `O${i + 1}: ${c}`).join("\n"));
  if (a.acceptance.length) push("acceptance", "Acceptance criteria:\n" + a.acceptance.map((c, i) => `${i + 1}. ${c}`).join("\n"));
  if (a.assumptions.length) push("assumptions", "Assumptions:\n" + a.assumptions.join("\n"));
  if (a.security.length) push("security notes", "Security notes:\n" + a.security.join("\n"));

  const text: string[] = [];
  const omitted: string[] = [];
  let used = 0;
  for (const b of blocks) {
    const cost = (text.length ? 2 : 0) + b.text.length;
    if (used + cost <= maxChars) { text.push(b.text); used += cost; }
    else omitted.push(b.id);
  }
  const joined = text.join("\n\n");
  return { text: joined, omitted, tokens: estTokens(joined) };
}
