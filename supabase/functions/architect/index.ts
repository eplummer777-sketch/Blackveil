import type { SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { aiPlan, aiQuestions, type ModelResult } from "./ai.ts";
import { type Answers, BASE_QUESTIONS, buildTemplatePlan, FALLBACK_EXTRA_QUESTIONS, normalizeUrl } from "./templates.ts";
import { runSandbox, sha256 } from "./sandbox.ts";
import { canTransition, type LifecycleAction } from "./lifecycle.ts";
import type { ArtifactType, ChangeStatus, Question, RiskLevel, VerificationSpec } from "./types.ts";
import { verifyHeaders } from "./verify.ts";

const MONTHLY_PROJECT_LIMITS: Record<string, number> = { free: 2, malware_removal: 3, pro: 25, elite: 100 };
const ADMIN_LIMIT = 100;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

interface ChangeRow {
  id: string;
  project_id: string;
  user_id: string;
  artifact_type: ArtifactType;
  content: string;
  status: ChangeStatus;
  risk_level: RiskLevel;
  rollback_supported: boolean;
  verification_supported: boolean;
  verification_spec: VerificationSpec | null;
}

interface Ctx {
  svc: SupabaseClient;
  userId: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function logEvent(ctx: Ctx, actor: "user" | "ai" | "system", action: string, ids: { project_id?: string; change_id?: string }, detail: Record<string, unknown> = {}) {
  await ctx.svc.from("architect_events").insert({ user_id: ctx.userId, actor, action, detail, ...ids });
  await ctx.svc.from("audit_logs").insert({ user_id: ctx.userId, action: "architect_" + action, detail: { ...ids, ...detail } });
}

async function logUsage(ctx: Ctx, r: ModelResult) {
  await ctx.svc.from("ai_usage").insert({
    user_id: ctx.userId, feature: "architect", model: r.model, input_tokens: r.inputTokens, output_tokens: r.outputTokens, cost_usd: 0,
  });
}

async function loadOwnedProject(ctx: Ctx, id: unknown) {
  if (typeof id !== "string" || !UUID.test(id)) throw new HttpError(400, "Invalid project id.");
  const { data } = await ctx.svc.from("architect_projects").select("*").eq("id", id).maybeSingle();
  if (!data || data.user_id !== ctx.userId) throw new HttpError(404, "Project not found.");
  return data as { id: string; description: string; status: string; questions: Question[]; answers: Answers };
}

async function loadOwnedChange(ctx: Ctx, id: unknown): Promise<ChangeRow> {
  if (typeof id !== "string" || !UUID.test(id)) throw new HttpError(400, "Invalid change id.");
  const { data } = await ctx.svc.from("architect_changes").select("*").eq("id", id).maybeSingle();
  if (!data || data.user_id !== ctx.userId) throw new HttpError(404, "Change not found.");
  return data as ChangeRow;
}

async function createProject(ctx: Ctx, limit: number, body: Record<string, unknown>) {
  const description = typeof body.description === "string" ? body.description.trim() : "";
  if (description.length < 10) throw new HttpError(400, "Describe what you want to protect in at least a sentence.");
  if (description.length > 4000) throw new HttpError(400, "Please keep the description under 4,000 characters.");

  const since = new Date(Date.now() - 30 * 86400000).toISOString();
  const { count } = await ctx.svc.from("architect_projects").select("id", { count: "exact", head: true })
    .eq("user_id", ctx.userId).gte("created_at", since);
  if ((count ?? 0) >= limit) throw new HttpError(429, `You've reached your plan's limit of ${limit} Architect projects in 30 days.`);

  let title = description.split(/[.!?\n]/)[0].slice(0, 60) || "Security project";
  let extra: Question[] = FALLBACK_EXTRA_QUESTIONS;
  let source: "ai" | "template" = "template";
  try {
    const { normalized, result } = await aiQuestions(description);
    await logUsage(ctx, result);
    if (normalized && normalized.questions.length) {
      title = normalized.title;
      extra = normalized.questions;
      source = "ai";
    }
  } catch (e) {
    console.warn("architect questions fallback", (e as Error).message);
  }

  const { data, error } = await ctx.svc.from("architect_projects").insert({
    user_id: ctx.userId, title, description, questions: [...BASE_QUESTIONS, ...extra], status: "needs_answers",
  }).select("*").maybeSingle();
  if (error || !data) throw new HttpError(500, "Could not create the project.");
  await logEvent(ctx, "user", "project_created", { project_id: data.id }, { length: description.length });
  await logEvent(ctx, source === "ai" ? "ai" : "system", "questions_generated", { project_id: data.id }, { count: extra.length, source });
  return { project: data };
}

function cleanAnswers(questions: Question[], raw: unknown): Answers {
  const input = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  const out: Answers = {};
  for (const q of questions) {
    const v = input[q.id];
    if (q.type === "multi") {
      const arr = Array.isArray(v) ? v.filter((x) => typeof x === "string" && q.options.includes(x)) : [];
      if (arr.length) out[q.id] = arr as string[];
    } else if (q.type === "single") {
      if (typeof v === "string" && q.options.includes(v)) out[q.id] = v;
    } else if (typeof v === "string" && v.trim()) {
      out[q.id] = v.trim().slice(0, 500);
    }
  }
  return out;
}

async function submitAnswers(ctx: Ctx, body: Record<string, unknown>) {
  const project = await loadOwnedProject(ctx, body.project_id);
  if (project.status === "planned") throw new HttpError(409, "This project already has a plan.");
  const answers = cleanAnswers(project.questions, body.answers);
  if (!answers.systems) throw new HttpError(400, "Choose at least one thing you want to protect.");
  if (answers.website_url && !normalizeUrl(answers.website_url)) throw new HttpError(400, "The website address must be a valid https:// address.");

  let generated = null;
  let source: "ai" | "template" = "ai";
  try {
    const { normalized, result } = await aiPlan(project.description, project.questions, answers);
    await logUsage(ctx, result);
    generated = normalized;
  } catch (e) {
    console.warn("architect plan fallback", (e as Error).message);
  }
  if (!generated) {
    generated = buildTemplatePlan(project.description, answers);
    source = "template";
  }

  const rows = generated.changes.map((c, i) => ({
    project_id: project.id, user_id: ctx.userId, position: i, title: c.title, category: c.category,
    target_system: c.target_system, artifact_type: c.artifact_type, filename: c.filename, content: c.content,
    explanation: c.explanation, risks: c.risks, risk_level: c.risk_level, rollback_supported: c.rollback_supported,
    rollback_instructions: c.rollback_instructions, verification_supported: !!c.verification,
    verification_spec: c.verification, status: "proposed",
  }));
  const { error: insertError } = await ctx.svc.from("architect_changes").insert(rows);
  if (insertError) throw new HttpError(500, "Could not save the generated changes.");

  const { data } = await ctx.svc.from("architect_projects").update({
    answers, plan: generated.plan, plan_source: source, status: "planned",
  }).eq("id", project.id).select("*").maybeSingle();
  await logEvent(ctx, "user", "answers_submitted", { project_id: project.id }, { answered: Object.keys(answers).length });
  await logEvent(ctx, source === "ai" ? "ai" : "system", "plan_generated", { project_id: project.id }, { changes: rows.length, source });
  return { project: data };
}

async function testChange(ctx: Ctx, change: ChangeRow) {
  const check = canTransition({
    action: "test", status: change.status, actorKind: "human", isOwner: true, riskLevel: change.risk_level,
    note: null, acknowledgedRisks: false, confirmed: false, verificationSupported: change.verification_supported,
  });
  if (!check.ok) throw new HttpError(409, check.error);
  const result = runSandbox(change.artifact_type, change.content, change.rollback_supported);
  const hash = await sha256(change.content);
  const now = new Date().toISOString();
  await ctx.svc.from("architect_tests").insert({
    change_id: change.id, user_id: ctx.userId, sandbox: "static_analysis", passed: result.passed,
    checks: result.checks, summary: result.summary, content_hash: hash,
  });
  await ctx.svc.from("architect_changes").update({
    status: result.passed ? "tested" : "test_failed", last_test_passed: result.passed, last_tested_at: now,
  }).eq("id", change.id);
  await logEvent(ctx, "system", result.passed ? "sandbox_passed" : "sandbox_failed",
    { project_id: change.project_id, change_id: change.id }, { summary: result.summary, content_hash: hash.slice(0, 16) });
  return { passed: result.passed, summary: result.summary };
}

async function transition(ctx: Ctx, action: LifecycleAction, body: Record<string, unknown>) {
  const change = await loadOwnedChange(ctx, body.change_id);
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 1000) || null : null;
  const check = canTransition({
    action, status: change.status, actorKind: "human", isOwner: change.user_id === ctx.userId,
    riskLevel: change.risk_level, note, acknowledgedRisks: body.acknowledged_risks === true,
    confirmed: body.confirmed === true, verificationSupported: change.verification_supported,
  });
  if (!check.ok) throw new HttpError(409, check.error);
  const now = new Date().toISOString();
  const ids = { project_id: change.project_id, change_id: change.id };

  let patch: Record<string, unknown>;
  let message: string;
  switch (action) {
    case "approve":
      patch = { status: "approved", approved_by: ctx.userId, approved_at: now, approval_note: note };
      message = "Approved. Nothing has been applied yet. Apply it yourself, then mark it as applied.";
      break;
    case "reject":
      patch = { status: "rejected", rejected_at: now, approval_note: note };
      message = "Rejected. This change will not be used.";
      break;
    case "mark_deployed":
      patch = { status: "deployed", deployed_method: "manual_self_reported", deployed_at: now, deploy_note: note };
      message = change.verification_supported
        ? "Recorded as applied by you. Run verification to confirm it is live."
        : "Recorded as applied by you. Automatic verification is not available for this change type.";
      break;
    case "mark_rolled_back":
      patch = { status: "rolled_back", rolled_back_at: now, rollback_note: note };
      message = "Recorded as rolled back by you.";
      break;
    case "verify": {
      const spec = change.verification_spec;
      if (!spec || spec.type !== "http_headers") throw new HttpError(409, "No verification is configured for this change.");
      const result = await verifyHeaders(spec.url, spec.expect_headers);
      const passed = result.ok && result.missing.length === 0;
      patch = passed
        ? { status: "verified", verified_at: now, verification_result: result }
        : { status: "deployed", verified_at: null, verification_result: result };
      message = passed
        ? `Verified: all ${result.present.length} expected headers were found on ${result.checked_url}.`
        : result.ok
          ? `Not verified: ${result.missing.length} expected header(s) missing on ${result.checked_url}.`
          : `Not verified: ${result.error}`;
      await ctx.svc.from("architect_changes").update(patch).eq("id", change.id).eq("status", change.status);
      await logEvent(ctx, "system", passed ? "verification_passed" : "verification_failed", ids, { missing: result.missing, error: result.error ?? null });
      return { message, passed };
    }
    default:
      throw new HttpError(400, "Unknown action.");
  }
  const { data, error } = await ctx.svc.from("architect_changes").update(patch).eq("id", change.id).eq("status", change.status).select("id").maybeSingle();
  if (error || !data) throw new HttpError(409, "This change was updated elsewhere. Refresh and try again.");
  const eventName = ({ approve: "approved", reject: "rejected", mark_deployed: "marked_applied", mark_rolled_back: "marked_rolled_back" } as Record<string, string>)[action];
  await logEvent(ctx, "user", eventName, ids, { note: note ? note.slice(0, 200) : null, risk_level: change.risk_level });
  return { message };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return errorResponse("Method not allowed", 405);

  try {
    const { user, error: authError } = await getAuthenticatedUser(req);
    if (!user) return errorResponse(authError ?? "Unauthorized", 401);

    const svc = getServiceClient();
    const admin = (user.app_metadata as Record<string, unknown> | undefined)?.role === "admin";
    const { data: sub } = await svc.from("subscriptions").select("plan, status").eq("user_id", user.id).maybeSingle();
    const activePlan = sub && (sub.status === "active" || sub.status === "trialing") ? String(sub.plan) : "free";
    const limit = admin ? ADMIN_LIMIT : MONTHLY_PROJECT_LIMITS[activePlan] ?? MONTHLY_PROJECT_LIMITS.free;
    const ctx: Ctx = { svc, userId: user.id };

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid request body.", 400);
    }

    switch (body.action) {
      case "create_project":
        return json(await createProject(ctx, limit, body));
      case "submit_answers":
        return json(await submitAnswers(ctx, body));
      case "test_change":
        return json(await testChange(ctx, await loadOwnedChange(ctx, body.change_id)));
      case "test_all": {
        const project = await loadOwnedProject(ctx, body.project_id);
        const { data } = await svc.from("architect_changes").select("*").eq("project_id", project.id).in("status", ["proposed", "test_failed"]);
        const results = [];
        for (const c of (data as ChangeRow[]) ?? []) results.push(await testChange(ctx, c));
        return json({ tested: results.length, passed: results.filter((r) => r.passed).length });
      }
      case "approve":
      case "reject":
      case "mark_deployed":
      case "verify":
      case "mark_rolled_back":
        return json(await transition(ctx, body.action, body));
      default:
        return errorResponse("Unknown action.", 400);
    }
  } catch (e) {
    if (e instanceof HttpError) return errorResponse(e.message, e.status);
    console.error("architect error", e);
    return errorResponse("Something went wrong. Please try again.", 500);
  }
});
