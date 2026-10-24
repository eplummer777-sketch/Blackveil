import { buildIndex, checkConsistency } from "../_lib/projectIndex.ts";
import { fileHashes, MEMORY_KINDS, projectProfile, staleFiles, type FixRow, type MemoryRow } from "../_lib/memory.ts";
import { syntaxCheck } from "../_lib/syntax.ts";
import type { ChangeFile } from "../_lib/changeset.ts";
import type { Analysis } from "./agent.ts";
import { HttpError, loadFiles, loadProject, must, str, uuid, type Body, type Svc } from "./store.ts";

const MEM_COLS = "id, kind, title, body, source, status, files, file_hashes, created_at, updated_at";
const FIX_COLS = "id, change_id, problem, root_cause, environment, evidence, fix_summary, files, checks, limitations, status, confidence, created_at, updated_at";

export async function loadLearning(svc: Svc, projectId: string): Promise<{ memories: MemoryRow[]; fixes: FixRow[] }> {
  const [memories, fixes] = await Promise.all([
    must(svc.from("wb_memories").select(MEM_COLS).eq("project_id", projectId).eq("status", "active").order("updated_at", { ascending: false }).limit(200)),
    must(svc.from("wb_fixes").select(FIX_COLS).eq("project_id", projectId).eq("status", "verified").order("updated_at", { ascending: false }).limit(100)),
  ]);
  return { memories: memories as MemoryRow[], fixes: fixes as FixRow[] };
}

function memoryFields(body: Body, files: Record<string, string>) {
  const kind = String(body.kind ?? "");
  if (!(MEMORY_KINDS as readonly string[]).includes(kind) || kind === "architecture") throw new HttpError(400, "Unknown memory type.");
  const title = str(body.title, 200).trim();
  if (!title) throw new HttpError(400, "A memory needs a title.");
  const paths = (Array.isArray(body.files) ? body.files : []).filter((p): p is string => typeof p === "string" && p in files).slice(0, 20);
  return { kind, title, body: str(body.body, 4000).trim(), files: paths, file_hashes: fileHashes(files, paths) };
}

async function memoryRow(svc: Svc, projectId: string, id: string): Promise<MemoryRow> {
  const m = await must(svc.from("wb_memories").select(MEM_COLS).eq("id", id).eq("project_id", projectId).maybeSingle()) as MemoryRow | null;
  if (!m) throw new HttpError(404, "Memory not found.");
  return m;
}

async function refreshProfile(svc: Svc, projectId: string, files: Record<string, string>) {
  const p = projectProfile(files, buildIndex(files));
  const existing = await must(svc.from("wb_memories").select("id").eq("project_id", projectId).eq("kind", "architecture").eq("source", "system").maybeSingle()) as { id: string } | null;
  const row = { title: p.title, body: p.body, files: p.files, file_hashes: fileHashes(files, p.files), status: "active", updated_at: new Date().toISOString() };
  if (existing) await must(svc.from("wb_memories").update(row).eq("id", existing.id).select("id"));
  else await must(svc.from("wb_memories").insert({ project_id: projectId, kind: "architecture", source: "system", ...row }).select("id"));
}

export async function listMemories(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const files = await loadFiles(svc, projectId);
  const rows = await must(svc.from("wb_memories").select(MEM_COLS).eq("project_id", projectId).neq("status", "archived").order("updated_at", { ascending: false }).limit(200)) as MemoryRow[];
  const profile = rows.find((m) => m.kind === "architecture" && m.source === "system");
  if (!profile || staleFiles(profile, files).length) {
    await refreshProfile(svc, projectId, files);
    return listMemories(svc, body);
  }
  const fixes = await must(svc.from("wb_fixes").select(FIX_COLS).eq("project_id", projectId).order("updated_at", { ascending: false }).limit(100));
  return { memories: rows.map((m) => ({ ...m, stale: staleFiles(m, files) })), fixes };
}

export async function saveMemory(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const files = await loadFiles(svc, projectId);
  const memory = await must(svc.from("wb_memories").insert({ project_id: projectId, source: "user", status: "active", ...memoryFields(body, files) }).select(MEM_COLS).single());
  return { memory };
}

export async function updateMemory(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const m = await memoryRow(svc, projectId, uuid(body.memory_id));
  if (m.kind === "architecture" && m.source === "system") throw new HttpError(409, "The project overview is generated from your files. It updates by itself when they change.");
  const files = await loadFiles(svc, projectId);
  const status = body.status === undefined ? m.status : String(body.status);
  if (!["active", "unverified", "archived"].includes(status)) throw new HttpError(400, "Unknown status.");
  const fields = memoryFields({ kind: body.kind ?? m.kind, title: body.title ?? m.title, body: body.body ?? m.body, files: body.files ?? m.files }, files);
  // An owner editing or confirming an AI note takes responsibility for it, so it becomes an owner memory.
  const memory = await must(svc.from("wb_memories").update({ ...fields, status, source: m.source === "ai" && status === "active" ? "user" : m.source, updated_at: new Date().toISOString() })
    .eq("id", m.id).eq("project_id", projectId).select(MEM_COLS).single());
  return { memory };
}

export async function deleteMemory(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const m = await memoryRow(svc, projectId, uuid(body.memory_id));
  if (m.kind === "architecture" && m.source === "system") throw new HttpError(409, "The project overview is generated from your files and cannot be deleted.");
  await must(svc.from("wb_memories").delete().eq("id", m.id).eq("project_id", projectId).select("id"));
  return { deleted: true };
}

export async function verifyFix(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const fix = await must(svc.from("wb_fixes").select(FIX_COLS).eq("id", uuid(body.fix_id)).eq("project_id", projectId).maybeSingle()) as (FixRow & { change_id: string | null }) | null;
  if (!fix) throw new HttpError(404, "Fix not found.");
  if (body.outcome === "failed") {
    const updated = await must(svc.from("wb_fixes").update({ status: "failed", updated_at: new Date().toISOString() }).eq("id", fix.id).select(FIX_COLS).single());
    return { fix: updated };
  }
  if (body.owner_tested !== true) throw new HttpError(400, "Confirm that you tested the fix in the preview and the problem is gone.");
  const rootCause = str(body.root_cause, 1000).trim() || fix.root_cause;
  if (!rootCause) throw new HttpError(400, "Add the root cause before marking this fix as verified.");
  if (!fix.change_id) throw new HttpError(409, "This fix is not linked to an applied change, so it cannot be verified.");
  const ch = await must(svc.from("wb_changes").select("status, files").eq("id", fix.change_id).eq("project_id", projectId).maybeSingle()) as { status: string; files: ChangeFile[] } | null;
  if (ch?.status !== "applied") throw new HttpError(409, "The linked change is not applied (it was undone or rejected), so the fix cannot be verified.");
  const project = await loadProject(svc, projectId);
  const files = await loadFiles(svc, projectId);
  const changed = ch.files.filter((f) => f.after !== null).map((f) => f.path);
  const checks = [...checkConsistency(files, project.kind), syntaxCheck(files, changed)];
  const failing = checks.filter((c) => !c.ok && !c.warn);
  if (failing.length) throw new HttpError(409, `Checks are failing, so the fix cannot be verified yet: ${failing.map((c) => `${c.name}: ${c.detail}`).join("; ").slice(0, 600)}`);
  const evidence = [`Owner tested in the preview and confirmed the problem is gone (${new Date().toISOString().slice(0, 10)}).`, `Static checks passed: ${checks.filter((c) => c.ok).length}/${checks.length}.`, fix.evidence].filter(Boolean).join(" ");
  const updated = await must(svc.from("wb_fixes").update({
    status: "verified", root_cause: rootCause, evidence: evidence.slice(0, 4000), checks, confidence: "high",
    environment: str(body.environment, 300).trim() || fix.environment || "Blackveil Web Builder preview", updated_at: new Date().toISOString(),
  }).eq("id", fix.id).select(FIX_COLS).single());
  return { fix: updated };
}

export async function rateMessage(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const rating = String(body.rating ?? "");
  if (!["helpful", "incorrect", "incomplete", "verified"].includes(rating)) throw new HttpError(400, "Unknown rating.");
  const msg = await must(svc.from("wb_messages").select("id, role").eq("id", uuid(body.message_id)).eq("project_id", projectId).maybeSingle()) as { id: string; role: string } | null;
  if (!msg || msg.role !== "assistant") throw new HttpError(404, "Message not found.");
  const change = await must(svc.from("wb_changes").select("id").eq("message_id", msg.id).eq("project_id", projectId).maybeSingle()) as { id: string } | null;
  await must(svc.from("wb_feedback").upsert({ project_id: projectId, message_id: msg.id, change_id: change?.id ?? null, rating, note: str(body.note, 1000) }, { onConflict: "message_id" }).select("id"));
  return { rated: rating };
}

interface CallRow { pipeline: string | null; parse_ok: boolean | null; duration_ms: number | null; output_tokens: number; tokens_estimated: boolean | null; purpose: string }

function summarize(rows: CallRow[]) {
  const parsed = rows.filter((r) => r.parse_ok !== null);
  const timed = rows.filter((r) => r.duration_ms !== null);
  return {
    calls: rows.length,
    readable_rate: parsed.length ? Math.round((parsed.filter((r) => r.parse_ok).length / parsed.length) * 100) : null,
    repairs: rows.filter((r) => r.purpose.endsWith("(repair)")).length,
    avg_seconds: timed.length ? Math.round(timed.reduce((n, r) => n + (r.duration_ms ?? 0), 0) / timed.length / 100) / 10 : null,
    avg_output_tokens: rows.length ? Math.round(rows.reduce((n, r) => n + r.output_tokens, 0) / rows.length) : null,
    estimated_token_share: rows.length ? Math.round((rows.filter((r) => r.tokens_estimated !== false).length / rows.length) * 100) : null,
  };
}

export async function aiMetrics(svc: Svc, body: Body) {
  const projectId = uuid(body.project_id);
  const [calls, changes, feedback, fixes] = await Promise.all([
    must(svc.from("wb_ai_calls").select("pipeline, parse_ok, duration_ms, output_tokens, tokens_estimated, purpose").eq("project_id", projectId).order("created_at", { ascending: false }).limit(1000)),
    must(svc.from("wb_changes").select("status, analysis").eq("project_id", projectId).order("created_at", { ascending: false }).limit(500)),
    must(svc.from("wb_feedback").select("rating").eq("project_id", projectId).limit(1000)),
    must(svc.from("wb_fixes").select("status").eq("project_id", projectId).limit(1000)),
  ]) as [CallRow[], { status: string; analysis: Partial<Analysis> | null }[], { rating: string }[], { status: string }[]];
  const count = <T,>(rows: T[], key: (r: T) => string) => rows.reduce<Record<string, number>>((o, r) => ({ ...o, [key(r)]: (o[key(r)] ?? 0) + 1 }), {});
  const split = (v2: boolean) => changes.filter((c) => !!c.analysis?.request_analysis === v2);
  return {
    baseline: { ai: summarize(calls.filter((c) => c.pipeline === null)), changes: count(split(false), (c) => c.status) },
    current: { ai: summarize(calls.filter((c) => c.pipeline === "v2")), changes: count(split(true), (c) => c.status) },
    feedback: count(feedback, (f) => f.rating),
    fixes: count(fixes, (f) => f.status),
    note: "Earlier requests did not record readability or timing, so those baseline figures show as not recorded. Figures cover the latest 1000 AI calls.",
  };
}

// Facts the app itself observed are saved as active; anything the AI claimed is saved as unverified for the owner to confirm.
export async function learnFromApplied(svc: Svc, projectId: string, changeId: string, a: Partial<Analysis>, changed: ChangeFile[], files: Record<string, string>) {
  const paths = changed.filter((f) => f.after !== null).map((f) => f.path).slice(0, 20);
  const hashes = fileHashes(files, paths);
  const rows: Record<string, unknown>[] = [{
    project_id: projectId, kind: "milestone", source: "system", status: "active",
    title: `Applied: ${(a.understanding || a.request || "AI change").slice(0, 180)}`,
    body: `Files: ${changed.map((f) => f.path).join(", ")}`.slice(0, 4000), files: paths, file_hashes: hashes,
  }];
  if (a.shared_notes?.trim()) {
    rows.push({ project_id: projectId, kind: "decision", source: "ai", status: "unverified", title: "Decisions the AI followed in this change", body: a.shared_notes.slice(0, 4000), files: paths, file_hashes: hashes });
  }
  await must(svc.from("wb_memories").insert(rows).select("id"));
  if (a.workflow === "debug") {
    const top = a.causes?.[0];
    await must(svc.from("wb_fixes").insert({
      project_id: projectId, change_id: changeId, problem: (a.request ?? "").slice(0, 2000) || "Reported problem",
      root_cause: top?.cause ?? "", evidence: top ? `AI's suspected cause, from ${top.evidence}` : "", fix_summary: (a.understanding || a.replies?.join(" ") || "").slice(0, 2000),
      files: paths, status: "hypothesis", confidence: top?.likelihood === "high" ? "medium" : "low",
      limitations: "Static review only: the fix was not run or tested by the app.",
    }).select("id"));
  }
}
