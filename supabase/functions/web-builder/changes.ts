import { validatePath, verifyAppliedFiles, type FileMap } from "../_lib/webbuilder.ts";
import { buildIndex, checkConsistency } from "../_lib/projectIndex.ts";
import type { ChangeFile } from "../_lib/changeset.ts";
import type { Analysis } from "./agent.ts";
import { appliedRequirementStates } from "../_lib/taskPlan.ts";
import { learnFromApplied } from "./learning.ts";
import { syntaxCheck } from "../_lib/syntax.ts";
import { ensureSize, HttpError, loadFiles, loadProject, must, path, replaceAllFiles, snapshot, str, uuid, writeFiles, type Body, type Svc } from "./store.ts";

interface ChangeRow { id: string; project_id: string; status: string; files: ChangeFile[]; analysis: Partial<Analysis>; snapshot_id: string | null }

async function loadChange(svc: Svc, id: string): Promise<ChangeRow> {
  const ch = await must(svc.from("wb_changes").select("*").eq("id", id).maybeSingle()) as ChangeRow | null;
  if (!ch) throw new HttpError(404, "Change not found.");
  return ch;
}

export async function applyChange(svc: Svc, body: Body) {
  const id = uuid(body.change_id);
  const ch = await loadChange(svc, id);
  if (ch.status !== "pending") throw new HttpError(409, `Change is already ${ch.status}.`);
  const a = ch.analysis ?? {};
  if (a.batches && !a.complete) throw new HttpError(409, "The AI has not finished writing this proposal yet. Continue it first.");
  if (!ch.files.length) throw new HttpError(409, "This proposal has no file changes.");
  if (a.risks?.length && body.confirm_risks !== true) {
    throw new HttpError(428, "This change includes items that need your explicit confirmation: " + a.risks.join(" "));
  }
  const project = await loadProject(svc, ch.project_id);
  const current = await loadFiles(svc, ch.project_id);
  const conflicts = ch.files.filter((f) => (current[f.path] ?? null) !== f.before).map((f) => f.path);
  if (conflicts.length && body.force !== true) {
    throw new HttpError(409, `These files changed since the proposal was made: ${conflicts.join(", ")}. Re-run the request or apply anyway.`);
  }
  const next: FileMap = { ...current };
  const removed: string[] = [];
  const upserts: FileMap = {};
  for (const f of ch.files) {
    validatePath(f.path);
    if (f.after === null) { delete next[f.path]; removed.push(f.path); } else { next[f.path] = f.after; upserts[f.path] = f.after; }
  }
  ensureSize(next);
  const snapId = await snapshot(svc, ch.project_id, "Before AI change");
  await writeFiles(svc, ch.project_id, upserts, removed);
  await must(svc.from("wb_changes").update({ status: "applied", snapshot_id: snapId, decided_at: new Date().toISOString() }).eq("id", id));

  const stored = await loadFiles(svc, ch.project_id);
  const changed = ch.files.filter((f) => f.after !== null).map((f) => f.path);
  const before = new Set([...checkConsistency(current, project.kind), syntaxCheck(current, changed)].filter((c) => !c.ok).map((c) => c.name));
  const checks = [...verifyAppliedFiles(stored, ch.files), ...checkConsistency(stored, project.kind), syntaxCheck(stored, changed)]
    .map((c) => (!c.ok && before.has(c.name) ? { ...c, detail: `${c.detail} (already failing before this change)` } : c));
  const failing = checks.filter((c) => !c.ok && !c.warn);
  const summary = ch.files.map((f) => `${f.renamed_from ? `renamed ${f.renamed_from} ->` : f.action} ${f.path}`).join(", ");
  // Requirements are recorded as completed only now, from files that were really written. The model
  // claiming a requirement is done never sets this.
  let requirementNote = "";
  if (a.requirements_state?.length && a.plan_steps?.length) {
    const state = appliedRequirementStates(a.requirements_state, a.plan_steps, ch.files.filter((f) => f.after !== null).map((f) => f.path));
    const completed = state.filter((s) => s.status === "completed").length;
    const failed = state.filter((s) => s.status === "failed").length;
    requirementNote = ` Requirements: ${completed} completed, ${failed} not completed${state.some((s) => s.status === "unresolved") ? `, ${state.filter((s) => s.status === "unresolved").length} unresolved` : ""}. Completed means its files were applied; nothing was rendered or tested in a browser.`;
    await must(svc.from("wb_changes").update({ analysis: { ...a, requirements_state: state } }).eq("id", id));
  }
  await must(svc.from("wb_messages").insert({
    project_id: ch.project_id, role: "system",
    content: `Applied ${ch.files.length} file change(s): ${summary}. Checkpoint saved. Re-read checks: ${checks.length - failing.length}/${checks.length} passed${failing.length ? " (" + failing.map((c) => `${c.name}: ${c.detail}`).join("; ") + ")" : ""}.${requirementNote} Nothing was built or executed.`,
  }));
  try {
    await learnFromApplied(svc, ch.project_id, id, a, ch.files, stored);
  } catch (e) {
    // The files are already applied; a failed memory note must not report the apply as failed.
    console.error("web-builder: could not record project memory", e);
  }
  return {
    applied: true, snapshot_id: snapId, files: stored,
    verification: { checks, note: "Static checks only: files were re-read and cross-checked for broken links, imports, invalid JSON, unbalanced brackets or tags, and leaked secrets. Nothing was built, run or tested." },
  };
}

export async function revertChange(svc: Svc, body: Body) {
  const ch = await loadChange(svc, uuid(body.change_id));
  if (ch.status !== "applied") throw new HttpError(409, "Only applied changes can be undone.");
  const current = await loadFiles(svc, ch.project_id);
  const drifted = ch.files.filter((f) => (current[f.path] ?? null) !== f.after).map((f) => f.path);
  if (drifted.length && body.force !== true) {
    throw new HttpError(409, `These files were edited after the change was applied: ${drifted.join(", ")}. Undo anyway to discard those edits too.`);
  }
  const next: FileMap = { ...current };
  for (const f of ch.files) {
    if (f.before === null) delete next[f.path]; else next[f.path] = f.before;
  }
  ensureSize(next);
  const snapId = await snapshot(svc, ch.project_id, "Before undoing an AI change");
  await replaceAllFiles(svc, ch.project_id, next);
  await must(svc.from("wb_changes").update({ status: "reverted", reverted_at: new Date().toISOString() }).eq("id", ch.id));
  await must(svc.from("wb_messages").insert({ project_id: ch.project_id, role: "system", content: `Undid an applied change (${ch.files.length} file(s) restored). A checkpoint of the previous state was saved.` }));
  return { reverted: true, snapshot_id: snapId, files: await loadFiles(svc, ch.project_id) };
}

export async function checkProject(svc: Svc, body: Body) {
  const id = uuid(body.project_id);
  const project = await loadProject(svc, id);
  const files = await loadFiles(svc, id);
  return { checks: checkConsistency(files, project.kind), note: "Static cross-file checks only. Nothing was built, run or tested." };
}

export async function projectIndex(svc: Svc, body: Body) {
  const id = uuid(body.project_id);
  await loadProject(svc, id);
  return { index: buildIndex(await loadFiles(svc, id)) };
}

export async function renameFolder(svc: Svc, body: Body) {
  const id = uuid(body.project_id);
  const from = str(body.from, 300).replace(/\/+$/, "");
  const to = str(body.to, 300).replace(/\/+$/, "");
  path(from); path(to);
  if (from === to || to.startsWith(from + "/")) throw new HttpError(400, "Choose a different folder name.");
  const files = await loadFiles(svc, id);
  const moving = Object.keys(files).filter((p) => p.startsWith(from + "/"));
  if (!moving.length) throw new HttpError(404, "Folder not found.");
  const upserts: FileMap = {};
  for (const p of moving) {
    const target = to + p.slice(from.length);
    validatePath(target);
    if (target in files) throw new HttpError(409, `A file named ${target} already exists.`);
    upserts[target] = files[p];
  }
  await snapshot(svc, id, `Before renaming folder ${from}`);
  await writeFiles(svc, id, upserts, moving);
  return { renamed: moving.length };
}
