import type { FileMap, PatchEdit, ProposedFile } from "./webbuilder.ts";
import { findSecrets, kindOf, REDACTED } from "./projectIndex.ts";
import { syntaxProblem } from "./syntax.ts";

export interface ChangeFile {
  path: string;
  action: "create" | "update" | "delete";
  before: string | null;
  after: string | null;
  renamed_from?: string;
  renamed_to?: string;
}

export function applyPatch(content: string, edits: PatchEdit[]): { content: string } | { error: string } {
  let out = content;
  for (const [i, e] of edits.entries()) {
    const at = out.indexOf(e.find);
    if (at < 0) return { error: `edit ${i + 1} did not match the file` };
    if (out.indexOf(e.find, at + 1) >= 0) return { error: `edit ${i + 1} matched more than once` };
    out = out.slice(0, at) + e.replace + out.slice(at + e.find.length);
  }
  return { content: out };
}

export function applyToMap(original: FileMap, files: ChangeFile[]): FileMap {
  const next: FileMap = { ...original };
  for (const f of files) {
    if (f.after === null) delete next[f.path];
    else next[f.path] = f.after;
  }
  return next;
}

export function mergeProposals(original: FileMap, existing: ChangeFile[], proposals: ProposedFile[], projectKind: string): { files: ChangeFile[]; notes: string[] } {
  const work = applyToMap(original, existing);
  const meta = new Map<string, { renamed_from?: string; renamed_to?: string }>();
  for (const f of existing) meta.set(f.path, { renamed_from: f.renamed_from, renamed_to: f.renamed_to });
  const notes: string[] = [];
  const protectedPath = (p: string) => kindOf(p) === "env";
  // A full-file write must be structurally complete before it can replace a working file. This is the
  // guard against a cut-off model reply silently overwriting a file with half of its content.
  const write = (p: string, content: string, fullFile = false) => {
    if (content.includes(REDACTED)) { notes.push(`Skipped ${p}: it would have replaced a hidden secret with a placeholder.`); return false; }
    if (fullFile) {
      const problem = syntaxProblem(p, content);
      if (problem) {
        notes.push(`Skipped ${p}: the proposed content looks cut off (${problem}). The existing file was left untouched; ask for a smaller, targeted edit.`);
        return false;
      }
    }
    work[p] = content;
    return true;
  };

  for (const c of proposals) {
    if (protectedPath(c.path) || (c.action === "rename" && protectedPath(c.from))) {
      notes.push(`Skipped ${c.path}: environment files hold secrets and must be edited by you, not the AI.`);
      continue;
    }
    if (c.action === "delete") {
      if (!(c.path in work)) continue;
      if (c.path === "index.html" && projectKind !== "other") { notes.push("Refused to delete index.html: the site needs it."); continue; }
      delete work[c.path];
    } else if (c.action === "create" || c.action === "update") {
      write(c.path, c.content, true);
    } else if (c.action === "rename") {
      if (!(c.from in work)) { notes.push(`Skipped rename of ${c.from}: file not found.`); continue; }
      if (c.path in work) { notes.push(`Skipped rename to ${c.path}: a file with that name already exists.`); continue; }
      if (c.from === "index.html" && projectKind !== "other") { notes.push("Refused to rename index.html: the site needs it."); continue; }
      if (!write(c.path, c.content ?? work[c.from], c.content !== undefined)) continue;
      delete work[c.from];
      meta.set(c.path, { renamed_from: c.from });
      meta.set(c.from, { renamed_to: c.path });
    } else {
      if (!(c.path in work)) { notes.push(`Skipped edits to ${c.path}: file not found.`); continue; }
      const r = applyPatch(work[c.path], c.edits);
      if ("error" in r) { notes.push(`Skipped edits to ${c.path}: ${r.error}. Ask the AI to retry this file.`); continue; }
      // The patched result is only accepted when the file is still structurally complete.
      write(c.path, r.content, true);
    }
  }

  const files: ChangeFile[] = [];
  for (const p of [...new Set([...Object.keys(original), ...Object.keys(work)])].sort()) {
    const before = original[p] ?? null;
    const after = work[p] ?? null;
    if (before === after) continue;
    const action = before === null ? "create" : after === null ? "delete" : "update";
    files.push({ path: p, action, before, after, ...(meta.get(p) ?? {}) });
  }
  return { files, notes };
}

const DESTRUCTIVE_SQL = /\b(drop\s+(table|column|schema|database|policy|function)|truncate\b|delete\s+from|alter\s+table\s+[\w."]+\s+(drop|rename|alter\s+column\s+[\w"]+\s+type))/i;
const AUTH_PATH = /(auth|login|signin|signup|register|session|password|role|permission|policy|policies)/i;

export function riskNotes(files: ChangeFile[], projectKind: string): string[] {
  const notes: string[] = [];
  for (const f of files) {
    const kind = kindOf(f.path);
    if (f.renamed_to) { notes.push(`Renames ${f.path} to ${f.renamed_to}. Anything still pointing at the old name will break.`); continue; }
    if (f.action === "delete") notes.push(`Deletes ${f.path}${f.before && f.before.length > 2000 ? ` (${f.before.length} characters)` : ""}.`);
    if (kind === "config" && f.action !== "delete") notes.push(`Changes configuration in ${f.path}, which can affect how the whole site loads or deploys.`);
    if (kind === "database" && f.after !== null) {
      notes.push(DESTRUCTIVE_SQL.test(f.after)
        ? `${f.path} contains a destructive database statement (drop, truncate, delete or type change). It will NOT be run automatically; review it carefully before running it anywhere.`
        : `Adds or changes database file ${f.path}. It is saved only; it will not be run automatically.`);
    }
    if (kind === "backend" && f.after !== null) notes.push(`Changes server code in ${f.path}. It cannot be run or tested here.`);
    if (AUTH_PATH.test(f.path) && f.action !== "create") notes.push(`Touches sign-in, session or permission code in ${f.path}.`);
    if (f.after !== null && findSecrets(f.after).length && !(f.before && findSecrets(f.before).length)) notes.push(`${f.path} appears to contain a secret value. Secrets belong in server-side secret storage.`);
    if (f.action === "update" && f.before && f.after && f.before.length > 2000 && f.after.length < f.before.length * 0.4) {
      notes.push(`Shrinks ${f.path} from ${f.before.length} to ${f.after.length} characters. Check that nothing important was dropped.`);
    }
  }
  if (projectKind !== "other" && files.some((f) => f.path === "index.html" && f.after === null)) notes.push("Removes index.html, so the preview will stop working.");
  return [...new Set(notes)];
}
