import type { getServiceClient } from "../_lib/auth.ts";
import { checkProjectSize, LIMITS, validatePath, type FileMap } from "../_lib/webbuilder.ts";

export type Svc = ReturnType<typeof getServiceClient>;
export type Body = Record<string, unknown>;

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function str(v: unknown, max: number): string {
  return typeof v === "string" ? v.slice(0, max) : "";
}

export function uuid(v: unknown): string {
  if (typeof v !== "string" || !/^[0-9a-f-]{36}$/i.test(v)) throw new HttpError(400, "Invalid id.");
  return v;
}

export function path(v: unknown): string {
  const r = validatePath(v);
  if (!r.ok) throw new HttpError(400, r.error);
  return r.path;
}

export async function must<T>(p: PromiseLike<{ data: T; error: { message: string } | null }>): Promise<T> {
  const { data, error } = await p;
  if (error) throw new HttpError(500, "Storage error: " + error.message);
  return data;
}

export async function loadProject(svc: Svc, id: string) {
  const p = await must(svc.from("wb_projects").select("*").eq("id", id).maybeSingle());
  if (!p) throw new HttpError(404, "Project not found.");
  return p as { id: string; name: string; description: string; kind: string };
}

export async function loadFiles(svc: Svc, projectId: string): Promise<FileMap> {
  const rows = await must(svc.from("wb_files").select("path, content").eq("project_id", projectId));
  const map: FileMap = {};
  for (const r of (rows ?? []) as { path: string; content: string }[]) map[r.path] = r.content;
  return map;
}

export async function snapshot(svc: Svc, projectId: string, label: string): Promise<string> {
  const files = await loadFiles(svc, projectId);
  const row = await must(svc.from("wb_snapshots").insert({ project_id: projectId, label: label.slice(0, 120), files }).select("id").single());
  const old = await must(svc.from("wb_snapshots").select("id").eq("project_id", projectId)
    .order("created_at", { ascending: false }).range(LIMITS.maxSnapshots, LIMITS.maxSnapshots + 50));
  const ids = ((old ?? []) as { id: string }[]).map((r) => r.id);
  if (ids.length) await must(svc.from("wb_snapshots").delete().in("id", ids));
  return (row as { id: string }).id;
}

export async function writeFiles(svc: Svc, projectId: string, files: FileMap, removed: string[] = []) {
  const now = new Date().toISOString();
  const rows = Object.entries(files).map(([p, content]) => ({ project_id: projectId, path: p, content, updated_at: now }));
  if (rows.length) await must(svc.from("wb_files").upsert(rows, { onConflict: "project_id,path" }));
  if (removed.length) await must(svc.from("wb_files").delete().eq("project_id", projectId).in("path", removed));
  await must(svc.from("wb_projects").update({ updated_at: now }).eq("id", projectId));
}

export async function replaceAllFiles(svc: Svc, projectId: string, files: FileMap) {
  const current = await loadFiles(svc, projectId);
  await writeFiles(svc, projectId, files, Object.keys(current).filter((p) => !(p in files)));
}

export function ensureSize(files: FileMap) {
  const err = checkProjectSize(files);
  if (err) throw new HttpError(413, err);
}

export async function createProject(svc: Svc, name: string, description: string, kind: string, files: FileMap) {
  if (!name.trim()) throw new HttpError(400, "Project name is required.");
  ensureSize(files);
  const p = await must(svc.from("wb_projects").insert({ name: name.trim(), description, kind: kind === "other" ? "other" : "static" }).select("*").single());
  const id = (p as { id: string }).id;
  await writeFiles(svc, id, files);
  return p;
}
