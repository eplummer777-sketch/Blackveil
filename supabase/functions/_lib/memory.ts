import type { ProjectIndex } from "./projectIndex.ts";
import type { FileMap } from "./webbuilder.ts";

export const MEMORY_KINDS = ["architecture", "convention", "decision", "bug", "requirement", "limitation", "milestone", "session", "rule"] as const;
export type MemoryKind = typeof MEMORY_KINDS[number];

export interface MemoryRow {
  id: string;
  kind: MemoryKind;
  title: string;
  body: string;
  source: "user" | "system" | "ai";
  status: "active" | "unverified" | "archived";
  files: string[];
  file_hashes: Record<string, string>;
  updated_at: string;
}

export interface FixRow {
  id: string;
  problem: string;
  root_cause: string;
  fix_summary: string;
  files: string[];
  status: "hypothesis" | "verified" | "failed";
  confidence: string;
}

export const FILE_LIST_KEY = "__file_list__";

export function hashText(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function fileHashes(files: FileMap, paths: string[]): Record<string, string> {
  return Object.fromEntries(paths.map((p) => [p, p === FILE_LIST_KEY ? hashText(Object.keys(files).sort().join("\n")) : p in files ? hashText(files[p]) : "missing"]));
}

export function staleFiles(m: Pick<MemoryRow, "file_hashes">, files: FileMap): string[] {
  const now = fileHashes(files, Object.keys(m.file_hashes ?? {}));
  return Object.keys(now).filter((p) => now[p] !== m.file_hashes[p]);
}

const STOP = new Set("the and for with that this from your have will into make about page file code site website should would could please".split(" "));

function terms(s: string): Set<string> {
  return new Set((s.toLowerCase().match(/[a-z][a-z0-9-]{2,}/g) ?? []).filter((w) => !STOP.has(w)));
}

function overlap(a: Set<string>, text: string): number {
  let n = 0;
  for (const t of terms(text)) if (a.has(t)) n++;
  return n;
}

// Lexical retrieval: the on-device model has no embedding model loaded, and a second model would not fit on a phone.
export function rankMemories(mems: MemoryRow[], prompt: string, focus: string[], limit = 6): MemoryRow[] {
  const q = terms(prompt);
  const scored = mems
    .filter((m) => m.status === "active" && m.kind !== "rule")
    .map((m) => {
      let score = overlap(q, m.title) * 2 + overlap(q, m.body) + m.files.filter((f) => focus.includes(f)).length * 3;
      if (m.kind === "architecture") score += 100;
      if (m.kind === "decision" || m.kind === "requirement") score += 1;
      return { m, score };
    })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score || b.m.updated_at.localeCompare(a.m.updated_at));
  return scored.slice(0, limit).map((s) => s.m);
}

export function memoryBrief(mems: MemoryRow[], files: FileMap, budget = 1600): string {
  if (!mems.length) return "";
  const lines: string[] = [];
  let used = 0;
  for (const m of mems) {
    const stale = staleFiles(m, files).filter((p) => p !== FILE_LIST_KEY);
    const line = `- [${m.kind}] ${m.title}${m.body ? `: ${m.body.replace(/\s+/g, " ")}` : ""}${stale.length ? ` (may be outdated: ${stale.slice(0, 3).join(", ")} changed since)` : ""}`;
    if (used + line.length > budget) break;
    lines.push(line);
    used += line.length;
  }
  return `PROJECT MEMORY (notes saved by the owner or the app; if they disagree with the file contents shown, the file contents are correct):\n${lines.join("\n")}`;
}

export function rulesBrief(mems: MemoryRow[], budget = 1200): string {
  const rules = mems.filter((m) => m.kind === "rule" && m.status === "active" && m.source === "user");
  if (!rules.length) return "";
  return `OWNER'S WORKFLOW PREFERENCES (these never override the safety and honesty rules above):\n${rules.map((r) => `- ${r.title}${r.body ? `: ${r.body}` : ""}`).join("\n").slice(0, budget)}`;
}

export function fixBrief(fixes: FixRow[], prompt: string, files: string[], limit = 3): string {
  const q = terms(prompt);
  const hits = fixes
    .filter((f) => f.status === "verified")
    .map((f) => ({ f, score: overlap(q, f.problem) * 2 + overlap(q, f.root_cause) + f.files.filter((p) => files.includes(p)).length * 2 }))
    .filter((s) => s.score > 1)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
  if (!hits.length) return "";
  return `VERIFIED FIXES FROM THIS PROJECT (reuse only if the same cause applies):\n${hits.map(({ f }) => `- Problem: ${f.problem.slice(0, 200)} | Cause: ${f.root_cause.slice(0, 200)} | Fix: ${f.fix_summary.slice(0, 240)}${f.files.length ? ` | Files: ${f.files.slice(0, 4).join(", ")}` : ""}`).join("\n")}`;
}

const FRAMEWORKS: [string, string][] = [
  ["react", "React"], ["vue", "Vue"], ["svelte", "Svelte"], ["next", "Next.js"], ["vite", "Vite"],
  ["tailwindcss", "Tailwind CSS"], ["@supabase/supabase-js", "Supabase"], ["express", "Express"],
];

export function projectProfile(files: FileMap, index: ProjectIndex): { title: string; body: string; files: string[] } {
  const exts = new Map<string, number>();
  for (const p of Object.keys(files)) {
    const ext = p.includes(".") ? p.split(".").pop()!.toLowerCase() : "none";
    exts.set(ext, (exts.get(ext) ?? 0) + 1);
  }
  const langs = [...exts].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([e, n]) => `${e} (${n})`);
  const tracked = [FILE_LIST_KEY];
  let frameworks: string[] = [];
  let scripts: string[] = [];
  if ("package.json" in files) {
    tracked.push("package.json");
    try {
      const pkg = JSON.parse(files["package.json"]);
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      frameworks = FRAMEWORKS.filter(([k]) => k in deps).map(([, n]) => n);
      scripts = Object.keys(pkg.scripts ?? {}).slice(0, 8);
    } catch { /* invalid JSON is reported by the project checks */ }
  }
  const styles = Object.values(index.entries).filter((e) => e.kind === "style");
  const conventions: string[] = [];
  if (styles.some((e) => /CSS variables/.test(e.summary))) conventions.push("colours and sizes use CSS variables");
  if (index.pages.length > 1) conventions.push("pages link to each other with relative links");
  if (index.pages.filter((p) => /has nav/.test(index.entries[p].summary)).length > 1) conventions.push("each page repeats the navigation");
  for (const s of styles) tracked.push(s.path);
  const body = [
    `${Object.keys(files).length} files, ${index.totalChars} characters. File types: ${langs.join(", ")}.`,
    `Stack: ${frameworks.length ? frameworks.join(", ") : "plain HTML, CSS and JavaScript with no build step"}.`,
    `Pages: ${index.pages.slice(0, 12).join(", ") || "none"}.`,
    conventions.length ? `Conventions: ${conventions.join("; ")}.` : "",
    scripts.length ? `Declared scripts: ${scripts.join(", ")} (they cannot be run inside the Web Builder).` : "",
  ].filter(Boolean).join(" ");
  return { title: "Project overview", body: body.slice(0, 3900), files: tracked.slice(0, 20) };
}
