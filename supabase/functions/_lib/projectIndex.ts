import type { FileMap, VerifyCheck } from "./webbuilder.ts";

export type FileKind =
  | "page" | "style" | "script" | "component" | "backend" | "database" | "config"
  | "test" | "doc" | "data" | "asset" | "env" | "other";

export interface IndexEntry {
  path: string;
  kind: FileKind;
  size: number;
  refs: string[];
  missing: string[];
  packages: string[];
  dependents: string[];
  summary: string;
}

export interface ProjectIndex {
  entries: Record<string, IndexEntry>;
  pages: string[];
  orphanPages: string[];
  totalChars: number;
}

const CODE_EXT = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

export function kindOf(path: string): FileKind {
  const p = path.toLowerCase();
  const name = p.split("/").pop() ?? p;
  const ext = name.includes(".") ? name.split(".").pop()! : "";
  if (name === ".env" || name.startsWith(".env.")) return "env";
  if (/(^|\/)(tests?|__tests__)\//.test(p) || /\.(test|spec)\.[jt]sx?$/.test(p)) return "test";
  if (ext === "sql" || /(^|\/)migrations?\//.test(p)) return "database";
  if (/(^|\/)(supabase\/functions|api|server|backend|functions)\//.test(p) || /^server\.[jt]s$/.test(name)) return "backend";
  if (ext === "html" || ext === "htm") return "page";
  if (CODE_EXT.includes(ext) && /(^|\/)(pages|routes|views|app)\//.test(p)) return "page";
  if (ext === "css" || ext === "scss") return "style";
  if (name === "package.json" || /\.config\.[a-z]+$/.test(name) || name.startsWith("tsconfig") ||
    ["toml", "yml", "yaml"].includes(ext) || ["_headers", "_redirects", "vercel.json", "manifest.webmanifest"].includes(name)) return "config";
  if (ext === "tsx" || ext === "jsx" || /(^|\/)components\//.test(p)) return "component";
  if (CODE_EXT.includes(ext)) return "script";
  if (ext === "md" || ext === "txt") return "doc";
  if (ext === "json" || ext === "csv") return "data";
  if (["svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf"].includes(ext)) return "asset";
  return "other";
}

function normalize(fromPath: string, ref: string): string {
  const dir = fromPath.includes("/") ? fromPath.slice(0, fromPath.lastIndexOf("/") + 1) : "";
  const base = ref.startsWith("@/") ? "src/" + ref.slice(2) : ref.startsWith("/") ? ref.slice(1) : dir + ref;
  const parts: string[] = [];
  for (const seg of base.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg && seg !== ".") parts.push(seg);
  }
  return parts.join("/");
}

function isExternal(ref: string): boolean {
  return !ref || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(ref) || ref.includes("${");
}

function resolveCode(files: FileMap, target: string): string | null {
  if (target in files) return target;
  for (const ext of CODE_EXT) if (`${target}.${ext}` in files) return `${target}.${ext}`;
  for (const ext of CODE_EXT) if (`${target}/index.${ext}` in files) return `${target}/index.${ext}`;
  return null;
}

interface RawRefs { local: string[]; packages: string[] }

function extractRefs(path: string, content: string, kind: FileKind): RawRefs {
  const local: string[] = [];
  const packages: string[] = [];
  const add = (raw: string, code: boolean) => {
    const ref = raw.trim().split(/[?#]/)[0];
    if (isExternal(raw.trim())) return;
    if (code && !/^(\.{1,2}\/|\/|@\/)/.test(ref)) { packages.push(ref.split("/").slice(0, ref.startsWith("@") ? 2 : 1).join("/")); return; }
    local.push(ref);
  };
  if (kind === "page" || path.endsWith(".svg")) {
    for (const m of content.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) add(m[1], false);
  }
  if (kind === "style" || kind === "page") {
    for (const m of content.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi)) add(m[1], false);
    for (const m of content.matchAll(/@import\s+["']([^"']+)["']/gi)) add(m[1], false);
  }
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  if (CODE_EXT.includes(ext)) {
    const re = /(?:\bimport\s+(?:[\w*{}\s,$]+\s+from\s+)?|\bexport\s+[\w*{}\s,$]+\s+from\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"']+)["']/g;
    for (const m of content.matchAll(re)) add(m[1], true);
    for (const m of content.matchAll(/\bfetch\s*\(\s*["'](\.{0,2}\/?[\w./-]+\.(?:json|html|txt|csv))["']/g)) add(m[1], false);
  }
  return { local, packages };
}

function summarize(path: string, content: string, kind: FileKind): string {
  const bits: string[] = [];
  if (kind === "page") {
    const title = /<title[^>]*>([^<]*)<\/title>/i.exec(content)?.[1]?.trim();
    const h1 = /<h1[^>]*>([\s\S]*?)<\/h1>/i.exec(content)?.[1]?.replace(/<[^>]+>/g, "").trim();
    if (title) bits.push(`title "${title.slice(0, 60)}"`);
    if (h1) bits.push(`h1 "${h1.slice(0, 60)}"`);
    if (/<nav\b/i.test(content)) bits.push("has nav");
    if (/<form\b/i.test(content)) bits.push("has form");
  } else if (kind === "style") {
    const vars = new Set([...content.matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]));
    const media = (content.match(/@media/g) ?? []).length;
    if (vars.size) bits.push(`${vars.size} CSS variables`);
    if (media) bits.push(`${media} media queries`);
  } else if (CODE_EXT.some((e) => path.endsWith("." + e))) {
    const names = [...content.matchAll(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|const|class|let|interface|type)\s+([A-Za-z_$][\w$]*)/g)].map((m) => m[1]);
    if (names.length) bits.push(`exports ${[...new Set(names)].slice(0, 8).join(", ")}`);
    if (/addEventListener|onClick=/.test(content)) bits.push("handles events");
  } else if (kind === "database") {
    const tables = [...content.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/gi)].map((m) => m[1]);
    if (tables.length) bits.push(`creates ${tables.slice(0, 6).join(", ")}`);
  }
  return bits.join("; ");
}

export function buildIndex(files: FileMap): ProjectIndex {
  const entries: Record<string, IndexEntry> = {};
  let totalChars = 0;
  for (const path of Object.keys(files).sort()) {
    const content = files[path];
    const kind = kindOf(path);
    totalChars += content.length;
    const raw = extractRefs(path, content, kind);
    const refs: string[] = [];
    const missing: string[] = [];
    for (const r of raw.local) {
      const target = normalize(path, r);
      const resolved = CODE_EXT.some((e) => path.endsWith("." + e)) && !/\.\w+$/.test(target) ? resolveCode(files, target) : (target in files ? target : null);
      if (resolved) { if (resolved !== path && !refs.includes(resolved)) refs.push(resolved); }
      else if (!missing.includes(target)) missing.push(target);
    }
    entries[path] = { path, kind, size: content.length, refs, missing, packages: [...new Set(raw.packages)], dependents: [], summary: summarize(path, content, kind) };
  }
  for (const e of Object.values(entries)) for (const r of e.refs) entries[r]?.dependents.push(e.path);
  const pages = Object.values(entries).filter((e) => e.kind === "page").map((e) => e.path);
  const orphanPages = pages.filter((p) => p !== "index.html" && !entries[p].dependents.some((d) => entries[d].kind === "page" || entries[d].kind === "script" || entries[d].kind === "component"));
  return { entries, pages, orphanPages, totalChars };
}

export function indexText(index: ProjectIndex): string {
  const lines = Object.values(index.entries).map((e) => {
    const parts = [`${e.path} [${e.kind}, ${e.size} chars]`];
    if (e.summary) parts.push(e.summary);
    if (e.refs.length) parts.push(`uses: ${e.refs.slice(0, 12).join(", ")}`);
    if (e.dependents.length) parts.push(`used by: ${e.dependents.slice(0, 12).join(", ")}`);
    if (e.packages.length) parts.push(`packages: ${e.packages.slice(0, 8).join(", ")}`);
    if (e.missing.length) parts.push(`BROKEN refs: ${e.missing.slice(0, 6).join(", ")}`);
    return parts.join(" | ");
  });
  return `${lines.length} files, ${index.totalChars} chars total. Pages: ${index.pages.join(", ") || "none"}\n${lines.join("\n")}`;
}

export function expandSelection(index: ProjectIndex, seeds: string[], max = 80): string[] {
  const out: string[] = [];
  const push = (p: string) => { if (index.entries[p] && !out.includes(p) && out.length < max) out.push(p); };
  seeds.forEach(push);
  for (const s of seeds) index.entries[s]?.refs.forEach(push);
  for (const s of seeds) index.entries[s]?.dependents.forEach(push);
  return out;
}

export function planBatches(sizes: Record<string, number>, targets: string[], budget: number): string[][] {
  const batches: string[][] = [];
  let cur: string[] = [];
  let used = 0;
  for (const t of targets) {
    const s = sizes[t] ?? 0;
    if (cur.length && used + s > budget) { batches.push(cur); cur = []; used = 0; }
    cur.push(t);
    used += s;
  }
  if (cur.length) batches.push(cur);
  return batches;
}

const SECRET_PATTERNS: [string, RegExp][] = [
  ["Stripe secret key", /\b(?:sk|rk)_live_[0-9A-Za-z]{10,}/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{30,}/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[0-9A-Za-z]{30,}/],
  ["Slack token", /\bxox[abpr]-[0-9A-Za-z-]{10,}/],
  ["Private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["OpenAI key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
];

export function findSecrets(content: string): string[] {
  return SECRET_PATTERNS.filter(([, re]) => re.test(content)).map(([name]) => name);
}

export const REDACTED = "<redacted-secret>";

export function redactForModel(path: string, content: string): string {
  let out = content;
  if (kindOf(path) === "env") out = out.replace(/^(\s*[A-Za-z_][\w]*\s*=).*$/gm, `$1${REDACTED}`);
  for (const [, re] of SECRET_PATTERNS) out = out.replace(new RegExp(re.source, "g"), REDACTED);
  return out;
}

export function checkConsistency(files: FileMap, projectKind: string): VerifyCheck[] {
  const index = buildIndex(files);
  const checks: VerifyCheck[] = [];
  const broken = Object.values(index.entries).filter((e) => e.missing.length);
  checks.push({
    name: "Every local link, import and asset reference resolves",
    ok: broken.length === 0,
    detail: broken.length ? broken.map((e) => `${e.path} -> ${e.missing.join(", ")}`).join("; ").slice(0, 1500) : `${Object.values(index.entries).reduce((n, e) => n + e.refs.length, 0)} references checked`,
  });
  const badJson = Object.keys(files).filter((p) => p.endsWith(".json") || p.endsWith(".webmanifest")).filter((p) => {
    try { JSON.parse(files[p]); return false; } catch { return true; }
  });
  checks.push({ name: "JSON files parse", ok: badJson.length === 0, detail: badJson.length ? `Invalid: ${badJson.join(", ")}` : "All valid" });
  const empty = Object.keys(files).filter((p) => !files[p].trim() && kindOf(p) !== "asset");
  checks.push({ name: "No empty files", ok: empty.length === 0, detail: empty.length ? `Empty: ${empty.join(", ")}` : "None empty" });
  const leaks = Object.keys(files).filter((p) => kindOf(p) !== "env").map((p) => [p, findSecrets(files[p])] as const).filter(([, s]) => s.length);
  checks.push({ name: "No secret values in project files", ok: leaks.length === 0, detail: leaks.length ? leaks.map(([p, s]) => `${p}: ${s.join(", ")}`).join("; ") : "No known secret formats found" });
  if (projectKind !== "other") {
    checks.push({ name: "Project has index.html", ok: "index.html" in files, detail: "index.html" in files ? "Found" : "The preview needs index.html at the top level" });
  }
  checks.push({
    name: "Every page is linked from somewhere", ok: index.orphanPages.length === 0, warn: true,
    detail: index.orphanPages.length ? `Not linked: ${index.orphanPages.join(", ")}` : `${index.pages.length} page(s) reachable`,
  });
  return checks;
}
