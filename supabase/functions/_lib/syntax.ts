import type { FileMap, VerifyCheck } from "./webbuilder.ts";

const PAIRS: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
const lineAt = (s: string, i: number) => s.slice(0, i).split("\n").length;

// A lightweight structural check, not a parser: catches the truncated or half-written code a small model produces.
export function checkBrackets(src: string, js: boolean): string | null {
  const stack: { ch: string; at: number }[] = [];
  let lastSig = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "*") { const end = src.indexOf("*/", i + 2); if (end < 0) return `Unclosed comment starting on line ${lineAt(src, i)}`; i = end + 1; continue; }
    if (js && c === "/" && n === "/") { const end = src.indexOf("\n", i); i = end < 0 ? src.length : end; continue; }
    if (c === '"' || c === "'" || (js && c === "`")) {
      let j = i + 1;
      while (j < src.length && src[j] !== c) { if (src[j] === "\\") j++; else if (c !== "`" && src[j] === "\n") break; j++; }
      if (j >= src.length || src[j] !== c) return `Unclosed ${c === "`" ? "template" : "string"} starting on line ${lineAt(src, i)}`;
      i = j; lastSig = c; continue;
    }
    if (js && c === "/" && (lastSig === "" || "(,=:[!&|?{};+-*%<>~^".includes(lastSig))) {
      let j = i + 1;
      let cls = false;
      while (j < src.length && src[j] !== "\n" && (cls || src[j] !== "/")) { if (src[j] === "\\") j++; else if (src[j] === "[") cls = true; else if (src[j] === "]") cls = false; j++; }
      if (src[j] === "/") { i = j; lastSig = "/"; continue; }
    }
    if (c === "(" || c === "[" || c === "{") stack.push({ ch: c, at: i });
    else if (c in PAIRS) {
      const top = stack.pop();
      if (!top) return `Unexpected "${c}" on line ${lineAt(src, i)}`;
      if (top.ch !== PAIRS[c]) return `"${top.ch}" on line ${lineAt(src, top.at)} is closed by "${c}" on line ${lineAt(src, i)}`;
    }
    if (!/\s/.test(c)) lastSig = c;
  }
  const open = stack.pop();
  return open ? `"${open.ch}" on line ${lineAt(src, open.at)} is never closed` : null;
}

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "path", "circle", "rect", "line", "polyline", "polygon", "ellipse", "stop", "use"]);
const OPTIONAL_CLOSE = new Set(["li", "p", "td", "th", "tr", "option", "dt", "dd", "thead", "tbody", "html", "head", "body", "colgroup"]);

export function checkHtml(src: string): string | null {
  const stack: { tag: string; at: number }[] = [];
  const re = /<!--[\s\S]*?(?:-->|$)|<(\/?)([a-zA-Z][\w-]*)\b((?:[^>"']|"[^"]*"|'[^']*')*)(\/?)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (m[0].startsWith("<!--")) { if (!m[0].endsWith("-->")) return `Unclosed comment on line ${lineAt(src, m.index)}`; continue; }
    const tag = m[2].toLowerCase();
    if (m[1]) {
      if (VOID.has(tag)) continue;
      while (stack.length && stack[stack.length - 1].tag !== tag && OPTIONAL_CLOSE.has(stack[stack.length - 1].tag)) stack.pop();
      const top = stack.pop();
      if (!top) return `Closing </${tag}> on line ${lineAt(src, m.index)} has no matching opening tag`;
      if (top.tag !== tag) return `<${top.tag}> on line ${lineAt(src, top.at)} is closed by </${tag}> on line ${lineAt(src, m.index)}`;
      continue;
    }
    if (VOID.has(tag) || m[4]) continue;
    if (tag === "script" || tag === "style") {
      const end = src.toLowerCase().indexOf(`</${tag}`, re.lastIndex);
      if (end < 0) return `<${tag}> on line ${lineAt(src, m.index)} is never closed`;
      const inner = src.slice(re.lastIndex, end);
      if (!/\bsrc\s*=/.test(m[3]) && !/type\s*=\s*["']?(?!module|text\/javascript)[\w/+-]+/i.test(m[3])) {
        const err = checkBrackets(inner, tag === "script");
        if (err) return `Inside <${tag}> starting on line ${lineAt(src, m.index)}: ${err.replace(/line (\d+)/g, (_, l) => `line ${Number(l) + lineAt(src, re.lastIndex) - 1}`)}`;
      }
      re.lastIndex = src.indexOf(">", end) + 1 || src.length;
      continue;
    }
    stack.push({ tag, at: m.index });
  }
  const left = stack.filter((s) => !OPTIONAL_CLOSE.has(s.tag));
  return left.length ? `<${left[left.length - 1].tag}> on line ${lineAt(src, left[left.length - 1].at)} is never closed` : null;
}

export function syntaxProblem(path: string, content: string): string | null {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  if (ext === "html" || ext === "htm") return checkHtml(content);
  // JSX text can contain bare apostrophes, so .jsx/.tsx are not checked.
  if (["js", "mjs", "cjs", "ts"].includes(ext)) return checkBrackets(content, true);
  if (ext === "css" || ext === "scss") return checkBrackets(content, false);
  return null;
}

export function syntaxCheck(files: FileMap, paths: string[]): VerifyCheck {
  const problems = paths.filter((p) => p in files).map((p) => [p, syntaxProblem(p, files[p])] as const).filter(([, e]) => e);
  return {
    name: "Changed code is structurally complete (brackets, strings, tags)",
    ok: problems.length === 0,
    detail: problems.length ? problems.map(([p, e]) => `${p}: ${e}`).join("; ").slice(0, 1500) : `${paths.length} changed file(s) checked`,
  };
}
