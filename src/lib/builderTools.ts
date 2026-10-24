export type FileMap = Record<string, string>;

export type DiffLine = { kind: 'same' | 'add' | 'del'; text: string };

const MAX_DIFF_LINES = 2000;

export function lineDiff(before: string | null, after: string | null): DiffLine[] {
  const a = before === null ? [] : before.split('\n');
  const b = after === null ? [] : after.split('\n');
  if (a.length > MAX_DIFF_LINES || b.length > MAX_DIFF_LINES) {
    return [...a.map((text) => ({ kind: 'del' as const, text })), ...b.map((text) => ({ kind: 'add' as const, text }))];
  }
  const n = a.length;
  const m = b.length;
  const lcs: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ kind: 'same', text: a[i] }); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) out.push({ kind: 'del', text: a[i++] });
    else out.push({ kind: 'add', text: b[j++] });
  }
  while (i < n) out.push({ kind: 'del', text: a[i++] });
  while (j < m) out.push({ kind: 'add', text: b[j++] });
  return out;
}

export { buildPreview, resolveLocal } from '../../supabase/functions/_lib/sitebuild.ts';

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const JS_KEYWORDS = 'const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|class|extends|import|export|from|default|async|await|try|catch|finally|throw|typeof|instanceof|in|of|this|null|undefined|true|false';

const RULES: Record<string, [RegExp, string][]> = {
  js: [
    [/^\/\/[^\n]*|^\/\*[\s\S]*?\*\//, 'text-slate-500'],
    [/^(["'`])(?:\\[\s\S]|(?!\1)[^\\])*\1/, 'text-emerald-300'],
    [new RegExp(`^\\b(?:${JS_KEYWORDS})\\b`), 'text-sky-300'],
    [/^\b\d+(?:\.\d+)?\b/, 'text-amber-300'],
  ],
  css: [
    [/^\/\*[\s\S]*?\*\//, 'text-slate-500'],
    [/^(["'])(?:\\.|(?!\1)[^\\])*\1/, 'text-emerald-300'],
    [/^[a-z-]+(?=\s*:)/i, 'text-sky-300'],
    [/^#[0-9a-f]{3,8}\b|^\b\d+(?:\.\d+)?(?:px|rem|em|%|vh|vw|s|ms)?\b/i, 'text-amber-300'],
  ],
  html: [
    [/^<!--[\s\S]*?-->/, 'text-slate-500'],
    [/^<\/?[a-zA-Z][\w-]*|^\/?>/, 'text-sky-300'],
    [/^(["'])(?:(?!\1)[^\\])*\1/, 'text-emerald-300'],
    [/^\b[a-zA-Z-:]+(?==)/, 'text-amber-200'],
  ],
};

export function languageOf(path: string): 'js' | 'css' | 'html' | 'text' {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  if (['js', 'mjs', 'ts', 'tsx', 'jsx', 'json'].includes(ext)) return 'js';
  if (ext === 'css') return 'css';
  if (['html', 'htm', 'svg', 'xml'].includes(ext)) return 'html';
  return 'text';
}

export function highlight(code: string, lang: ReturnType<typeof languageOf>): string {
  const rules = RULES[lang];
  if (!rules || code.length > 150_000) return esc(code);
  let out = '';
  let rest = code;
  let plain = '';
  while (rest.length) {
    let matched = false;
    for (const [re, cls] of rules) {
      const m = re.exec(rest);
      if (m && m[0].length) {
        out += esc(plain);
        plain = '';
        out += `<span class="${cls}">${esc(m[0])}</span>`;
        rest = rest.slice(m[0].length);
        matched = true;
        break;
      }
    }
    if (!matched) {
      const word = /^[A-Za-z_$][\w$]*|^[\s\S]/.exec(rest)![0];
      plain += word;
      rest = rest.slice(word.length);
    }
  }
  return out + esc(plain);
}
