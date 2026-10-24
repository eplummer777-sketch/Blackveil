import { useEffect, useMemo, useRef, useState } from 'react';
import { buildPreview, FileMap, resolveLocal } from '@/lib/builderTools';
import { RefreshCw, AlertTriangle, Download, Bug, Wand2, X } from 'lucide-react';

function download(html: string, name: string) {
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name.replace(/\//g, '-');
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface RuntimeIssue { kind: 'error' | 'console'; message: string; page: string }

export function Preview({ files, onFix }: { files: FileMap; onFix: (message: string) => void }) {
  const [nonce, setNonce] = useState(0);
  const pages = useMemo(() => Object.keys(files).filter((p) => /\.html?$/i.test(p)).sort((a, b) => (a === 'index.html' ? -1 : b === 'index.html' ? 1 : a.localeCompare(b))), [files]);
  const [page, setPage] = useState('index.html');
  const current = pages.includes(page) ? page : pages[0] ?? 'index.html';
  const result = useMemo(() => buildPreview(files, current), [files, current]);
  const [issues, setIssues] = useState<RuntimeIssue[]>([]);
  const [navMissing, setNavMissing] = useState<string | null>(null);
  const frame = useRef<HTMLIFrameElement>(null);

  useEffect(() => { setIssues([]); setNavMissing(null); }, [result, nonce]);

  useEffect(() => {
    function onMessage(e: MessageEvent) {
      if (e.source !== frame.current?.contentWindow || !e.data || e.data.bv !== 1) return;
      const d = e.data as { type: string; message?: unknown; line?: unknown; href?: unknown };
      if (d.type === 'nav' && typeof d.href === 'string') {
        const target = resolveLocal(d.href, current);
        if (target && target in files && /\.html?$/i.test(target)) { setPage(target); setNavMissing(null); }
        else setNavMissing(target ?? d.href);
      } else if ((d.type === 'error' || d.type === 'console') && typeof d.message === 'string') {
        const msg = d.message.slice(0, 500) + (typeof d.line === 'number' && d.line ? ` (line ${d.line})` : '');
        setIssues((list) => (list.length >= 20 || list.some((i) => i.message === msg) ? list : [...list, { kind: d.type as RuntimeIssue['kind'], message: msg, page: current }]));
      }
    }
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [files, current]);

  if (!result) {
    return <div className="h-full grid place-content-center text-sm text-slate-400 p-6 text-center">Add an <span className="font-mono text-slate-200">index.html</span> page to see a preview.</div>;
  }
  const errors = issues.filter((i) => i.kind === 'error');
  return (
    <div className="flex flex-col h-full">
      <div className="flex flex-wrap items-center gap-3 px-3 py-2 border-b border-slate-800 text-xs text-slate-400">
        {pages.length > 1 ? (
          <select value={current} onChange={(e) => setPage(e.target.value)} aria-label="Page"
            className="rounded-md bg-veil-950/60 border border-slate-700 px-2 py-1 font-mono text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
            {pages.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        ) : <span className="font-mono text-slate-300">{current}</span>}
        <span className="hidden sm:inline">Saved files, run in your browser (HTML, CSS, JavaScript; no build step)</span>
        <button onClick={() => setNonce((n) => n + 1)} className="ml-auto flex items-center gap-1 hover:text-cyan-300"><RefreshCw size={12} /> Reload</button>
        <button onClick={() => download(result.html, current)} className="flex items-center gap-1 hover:text-cyan-300" title="Download a single-file copy of this page"><Download size={12} /> Standalone</button>
      </div>
      {result.missing.length > 0 && (
        <div className="flex items-center gap-2 px-3 py-2 text-xs text-amber-200 bg-amber-500/10 border-b border-amber-500/30">
          <AlertTriangle size={13} /> Referenced but not in the project: {result.missing.join(', ')}
        </div>
      )}
      {navMissing && (
        <div className="flex items-center gap-2 px-3 py-2 text-xs text-amber-200 bg-amber-500/10 border-b border-amber-500/30">
          <AlertTriangle size={13} /> A link points to a page that does not exist: <span className="font-mono">{navMissing}</span>
          <button onClick={() => setNavMissing(null)} className="ml-auto" aria-label="Dismiss"><X size={12} /></button>
        </div>
      )}
      <iframe ref={frame} key={`${current}-${nonce}`} title="Project preview" srcDoc={result.html} sandbox="allow-scripts allow-forms allow-modals" referrerPolicy="no-referrer" className="flex-1 w-full bg-white min-h-0" />
      {issues.length > 0 && (
        <div className="max-h-40 overflow-y-auto scrollbar-thin border-t border-rose-500/30 bg-rose-500/5 px-3 py-2 text-xs">
          <div className="flex items-center gap-2 mb-1.5 text-rose-200">
            <Bug size={13} /> {errors.length} runtime error(s), {issues.length - errors.length} console error(s) reported by this page
            {errors.length > 0 && (
              <button onClick={() => onFix(`The preview of ${current} reports these runtime errors. Find the cause across the project and fix it:\n${errors.map((i) => `- ${i.message}`).join('\n')}`)}
                className="ml-auto flex items-center gap-1 text-cyan-300 hover:text-cyan-200"><Wand2 size={12} /> Ask the AI to fix</button>
            )}
          </div>
          <ul className="space-y-1 font-mono text-rose-100/90">{issues.map((i) => <li key={i.message}>{i.kind === 'console' ? 'console: ' : ''}{i.message}</li>)}</ul>
        </div>
      )}
    </div>
  );
}
