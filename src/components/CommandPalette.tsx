import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, CornerDownLeft } from 'lucide-react';
import type { NavItem, Route } from '@/components/AppShell';

export function CommandPalette({ items, onSelect, onClose }: { items: NavItem[]; onSelect: (r: Route) => void; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((i) => `${i.label} ${i.desc} ${i.group}`.toLowerCase().includes(q));
  }, [items, query]);

  useEffect(() => { inputRef.current?.focus(); }, []);
  useEffect(() => { setIndex(0); }, [query]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') onClose();
    else if (e.key === 'ArrowDown') { e.preventDefault(); setIndex((i) => Math.min(i + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter' && results[index]) onSelect(results[index].id);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh] fade-in" onKeyDown={onKeyDown}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-2xl border border-slate-700/70 bg-veil-900 shadow-2xl overflow-hidden fade-up">
        <div className="flex items-center gap-3 px-4 border-b border-slate-800">
          <Search size={17} className="text-slate-500" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to a page..."
            className="flex-1 bg-transparent py-4 text-sm text-slate-100 placeholder:text-slate-500 outline-none"
          />
          <kbd className="text-[10px] text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">Esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto scrollbar-thin p-2">
          {results.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-500">No pages match "{query}"</p>
          ) : results.map((item, i) => {
            const Icon = item.icon;
            const active = i === index;
            return (
              <button
                key={item.id}
                onMouseEnter={() => setIndex(i)}
                onClick={() => onSelect(item.id)}
                className={`w-full flex items-center gap-3 rounded-xl px-3 py-2.5 text-left transition ${active ? 'bg-cyan-400/10' : ''}`}
              >
                <span className={`w-9 h-9 rounded-lg flex items-center justify-center border ${active ? 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300' : 'border-slate-800 bg-veil-950 text-slate-400'}`}>
                  <Icon size={16} />
                </span>
                <span className="flex-1 min-w-0">
                  <span className="block text-sm font-medium text-slate-100">{item.label}</span>
                  <span className="block text-xs text-slate-500 truncate">{item.group} · {item.desc}</span>
                </span>
                {active && <CornerDownLeft size={14} className="text-cyan-300" />}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
