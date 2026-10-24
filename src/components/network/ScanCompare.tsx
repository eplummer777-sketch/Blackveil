import { useEffect, useState } from 'react';
import { ArrowLeft, ArrowRight, Minus, Plus, RefreshCw } from 'lucide-react';
import { Button, Card, ErrorBanner, Spinner } from '@/components/ui';
import { supabase } from '@/lib/supabase';
import { flattenPorts, NetHost, NetScan, PortRow, PROFILE_INFO } from '@/lib/network';

type Change = { kind: 'new' | 'gone' | 'changed'; key: string; before?: PortRow; after?: PortRow };

const svc = (p?: PortRow) => (p ? [p.service, p.product, p.version].filter(Boolean).join(' ') || '-' : '-');

function diff(a: NetHost[], b: NetHost[]): Change[] {
  const map = (h: NetHost[]) => new Map(flattenPorts(h).filter((p) => p.state === 'open').map((p) => [`${p.address}:${p.port}/${p.protocol}`, p]));
  const [before, after] = [map(a), map(b)];
  const out: Change[] = [];
  for (const [k, p] of after) {
    const old = before.get(k);
    if (!old) out.push({ kind: 'new', key: k, after: p });
    else if (svc(old) !== svc(p)) out.push({ kind: 'changed', key: k, before: old, after: p });
  }
  for (const [k, p] of before) if (!after.has(k)) out.push({ kind: 'gone', key: k, before: p });
  return out.sort((x, y) => x.key.localeCompare(y.key, undefined, { numeric: true }));
}

const STYLE = {
  new: { label: 'Newly open', icon: Plus, cls: 'border-amber-400/30 bg-amber-400/5 text-amber-300' },
  gone: { label: 'No longer open', icon: Minus, cls: 'border-emerald-400/30 bg-emerald-400/5 text-emerald-300' },
  changed: { label: 'Service changed', icon: RefreshCw, cls: 'border-cyan-400/30 bg-cyan-400/5 text-cyan-300' },
};

export function ScanCompare({ a, b, onBack }: { a: NetScan; b: NetScan; onBack: () => void }) {
  const [changes, setChanges] = useState<Change[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([a.id, b.id].map((id) => supabase.from('nmap_hosts').select('*').eq('scan_id', id))).then(([ra, rb]) => {
      if (ra.error || rb.error) { setError('Could not load the scans to compare.'); setChanges([]); return; }
      setChanges(diff((ra.data ?? []) as NetHost[], (rb.data ?? []) as NetHost[]));
    });
  }, [a.id, b.id]);

  const incomplete = [a, b].some((s) => s.status === 'partial');
  const head = (s: NetScan, label: string) => (
    <div className="min-w-0 flex-1 rounded-xl border border-slate-800 bg-veil-900/50 p-4">
      <p className="text-[11px] uppercase tracking-widest text-slate-500">{label}</p>
      <p className="mt-1 truncate font-mono text-sm text-slate-100">{s.target_input}</p>
      <p className="mt-1 text-xs text-slate-500">{PROFILE_INFO[s.profile].label} · {new Date(s.created_at).toLocaleString()} · {s.summary.open ?? 0} open</p>
    </div>
  );

  return (
    <div className="space-y-6 fade-up">
      <Button variant="ghost" size="sm" onClick={onBack}><ArrowLeft size={14} />Scan history</Button>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-center">
        {head(a, 'Earlier scan')}<ArrowRight size={18} className="mx-auto shrink-0 rotate-90 text-slate-600 sm:rotate-0" />{head(b, 'Later scan')}
      </div>
      {(incomplete || a.profile !== b.profile) && (
        <p className="rounded-xl border border-amber-400/20 bg-amber-400/5 px-4 py-3 text-xs leading-relaxed text-amber-200">
          {incomplete ? 'At least one of these scans is partial, so some differences may come from incomplete coverage rather than real changes. ' : ''}
          {a.profile !== b.profile ? 'These scans used different profiles and checked different ports.' : ''}
        </p>
      )}
      {changes === null ? <Card className="flex justify-center p-8"><Spinner /></Card>
        : changes.length === 0 ? <Card className="p-6 text-sm text-slate-400">No differences in open ports or detected services between these scans.</Card>
        : (
          <Card className="divide-y divide-slate-800/80">
            {changes.map((c) => {
              const st = STYLE[c.kind];
              return (
                <div key={c.key} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                  <span className={`flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs ${st.cls}`}><st.icon size={12} />{st.label}</span>
                  <span className="font-mono text-slate-200">{c.key}</span>
                  <span className="ml-auto text-xs text-slate-400">{c.kind === 'changed' ? `${svc(c.before)} -> ${svc(c.after)}` : svc(c.after ?? c.before)}</span>
                </div>
              );
            })}
          </Card>
        )}
    </div>
  );
}
