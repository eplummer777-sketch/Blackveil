import { CheckCircle2, RefreshCw, Search, ShieldAlert, XCircle } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Button, Card } from '@/components/ui';
import { CfSetting, formatValue } from '@/lib/cloudflare';

export function CfSettingsView({ settings, loading, onRefresh }: {
  settings: CfSetting[];
  loading: boolean;
  onRefresh: () => void;
}) {
  const [filter, setFilter] = useState<'all' | 'gaps'>('all');
  const [search, setSearch] = useState('');

  const categories = useMemo(() => {
    const filtered = settings.filter((s) => {
      if (filter === 'gaps' && !s.has_gap) return false;
      if (search && !s.label.toLowerCase().includes(search.toLowerCase()) && !s.category.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
    const map = new Map<string, CfSetting[]>();
    for (const s of filtered) {
      const arr = map.get(s.category) ?? [];
      arr.push(s);
      map.set(s.category, arr);
    }
    return Array.from(map.entries());
  }, [settings, filter, search]);

  const gapCount = settings.filter((s) => s.has_gap).length;

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">Current settings</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            {settings.length} settings read from Cloudflare
            {gapCount > 0 && <span className="text-amber-300"> · {gapCount} gap{gapCount === 1 ? '' : 's'} found</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-slate-800 bg-veil-950/50 p-0.5">
            <button onClick={() => setFilter('all')} className={`rounded-md px-2.5 py-1 text-xs transition ${filter === 'all' ? 'bg-veil-800 text-slate-200' : 'text-slate-500 hover:text-slate-300'}`}>All</button>
            <button onClick={() => setFilter('gaps')} className={`rounded-md px-2.5 py-1 text-xs transition ${filter === 'gaps' ? 'bg-amber-500/15 text-amber-200' : 'text-slate-500 hover:text-slate-300'}`}>Gaps only</button>
          </div>
          <Button variant="secondary" size="sm" onClick={onRefresh} loading={loading}>{!loading && <RefreshCw size={13} />}</Button>
        </div>
      </div>

      <div className="relative mb-4">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search settings..."
          className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition"
        />
      </div>

      <div className="space-y-5">
        {categories.map(([category, items]) => (
          <div key={category}>
            <p className="text-xs uppercase tracking-wider text-slate-500 mb-2">{category}</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {items.map((s) => <SettingRow key={s.key} setting={s} />)}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SettingRow({ setting }: { setting: CfSetting }) {
  if (setting.error) {
    return (
      <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
        <div className="flex items-center gap-2">
          <XCircle size={14} className="text-rose-300 shrink-0" />
          <p className="text-sm font-medium text-slate-200 truncate">{setting.label}</p>
        </div>
        <p className="mt-1 text-xs text-rose-300/80">{setting.error}</p>
      </div>
    );
  }

  return (
    <div className={`rounded-lg border p-3 transition ${setting.has_gap ? 'border-amber-500/30 bg-amber-500/5' : 'border-slate-800 bg-veil-950/40'}`}>
      <div className="flex items-center gap-2">
        {setting.has_gap ? <ShieldAlert size={14} className="text-amber-300 shrink-0" /> : <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />}
        <p className="text-sm font-medium text-slate-200 truncate flex-1">{setting.label}</p>
      </div>
      <div className="mt-2 flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-wider text-slate-600">Current</p>
          <p className={`text-sm font-mono-tight truncate ${setting.has_gap ? 'text-amber-200' : 'text-slate-300'}`}>{formatValue(setting.value)}</p>
        </div>
        {setting.has_gap && (
          <div className="text-right min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-slate-600">Recommended</p>
            <p className="text-sm font-mono-tight truncate text-cyan-200">{formatValue(setting.recommended)}</p>
          </div>
        )}
      </div>
    </div>
  );
}
