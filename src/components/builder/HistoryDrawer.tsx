import { useState } from 'react';
import { Drawer, Button, ErrorBanner } from '@/components/ui';
import { WbSnapshot } from '@/lib/builder';
import { History, RotateCcw, Save } from 'lucide-react';

export function HistoryDrawer({ snapshots, onClose, onRestore, onCheckpoint }: {
  snapshots: WbSnapshot[];
  onClose: () => void;
  onRestore: (id: string) => Promise<string | null>;
  onCheckpoint: () => Promise<string | null>;
}) {
  const [confirm, setConfirm] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(key: string, fn: () => Promise<string | null>) {
    setBusy(key);
    setError(null);
    const err = await fn();
    setBusy(null);
    setConfirm(null);
    if (err) setError(err);
  }

  return (
    <Drawer title="Version history" onClose={onClose}
      subtitle={<p className="text-xs text-slate-400">Snapshots are saved automatically before every change. The 30 most recent are kept.</p>}>
      {error && <div className="mb-4"><ErrorBanner message={error} /></div>}
      <Button variant="secondary" size="sm" onClick={() => run('cp', onCheckpoint)} loading={busy === 'cp'}><Save size={14} /> Save checkpoint now</Button>
      <ul className="mt-5 space-y-2">
        {snapshots.map((s) => (
          <li key={s.id} className="rounded-lg border border-slate-800 p-3 flex items-center gap-3">
            <History size={15} className="text-slate-500 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="text-sm text-slate-200 truncate">{s.label}</div>
              <div className="text-xs text-slate-500">{new Date(s.created_at).toLocaleString()}</div>
            </div>
            {confirm === s.id ? (
              <div className="flex gap-1.5">
                <Button size="sm" variant="ghost" onClick={() => setConfirm(null)}>Cancel</Button>
                <Button size="sm" onClick={() => run(s.id, () => onRestore(s.id))} loading={busy === s.id}>Restore</Button>
              </div>
            ) : (
              <Button size="sm" variant="ghost" onClick={() => setConfirm(s.id)}><RotateCcw size={14} /> Restore</Button>
            )}
          </li>
        ))}
        {snapshots.length === 0 && <li className="text-sm text-slate-500">No snapshots yet.</li>}
      </ul>
    </Drawer>
  );
}
