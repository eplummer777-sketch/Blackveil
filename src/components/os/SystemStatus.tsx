import { useEffect, useState } from 'react';
import { Server, Cpu, HardDrive, Globe, RefreshCw, ShieldCheck, CircleDot } from 'lucide-react';
import { callBv, BvStatus } from '@/lib/bvos';
import { useAuth } from '@/lib/auth';
import { OsWorkerAdmin } from '@/components/os/WorkerAdmin';

export function OsSystemStatus() {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [status, setStatus] = useState<BvStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    const r = await callBv<BvStatus>(token, { action: 'status' });
    setLoading(false);
    if (r.ok) setStatus(r.data ?? null); else setError(r.error);
  }

  useEffect(() => { if (token) load(); }, [token]);

  if (loading && !status) {
    return <div className="flex h-full items-center justify-center text-slate-500"><RefreshCw size={16} className="animate-spin" /></div>;
  }

  return (
    <div className="h-full overflow-y-auto scrollbar-thin p-5 space-y-6 bg-[#080b11] text-slate-200">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-100">
          <Server size={16} className="text-cyan-300" /> System Status
        </div>
        <button onClick={load} className="rounded-md border border-slate-700 p-1.5 text-slate-400 hover:text-cyan-300 transition" aria-label="Refresh">
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
        </button>
      </header>

      {error && <p className="text-xs text-rose-300">{error}</p>}

      {status && (
        <>
          <section>
            <p className="mb-2 text-[10px] uppercase tracking-widest text-slate-500">Isolation sandbox</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <StatusCell icon={ShieldCheck} label="Version" value={status.sandbox.version} />
              <StatusCell icon={Server} label="Isolation" value={status.sandbox.isolation} />
              <StatusCell icon={Globe} label="Network" value={status.sandbox.network} />
              <StatusCell icon={Cpu} label="Privileges" value={status.sandbox.user} />
              <StatusCell icon={CircleDot} label="Filesystem" value={status.sandbox.fs} />
              <StatusCell icon={HardDrive} label="Executors online" value={`${status.workersOnline}`} />
            </div>
          </section>

          {status.admin ? <OsWorkerAdmin /> : (
            <section>
              <p className="mb-2 text-[10px] uppercase tracking-widest text-slate-500">Execution workers</p>
              <p className="text-xs text-slate-400">
                {status.workersOnline > 0
                  ? `${status.workersOnline} of ${status.workersTotal} Linux worker${status.workersTotal === 1 ? '' : 's'} ready.`
                  : 'The Linux execution worker is offline. Commands cannot run until an administrator brings it online.'}
              </p>
            </section>
          )}
        </>
      )}
    </div>
  );
}

function StatusCell({ icon: Icon, label, value }: { icon: typeof Server; label: string; value: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-veil-900/50 px-3 py-2.5">
      <Icon size={14} className="mt-0.5 shrink-0 text-cyan-300" />
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
        <p className="truncate text-xs text-slate-200">{value}</p>
      </div>
    </div>
  );
}
