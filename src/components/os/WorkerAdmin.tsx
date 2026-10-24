import { useEffect, useState } from 'react';
import { Check, Copy, KeyRound, Plus, RefreshCw, ShieldOff, X } from 'lucide-react';
import { callBv, BvWorker, BvWorkerCap, WORKER_STATE_STYLE } from '@/lib/bvos';
import { useAuth } from '@/lib/auth';

type AdminList = { workers: BvWorker[]; endpoint: string };
type Created = { token: string; endpoint: string; worker: { id: string; name: string } };

function setupScript(endpoint: string, token: string, scriptUrl: string) {
  return `# Run on a fresh Ubuntu 24.04 server as a sudo user
curl -fsSL https://get.docker.com | sudo sh
sudo apt-get update && sudo apt-get install -y nodejs
sudo useradd --system --create-home --shell /usr/sbin/nologin bvos || true
sudo usermod -aG docker bvos
sudo mkdir -p /opt/blackveil
sudo curl -fsSLo /opt/blackveil/blackveil-os-worker.mjs ${scriptUrl}
printf 'BLACKVEIL_ENDPOINT=${endpoint}\\nBLACKVEIL_WORKER_TOKEN=${token}\\n' | sudo tee /etc/blackveil-os.env >/dev/null
sudo chmod 600 /etc/blackveil-os.env
sudo tee /etc/systemd/system/blackveil-os-worker.service >/dev/null <<'UNIT'
[Unit]
Description=Blackveil OS execution worker
After=docker.service network-online.target
Requires=docker.service

[Service]
User=bvos
EnvironmentFile=/etc/blackveil-os.env
ExecStart=/usr/bin/node /opt/blackveil/blackveil-os-worker.mjs
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=1 2

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now blackveil-os-worker
sudo journalctl -u blackveil-os-worker -n 20 --no-pager`;
}

function ago(iso: string | null) {
  if (!iso) return 'never';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return new Date(iso).toLocaleString();
}

function CopyBlock({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="rounded-lg border border-slate-800 bg-black/60">
      <div className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5">
        <span className="text-[10px] uppercase tracking-widest text-slate-500">{label}</span>
        <button
          onClick={() => { navigator.clipboard.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }); }}
          className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300 transition"
        >
          {done ? <Check size={12} /> : <Copy size={12} />} {done ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto scrollbar-thin whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-relaxed text-cyan-100">{text}</pre>
    </div>
  );
}

export function OsWorkerAdmin() {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [list, setList] = useState<AdminList | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [created, setCreated] = useState<Created | null>(null);
  const [scriptUrl, setScriptUrl] = useState(`${window.location.origin}/agent/blackveil-os-worker.mjs`);

  async function load() {
    const r = await callBv<AdminList>(token, { action: 'admin_workers' });
    if (r.ok && r.data && Array.isArray(r.data.workers)) { setList(r.data); setError(''); } else if (!r.ok) setError(r.error);
  }

  useEffect(() => {
    if (!token) return;
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [token]);

  async function register() {
    if (!name.trim()) return;
    setBusy(true);
    const r = await callBv<Created>(token, { action: 'admin_worker_create', name: name.trim() });
    setBusy(false);
    if (!r.ok || !r.data?.token) { setError(r.ok ? 'Could not register the worker.' : r.error); return; }
    setCreated(r.data);
    setName('');
    load();
  }

  async function revoke(w: BvWorker) {
    if (!confirm(`Revoke "${w.name}"? It will stop running commands immediately.`)) return;
    const r = await callBv(token, { action: 'admin_worker_revoke', worker_id: w.id });
    if (!r.ok) setError(r.error);
    load();
  }

  const active = (list?.workers ?? []).filter((w) => !w.revoked);
  const revoked = (list?.workers ?? []).filter((w) => w.revoked);

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[10px] uppercase tracking-widest text-slate-500">Execution workers (admin)</p>
        <button onClick={load} className="rounded-md border border-slate-700 p-1 text-slate-400 hover:text-cyan-300 transition" aria-label="Refresh workers">
          <RefreshCw size={12} />
        </button>
      </div>

      {error && <p className="text-xs text-rose-300">{error}</p>}

      {active.length === 0 && !created && (
        <p className="text-xs text-slate-500">No workers registered. Register one below, then run the setup commands on a Linux server with Docker.</p>
      )}

      {active.map((w) => {
        const st = WORKER_STATE_STYLE[w.state];
        const caps = w.caps as Partial<BvWorkerCap>;
        return (
          <div key={w.id} className="rounded-lg border border-slate-800 bg-veil-900/50 px-3 py-2.5 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 shrink-0 rounded-full ${st.dot} ${w.state === 'online' ? 'animate-pulse' : ''}`} />
              <p className="min-w-0 flex-1 truncate text-sm text-slate-100">{w.name}</p>
              <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] ${st.pill}`}>{st.label}</span>
              <button onClick={() => revoke(w)} title="Revoke worker" className="rounded p-1 text-slate-500 hover:text-rose-300 transition">
                <ShieldOff size={13} />
              </button>
            </div>
            <p className="text-[11px] text-slate-400">{w.reason}</p>
            <p className="text-[11px] text-slate-500">
              Last heartbeat {ago(w.last_seen_at)}
              {caps.docker_version ? ` · Docker ${caps.docker_version}` : ''}
              {caps.image ? ` · ${caps.image}` : ''}
              {caps.selftest_uid ? ` · runs as uid ${caps.selftest_uid}` : ''}
              {w.last_seen_at ? ` · network ${caps.network_isolated ? 'isolated' : 'NOT isolated'}` : ''}
              {w.token_prefix ? ` · token ${w.token_prefix}...` : ''}
            </p>
          </div>
        );
      })}

      {created ? (
        <div className="space-y-3 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3">
          <div className="flex items-start gap-2">
            <KeyRound size={14} className="mt-0.5 shrink-0 text-cyan-300" />
            <p className="flex-1 text-xs text-slate-200">
              Worker <span className="text-cyan-200">{created.worker.name}</span> registered. This token is shown only once. Copy the setup script now.
            </p>
            <button onClick={() => setCreated(null)} className="text-slate-500 hover:text-slate-200" aria-label="Close"><X size={14} /></button>
          </div>
          <label className="block text-[11px] text-slate-400">
            Worker program address (must be your published app address)
            <input
              value={scriptUrl}
              onChange={(e) => setScriptUrl(e.target.value.trim())}
              className="mt-1 w-full rounded-md border border-slate-700 bg-black/50 px-2 py-1.5 font-mono text-[11px] text-slate-200 focus:border-cyan-400 focus:outline-none"
            />
          </label>
          <CopyBlock label="Worker token" text={created.token} />
          <CopyBlock label="Server setup script" text={setupScript(created.endpoint, created.token, scriptUrl)} />
        </div>
      ) : (
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && register()}
            placeholder="Worker name, e.g. vps-1"
            maxLength={60}
            className="min-w-0 flex-1 rounded-md border border-slate-700 bg-black/50 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-400 focus:outline-none"
          />
          <button
            onClick={register}
            disabled={busy || !name.trim()}
            className="flex items-center gap-1 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-40 transition"
          >
            <Plus size={12} /> Register
          </button>
        </div>
      )}

      {revoked.length > 0 && <p className="text-[11px] text-slate-600">{revoked.length} revoked worker{revoked.length === 1 ? '' : 's'} hidden.</p>}
    </section>
  );
}
