import { FormEvent, useState } from 'react';
import { Cpu, Play, ShieldCheck } from 'lucide-react';
import { Button, Card, Input, Label } from '@/components/ui';
import { callNet, NATIVE_PROFILES, NetProfile, NetScan, PROFILE_INFO } from '@/lib/network';

export function NetworkScanForm({ token, paused, onStarted }: { token: string; paused: boolean; onStarted: (s: NetScan) => void }) {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<NetProfile>('native_quick');
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    const r = await callNet<{ scan: NetScan }>(token, { action: 'start', target: target.trim(), profile, authorized });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    if (!r.data?.scan?.id) return setError('Unexpected response from the scanner.');
    setTarget('');
    setAuthorized(false);
    onStarted(r.data.scan);
  };

  return (
    <Card className="p-6">
      <form onSubmit={submit} className="space-y-6">
        <div>
          <Label>Target</Label>
          <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="203.0.113.10, 10.20.0.0/28 or server.example.com" maxLength={253} spellCheck={false} />
          <p className="mt-2 text-xs leading-relaxed text-slate-500">
            Hostnames must be verified in Proof-of-Breach. IP addresses, ranges and private or lab networks must be approved for your account by an administrator.
          </p>
        </div>

        <div>
          <Label>Blackveil Discovery Engine</Label>
          <div className="grid gap-3 sm:grid-cols-2">
            {NATIVE_PROFILES.map((p) => {
              const info = PROFILE_INFO[p];
              const sel = profile === p;
              return (
                <button key={p} type="button" onClick={() => setProfile(p)}
                  className={`rounded-xl border p-4 text-left transition duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-400/40 ${sel ? 'border-cyan-400/60 bg-cyan-400/10' : 'border-slate-800 bg-veil-900/40 hover:-translate-y-0.5 hover:border-slate-600'}`}>
                  <span className="flex items-center gap-2 text-sm font-medium text-slate-100"><Cpu size={13} className="text-cyan-300" />{info.label}</span>
                  <span className="mt-1 block text-xs leading-relaxed text-slate-400">{info.hint}</span>
                </button>
              );
            })}
          </div>
          <p className="mt-2 text-xs leading-relaxed text-slate-500">Finds live hosts, open TCP ports and the services behind them, then Proof-of-Breach AI explains the risks and recommends fixes.</p>
        </div>

        <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/5 p-4">
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5 h-4 w-4 accent-cyan-400" />
          <span className="text-xs leading-relaxed text-slate-300">
            I own this target or have explicit written authorization to scan it. I understand scans are logged and that unauthorized scanning may be illegal.
          </span>
        </label>

        {error && <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</p>}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="flex items-center gap-2 text-xs text-slate-500"><ShieldCheck size={14} className="text-emerald-400" />Targets are checked on the server before any scan runs.</p>
          <Button type="submit" loading={busy} disabled={paused || !authorized || !target.trim()}><Play size={14} />Start scan</Button>
        </div>
      </form>
    </Card>
  );
}
