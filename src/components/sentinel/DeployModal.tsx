import { FormEvent, useEffect, useState } from 'react';
import { Cloud, FlaskConical, Lock, Rocket, X } from 'lucide-react';
import { Button, Input, Label, ErrorBanner } from '@/components/ui';
import { DECOY_CATALOG, DecoyType, callCloudflare } from '@/lib/sentinel';
import type { CfIntegration } from '@/lib/cloudflare';

interface Props {
  onClose: () => void;
  onDeploy: (name: string, type: DecoyType, opts: DeployOpts) => Promise<string | null>;
  token: string;
}

export interface DeployOpts {
  provider: 'simulator' | 'cloud';
  injectFault: boolean;
  cfIntegrationId: string | null;
}

export function DeployModal({ onClose, onDeploy, token }: Props) {
  const [name, setName] = useState('');
  const [type, setType] = useState<DecoyType>('ssh');
  const [provider, setProvider] = useState<'simulator' | 'cloud'>('simulator');
  const [injectFault, setInjectFault] = useState(false);
  const [integrations, setIntegrations] = useState<CfIntegration[]>([]);
  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null);
  const [loadingIntegrations, setLoadingIntegrations] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (provider !== 'cloud') return;
    setLoadingIntegrations(true);
    (async () => {
      const res = await callCloudflare<{ integrations?: CfIntegration[] }>(token, { action: 'list_integrations' });
      setLoadingIntegrations(false);
      if (res.ok && res.data?.integrations) {
        const writable = res.data.integrations.filter((i) => i.status === 'connected' && i.mode === 'write');
        setIntegrations(writable);
        if (writable.length > 0) setSelectedIntegration(writable[0].id);
      }
    })();
  }, [provider, token]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setError('Give your decoy a name.'); return; }
    if (provider === 'cloud' && !selectedIntegration) { setError('Select a Cloudflare integration with write mode.'); return; }
    setBusy(true);
    setError(null);
    const err = await onDeploy(name.trim(), type, { provider, injectFault, cfIntegrationId: selectedIntegration });
    setBusy(false);
    if (err) setError(err);
    else onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm fade-in" onClick={onClose} />
      <form onSubmit={submit} className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto scrollbar-thin rounded-2xl border border-slate-800 bg-veil-900 shadow-2xl fade-up">
        <div className="flex items-start justify-between px-6 py-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Deploy a decoy</h2>
            <p className="text-sm text-slate-400 mt-0.5">Choose simulator for safe testing or cloud for real attacker capture.</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-slate-500 hover:text-slate-200 hover:bg-veil-800"><X size={18} /></button>
        </div>

        <div className="px-6 py-5 space-y-5">
          <div>
            <Label>Decoy name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="e.g. Finance SSH bastion decoy" autoFocus />
          </div>

          <div>
            <Label>Deployment target</Label>
            <div className="grid sm:grid-cols-2 gap-3">
              <button type="button" onClick={() => setProvider('simulator')}
                className={`text-left rounded-xl border p-4 transition-all ${provider === 'simulator' ? 'border-amber-400/60 bg-amber-400/5' : 'border-slate-800 hover:border-slate-600 bg-veil-950/40'}`}>
                <div className="flex items-center gap-2">
                  <FlaskConical size={16} className={provider === 'simulator' ? 'text-amber-300' : 'text-slate-400'} />
                  <span className={`text-sm font-medium ${provider === 'simulator' ? 'text-amber-200' : 'text-slate-200'}`}>Safe simulator</span>
                </div>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">Runs in-process. No network exposure. Events are synthetic and labeled as simulated.</p>
              </button>
              <button type="button" onClick={() => setProvider('cloud')}
                className={`text-left rounded-xl border p-4 transition-all ${provider === 'cloud' ? 'border-cyan-400/60 bg-cyan-400/5 shadow-glow-cyan' : 'border-slate-800 hover:border-slate-600 bg-veil-950/40'}`}>
                <div className="flex items-center gap-2">
                  <Cloud size={16} className={provider === 'cloud' ? 'text-cyan-300' : 'text-slate-400'} />
                  <span className={`text-sm font-medium ${provider === 'cloud' ? 'text-cyan-200' : 'text-slate-200'}`}>Cloud (Cloudflare Worker)</span>
                </div>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">Deploys an isolated Worker on your Cloudflare account. Captures real attacker interactions. Requires a connected integration.</p>
              </button>
            </div>
          </div>

          {provider === 'cloud' && (
            <div>
              <Label>Cloudflare integration</Label>
              {loadingIntegrations ? (
                <p className="text-sm text-slate-400">Loading your integrations...</p>
              ) : integrations.length === 0 ? (
                <div className="rounded-lg border border-amber-400/30 bg-amber-400/5 px-3.5 py-2.5 text-xs text-amber-200">
                  No writable Cloudflare integrations found. Go to Architect and connect a Cloudflare integration with write mode enabled.
                </div>
              ) : (
                <select value={selectedIntegration ?? ''} onChange={(e) => setSelectedIntegration(e.target.value)}
                  className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400/60">
                  {integrations.map((i) => <option key={i.id} value={i.id}>{i.zone_name} · {i.mode}</option>)}
                </select>
              )}
              <p className="mt-2 text-xs text-slate-500">Estimated cost: ~$0.50/month per decoy. You can set a monthly budget in Settings.</p>
            </div>
          )}

          <div>
            <Label>Decoy type</Label>
            <div className="grid sm:grid-cols-2 gap-3">
              {(Object.keys(DECOY_CATALOG) as DecoyType[]).map((t) => {
                const active = t === type;
                return (
                  <button key={t} type="button" onClick={() => setType(t)}
                    className={`text-left rounded-xl border p-3.5 transition-all ${active ? 'border-cyan-400/60 bg-cyan-400/5 shadow-glow-cyan' : 'border-slate-800 hover:border-slate-600 bg-veil-950/40'}`}>
                    <div className="flex items-center justify-between">
                      <span className={`text-sm font-medium ${active ? 'text-cyan-200' : 'text-slate-200'}`}>{DECOY_CATALOG[t].label}</span>
                      <span className="text-[10px] font-mono text-slate-500">{DECOY_CATALOG[t].port}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{DECOY_CATALOG[t].desc}</p>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-veil-950/50 p-4 space-y-2 text-xs text-slate-400">
            <div className="flex items-center gap-2 text-slate-200 text-sm font-medium"><Lock size={14} className="text-cyan-300" /> Isolation guarantees</div>
            {provider === 'simulator' ? (
              <>
                <p>Provider: <span className="text-slate-200">Safe simulator</span> · Exposure: <span className="text-slate-200">Internal only</span></p>
                <p>No real passwords, files, or customer devices are touched. All events are labeled simulated.</p>
              </>
            ) : (
              <>
                <p>Provider: <span className="text-slate-200">Cloudflare Workers</span> · Exposure: <span className="text-slate-200">workers.dev subdomain</span></p>
                <p>Runs in Cloudflare's V8 sandbox: no filesystem, no raw sockets, no outbound calls except to Sentinel's ingest endpoint. Passwords are never captured.</p>
              </>
            )}
          </div>

          {provider === 'simulator' && (
            <label className="flex items-start gap-3 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={injectFault} onChange={(e) => setInjectFault(e.target.checked)} className="mt-1 accent-cyan-400" />
              <span>Test failure handling<span className="block text-xs text-slate-500">Makes this decoy fail its health check, so you can see how Sentinel refuses to mark it as verified.</span></span>
            </label>
          )}

          {error && <ErrorBanner message={error} />}
        </div>

        <div className="flex justify-end gap-2 px-6 py-4 border-t border-slate-800/80">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={busy}><Rocket size={15} /> Deploy and verify</Button>
        </div>
      </form>
    </div>
  );
}
