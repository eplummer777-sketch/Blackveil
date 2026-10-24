import { useState } from 'react';
import { Cloud, ExternalLink, KeyRound, Loader2, ShieldCheck, X } from 'lucide-react';
import { callCloudflare, CfZone } from '@/lib/cloudflare';

export function CfConnectModal({ token, onClose, onConnected }: {
  token: string;
  onClose: () => void;
  onConnected: (integrationId: string) => void;
}) {
  const [step, setStep] = useState<'input' | 'zones'>('input');
  const [apiToken, setApiToken] = useState('');
  const [zones, setZones] = useState<CfZone[]>([]);
  const [selectedZone, setSelectedZone] = useState<string>('');
  const [mode, setMode] = useState<'read_only' | 'write'>('read_only');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function verify() {
    setLoading(true);
    setError(null);
    const res = await callCloudflare<{ integration?: { id: string }; zones?: CfZone[] }>(token, {
      action: 'connect',
      api_token: apiToken,
      mode,
    });
    setLoading(false);
    if (!res.ok) { setError(res.error); return; }
    if (res.data?.integration?.id) {
      onConnected(res.data.integration.id);
      return;
    }
    if (res.data?.zones?.length === 1) {
      // Single zone — already connected.
      onConnected('');
      return;
    }
    setZones(res.data?.zones ?? []);
    setStep('zones');
  }

  async function connectZone() {
    if (!selectedZone) { setError('Select a zone to continue.'); return; }
    setLoading(true);
    setError(null);
    const res = await callCloudflare<{ integration: { id: string } }>(token, {
      action: 'connect',
      api_token: apiToken,
      mode,
      zone_id: selectedZone,
    });
    setLoading(false);
    if (!res.ok) { setError(res.error); return; }
    onConnected(res.data?.integration?.id ?? '');
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm fade-in" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-2xl border border-slate-800 bg-veil-900 shadow-2xl drawer-in">
        <header className="flex items-center justify-between border-b border-slate-800/80 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-orange-500/10 border border-orange-500/30">
              <Cloud size={18} className="text-orange-300" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Connect Cloudflare</h2>
              <p className="text-xs text-slate-500">Read and harden your zone's security settings</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-slate-500 hover:text-slate-200 hover:bg-veil-800 transition">
            <X size={18} />
          </button>
        </header>

        <div className="px-6 py-5 space-y-5">
          {step === 'input' && (
            <>
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
                <p className="text-sm text-cyan-100/90 leading-relaxed">
                  Create a <span className="font-medium">scoped API token</span> in your Cloudflare dashboard with these permissions for the zone you want to protect:
                </p>
                <ul className="mt-2 space-y-1 text-xs text-slate-400">
                  <li className="flex items-center gap-2"><ShieldCheck size={12} className="text-cyan-300" /> Zone &gt; Zone &gt; <span className="text-slate-200">Read</span> (required)</li>
                  <li className="flex items-center gap-2"><ShieldCheck size={12} className="text-cyan-300" /> Zone &gt; Zone Settings &gt; <span className="text-slate-200">Read</span> (required)</li>
                  <li className="flex items-center gap-2 text-slate-500">Zone &gt; Zone Settings &gt; <span className="text-slate-300">Edit</span> (only needed to apply changes)</li>
                </ul>
                <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer" className="mt-3 inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                  Open Cloudflare API tokens <ExternalLink size={11} />
                </a>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">API token</label>
                <div className="relative">
                  <KeyRound size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="password"
                    value={apiToken}
                    onChange={(e) => setApiToken(e.target.value)}
                    placeholder="Paste your Cloudflare API token"
                    className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 pl-9 pr-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition"
                  />
                </div>
                <p className="mt-1.5 text-xs text-slate-500">Your token is encrypted and stored securely. It never appears in the browser after connecting.</p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-2 uppercase tracking-wider">Mode</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setMode('read_only')}
                    className={`rounded-lg border p-3 text-left transition ${mode === 'read_only' ? 'border-cyan-400/60 bg-cyan-500/10 text-cyan-100' : 'border-slate-700/80 bg-veil-950/50 text-slate-300 hover:border-slate-500'}`}
                  >
                    <p className="text-sm font-medium">Read only</p>
                    <p className="text-xs text-slate-500 mt-0.5">Read settings and find gaps. No changes.</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setMode('write')}
                    className={`rounded-lg border p-3 text-left transition ${mode === 'write' ? 'border-cyan-400/60 bg-cyan-500/10 text-cyan-100' : 'border-slate-700/80 bg-veil-950/50 text-slate-300 hover:border-slate-500'}`}
                  >
                    <p className="text-sm font-medium">Read + Apply</p>
                    <p className="text-xs text-slate-500 mt-0.5">Apply approved changes via the API.</p>
                  </button>
                </div>
              </div>

              {error && <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-200">{error}</div>}

              <button
                onClick={verify}
                disabled={apiToken.length < 10 || loading}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-medium text-veil-950 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Cloud size={16} />}
                {loading ? 'Verifying with Cloudflare...' : 'Verify and connect'}
              </button>
            </>
          )}

          {step === 'zones' && (
            <>
              <p className="text-sm text-slate-300">Your token can access {zones.length} zones. Select the one you want to protect:</p>
              <div className="space-y-2 max-h-72 overflow-y-auto scrollbar-thin">
                {zones.map((z) => (
                  <button
                    key={z.id}
                    onClick={() => setSelectedZone(z.id)}
                    className={`w-full rounded-lg border p-3 text-left transition ${selectedZone === z.id ? 'border-cyan-400/60 bg-cyan-500/10' : 'border-slate-800 bg-veil-950/40 hover:border-slate-600'}`}
                  >
                    <p className="text-sm font-medium text-slate-100">{z.name}</p>
                    <p className="text-xs text-slate-500">{z.account} · {z.status}</p>
                  </button>
                ))}
              </div>
              {error && <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-200">{error}</div>}
              <button
                onClick={connectZone}
                disabled={!selectedZone || loading}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-medium text-veil-950 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Cloud size={16} />}
                {loading ? 'Connecting...' : 'Connect this zone'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
