import { useEffect, useState } from 'react';
import { Badge, Button, Drawer, ErrorBanner } from '@/components/ui';
import { wb, errText, WbAiSettings } from '@/lib/builder';
import { useLocalAi } from '@/lib/localAi/LocalAiContext';
import { modelIdFor, vramMB } from '@/lib/localAi/runtime';
import { CheckCircle2, Cpu, Download, HardDrive, Play, Power, ShieldCheck, Trash2, Zap } from 'lucide-react';

export function BlackveilAiPanel({ onClose }: { onClose: () => void }) {
  const ai = useLocalAi();
  const [consent, setConsent] = useState(false);
  const [usage, setUsage] = useState<number | null>(null);

  useEffect(() => {
    wb<WbAiSettings>('get_ai_settings').then((d) => setUsage(d.usage.today)).catch(() => setUsage(null));
  }, []);

  const selected = ai.models.find((m) => m.key === ai.modelKey);
  const isCached = !!ai.cached[ai.modelKey];
  const running = ai.status === 'ready' || ai.status === 'generating';
  const busy = ai.status === 'loading' || ai.status === 'generating';
  const lowStorage = selected && ai.support?.storageFreeMB != null && !isCached && ai.support.storageFreeMB < selected.approxDownloadMB * 1.2;

  return (
    <Drawer title="Blackveil AI" onClose={onClose}
      subtitle={<p className="text-xs text-slate-400">Your private coding assistant. It runs on this device; your prompts and code never go to an AI company.</p>}>
      <div className="space-y-5">
        <div className="rounded-xl border border-slate-800 bg-veil-950/50 p-4 flex items-start gap-3">
          <div className={`h-10 w-10 shrink-0 rounded-xl grid place-content-center ${running ? 'bg-emerald-500/15 text-emerald-300' : 'bg-cyan-500/10 text-cyan-300'}`}><Cpu size={18} /></div>
          <div className="min-w-0 text-sm">
            <div className="font-medium text-slate-100">{statusTitle(ai.status)}</div>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              {running && ai.loadedId ? `Running ${ai.loadedId} on this device.` : statusHint(ai.status, ai.support?.reason)}
            </p>
            {usage != null && <p className="text-[11px] text-slate-500 mt-1.5">{usage} on-device replies used by the builder today. No cost.</p>}
          </div>
        </div>

        {ai.error && <ErrorBanner message={ai.error} />}

        {ai.status === 'loading' && ai.progress && (
          <div className="space-y-2" aria-live="polite">
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div className="h-full bg-cyan-400 transition-all duration-300" style={{ width: `${Math.max(2, Math.round(ai.progress.fraction * 100))}%` }} />
            </div>
            <p className="text-[11px] text-slate-400 break-words">{Math.round(ai.progress.fraction * 100)}% · {ai.progress.text}</p>
            <p className="text-[11px] text-slate-500">Keep this screen open. If the download is interrupted, tap Start again and it continues from the parts already saved.</p>
          </div>
        )}

        {ai.support?.ok && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Model</h3>
            {ai.models.map((m) => {
              const id = modelIdFor(m, ai.support!.f16);
              const vram = vramMB(id);
              const active = m.key === ai.modelKey;
              return (
                <label key={m.key} className={`flex gap-3 rounded-xl border p-3.5 transition ${busy ? 'opacity-60' : 'cursor-pointer'} ${active ? 'border-cyan-400/60 bg-cyan-400/5' : 'border-slate-800 hover:border-slate-700'}`}>
                  <input type="radio" name="model" className="mt-1 accent-cyan-400" checked={active} disabled={busy} onChange={() => ai.setModelKey(m.key)} />
                  <div className="text-sm min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-slate-100">{m.label}</span>
                      {ai.cached[m.key] ? <Badge tone="green">Saved on device</Badge> : <Badge>About {m.approxDownloadMB} MB download</Badge>}
                      {ai.loadedId === id && <Badge tone="cyan">Running</Badge>}
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{m.note}</p>
                    {vram && <p className="text-[11px] text-slate-500 mt-1">Needs about {(vram / 1024).toFixed(1)} GB of graphics memory · {ai.support!.f16 ? '16-bit' : '32-bit'} build for this device</p>}
                  </div>
                  {ai.cached[m.key] && !busy && (
                    <button type="button" onClick={(e) => { e.preventDefault(); ai.clear(m.key); }} title="Delete the saved model from this device"
                      className="self-start p-1.5 rounded-lg text-slate-500 hover:text-rose-300 hover:bg-rose-500/10 transition">
                      <Trash2 size={14} />
                    </button>
                  )}
                </label>
              );
            })}
          </div>
        )}

        {ai.support?.ok && !running && !isCached && (
          <label className="flex gap-3 rounded-xl border border-slate-800 bg-veil-950/40 p-3.5 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" className="mt-0.5 accent-cyan-400" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span className="leading-relaxed">
              Download about {selected?.approxDownloadMB} MB of model files from Hugging Face to this device. This only downloads files; no prompts or code are sent. Use Wi-Fi if you have a data limit.
            </span>
          </label>
        )}
        {lowStorage && <p className="text-xs text-amber-300">This browser reports only about {ai.support!.storageFreeMB} MB free for saved data, which may not be enough.</p>}

        <div className="flex flex-wrap gap-2">
          {!running && ai.support?.ok && (
            <Button onClick={ai.start} loading={ai.status === 'loading'} disabled={ai.status === 'loading' || (!isCached && !consent)}>
              {isCached ? <Play size={15} /> : <Download size={15} />} {ai.status === 'error' ? 'Try again' : isCached ? 'Start Blackveil AI' : 'Download and start'}
            </Button>
          )}
          {running && <Button variant="secondary" onClick={ai.unload} disabled={ai.status === 'generating'}><Power size={15} /> Stop and free memory</Button>}
        </div>

        {running && <QuickTest />}

        <div className="rounded-xl border border-slate-800 p-4 space-y-2 text-xs text-slate-400 leading-relaxed">
          <div className="flex items-center gap-2 text-slate-200 font-medium"><ShieldCheck size={14} className="text-emerald-300" /> Privacy and limits</div>
          <p>Prompts are answered on this device. The builder server prepares the request from your website files (with secrets hidden) and checks every proposed change before you approve it.</p>
          <p>Small on-device models are less capable than large cloud models. Keep requests focused, and review every change before applying it.</p>
          <p className="flex gap-1.5"><HardDrive size={13} className="shrink-0 mt-0.5" /> The browser may delete the saved model if storage runs low, and iOS pauses work when Safari is in the background, so keep this screen open while Blackveil AI is working.</p>
        </div>
      </div>
    </Drawer>
  );
}

function QuickTest() {
  const ai = useLocalAi();
  const [result, setResult] = useState<{ text: string; ms: number; tokens: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [prompt, setPrompt] = useState('Reply exactly: BLACKVEIL LOCAL AI ONLINE');

  async function run() {
    if (!prompt.trim()) return;
    setRunning(true);
    setError(null);
    setResult(null);
    const started = performance.now();
    try {
      const r = await ai.generate({
        purpose: 'device-test', max_tokens: 96, prompt_hash: '', format: 'text',
        messages: [
          { role: 'system', content: 'You are Blackveil AI. Follow the instruction exactly and keep the answer short.' },
          { role: 'user', content: prompt.trim().slice(0, 500) },
        ],
      });
      setResult({ text: r.content.trim(), ms: Math.round(performance.now() - started), tokens: r.usage.output_tokens });
    } catch (e) {
      setError(errText(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Zap size={14} className="text-cyan-300" />
        <span className="text-sm font-medium text-slate-100">Device test</span>
        <Button size="sm" variant="secondary" className="ml-auto" onClick={run} loading={running} disabled={running || !prompt.trim()}>Run test</Button>
      </div>
      <p className="text-xs text-slate-400">Asks the model a short question on this device and shows its exact answer. Nothing is saved. This confirms the model loads and answers; it does not test the editing pipeline.</p>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        rows={2}
        maxLength={500}
        disabled={running}
        aria-label="Device test question"
        className="w-full resize-none rounded-lg border border-slate-800 bg-veil-950/70 px-3 py-2 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/60 transition-colors"
      />
      {error && <ErrorBanner message={error} />}
      {result && (
        <div className="space-y-1.5">
          <p className="text-[11px] text-emerald-300 flex items-center gap-1.5"><CheckCircle2 size={12} /> Real reply in {(result.ms / 1000).toFixed(1)}s · {result.tokens} tokens</p>
          <pre className="text-[11px] text-slate-300 bg-veil-950/70 border border-slate-800 rounded-lg p-2.5 whitespace-pre-wrap break-words">{result.text}</pre>
        </div>
      )}
    </div>
  );
}

function statusTitle(s: string) {
  return ({
    checking: 'Checking this device…', unsupported: 'Not supported on this browser', idle: 'Not running', loading: 'Loading Blackveil AI…',
    ready: 'Ready on this device', generating: 'Working…', error: 'Blackveil AI stopped',
  } as Record<string, string>)[s] ?? s;
}

function statusHint(s: string, reason?: string) {
  if (s === 'unsupported') return reason || 'This browser cannot run on-device AI.';
  if (s === 'loading') return 'Setting up the model in graphics memory. The rest of the app stays usable.';
  if (s === 'error') return 'Fix the problem below, then try again.';
  return 'Choose a model and start it. It only downloads once per device and is reused afterwards.';
}
