import { useState } from 'react';
import { Copy, Check, Download, Terminal, ShieldAlert } from 'lucide-react';
import { Drawer, Button, Input, Label, ErrorBanner } from '@/components/ui';
import { AGENT_SCRIPT_PATH, AGENT_SERVER_URL, SCAN_LABEL, ScanType, EndpointDevice, control } from '@/lib/endpoint';

const SCOPES: ScanType[] = ['quick', 'full', 'custom'];

function ScopeFields({ scopes, setScopes, paths, setPaths }: {
  scopes: ScanType[]; setScopes: (s: ScanType[]) => void; paths: string; setPaths: (p: string) => void;
}) {
  return (
    <div className="space-y-3">
      <Label>Scans this device allows</Label>
      <div className="flex flex-wrap gap-2">
        {SCOPES.map((s) => {
          const on = scopes.includes(s);
          return (
            <button key={s} type="button"
              onClick={() => setScopes(on ? scopes.filter((x) => x !== s) : [...scopes, s])}
              className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${on ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-200' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>
              {SCAN_LABEL[s]}
            </button>
          );
        })}
      </div>
      {scopes.includes('custom') && (
        <div>
          <Label>Folders allowed for folder scans (one per line)</Label>
          <textarea value={paths} onChange={(e) => setPaths(e.target.value)} rows={3}
            placeholder={'C:\\Users\\Alex\\Downloads'}
            className="w-full rounded-lg bg-veil-900 border border-slate-700 px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:ring-2 focus:ring-cyan-400/40" />
        </div>
      )}
    </div>
  );
}

const toPaths = (s: string) => s.split('\n').map((p) => p.trim()).filter(Boolean);

function CopyBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <Label>{label}</Label>
      <div className="relative">
        <pre className="rounded-lg bg-veil-950 border border-slate-800 p-3 pr-10 text-xs text-slate-200 font-mono whitespace-pre-wrap break-all">{text}</pre>
        <button type="button" aria-label="Copy"
          onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); }}
          className="absolute top-2 right-2 p-1.5 rounded-md text-slate-400 hover:text-cyan-300 hover:bg-veil-800">
          {copied ? <Check size={14} /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  );
}

export function EnrollDrawer({ token, onClose, onDone }: { token: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<ScanType[]>(['quick', 'full']);
  const [paths, setPaths] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [deviceToken, setDeviceToken] = useState('');

  const submit = async () => {
    setBusy(true); setError('');
    const r = await control<{ deviceId: string; token: string }>(token, { action: 'enroll', name, scopes, paths: toPaths(paths) });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    if (typeof r.data?.token !== 'string') return setError('Unexpected response from server.');
    setDeviceToken(r.data.token);
    onDone();
  };

  const command = `Set-ExecutionPolicy -Scope Process Bypass -Force\n.\\blackveil-agent.ps1 -Server "${AGENT_SERVER_URL}"`;

  return (
    <Drawer title="Connect a Windows device" subtitle="Uses Microsoft Defender already built into Windows" onClose={onClose} wide>
      {!deviceToken ? (
        <div className="space-y-5">
          {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
          <div><Label>Device name</Label><Input value={name} maxLength={60} onChange={(e) => setName(e.target.value)} placeholder="Office laptop" /></div>
          <ScopeFields scopes={scopes} setScopes={setScopes} paths={paths} setPaths={setPaths} />
          <p className="text-xs text-slate-500">Scans are limited to what you allow here. The agent never runs suspicious files and never uploads file contents.</p>
          <Button onClick={submit} loading={busy} disabled={!name.trim() || scopes.length === 0} full>Create device key</Button>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-200 flex gap-2">
            <ShieldAlert size={16} className="shrink-0 mt-0.5" /> This device key is shown only once. You will paste it when the agent asks for it.
          </div>
          <CopyBlock label="Device key" text={deviceToken} />
          <ol className="space-y-4 text-sm text-slate-300">
            <li className="flex gap-3"><span className="text-cyan-300 font-semibold">1</span>
              <div className="flex-1 space-y-2">On the Windows PC, download the agent script.
                <a href={AGENT_SCRIPT_PATH} download className="inline-flex items-center gap-2 text-cyan-300 hover:text-cyan-200"><Download size={14} /> blackveil-agent.ps1</a>
              </div></li>
            <li className="flex gap-3"><span className="text-cyan-300 font-semibold">2</span>
              <div className="flex-1">Open <span className="text-slate-100">Windows PowerShell as Administrator</span> and go to the download folder. Windows will ask you to confirm administrator access; the agent never elevates itself.</div></li>
            <li className="flex gap-3"><span className="text-cyan-300 font-semibold">3</span>
              <div className="flex-1 space-y-2"><span className="flex items-center gap-2"><Terminal size={14} /> Run:</span><CopyBlock label="" text={command} /></div></li>
            <li className="flex gap-3"><span className="text-cyan-300 font-semibold">4</span>
              <div className="flex-1">Paste the device key when asked. Keep the window open while scanning and remediating. The device shows as online here within a minute.</div></li>
          </ol>
          <Button variant="secondary" onClick={onClose} full>Done</Button>
        </div>
      )}
    </Drawer>
  );
}

export function ScopeDrawer({ token, device, onClose, onDone }: { token: string; device: EndpointDevice; onClose: () => void; onDone: () => void }) {
  const [scopes, setScopes] = useState<ScanType[]>(device.allowed_scopes);
  const [paths, setPaths] = useState(device.allowed_paths.join('\n'));
  const [schedule, setSchedule] = useState(device.scan_schedule);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const save = async () => {
    setBusy(true); setError('');
    const r = await control(token, { action: 'update_scope', deviceId: device.id, scopes, paths: toPaths(paths), schedule });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    onDone(); onClose();
  };
  return (
    <Drawer title="Scan permissions" subtitle={device.name} onClose={onClose}>
      <div className="space-y-5">
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        <ScopeFields scopes={scopes} setScopes={setScopes} paths={paths} setPaths={setPaths} />
        <div className="space-y-2">
          <Label>Automatic scan schedule</Label>
          <div className="flex gap-2">
            {(['off', 'daily', 'weekly'] as const).map((s) => (
              <button key={s} type="button" onClick={() => setSchedule(s)}
                className={`px-3 py-1.5 rounded-lg text-xs border capitalize transition-colors ${schedule === s ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-200' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>
                {s}
              </button>
            ))}
          </div>
          <p className="text-xs text-slate-500">Scheduled scans are queued by Blackveil's server and run a Quick scan (or Full if Quick is not allowed) the next time the agent is running. Scans never quarantine or remove anything without your approval.</p>
        </div>
        <Button onClick={save} loading={busy} disabled={scopes.length === 0} full>Save permissions</Button>
      </div>
    </Drawer>
  );
}
