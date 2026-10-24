import { useState } from 'react';
import { FileWarning, FlaskConical, Repeat, Undo2, ChevronDown } from 'lucide-react';
import { Badge, SeverityPill, Button, Drawer, Input, Label, ErrorBanner, EmptyState } from '@/components/ui';
import { EndpointThreat, STATUS_META, recommendedAction, filePath, isTestSignature, formatWhen, control } from '@/lib/endpoint';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
const sev = (s: string): Sev => (['critical', 'high', 'medium', 'low'].includes(s) ? (s as Sev) : 'info');

function RestoreDrawer({ token, threat, onClose, onDone }: { token: string; threat: EndpointThreat; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async () => {
    setBusy(true); setError('');
    const r = await control(token, { action: 'restore', threatId: threat.id, confirmName: typed });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    onDone(); onClose();
  };
  return (
    <Drawer title="Restore from quarantine" subtitle={threat.name} onClose={onClose}>
      <div className="space-y-4 text-sm text-slate-300">
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        <p>Only restore if you are certain this is a false positive. Restoring puts the file back where it was and Microsoft Defender may detect it again on the next scan.</p>
        <div className="rounded-lg bg-veil-950 border border-slate-800 p-3 font-mono text-xs space-y-1 break-all">
          {threat.resources.map((r) => <div key={r}>{filePath(r)}</div>)}
          <div className="text-slate-500">sha256: {threat.sha256 ?? 'not provided by engine'}</div>
        </div>
        <div><Label>Type the threat name to confirm</Label><Input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={threat.name} /></div>
        <Button variant="danger" onClick={submit} loading={busy} disabled={typed !== threat.name} full>Restore file</Button>
      </div>
    </Drawer>
  );
}

function ThreatRow({ t, onRestore }: { t: EndpointThreat; onRestore: () => void }) {
  const [open, setOpen] = useState(false);
  const meta = STATUS_META[t.status];
  return (
    <div className="rounded-xl border border-slate-800 bg-veil-900/60 hover:border-slate-700 transition-colors">
      <button type="button" onClick={() => setOpen(!open)} className="w-full text-left p-4 flex flex-col md:flex-row md:items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-slate-100 truncate">{t.name}</span>
            {isTestSignature(t.name) && <Badge tone="slate"><FlaskConical size={11} /> Test file (EICAR)</Badge>}
            {t.times_seen > 1 && <Badge tone="amber"><Repeat size={11} /> Seen {t.times_seen}x</Badge>}
          </div>
          <p className="text-xs text-slate-500 font-mono truncate mt-1">{t.resources[0] ? filePath(t.resources[0]) : 'Location not reported'}{t.resources.length > 1 ? ` +${t.resources.length - 1} more` : ''}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityPill severity={sev(t.severity)} />
          <Badge tone={meta.tone}>{meta.label}</Badge>
          <ChevronDown size={16} className={`text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 grid md:grid-cols-2 gap-4 text-sm border-t border-slate-800 pt-4">
          <dl className="space-y-2">
            {[
              ['Classification', t.category ?? 'Unknown'],
              ['Detection source', t.detection_source],
              ['Engine action', t.engine_action ?? 'None yet'],
              ['First seen', formatWhen(t.first_seen_at)],
              ['Last seen', formatWhen(t.last_seen_at)],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-3"><dt className="w-36 text-slate-500 shrink-0">{k}</dt><dd className="text-slate-200">{v}</dd></div>
            ))}
            <div className="flex gap-3"><dt className="w-36 text-slate-500 shrink-0">SHA-256</dt><dd className="text-slate-300 font-mono text-xs break-all">{t.sha256 ?? 'Not provided by engine'}</dd></div>
          </dl>
          <div className="space-y-3">
            <div className="rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-3">
              <p className="text-xs uppercase tracking-wide text-cyan-300 mb-1">Recommended action</p>
              <p className="text-slate-200">{recommendedAction(t)}</p>
            </div>
            {t.verification && (
              <div className="rounded-lg bg-veil-950 border border-slate-800 p-3">
                <p className="text-xs uppercase tracking-wide text-slate-400 mb-1">Verification - {formatWhen(t.verification.checked_at)}</p>
                <ul className="list-disc pl-4 text-slate-300 space-y-1">{t.verification.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              </div>
            )}
            {t.resources.length > 1 && (
              <div className="text-xs font-mono text-slate-400 space-y-1 break-all">{t.resources.map((r) => <div key={r}>{filePath(r)}</div>)}</div>
            )}
            {t.status === 'quarantined' && (
              <Button variant="ghost" size="sm" onClick={onRestore}><Undo2 size={14} /> Restore (false positive)</Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function ThreatList({ token, threats, onChange }: { token: string; threats: EndpointThreat[]; onChange: () => void }) {
  const [restoring, setRestoring] = useState<EndpointThreat | null>(null);
  if (threats.length === 0) {
    return <EmptyState icon={<FileWarning size={22} />} title="No detections recorded" hint="Results appear here after the agent completes a scan. No detections does not guarantee the device is clean." />;
  }
  return (
    <div className="space-y-3">
      {threats.map((t) => <ThreatRow key={t.id} t={t} onRestore={() => setRestoring(t)} />)}
      {restoring && <RestoreDrawer token={token} threat={restoring} onClose={() => setRestoring(null)} onDone={onChange} />}
    </div>
  );
}
