import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, Circle, Loader2, AlertTriangle, RotateCcw, FileDown, ShieldCheck } from 'lucide-react';
import { Drawer, Button, Badge, SeverityPill, ErrorBanner } from '@/components/ui';
import {
  EndpointDevice, EndpointThreat, EndpointJob, ScanType, SCAN_LABEL, STATUS_META, JOB_DONE,
  control, getJob, isAgentOnline, filePath, isTestSignature, buildReport, downloadText,
} from '@/lib/endpoint';

type Step = 'confirm' | 'scan' | 'findings' | 'remediate' | 'verify' | 'report';
const STEPS: { id: Step; label: string }[] = [
  { id: 'confirm', label: 'Confirm' }, { id: 'scan', label: 'Scan' }, { id: 'findings', label: 'Findings' },
  { id: 'remediate', label: 'Remediate' }, { id: 'verify', label: 'Verify' }, { id: 'report', label: 'Report' },
];
const NEEDS_VERIFY = ['quarantined', 'removed', 'failed'];

interface Props {
  token: string;
  device: EndpointDevice;
  threats: EndpointThreat[];
  refresh: () => Promise<void>;
  onClose: () => void;
}

export function ScanRemediateFlow({ token, device, threats, refresh, onClose }: Props) {
  const [step, setStep] = useState<Step>('confirm');
  const [scanType, setScanType] = useState<ScanType>(device.allowed_scopes[0] ?? 'quick');
  const [path, setPath] = useState(device.allowed_paths[0] ?? '');
  const [job, setJob] = useState<EndpointJob | null>(null);
  const [history, setHistory] = useState<EndpointJob[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [ack, setAck] = useState(false);
  const [reboot, setReboot] = useState(false);
  const online = isAgentOnline(device);
  const pending = threats.filter((t) => t.status === 'awaiting_approval');
  const toVerify = threats.filter((t) => NEEDS_VERIFY.includes(t.status));
  const finishRef = useRef<(j: EndpointJob) => void>(() => {});

  useEffect(() => {
    if (!job || JOB_DONE.includes(job.status)) return;
    const id = setInterval(async () => {
      const latest = await getJob(job.id);
      if (!latest) return;
      setJob(latest);
      if (JOB_DONE.includes(latest.status)) finishRef.current(latest);
    }, 4000);
    return () => clearInterval(id);
  }, [job]);

  const start = async (body: Record<string, unknown>, next: Step) => {
    setBusy(true); setError('');
    const r = await control<{ jobId: string }>(token, body);
    setBusy(false);
    if (!r.ok) { setError(r.error); return false; }
    const j = typeof r.data?.jobId === 'string' ? await getJob(r.data.jobId) : null;
    if (!j) { setError('The job was created but could not be loaded. Refresh and try again.'); return false; }
    setJob(j); setStep(next);
    return true;
  };

  const runVerify = () => start({ action: 'verify', deviceId: device.id }, 'verify');

  finishRef.current = async (j) => {
    setHistory((h) => [...h, j]);
    await refresh();
    if (j.status !== 'succeeded') {
      setError(j.error ?? (j.status === 'expired' ? 'The agent did not respond in time. Check the agent window is still open.' : `The ${j.kind} did not complete.`));
      setJob(null);
      setStep(j.kind === 'scan' ? 'confirm' : 'report');
      return;
    }
    setJob(null);
    if (j.kind === 'scan') setStep('findings');
    if (j.kind === 'remediate') {
      setReboot(j.result?.rebootRequired === true);
      await runVerify();
    }
    if (j.kind === 'verify') setStep('report');
  };

  const cancel = async () => {
    if (!job || job.status !== 'queued') return;
    const r = await control(token, { action: 'cancel_job', jobId: job.id });
    if (!r.ok) return setError(r.error);
    setJob(null); setStep('confirm');
  };

  const idx = STEPS.findIndex((s) => s.id === step);
  const running = job && !JOB_DONE.includes(job.status);

  return (
    <Drawer title="Scan & Remediate" subtitle={`${device.name} - Microsoft Defender`} onClose={onClose} wide>
      <ol className="flex items-center gap-1 mb-6 overflow-x-auto">
        {STEPS.map((s, i) => (
          <li key={s.id} className="flex items-center gap-1 shrink-0">
            {i < idx ? <CheckCircle2 size={16} className="text-emerald-400" /> : <Circle size={16} className={i === idx ? 'text-cyan-300' : 'text-slate-600'} />}
            <span className={`text-xs ${i === idx ? 'text-slate-100' : 'text-slate-500'}`}>{s.label}</span>
            {i < STEPS.length - 1 && <span className="w-4 h-px bg-slate-700 mx-1" />}
          </li>
        ))}
      </ol>

      {error && <div className="mb-4"><ErrorBanner message={error} onDismiss={() => setError('')} /></div>}

      {running && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 mb-4 flex items-start gap-3">
          <Loader2 size={18} className="text-cyan-300 animate-spin mt-0.5" />
          <div className="flex-1 text-sm">
            <p className="text-slate-100">{job.status === 'queued' ? 'Waiting for the agent to pick up the job...' : `Agent is running the ${job.kind}...`}</p>
            <p className="text-slate-400 text-xs mt-1">Full scans can take hours. You can close this panel; progress is saved.</p>
          </div>
          {job.status === 'queued' && <Button size="sm" variant="ghost" onClick={cancel}>Cancel</Button>}
        </div>
      )}

      {step === 'confirm' && (
        <div className="space-y-5 text-sm">
          {!online && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-amber-200 flex gap-2">
              <AlertTriangle size={16} className="shrink-0 mt-0.5" /> The agent on this device is offline. Start it in an Administrator PowerShell window first.
            </div>
          )}
          {online && device.engine_status?.antivirusEnabled === false && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 text-rose-200 flex gap-2">
              <AlertTriangle size={16} className="shrink-0 mt-0.5" /> Microsoft Defender is disabled on this PC, so it cannot scan. Turn it on in Windows Security first.
            </div>
          )}
          <div>
            <p className="text-slate-400 mb-2">Scan type (limited to what this device allows)</p>
            <div className="flex flex-wrap gap-2">
              {device.allowed_scopes.map((s) => (
                <button key={s} type="button" onClick={() => setScanType(s)}
                  className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${scanType === s ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-200' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>
                  {SCAN_LABEL[s]}
                </button>
              ))}
            </div>
          </div>
          {scanType === 'custom' && (
            <select value={path} onChange={(e) => setPath(e.target.value)}
              className="w-full rounded-lg bg-veil-900 border border-slate-700 px-3 py-2 text-sm text-slate-200 font-mono">
              {device.allowed_paths.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          )}
          <p className="text-xs text-slate-500">Microsoft Defender updates its signatures, then scans. Files are only hashed and inspected, never opened or uploaded.</p>
          <Button full disabled={!online || device.engine_status?.antivirusEnabled === false} loading={busy}
            onClick={() => start({ action: 'scan', deviceId: device.id, scanType, ...(scanType === 'custom' ? { path } : {}) }, 'scan')}>
            Start {SCAN_LABEL[scanType].toLowerCase()}
          </Button>
        </div>
      )}

      {step === 'findings' && (
        <div className="space-y-4 text-sm">
          {pending.length === 0 ? (
            <div className="rounded-xl border border-slate-800 p-4 text-slate-300">
              <p className="text-slate-100 font-medium">No active detections in this scan.</p>
              <p className="text-slate-400 mt-1">This means Microsoft Defender found nothing it recognizes; it does not guarantee the device is free of all malware.</p>
              {toVerify.length > 0 && <p className="text-slate-400 mt-2">{toVerify.length} earlier threat(s) still need verification.</p>}
            </div>
          ) : (
            <>
              <p className="text-slate-300">Review the evidence. Approving will quarantine and remove <span className="text-slate-100 font-medium">all {pending.length}</span> active threat(s) below; Defender acts on all active threats together.</p>
              {pending.map((t) => (
                <div key={t.id} className="rounded-lg border border-slate-800 bg-veil-950 p-3 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-slate-100 font-medium">{t.name}</span>
                    <SeverityPill severity={(['critical', 'high', 'medium', 'low'].includes(t.severity) ? t.severity : 'info') as 'info'} />
                    {isTestSignature(t.name) && <Badge tone="slate">Test file</Badge>}
                  </div>
                  <p className="text-xs text-slate-400">{t.category ?? 'Unknown classification'} - {t.detection_source}</p>
                  {t.resources.map((r) => <p key={r} className="text-xs font-mono text-slate-300 break-all">{filePath(r)}</p>)}
                  <p className="text-xs font-mono text-slate-500 break-all">sha256: {t.sha256 ?? 'not provided by engine'}</p>
                </div>
              ))}
              <label className="flex items-start gap-2 text-slate-300 cursor-pointer">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-1 accent-cyan-400" />
                I authorize Microsoft Defender to quarantine and remove these items. Quarantined files can be restored later.
              </label>
            </>
          )}
          <div className="flex gap-2">
            {pending.length > 0 && (
              <Button variant="danger" disabled={!ack} loading={busy}
                onClick={() => start({ action: 'approve_remediation', deviceId: device.id, threatIds: pending.map((t) => t.id), acknowledged: true }, 'remediate')}>
                Approve & remediate
              </Button>
            )}
            {pending.length === 0 && toVerify.length > 0 && <Button loading={busy} onClick={runVerify}>Verify earlier threats</Button>}
            {pending.length === 0 && <Button variant="secondary" onClick={() => setStep('report')}>View report</Button>}
          </div>
        </div>
      )}

      {step === 'report' && (
        <div className="space-y-4 text-sm">
          {reboot && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-amber-200 flex gap-2">
              <RotateCcw size={16} className="shrink-0 mt-0.5" /> Windows needs a restart to finish removal. Restart, start the agent again, then verify.
            </div>
          )}
          {threats.length === 0 ? <p className="text-slate-400">No threats recorded for this device.</p> : threats.map((t) => (
            <div key={t.id} className="flex items-start justify-between gap-3 rounded-lg border border-slate-800 p-3">
              <div className="min-w-0">
                <p className="text-slate-100 truncate">{t.name}</p>
                {t.verification?.reasons.map((r) => <p key={r} className="text-xs text-slate-400">{r}</p>)}
              </div>
              <Badge tone={STATUS_META[t.status].tone}>{STATUS_META[t.status].label}</Badge>
            </div>
          ))}
          <p className="text-xs text-slate-500 flex gap-2"><ShieldCheck size={14} className="shrink-0" /> Verified clean means the detected files, active detections and startup entries are gone. It is not a guarantee the device has no other malware.</p>
          <div className="flex gap-2">
            <Button onClick={() => downloadText(`blackveil-report-${device.name.replace(/[^\w-]/g, '_')}.txt`, buildReport(device, threats, history))}>
              <FileDown size={14} /> Download report
            </Button>
            {threats.some((t) => t.status === 'failed') && <Button variant="secondary" onClick={() => { setStep('confirm'); setAck(false); }}>Scan again</Button>}
          </div>
        </div>
      )}
    </Drawer>
  );
}
