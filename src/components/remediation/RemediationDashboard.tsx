import { useCallback, useEffect, useState } from 'react';
import { Monitor, Plus, Radar, ShieldCheck, ShieldOff, Settings2, History, Trash2, Wifi, WifiOff, Laptop } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { Card, Button, Badge, Spinner, EmptyState, ErrorBanner, Drawer } from '@/components/ui';
import {
  EndpointDevice, EndpointThreat, EndpointAudit, EndpointJob, EndpointIncident, loadEndpointData, isAgentOnline, formatWhen, control, JOB_DONE,
  monitoringState,
} from '@/lib/endpoint';
import { IncidentList } from '@/components/remediation/IncidentList';
import { EnrollDrawer, ScopeDrawer } from '@/components/remediation/DeviceSetup';
import { ThreatList } from '@/components/remediation/ThreatList';
import { ScanRemediateFlow } from '@/components/remediation/ScanRemediateFlow';

type Panel = 'enroll' | 'scope' | 'flow' | 'audit' | 'revoke' | null;

const SCAN_STATUS: Record<string, string> = {
  threats_found: 'Threats found',
  no_active_detections: 'No active detections',
  failed: 'Scan failed',
};

function DeviceCard({ d, threats, active, onSelect }: { d: EndpointDevice; threats: EndpointThreat[]; active: boolean; onSelect: () => void }) {
  const online = isAgentOnline(d);
  const open = threats.filter((t) => ['detected', 'awaiting_approval', 'failed'].includes(t.status)).length;
  return (
    <button type="button" onClick={onSelect}
      className={`text-left rounded-xl border p-4 transition-all ${active ? 'border-cyan-400/50 bg-cyan-500/5' : 'border-slate-800 bg-veil-900/60 hover:border-slate-700'}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-slate-100 font-medium truncate"><Laptop size={16} className="text-slate-400" />{d.name}</span>
        {online ? <Badge tone="green"><Wifi size={11} /> Online</Badge> : <Badge tone="slate"><WifiOff size={11} /> Offline</Badge>}
      </div>
      <div className="mt-2"><Badge tone={monitoringState(d).tone}>{monitoringState(d).label}</Badge></div>
      <p className="text-xs text-slate-500 mt-2">{d.os_version ?? 'Windows - agent not yet connected'}</p>
      <p className="text-xs text-slate-400 mt-1">{d.last_scan_at ? `Last scan: ${formatWhen(d.last_scan_at)}` : 'Not scanned'}</p>
      {open > 0 && <p className="text-xs text-rose-300 mt-1">{open} item(s) need attention</p>}
    </button>
  );
}

export function RemediationDashboard({ initialTab = 'threats' }: { initialTab?: 'threats' | 'incidents' }) {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [devices, setDevices] = useState<EndpointDevice[]>([]);
  const [threats, setThreats] = useState<EndpointThreat[]>([]);
  const [audit, setAudit] = useState<EndpointAudit[]>([]);
  const [jobs, setJobs] = useState<EndpointJob[]>([]);
  const [incidents, setIncidents] = useState<EndpointIncident[]>([]);
  const [tab, setTab] = useState<'threats' | 'incidents'>(initialTab);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [panel, setPanel] = useState<Panel>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const r = await loadEndpointData();
    setError(r.error ?? '');
    setDevices(r.devices); setThreats(r.threats); setAudit(r.audit); setJobs(r.jobs); setIncidents(r.incidents);
    setSelectedId((cur) => (cur && r.devices.some((d) => d.id === cur) ? cur : r.devices[0]?.id ?? null));
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  const device = devices.find((d) => d.id === selectedId) ?? null;
  const deviceThreats = threats.filter((t) => t.device_id === selectedId);
  const activeJob = jobs.find((j) => j.device_id === selectedId && !JOB_DONE.includes(j.status));
  const engine = device?.engine_status ?? {};
  const monitor = device ? monitoringState(device) : null;
  const deviceIncidents = incidents.filter((i) => i.device_id === selectedId);
  const openIncidents = deviceIncidents.filter((i) => i.status !== 'resolved').length;

  const revoke = async () => {
    if (!device) return;
    setBusy(true);
    const r = await control(token, { action: 'revoke', deviceId: device.id });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setPanel(null);
    refresh();
  };

  if (loading) return <div className="flex justify-center py-16"><Spinner /></div>;

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      {devices.length === 0 ? (
        <Card className="p-8">
          <EmptyState icon={<Monitor size={24} />} title="Setup required: connect a device"
            hint="Real scanning and removal run on your Windows PC through Microsoft Defender. A web browser cannot scan or delete files on your computer, so a small agent script is needed. No results are shown until a device is connected."
            action={<Button onClick={() => setPanel('enroll')}><Plus size={14} /> Connect Windows device</Button>} />
        </Card>
      ) : (
        <>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {devices.map((d) => (
              <DeviceCard key={d.id} d={d} threats={threats.filter((t) => t.device_id === d.id)} active={d.id === selectedId} onSelect={() => setSelectedId(d.id)} />
            ))}
            {devices.length < 5 && (
              <button type="button" onClick={() => setPanel('enroll')}
                className="rounded-xl border border-dashed border-slate-700 p-4 text-sm text-slate-400 hover:border-cyan-400/50 hover:text-cyan-300 transition-colors flex items-center justify-center gap-2">
                <Plus size={16} /> Add device
              </button>
            )}
          </div>

          {device && (
            <Card className="p-5 space-y-5">
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">{device.name}</h2>
                  <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400 mt-2">
                    <span>OS: {device.os_version ?? 'Windows'}</span>
                    <span>Last scan: {formatWhen(device.last_scan_at)}{device.last_scan_status ? ` - ${SCAN_STATUS[device.last_scan_status] ?? device.last_scan_status}` : ''}</span>
                    <span>Agent seen: {formatWhen(device.last_seen_at)}</span>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-3">
                    {engine.antivirusEnabled === undefined ? <Badge tone="slate">Defender status unknown</Badge>
                      : engine.antivirusEnabled ? <Badge tone="green"><ShieldCheck size={11} /> Defender active</Badge>
                      : <Badge tone="rose"><ShieldOff size={11} /> Defender disabled - not supported</Badge>}
                    {engine.realTimeProtection === false && <Badge tone="amber">Real-time protection off</Badge>}
                    {engine.signatureVersion && <Badge tone="slate">Signatures {engine.signatureVersion}</Badge>}
                    {activeJob && <Badge tone="cyan">{activeJob.kind} {activeJob.status}</Badge>}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => setPanel('flow')}><Radar size={14} /> Scan & Remediate</Button>
                  <Button variant="secondary" onClick={() => setPanel('scope')}><Settings2 size={14} /> Permissions</Button>
                  <Button variant="ghost" onClick={() => setPanel('audit')}><History size={14} /> Activity</Button>
                  <Button variant="ghost" onClick={() => setPanel('revoke')}><Trash2 size={14} /></Button>
                </div>
              </div>
              {monitor && (
                <div className="rounded-xl border border-slate-800 bg-veil-950/60 p-4 grid md:grid-cols-2 gap-4 text-sm">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2"><Badge tone={monitor.tone}>{monitor.label}</Badge></div>
                    <p className="text-xs text-slate-400">Mode: periodic server checks every 5 minutes, plus agent check-ins while the agent is running. Real-time file protection comes from Microsoft Defender on the PC, not from Blackveil.</p>
                    <p className="text-xs text-slate-400">Last server check: {formatWhen(device.last_monitored_at)}</p>
                    <p className="text-xs text-slate-400">Last agent check-in: {formatWhen(device.last_seen_at)}</p>
                    <p className="text-xs text-slate-400">Scan schedule: {device.scan_schedule === 'off' ? 'Off (manual only)' : `${device.scan_schedule}, next ${formatWhen(device.next_scan_at)}`}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-slate-500 mb-1.5">Known gaps</p>
                    {monitor.gaps.length === 0 ? <p className="text-xs text-slate-400">None detected by the last check.</p> : (
                      <ul className="list-disc pl-4 text-xs text-amber-200/90 space-y-1">{monitor.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
                    )}
                  </div>
                </div>
              )}
              <div className="flex gap-1 border-b border-slate-800">
                {([['threats', `Threats (${deviceThreats.length})`], ['incidents', `Incidents (${openIncidents} open)`]] as const).map(([id, label]) => (
                  <button key={id} type="button" onClick={() => setTab(id)}
                    className={`px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${tab === id ? 'border-cyan-400 text-slate-100' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
                    {label}
                  </button>
                ))}
              </div>
              {tab === 'threats'
                ? <ThreatList token={token} threats={deviceThreats} onChange={refresh} />
                : <IncidentList token={token} incidents={deviceIncidents} onChange={refresh} />}
            </Card>
          )}
        </>
      )}

      {panel === 'enroll' && <EnrollDrawer token={token} onClose={() => setPanel(null)} onDone={refresh} />}
      {panel === 'scope' && device && <ScopeDrawer token={token} device={device} onClose={() => setPanel(null)} onDone={refresh} />}
      {panel === 'flow' && device && (
        <ScanRemediateFlow token={token} device={device} threats={deviceThreats} refresh={refresh} onClose={() => { setPanel(null); refresh(); }} />
      )}
      {panel === 'revoke' && device && (
        <Drawer title="Disconnect device" subtitle={device.name} onClose={() => setPanel(null)}>
          <div className="space-y-4 text-sm text-slate-300">
            <p>The device key stops working immediately and queued jobs are cancelled. History stays in your activity log. Quarantined files remain in Defender's quarantine on the PC.</p>
            <Button variant="danger" loading={busy} onClick={revoke} full>Disconnect device</Button>
          </div>
        </Drawer>
      )}
      {panel === 'audit' && (
        <Drawer title="Activity log" subtitle="Who requested and approved each action, and the outcome" onClose={() => setPanel(null)} wide>
          <ul className="space-y-2">
            {audit.filter((a) => !selectedId || a.device_id === selectedId).map((a) => (
              <li key={a.id} className="rounded-lg border border-slate-800 p-3 text-sm flex items-start justify-between gap-3">
                <div>
                  <p className="text-slate-200">{a.action.replace(/_/g, ' ')}</p>
                  <p className="text-xs text-slate-500">{formatWhen(a.created_at)} - by {a.actor === 'user' ? 'you' : 'device agent'}</p>
                </div>
                <Badge tone={a.outcome === 'failed' ? 'rose' : a.outcome === 'succeeded' ? 'green' : 'slate'}>{a.outcome}</Badge>
              </li>
            ))}
            {audit.length === 0 && <p className="text-sm text-slate-500">No activity yet.</p>}
          </ul>
        </Drawer>
      )}
    </div>
  );
}
