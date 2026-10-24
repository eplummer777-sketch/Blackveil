import { useCallback, useEffect, useState } from 'react';
import { Activity, Bell, Mail, Smartphone, FileText, Send, Lock, Power, AlertTriangle, CheckCircle2, Clock, Download } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { Card, Button, Badge, Label, Spinner, EmptyState, ErrorBanner, Drawer, Toggle } from '@/components/ui';
import { PushSettings } from '@/components/monitoring/PushSettings';
import { formatWhen, downloadText } from '@/lib/endpoint';
import {
  AlertDelivery, MonitoringReport, MonitoringSettings, MonitoringStatus, Severity, DEFAULT_SETTINGS,
  loadMonitoringData, monitoringCall, localHourLabel,
} from '@/lib/monitoring';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical only', high: 'High and above', medium: 'Medium and above', low: 'Everything',
};

const DELIVERY_TONE: Record<AlertDelivery['status'], 'green' | 'amber' | 'rose' | 'slate' | 'cyan'> = {
  sent: 'green', pending: 'cyan', sending: 'cyan', failed: 'rose', not_configured: 'amber',
};
const DELIVERY_LABEL: Record<AlertDelivery['status'], string> = {
  sent: 'Delivered to provider', pending: 'Queued', sending: 'Sending', failed: 'Failed', not_configured: 'Provider not set up',
};

export function MonitoringPanel({ onUpgrade }: { onUpgrade: () => void }) {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [settings, setSettings] = useState<MonitoringSettings>(DEFAULT_SETTINGS);
  const [draft, setDraft] = useState<MonitoringSettings>(DEFAULT_SETTINGS);
  const [deliveries, setDeliveries] = useState<AlertDelivery[]>([]);
  const [reports, setReports] = useState<MonitoringReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [openReport, setOpenReport] = useState<MonitoringReport | null>(null);

  const refresh = useCallback(async () => {
    const [st, data] = await Promise.all([monitoringCall<MonitoringStatus>(token, { action: 'status' }), loadMonitoringData()]);
    if (st.ok && typeof st.data?.eligible === 'boolean') setStatus(st.data);
    else setError(st.ok ? 'Unexpected response from Blackveil.' : st.error);
    if (data.ok) {
      setSettings(data.settings);
      setDraft(data.settings);
      setDeliveries(data.deliveries);
      setReports(data.reports);
    } else setError(data.error);
    setLoading(false);
  }, [token]);

  useEffect(() => { if (token) refresh(); }, [token, refresh]);

  const save = async (patch: Partial<MonitoringSettings>, key: string) => {
    setBusy(key); setError(''); setNotice('');
    const next = { ...draft, ...patch };
    const r = await monitoringCall(token, {
      action: 'save', enabled: next.enabled, email_alerts: next.email_alerts, min_severity: next.min_severity, daily_report: next.daily_report, report_hour_utc: next.report_hour_utc,
    });
    setBusy('');
    if (!r.ok) { setError(r.error); return; }
    setNotice(key === 'power' ? (next.enabled ? '24/7 monitoring is on.' : '24/7 monitoring is paused.') : 'Settings saved.');
    await refresh();
  };

  const testEmail = async () => {
    setBusy('test-email'); setError(''); setNotice('');
    const r = await monitoringCall(token, { action: 'test', channel: 'email' });
    setBusy('');
    if (r.ok) setNotice('Test email handed to the delivery provider.');
    else setError(r.error);
    refresh();
  };

  const reportNow = async () => {
    setBusy('report'); setError(''); setNotice('');
    const r = await monitoringCall(token, { action: 'report_now' });
    setBusy('');
    if (!r.ok) { setError(r.error); return; }
    setNotice('A fresh report is ready below.');
    refresh();
  };

  if (loading) return <div className="flex justify-center py-16"><Spinner /></div>;

  if (status && !status.eligible) {
    return (
      <Card className="p-8">
        <EmptyState icon={<Lock size={24} />} title="24/7 monitoring comes with Pro and Elite"
          hint="Upgrade to get round-the-clock automated checks on your connected devices, instant email and phone push alerts when something goes wrong, and a security report every day."
          action={<Button onClick={onUpgrade}>Upgrade to Pro - $10/mo</Button>} />
      </Card>
    );
  }

  const dirty = draft.min_severity !== settings.min_severity || draft.report_hour_utc !== settings.report_hour_utc;
  const channels = status?.channels ?? { email: false, push: false };

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      {notice && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200 fade-up">
          <CheckCircle2 size={16} /> {notice}
        </div>
      )}

      <Card className={`p-6 transition-colors ${settings.enabled ? 'border-cyan-500/30' : ''}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`relative flex h-12 w-12 items-center justify-center rounded-xl ${settings.enabled ? 'bg-cyan-400/15 text-cyan-300' : 'bg-veil-800 text-slate-500'}`}>
              <Activity size={22} />
              {settings.enabled && <span className="absolute -top-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-400 animate-pulse" />}
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">24/7 automated monitoring</h2>
              <p className="text-sm text-slate-400 mt-1 max-w-xl leading-relaxed">
                {settings.enabled
                  ? `Active since ${formatWhen(settings.enabled_at)}. Every 5 minutes Blackveil checks your connected devices for offline agents, missed scans, failed jobs and new threats.`
                  : 'Paused. Turn it on to have Blackveil watch your connected devices around the clock and alert you the moment something needs attention.'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge tone={settings.enabled ? 'green' : 'slate'}>{settings.enabled ? 'On' : 'Off'}</Badge>
            {busy === 'power' ? <Spinner /> : <Toggle label="24/7 monitoring" on={settings.enabled} onChange={(v) => save({ enabled: v }, 'power')} />}
          </div>
        </div>
      </Card>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card className="p-6 space-y-5">
          <div className="flex items-center gap-2 text-slate-100 font-medium"><Bell size={18} className="text-cyan-300" /> Alerts</div>
          <p className="text-xs text-slate-500 -mt-3">Every alert also appears in the bell menu at the top of the app.</p>

          <div className="flex items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <Mail size={18} className="text-slate-400 mt-0.5" />
              <div>
                <div className="text-sm text-slate-200">Email alerts</div>
                <div className="text-xs text-slate-500">Sent to {session?.user.email ?? 'your account email'}</div>
                {!channels.email && <div className="text-xs text-amber-300 mt-1">Email delivery is not set up for Blackveil yet. Alerts are recorded but not emailed.</div>}
              </div>
            </div>
            <Toggle label="Email alerts" on={settings.email_alerts} disabled={!!busy} onChange={(v) => save({ email_alerts: v }, 'email')} />
          </div>

          <div className="border-t border-slate-800 pt-5">
            <PushSettings token={token} pushKey={status?.pushKey ?? null} />
          </div>

          <div>
            <Label>Alert me about</Label>
            <select value={draft.min_severity} onChange={(e) => setDraft({ ...draft, min_severity: e.target.value as Severity })}
              className="w-full rounded-lg border border-slate-700 bg-veil-900 px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
              {(Object.keys(SEVERITY_LABEL) as Severity[]).map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
            </select>
          </div>

          <div className="flex flex-wrap gap-2 pt-1">
            <Button size="sm" disabled={!dirty} loading={busy === 'settings'} onClick={() => save({}, 'settings')}>Save changes</Button>
            <Button size="sm" variant="secondary" loading={busy === 'test-email'} disabled={!!busy} onClick={testEmail}><Send size={13} /> Test email</Button>
          </div>
        </Card>

        <Card className="p-6 space-y-5">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-slate-100 font-medium"><FileText size={18} className="text-cyan-300" /> Daily report</div>
            <Toggle label="Daily report" on={settings.daily_report} disabled={!!busy} onChange={(v) => save({ daily_report: v }, 'daily')} />
          </div>
          <p className="text-sm text-slate-400 leading-relaxed -mt-2">
            While monitoring is on, you get a summary every day of device health, scans, threats and incidents, in the app and by email or as a push notification if those are on. Push sends one quiet summary a day, separate from urgent threat alerts.
          </p>
          <div>
            <Label>Deliver around</Label>
            <select value={draft.report_hour_utc} onChange={(e) => setDraft({ ...draft, report_hour_utc: Number(e.target.value) })}
              className="w-full rounded-lg border border-slate-700 bg-veil-900 px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
              {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{localHourLabel(h)} (your time)</option>)}
            </select>
          </div>
          <Button size="sm" variant="secondary" loading={busy === 'report'} disabled={!!busy} onClick={reportNow}><FileText size={13} /> Generate report now</Button>

          <div className="border-t border-slate-800 pt-4 space-y-2">
            {reports.length === 0 ? (
              <p className="text-xs text-slate-500">No reports yet. Your first one arrives at the time above once monitoring is on.</p>
            ) : reports.map((r) => (
              <button key={r.id} type="button" onClick={() => setOpenReport(r)}
                className="w-full flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-veil-900/50 px-3 py-2.5 text-left hover:border-cyan-500/40 transition-colors">
                <div>
                  <div className="text-sm text-slate-200">{new Date(r.report_date + 'T00:00:00').toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}</div>
                  <div className="text-xs text-slate-500">{String(r.summary.open_incidents ?? 0)} open incidents, {String(r.summary.threats_24h ?? 0)} threats in 24h</div>
                </div>
                <Badge tone={r.summary.status === 'No open issues' ? 'green' : r.summary.status === 'Action needed' ? 'rose' : 'amber'}>{String(r.summary.status ?? 'report')}</Badge>
              </button>
            ))}
          </div>
        </Card>
      </div>

      <Card className="p-6">
        <div className="flex items-center gap-2 text-slate-100 font-medium mb-4"><Clock size={18} className="text-cyan-300" /> Alert delivery history</div>
        {deliveries.length === 0 ? (
          <p className="text-sm text-slate-500">No alerts sent yet.</p>
        ) : (
          <div className="divide-y divide-slate-800">
            {deliveries.map((d) => (
              <div key={d.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 py-3">
                <div className="flex items-start gap-3 min-w-0">
                  {d.channel === 'email' ? <Mail size={16} className="text-slate-500 mt-0.5 shrink-0" /> : d.channel === 'push' ? <Smartphone size={16} className="text-slate-500 mt-0.5 shrink-0" /> : <Bell size={16} className="text-slate-500 mt-0.5 shrink-0" />}
                  <div className="min-w-0">
                    <div className="text-sm text-slate-200 truncate">{d.subject}</div>
                    <div className="text-xs text-slate-500">{formatWhen(d.created_at)}{d.error && d.status !== 'sent' ? ` - ${d.error}` : ''}</div>
                  </div>
                </div>
                <Badge tone={DELIVERY_TONE[d.status]}>
                  {d.status === 'failed' || d.status === 'not_configured' ? <AlertTriangle size={11} /> : null}
                  {DELIVERY_LABEL[d.status]}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </Card>

      {!settings.enabled && (
        <p className="flex items-center gap-2 text-xs text-slate-500"><Power size={13} /> Monitoring needs at least one connected device on the Remediation engine tab to have anything to watch.</p>
      )}

      {openReport && (
        <Drawer title="Daily security report" subtitle={openReport.report_date} onClose={() => setOpenReport(null)} wide>
          <pre className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300 font-mono bg-veil-900/60 border border-slate-800 rounded-lg p-4">{openReport.body}</pre>
          <div className="mt-4">
            <Button size="sm" variant="secondary" onClick={() => downloadText(`blackveil-report-${openReport.report_date}.txt`, openReport.body)}><Download size={13} /> Download</Button>
          </div>
        </Drawer>
      )}
    </div>
  );
}
