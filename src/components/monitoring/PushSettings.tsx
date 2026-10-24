import { useCallback, useEffect, useState } from 'react';
import { Smartphone, Send, Trash2, AlertTriangle, CheckCircle2, Share, PlusSquare, ChevronDown, BellOff } from 'lucide-react';
import { Button, Badge, Spinner, Toggle } from '@/components/ui';
import { formatWhen } from '@/lib/endpoint';
import { monitoringCall } from '@/lib/monitoring';
import {
  PushDevice, currentSubscription, disablePush, enablePush, forgetThisDevice, loadPushDevices, thisDeviceId, notificationPermission, pushSupport, waitForPushReceipt,
} from '@/lib/push';

type Feedback = { tone: 'ok' | 'warn' | 'error'; text: string } | null;

const FEEDBACK_STYLE = {
  ok: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  warn: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  error: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
};

function IphoneSteps() {
  return (
    <ol className="space-y-2 text-xs text-slate-400 leading-relaxed">
      <li className="flex gap-2"><span className="text-cyan-300 font-medium">1.</span> Use an iPhone or iPad on iOS / iPadOS 16.4 or newer.</li>
      <li className="flex gap-2"><span className="text-cyan-300 font-medium">2.</span> Open Blackveil in Safari, tap <Share size={13} className="inline -mt-0.5" /> Share, then <PlusSquare size={13} className="inline -mt-0.5" /> Add to Home Screen.</li>
      <li className="flex gap-2"><span className="text-cyan-300 font-medium">3.</span> Open Blackveil from the new Home Screen icon (not from Safari) and sign in.</li>
      <li className="flex gap-2"><span className="text-cyan-300 font-medium">4.</span> Come back here, switch on push notifications and tap Allow.</li>
      <li className="flex gap-2"><span className="text-cyan-300 font-medium">5.</span> If nothing arrives, check Settings &gt; Notifications &gt; Blackveil, and that Focus mode is not hiding it.</li>
    </ol>
  );
}

export function PushSettings({ token, pushKey }: { token: string; pushKey: string | null }) {
  const support = pushSupport();
  const [thisDevice, setThisDevice] = useState<string | null>(null);
  const [devices, setDevices] = useState<PushDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [showHelp, setShowHelp] = useState(support === 'needs-install');
  const [permission, setPermission] = useState(notificationPermission());

  const refresh = useCallback(async () => {
    const [sub, list] = await Promise.all([currentSubscription(), loadPushDevices()]);
    let endpoint = sub?.endpoint ?? null;
    if (list.ok) {
      setDevices(list.devices);
      const id = thisDeviceId();
      if (endpoint && (!id || !list.devices.some((d) => d.id === id))) { await forgetThisDevice(); endpoint = null; }
    } else setFeedback({ tone: 'error', text: list.error });
    setThisDevice(endpoint);
    setPermission(notificationPermission());
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const toggle = async (on: boolean) => {
    setFeedback(null);
    if (on) {
      if (!pushKey) { setFeedback({ tone: 'error', text: 'Push is not available right now. Reload the page and try again.' }); return; }
      setBusy('toggle');
      const r = await enablePush(token, pushKey);
      setBusy('');
      setFeedback(r.ok ? { tone: 'ok', text: 'Push notifications are on for this device. Send a test to confirm.' } : { tone: 'error', text: r.error });
    } else {
      setBusy('toggle');
      const r = await disablePush(token);
      setBusy('');
      setFeedback(r.ok ? { tone: 'ok', text: 'Push notifications are off for this device.' } : { tone: 'error', text: r.error });
    }
    refresh();
  };

  const sendTest = async () => {
    if (!thisDevice) return;
    setBusy('test'); setFeedback(null);
    const nonce = crypto.randomUUID();
    const receipt = waitForPushReceipt(nonce, 20_000);
    const r = await monitoringCall(token, { action: 'push_test', endpoint: thisDevice, nonce });
    if (!r.ok) {
      setBusy('');
      setFeedback({ tone: 'error', text: r.error });
      refresh();
      return;
    }
    setFeedback({ tone: 'warn', text: 'Sent. Waiting for this device to confirm it arrived...' });
    const arrived = await receipt;
    setBusy('');
    setFeedback(arrived
      ? { tone: 'ok', text: 'Test notification arrived on this device.' }
      : { tone: 'warn', text: 'The push service accepted the test, but this device has not confirmed it yet. If no notification appears, check notification settings for this browser or phone.' });
    refresh();
  };

  const remove = async (payload: Record<string, unknown>, key: string) => {
    setBusy(key); setFeedback(null);
    const r = await monitoringCall(token, { action: 'push_unsubscribe', ...payload });
    if (r.ok && (payload.all || payload.id === thisDeviceId())) await forgetThisDevice();
    setBusy('');
    setFeedback(r.ok ? { tone: 'ok', text: payload.all ? 'All devices removed.' : 'Device removed.' } : { tone: 'error', text: r.error });
    refresh();
  };

  const enabledHere = !!thisDevice && permission === 'granted';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <Smartphone size={18} className="text-slate-400 mt-0.5" />
          <div>
            <div className="text-sm text-slate-200">Enable push notifications</div>
            <div className="text-xs text-slate-500 leading-relaxed">High and critical threats, plus your daily report, on this device even when Blackveil is closed.</div>
          </div>
        </div>
        {loading || busy === 'toggle' ? <Spinner /> : (
          <Toggle label="Enable push notifications on this device" on={enabledHere}
            disabled={!!busy || support !== 'supported' || permission === 'denied'} onChange={toggle} />
        )}
      </div>

      {support === 'unsupported' && (
        <p className="flex gap-2 text-xs text-amber-300"><BellOff size={14} className="shrink-0 mt-0.5" /> This browser does not support push notifications. Try Chrome, Edge, Firefox or Safari 16.4 and newer.</p>
      )}
      {support === 'needs-install' && (
        <p className="flex gap-2 text-xs text-amber-300"><AlertTriangle size={14} className="shrink-0 mt-0.5" /> On iPhone and iPad, push only works after you add Blackveil to your Home Screen. Follow the steps below.</p>
      )}
      {support === 'supported' && permission === 'denied' && (
        <p className="flex gap-2 text-xs text-amber-300"><AlertTriangle size={14} className="shrink-0 mt-0.5" /> Notifications are blocked for Blackveil. Allow them in your browser's site settings (or Settings &gt; Notifications on iPhone), then reload.</p>
      )}

      {feedback && (
        <div className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs leading-relaxed fade-up ${FEEDBACK_STYLE[feedback.tone]}`}>
          {feedback.tone === 'ok' ? <CheckCircle2 size={14} className="shrink-0 mt-0.5" /> : <AlertTriangle size={14} className="shrink-0 mt-0.5" />}
          {feedback.text}
        </div>
      )}

      <Button size="sm" variant="secondary" loading={busy === 'test'} disabled={!!busy || !enabledHere} onClick={sendTest}>
        <Send size={13} /> Send test notification
      </Button>

      {devices.length > 0 && (
        <div className="rounded-lg border border-slate-800 divide-y divide-slate-800">
          {devices.map((d) => (
            <div key={d.id} className="flex items-center justify-between gap-3 px-3 py-2.5">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-sm text-slate-200">
                  {d.device_label}
                  {thisDevice && d.id === thisDeviceId() && <Badge tone="cyan">This device</Badge>}
                </div>
                <div className="text-xs text-slate-500 truncate">
                  Added {formatWhen(d.created_at)}{d.last_success_at ? ` - last delivered ${formatWhen(d.last_success_at)}` : ''}
                </div>
              </div>
              <button type="button" aria-label={`Remove ${d.device_label}`} disabled={!!busy} onClick={() => remove({ id: d.id }, `rm-${d.id}`)}
                className="p-2 rounded-md text-slate-500 hover:text-rose-300 hover:bg-rose-500/10 transition-colors disabled:opacity-50">
                {busy === `rm-${d.id}` ? <Spinner /> : <Trash2 size={14} />}
              </button>
            </div>
          ))}
          {devices.length > 1 && (
            <div className="px-3 py-2 flex justify-between items-center">
              <Badge tone="slate">{devices.length} devices</Badge>
              <button type="button" disabled={!!busy} onClick={() => remove({ all: true }, 'rm-all')}
                className="text-xs text-slate-400 hover:text-rose-300 transition-colors disabled:opacity-50">Remove all</button>
            </div>
          )}
        </div>
      )}

      <div className="rounded-lg border border-slate-800 bg-veil-900/40">
        <button type="button" onClick={() => setShowHelp(!showHelp)} aria-expanded={showHelp}
          className="w-full flex items-center justify-between px-3 py-2.5 text-xs text-slate-300 hover:text-slate-100 transition-colors">
          iPhone and iPad setup
          <ChevronDown size={14} className={`transition-transform duration-200 ${showHelp ? 'rotate-180' : ''}`} />
        </button>
        {showHelp && <div className="px-3 pb-3"><IphoneSteps /></div>}
      </div>
    </div>
  );
}
