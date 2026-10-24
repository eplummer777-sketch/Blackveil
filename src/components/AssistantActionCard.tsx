import { useState } from 'react';
import {
  ScanLine, ShieldCheck, ShieldOff, CalendarClock, Link2, Globe, Cloud, Check, X, Loader2, Clock, AlertCircle,
  Crosshair, Swords, Network, Mail, ArrowRight,
} from 'lucide-react';
import { edgeUrl } from '@/lib/supabase';

export interface AssistantAction {
  id: string;
  message_id: string;
  kind: string;
  summary: string;
  status: 'pending' | 'running' | 'succeeded' | 'failed' | 'rejected' | 'expired';
  result: { message?: string; page?: string } | null;
  created_at: string;
  expires_at: string;
}

interface QuotaUpdate { remaining: number }

const KIND_META: Record<string, { label: string; icon: typeof ScanLine; impact: string }> = {
  scan_device: { label: 'Device scan', icon: ScanLine, impact: 'Your device will start scanning right away.' },
  remove_threats: { label: 'Remove threats', icon: ShieldOff, impact: 'Files will be quarantined on your device. You can restore them later.' },
  verify_device: { label: 'Verify device', icon: ShieldCheck, impact: 'Your device will run a check to confirm it is clean.' },
  set_scan_schedule: { label: 'Scan schedule', icon: CalendarClock, impact: "Your device's automatic scan schedule will change." },
  scan_link: { label: 'Link check', icon: Link2, impact: 'The link is checked safely on our servers, never opened on your device.' },
  assess_website: { label: 'Website assessment', icon: Globe, impact: 'Only run this on a website you own or are allowed to test.' },
  apply_cloudflare_fix: { label: 'Website protection', icon: Cloud, impact: 'This changes a setting on your live Cloudflare site.' },
  pob_quick_scan: { label: 'Proof-of-Breach test', icon: Crosshair, impact: 'Runs safe, rate-limited checks against your verified domain.' },
  pentest_scan: { label: 'Penetration test', icon: Swords, impact: 'Tests your verified website for weaknesses. Only run this on sites you are authorized to test.' },
  network_scan: { label: 'Network scan', icon: Network, impact: 'Looks for open ports on your verified domain. Only run this on systems you are authorized to scan.' },
  send_report_now: { label: 'Security report', icon: Mail, impact: 'A summary report will be emailed to you.' },
  open_page: { label: 'Go to page', icon: ArrowRight, impact: '' },
};

const STATUS_STYLE: Record<AssistantAction['status'], string> = {
  pending: 'border-cyan-500/30 bg-cyan-500/[0.04]',
  running: 'border-cyan-500/40 bg-cyan-500/[0.06]',
  succeeded: 'border-emerald-500/30 bg-emerald-500/[0.05]',
  failed: 'border-rose-500/30 bg-rose-500/[0.05]',
  rejected: 'border-slate-700/70 bg-veil-950/40 opacity-75',
  expired: 'border-slate-700/70 bg-veil-950/40 opacity-75',
};

export function AssistantActionCard({
  action, accessToken, outOfUses, onChange, onNavigate,
}: {
  action: AssistantAction;
  accessToken: string | undefined;
  outOfUses: boolean;
  onNavigate?: (page: string) => void;
  onChange: (a: AssistantAction, quota?: QuotaUpdate) => void;
}) {
  const [stage, setStage] = useState<'idle' | 'confirming' | 'busy'>('idle');
  const [error, setError] = useState<string | null>(null);
  const meta = KIND_META[action.kind] ?? { label: 'Action', icon: ShieldCheck, impact: '' };
  const Icon = meta.icon;
  const expired = action.status === 'pending' && new Date(action.expires_at).getTime() < Date.now();
  const status: AssistantAction['status'] = expired ? 'expired' : action.status;
  const isNav = action.kind === 'open_page';
  const page = action.result?.page;

  async function decide(decision: 'confirm' | 'reject') {
    if (!accessToken) return;
    setStage('busy');
    setError(null);
    try {
      const resp = await fetch(edgeUrl('assistant-actions'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ actionId: action.id, decision, confirmed: decision === 'confirm' }),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok || !data?.action) {
        throw new Error(data?.message ?? data?.error ?? 'Could not complete this action. Please try again.');
      }
      const next = data.action as AssistantAction;
      onChange(next, typeof data.remaining === 'number' ? { remaining: data.remaining } : undefined);
      setStage('idle');
      if (next.kind === 'open_page' && next.status === 'succeeded' && next.result?.page) onNavigate?.(next.result.page);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
      setStage('idle');
    }
  }

  return (
    <div className={`mt-3 rounded-xl border p-3.5 transition-all duration-300 ${STATUS_STYLE[status]}`}>
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-300 shrink-0">
          <Icon size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] uppercase tracking-wider text-cyan-300/80 font-semibold">{meta.label}</span>
            <StatusPill status={status} />
          </div>
          <p className="text-sm text-slate-100 mt-1 leading-snug break-words">{action.summary}</p>
          {status === 'pending' && meta.impact && <p className="text-xs text-slate-400 mt-1">{meta.impact}</p>}
          {action.result?.message && (status === 'succeeded' || status === 'failed') && (
            <p className={`text-xs mt-1.5 ${status === 'succeeded' ? 'text-emerald-300' : 'text-rose-300'}`}>{action.result.message}</p>
          )}
          {status === 'succeeded' && page && onNavigate && (
            <button onClick={() => onNavigate(page)} className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-cyan-300 hover:text-cyan-200 transition">
              {isNav ? 'Open again' : 'View progress'} <ArrowRight size={12} />
            </button>
          )}
          {error && (
            <p className="text-xs mt-1.5 text-rose-300 flex items-start gap-1"><AlertCircle size={12} className="mt-0.5 shrink-0" />{error}</p>
          )}

          {status === 'pending' && (
            <div className="mt-3 flex items-center gap-2 flex-wrap">
              {isNav && stage === 'idle' ? (
                <button onClick={() => decide('confirm')} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500/90 hover:bg-cyan-400 text-veil-950 font-semibold text-xs px-3 py-1.5 transition">
                  <ArrowRight size={13} /> Take me there
                </button>
              ) : stage === 'confirming' ? (
                <>
                  <span className="text-xs text-amber-200 mr-1">Are you sure? This runs now and uses 1 AI use.</span>
                  <button onClick={() => decide('confirm')} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-veil-950 font-semibold text-xs px-3 py-1.5 transition">
                    <Check size={13} /> Yes, run it
                  </button>
                  <button onClick={() => setStage('idle')} className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1.5 transition">Back</button>
                </>
              ) : stage === 'busy' ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-cyan-200"><Loader2 size={13} className="animate-spin" /> Working…</span>
              ) : (
                <>
                  <button
                    onClick={() => setStage('confirming')}
                    disabled={outOfUses}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500/90 hover:bg-cyan-400 text-veil-950 font-semibold text-xs px-3 py-1.5 transition disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Check size={13} /> Confirm
                  </button>
                  <button onClick={() => decide('reject')} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-300 text-xs px-3 py-1.5 transition">
                    <X size={13} /> Decline
                  </button>
                  {outOfUses && <span className="text-[11px] text-amber-300">No AI uses left this cycle.</span>}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: AssistantAction['status'] }) {
  const map: Record<AssistantAction['status'], { text: string; cls: string; icon?: typeof Clock }> = {
    pending: { text: 'Needs your confirmation', cls: 'text-amber-200 bg-amber-500/10 border-amber-500/30', icon: Clock },
    running: { text: 'Running', cls: 'text-cyan-200 bg-cyan-500/10 border-cyan-500/30' },
    succeeded: { text: 'Done', cls: 'text-emerald-200 bg-emerald-500/10 border-emerald-500/30', icon: Check },
    failed: { text: 'Failed', cls: 'text-rose-200 bg-rose-500/10 border-rose-500/30', icon: AlertCircle },
    rejected: { text: 'Declined', cls: 'text-slate-400 bg-slate-500/10 border-slate-600/40', icon: X },
    expired: { text: 'Expired', cls: 'text-slate-400 bg-slate-500/10 border-slate-600/40', icon: Clock },
  };
  const s = map[status];
  const I = s.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] rounded-full border px-2 py-0.5 ${s.cls}`}>
      {I && <I size={10} />}{s.text}
    </span>
  );
}
