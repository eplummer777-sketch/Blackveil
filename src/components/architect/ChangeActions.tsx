import { ReactNode, useState } from 'react';
import { Ban, CheckCircle2, FlaskConical, Globe, Hand, Undo2 } from 'lucide-react';
import { Button } from '@/components/ui';
import type { ArchitectChange, ChangeAction } from '@/lib/architect';

export type ActionPayload = { note?: string; acknowledged_risks?: boolean; confirmed?: boolean };

export function ChangeActions({ change, busy, onTest, onAction }: {
  change: ArchitectChange;
  busy: string | null;
  onTest: () => void;
  onAction: (action: ChangeAction, payload: ActionPayload) => void;
}) {
  const [note, setNote] = useState('');
  const [ack, setAck] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const s = change.status;
  const highRisk = change.risk_level === 'high';
  const noteOk = !highRisk || note.trim().length >= 10;
  const canReject = ['proposed', 'test_failed', 'tested', 'approved'].includes(s);

  if (s === 'rejected' || s === 'rolled_back') {
    return <p className="text-sm text-slate-500">This change is closed. No further actions are available.</p>;
  }

  return (
    <div className="space-y-4">
      {(s === 'proposed' || s === 'test_failed' || s === 'tested') && (
        <Step
          title={s === 'tested' ? 'Re-run sandbox test' : 'Step 1: Test in the sandbox'}
          hint="Static analysis of the file's text. Nothing is executed and no network calls are made."
        >
          <Button variant={s === 'tested' ? 'secondary' : 'primary'} size="sm" loading={busy === 'test'} onClick={onTest}>
            <FlaskConical size={14} /> Run sandbox test
          </Button>
        </Step>
      )}

      {s === 'tested' && (
        <Step title="Step 2: Approve" hint="Approving does not apply anything. It records that you reviewed the change.">
          <label className="flex items-start gap-2.5 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 accent-cyan-400" />
            I have read the risks and the rollback instructions for this change.
          </label>
          <NoteField value={note} onChange={setNote} placeholder={highRisk ? 'Required for high-risk changes: why is this safe for you?' : 'Optional note'} />
          {highRisk && !noteOk && <p className="text-xs text-rose-300">High-risk changes need a written reason (at least 10 characters).</p>}
          <Button size="sm" disabled={!ack || !noteOk} loading={busy === 'approve'} onClick={() => onAction('approve', { note, acknowledged_risks: ack })}>
            <CheckCircle2 size={14} /> Approve change
          </Button>
        </Step>
      )}

      {s === 'approved' && (
        <Step title="Step 3: Apply it yourself" hint="Copy or download the file above and apply it on your system. Architect cannot apply it for you.">
          <label className="flex items-start gap-2.5 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5 accent-cyan-400" />
            I applied this change myself on my own system.
          </label>
          <NoteField value={note} onChange={setNote} placeholder="Optional: where and how you applied it" />
          <Button size="sm" disabled={!confirmed} loading={busy === 'mark_deployed'} onClick={() => onAction('mark_deployed', { note, confirmed })}>
            <Hand size={14} /> Mark as applied by me
          </Button>
        </Step>
      )}

      {(s === 'deployed' || s === 'verified') && (
        <>
          <Step
            title={s === 'verified' ? 'Re-check live' : 'Step 4: Verify'}
            hint={change.verification_supported
              ? `Makes one read-only request to ${change.verification_spec?.url ?? 'your site'} and checks the response headers.`
              : 'Automatic verification is not available for this type of change yet, so it stays as "Applied by you".'}
          >
            <Button size="sm" variant={s === 'verified' ? 'secondary' : 'primary'} disabled={!change.verification_supported} loading={busy === 'verify'} onClick={() => onAction('verify', {})}>
              <Globe size={14} /> Run live verification
            </Button>
          </Step>
          <Step title="Rolled it back?" hint="If you reverted this change on your system, record it here so the dashboard stays accurate.">
            <label className="flex items-start gap-2.5 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5 accent-cyan-400" />
              I reverted this change myself.
            </label>
            <NoteField value={note} onChange={setNote} placeholder="Optional: why it was rolled back" />
            <Button size="sm" variant="secondary" disabled={!confirmed} loading={busy === 'mark_rolled_back'} onClick={() => onAction('mark_rolled_back', { note, confirmed })}>
              <Undo2 size={14} /> Mark as rolled back
            </Button>
          </Step>
        </>
      )}

      {canReject && (
        <div className="pt-2 border-t border-slate-800/80">
          <Button size="sm" variant="ghost" loading={busy === 'reject'} onClick={() => onAction('reject', { note })}>
            <Ban size={14} /> Reject this change
          </Button>
        </div>
      )}
    </div>
  );
}

function Step({ title, hint, children }: { title: string; hint: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-veil-950/50 p-4 space-y-3">
      <div>
        <p className="text-sm font-medium text-slate-100">{title}</p>
        <p className="mt-0.5 text-xs text-slate-500 leading-relaxed">{hint}</p>
      </div>
      {children}
    </div>
  );
}

function NoteField({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      rows={2}
      maxLength={1000}
      placeholder={placeholder}
      className="w-full resize-none rounded-lg border border-slate-700/80 bg-veil-950/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition"
    />
  );
}
