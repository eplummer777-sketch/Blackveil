import { useState } from 'react';
import { ChevronDown, Siren } from 'lucide-react';
import { Badge, SeverityPill, Button, ErrorBanner, EmptyState } from '@/components/ui';
import { EndpointIncident, IncidentStatus, INCIDENT_META, formatWhen, control } from '@/lib/endpoint';

const ACTIONS: { status: IncidentStatus; label: string }[] = [
  { status: 'investigating', label: 'Mark investigating' },
  { status: 'unresolved', label: 'Mark unresolved' },
  { status: 'resolved', label: 'Close as resolved' },
];

function IncidentRow({ token, inc, onChange }: { token: string; inc: EndpointIncident; onChange: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<IncidentStatus | null>(null);
  const [error, setError] = useState('');
  const meta = INCIDENT_META[inc.status];

  const set = async (status: IncidentStatus) => {
    setBusy(status); setError('');
    const r = await control(token, { action: 'incident_status', incidentId: inc.id, status });
    setBusy(null);
    if (!r.ok) return setError(r.error);
    onChange();
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-veil-900/60">
      <button type="button" onClick={() => setOpen(!open)} className="w-full text-left p-4 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-slate-100 truncate">{inc.title}</p>
          <p className="text-xs text-slate-500 mt-1">Opened {formatWhen(inc.opened_at)}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityPill severity={inc.severity} />
          <Badge tone={meta.tone}>{meta.label}</Badge>
          <ChevronDown size={16} className={`text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-3 border-t border-slate-800 space-y-3 text-sm">
          {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
          {inc.detail?.summary && <p className="text-slate-300">{inc.detail.summary}</p>}
          {inc.resolution && <p className="text-xs text-slate-400">Resolution: {inc.resolution} ({formatWhen(inc.resolved_at)})</p>}
          {inc.status !== 'resolved' && (
            <div className="flex flex-wrap gap-2">
              {ACTIONS.filter((a) => a.status !== inc.status).map((a) => (
                <Button key={a.status} size="sm" variant={a.status === 'resolved' ? 'secondary' : 'ghost'} loading={busy === a.status} onClick={() => set(a.status)}>
                  {a.label}
                </Button>
              ))}
            </div>
          )}
          <p className="text-xs text-slate-500">Threat incidents update automatically as remediation and verification complete. Health incidents close on their own when the problem clears.</p>
        </div>
      )}
    </div>
  );
}

export function IncidentList({ token, incidents, onChange }: { token: string; incidents: EndpointIncident[]; onChange: () => void }) {
  const [showClosed, setShowClosed] = useState(false);
  const open = incidents.filter((i) => i.status !== 'resolved');
  const shown = showClosed ? incidents : open;
  return (
    <div className="space-y-3">
      {shown.length === 0
        ? <EmptyState icon={<Siren size={22} />} title={showClosed ? 'No incidents yet' : 'No open incidents'} hint="Incidents are raised by the server monitor every 5 minutes. No incidents does not mean a device is protected if its agent is offline." />
        : shown.map((i) => <IncidentRow key={i.id} token={token} inc={i} onChange={onChange} />)}
      {incidents.length > open.length && (
        <button type="button" onClick={() => setShowClosed(!showClosed)} className="text-xs text-cyan-300 hover:text-cyan-200">
          {showClosed ? 'Hide resolved incidents' : `Show ${incidents.length - open.length} resolved incident(s)`}
        </button>
      )}
    </div>
  );
}
