import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { Badge, Button, Card, ErrorBanner, Input, Label, Spinner } from '@/components/ui';
import { callNet } from '@/lib/network';

interface Scope { id: string; cidr: string; label: string; email: string; created_at: string }
interface AuditRow { id: string; actor: string; action: string; detail: Record<string, unknown>; created_at: string }
interface Overview { scopes: Scope[]; audit: AuditRow[] }

export function NetworkAdmin({ token }: { token: string }) {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState('');
  const [scope, setScope] = useState({ cidr: '', label: '', email: '' });
  const [busy, setBusy] = useState('');

  const load = useCallback(async () => {
    const r = await callNet<Overview>(token, { action: 'admin_overview' });
    if (r.ok && Array.isArray(r.data?.scopes)) setData(r.data); else setError(r.ok ? 'Unexpected response.' : r.error);
  }, [token]);
  useEffect(() => { load(); }, [load]);

  const act = async (key: string, body: Record<string, unknown>) => {
    setBusy(key); setError('');
    const r = await callNet<{ token?: string }>(token, body);
    setBusy('');
    if (!r.ok) { setError(r.error); return null; }
    load();
    return r.data;
  };

  const addScope = async (e: FormEvent) => {
    e.preventDefault();
    if (await act('scope', { action: 'scope_add', ...scope })) setScope({ cidr: '', label: '', email: '' });
  };

  if (!data) return error ? <ErrorBanner message={error} /> : <div className="flex justify-center py-12"><Spinner /></div>;

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      <Card className="p-6">
        <h3 className="text-sm font-semibold text-slate-100">Approved ranges</h3>
        <p className="mt-1 text-xs text-slate-500">Grant a user permission to scan specific IP ranges, including private lab networks. Metadata and link-local addresses can never be approved.</p>
        <form onSubmit={addScope} className="mt-4 grid gap-3 sm:grid-cols-[1fr_1fr_1fr_auto] sm:items-end">
          <div><Label>Range (CIDR)</Label><Input value={scope.cidr} onChange={(e) => setScope({ ...scope, cidr: e.target.value })} placeholder="10.20.0.0/24" /></div>
          <div><Label>Label</Label><Input value={scope.label} onChange={(e) => setScope({ ...scope, label: e.target.value })} placeholder="Staging lab" maxLength={80} /></div>
          <div><Label>User email</Label><Input type="email" value={scope.email} onChange={(e) => setScope({ ...scope, email: e.target.value })} placeholder="user@company.com" /></div>
          <Button type="submit" loading={busy === 'scope'} disabled={!scope.cidr || !scope.email}><Plus size={14} />Approve</Button>
        </form>
        <div className="mt-4 divide-y divide-slate-800/80">
          {data.scopes.length === 0 && <p className="py-3 text-sm text-slate-500">No approved ranges.</p>}
          {data.scopes.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center gap-3 py-3">
              <span className="font-mono text-sm text-slate-200">{s.cidr}</span>
              <span className="text-xs text-slate-500">{s.label || 'Unlabelled'} · {s.email}</span>
              <Button className="ml-auto" size="sm" variant="ghost" loading={busy === s.id} onClick={() => act(s.id, { action: 'scope_revoke', scope_id: s.id })}><Trash2 size={13} />Revoke</Button>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-6">
        <h3 className="text-sm font-semibold text-slate-100">Audit log</h3>
        <div className="mt-3 max-h-96 divide-y divide-slate-800/70 overflow-y-auto scrollbar-thin">
          {data.audit.map((r) => (
            <div key={r.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 text-xs">
              <span className="w-36 shrink-0 text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
              <Badge tone={r.actor === 'admin' ? 'amber' : r.actor === 'agent' ? 'cyan' : 'slate'}>{r.actor}</Badge>
              <span className="text-slate-200">{r.action.replace(/_/g, ' ')}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-slate-500">{JSON.stringify(r.detail)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
