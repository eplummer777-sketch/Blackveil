import { useState } from 'react';
import { Copy, Check, Globe, ShieldCheck, Trash2, RefreshCw, Plus, Clock } from 'lucide-react';
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Label } from '@/components/ui';
import { callPob, PobTarget } from '@/lib/pob';

function CopyField({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-black/40 px-3 py-2 font-mono text-xs text-slate-200">
      <span className="truncate flex-1">{value}</span>
      <button
        onClick={() => { navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500); }}
        className="text-slate-400 hover:text-cyan-300 transition" aria-label="Copy"
      >
        {done ? <Check size={14} /> : <Copy size={14} />}
      </button>
    </div>
  );
}

const STATUS_TONE = { verified: 'green', pending: 'amber', expired: 'rose', revoked: 'slate' } as const;

export function Targets({ token, targets, onChange }: { token: string; targets: PobTarget[]; onChange: () => void }) {
  const [host, setHost] = useState('');
  const [env, setEnv] = useState('production');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');

  const act = async (key: string, body: Record<string, unknown>) => {
    setBusy(key); setError('');
    const r = await callPob(token, body);
    setBusy(null);
    if (!r.ok) { setError(r.error); return false; }
    onChange();
    return true;
  };

  const add = async () => {
    if (await act('add', { action: 'add_target', hostname: host, environment: env })) setHost('');
  };

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      <Card className="p-6">
        <h3 className="text-sm font-semibold text-slate-100">Register a website you own</h3>
        <p className="mt-1 text-sm text-slate-400 leading-relaxed">
          Testing only starts after you prove control of the domain with a DNS record. Owning a login or knowing the URL is not enough.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_180px_auto] items-end">
          <div>
            <Label>Domain</Label>
            <Input placeholder="example.com" value={host} onChange={(e) => setHost(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && host && add()} />
          </div>
          <div>
            <Label>Environment</Label>
            <select value={env} onChange={(e) => setEnv(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-veil-950 px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400/40">
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
            </select>
          </div>
          <Button onClick={add} loading={busy === 'add'} disabled={!host.trim()}><Plus size={16} />Add target</Button>
        </div>
      </Card>

      {targets.length === 0 ? (
        <EmptyState icon={<Globe size={28} />} title="No targets yet" hint="Add a domain above to begin ownership verification." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {targets.map((t) => (
            <Card key={t.id} className="p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Globe size={16} className="text-cyan-300 shrink-0" />
                    <span className="font-mono text-sm text-slate-100 truncate">{t.hostname}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Badge tone={STATUS_TONE[t.status]}>{t.status === 'verified' ? 'Ownership verified' : t.status}</Badge>
                    <Badge>{t.environment}</Badge>
                  </div>
                </div>
                <button onClick={() => confirm(`Remove ${t.hostname}? Its scan history will be deleted.`) && act('rm' + t.id, { action: 'remove_target', target_id: t.id })}
                  className="rounded-lg p-2 text-slate-500 hover:text-rose-300 hover:bg-rose-500/10 transition" aria-label="Remove target">
                  <Trash2 size={16} />
                </button>
              </div>

              {t.status === 'verified' ? (
                <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                  <div><dt className="text-slate-500">Allowed paths</dt><dd className="mt-0.5 font-mono text-slate-300">{t.allowed_paths.join(', ')}</dd></div>
                  <div><dt className="text-slate-500">Request budget</dt><dd className="mt-0.5 text-slate-300">{t.max_requests_per_scan} per scan</dd></div>
                  <div className="col-span-2"><dt className="text-slate-500">Permitted tests</dt><dd className="mt-0.5 text-slate-300">{t.allowed_categories.join(' · ')} (passive, non-destructive)</dd></div>
                  <div className="col-span-2 flex items-center gap-1.5 text-slate-400"><Clock size={12} />Authorization expires {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'never'}</div>
                </dl>
              ) : (
                <div className="mt-4 space-y-3">
                  <p className="text-xs text-slate-400 leading-relaxed">Add this TXT record at your DNS provider, wait a few minutes, then verify.</p>
                  <div><Label>Name</Label><CopyField value={`_blackveil-verify.${t.hostname}`} /></div>
                  <div><Label>Value</Label><CopyField value={`blackveil-verify=${t.verify_token}`} /></div>
                  <Button size="sm" onClick={() => act('v' + t.id, { action: 'verify_target', target_id: t.id })} loading={busy === 'v' + t.id}>
                    {t.status === 'expired' ? <RefreshCw size={14} /> : <ShieldCheck size={14} />}
                    {t.status === 'expired' ? 'Re-verify ownership' : 'Verify ownership'}
                  </Button>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
