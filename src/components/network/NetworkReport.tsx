import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowLeft, Bot, Download, Info, RotateCcw, Search, Server, Sparkles } from 'lucide-react';
import { Badge, Button, Card, ErrorBanner, Input, Spinner } from '@/components/ui';
import { supabase } from '@/lib/supabase';
import { callNet, exportScan, fmtDuration, isNetFinished, NET_AI_SECTIONS, NET_STATUS_LABEL, NetHost, NetScan, netTone, PROFILE_INFO } from '@/lib/network';

const STATE_STYLE: Record<string, string> = {
  open: 'bg-emerald-400/10 text-emerald-300 border-emerald-400/30',
  closed: 'bg-slate-700/30 text-slate-400 border-slate-700',
};
const CONF_STYLE: Record<string, string> = { high: 'text-emerald-300', medium: 'text-cyan-300', low: 'text-slate-500' };

function Stat({ label, value, tone = 'text-slate-100' }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-veil-900/50 px-4 py-3">
      <p className="text-[11px] uppercase tracking-widest text-slate-500">{label}</p>
      <p className={`mt-1 text-xl font-semibold ${tone}`}>{value}</p>
    </div>
  );
}

function HostCard({ host, q }: { host: NetHost; q: string }) {
  const listed = host.ports.filter((p) => !q || `${p.port} ${p.service} ${p.product} ${p.version}`.toLowerCase().includes(q))
    .sort((a, b) => (a.state === 'open' ? -1 : 1) - (b.state === 'open' ? -1 : 1) || a.port - b.port);
  const showConf = host.ports.some((p) => p.confidence);
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-5 py-3">
        <Server size={16} className="text-cyan-300" />
        <span className="font-mono text-sm text-slate-100">{host.address}</span>
        {host.hostnames.length > 0 && <span className="truncate text-xs text-slate-500">{host.hostnames.join(', ')}</span>}
        <span className="ml-auto"><Badge tone={host.state === 'up' ? 'green' : 'slate'}>{host.state}</Badge></span>
      </div>
      {listed.length === 0 ? (
        <p className="px-5 py-4 text-xs text-slate-500">
          {q ? 'No ports match your search.' : host.extraports.length ? host.extraports.map((e) => `${e.count} ${e.state}`).join(', ') : 'No port details for this profile.'}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-[11px] uppercase tracking-widest text-slate-500">
              <tr><th className="px-5 py-2 font-medium">Port</th><th className="px-3 py-2 font-medium">State</th><th className="px-3 py-2 font-medium">Service</th><th className="px-3 py-2 font-medium">Detected version</th>{showConf && <th className="px-3 py-2 font-medium">Confidence</th>}</tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {listed.map((p) => (
                <tr key={`${p.protocol}${p.port}`} className="transition hover:bg-veil-800/30">
                  <td className="px-5 py-2 font-mono text-slate-200">{p.port}/{p.protocol}</td>
                  <td className="px-3 py-2"><span className={`rounded-md border px-2 py-0.5 text-xs ${STATE_STYLE[p.state] ?? 'bg-amber-400/10 text-amber-300 border-amber-400/30'}`}>{p.state}</span></td>
                  <td className="px-3 py-2 text-slate-300">{p.service || '-'}{p.tunnel ? ` (${p.tunnel})` : ''}</td>
                  <td className="px-3 py-2 text-xs text-slate-400">{[p.product, p.version, p.extrainfo].filter(Boolean).join(' ') || '-'}</td>
                  {showConf && <td className={`px-3 py-2 text-xs ${CONF_STYLE[p.confidence ?? ''] ?? 'text-slate-500'}`} title={p.confidence === 'low' ? 'Guessed from the port number only' : 'Identified from the service response'}>{p.confidence ?? '-'}</td>}
                </tr>
              ))}
            </tbody>
          </table>
          {host.extraports.length > 0 && <p className="border-t border-slate-800 px-5 py-2 text-xs text-slate-500">Not shown: {host.extraports.map((e) => `${e.count} ${e.state}`).join(', ')}</p>}
        </div>
      )}
    </Card>
  );
}

export function NetworkReport({ token, scan, onBack, onRetried }: { token: string; scan: NetScan; onBack: () => void; onRetried: (s: NetScan) => void }) {
  const [hosts, setHosts] = useState<NetHost[] | null>(null);
  const [ai, setAi] = useState({ status: scan.ai_status, analysis: scan.ai_analysis });
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const qn = q.trim().toLowerCase();
  const [openOnly, setOpenOnly] = useState(true);
  const [retry, setRetry] = useState<'idle' | 'confirm' | 'busy'>('idle');
  const [retryOk, setRetryOk] = useState(false);

  useEffect(() => {
    supabase.from('nmap_hosts').select('*').eq('scan_id', scan.id).order('address').then(({ data, error: e }) => {
      if (e) setError('Could not load scan results.');
      setHosts((data ?? []) as NetHost[]);
    });
  }, [scan.id]);

  useEffect(() => setAi({ status: scan.ai_status, analysis: scan.ai_analysis }), [scan.ai_status, scan.ai_analysis]);

  const shown = useMemo(() => (hosts ?? []).map((h) => ({ ...h, ports: openOnly ? h.ports.filter((p) => p.state === 'open') : h.ports }))
    .map((h) => ({ ...h, hostMatch: !qn || h.address.includes(qn) || h.hostnames.some((n) => n.toLowerCase().includes(qn)) }))
    .filter((h) => h.hostMatch || h.ports.some((p) => `${p.port} ${p.service} ${p.product} ${p.version}`.toLowerCase().includes(qn))), [hosts, qn, openOnly]);

  const analyze = async () => {
    setAi((a) => ({ ...a, status: 'pending' }));
    const r = await callNet<{ ai_status: 'ready'; ai_analysis: Record<string, string> }>(token, { action: 'analyze', scan_id: scan.id });
    if (r.ok && r.data?.ai_analysis) setAi({ status: 'ready', analysis: r.data.ai_analysis });
    else { setAi((a) => ({ ...a, status: 'failed' })); setError(r.ok ? 'Unexpected response from the AI analyst.' : r.error); }
  };

  const runAgain = async () => {
    setRetry('busy');
    const r = await callNet<{ scan: NetScan }>(token, { action: 'retry', scan_id: scan.id, authorized: retryOk });
    if (!r.ok || !r.data?.scan?.id) { setRetry('confirm'); setError(r.ok ? 'Unexpected response from the scanner.' : r.error); return; }
    onRetried(r.data.scan);
  };

  const s = scan.summary;
  const finished = isNetFinished(scan);
  return (
    <div className="space-y-6 fade-up">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button variant="ghost" size="sm" onClick={onBack}><ArrowLeft size={14} />All network scans</Button>
        <div className="flex flex-wrap gap-2">
          {hosts && finished && <>
            <Button size="sm" variant="secondary" onClick={() => exportScan(scan, hosts, 'csv')}><Download size={13} />CSV</Button>
            <Button size="sm" variant="secondary" onClick={() => exportScan(scan, hosts, 'json')}><Download size={13} />JSON</Button>
          </>}
          {retry === 'idle' && <Button size="sm" onClick={() => setRetry('confirm')}><RotateCcw size={13} />Run again</Button>}
        </div>
      </div>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      {retry !== 'idle' && (
        <Card className="flex flex-wrap items-center gap-4 p-4">
          <label className="flex flex-1 cursor-pointer items-start gap-3 text-xs leading-relaxed text-slate-300">
            <input type="checkbox" checked={retryOk} onChange={(e) => setRetryOk(e.target.checked)} className="mt-0.5 h-4 w-4 accent-cyan-400" />
            I am still authorized to scan {scan.target_input}. Authorization is checked again before the scan starts.
          </label>
          <Button size="sm" variant="ghost" onClick={() => setRetry('idle')}>Cancel</Button>
          <Button size="sm" onClick={runAgain} loading={retry === 'busy'} disabled={!retryOk}>Start</Button>
        </Card>
      )}

      <Card className="relative overflow-hidden p-6">
        <div className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-widest text-cyan-300/80">{PROFILE_INFO[scan.profile].label}</p>
            <h2 className="mt-1 truncate font-mono text-lg text-slate-100">{scan.target_input}</h2>
            <p className="mt-1 text-xs text-slate-500">
              Scanned {scan.targets.join(', ')} · {new Date(scan.created_at).toLocaleString()} · Duration {fmtDuration(scan.duration_ms)}{scan.nmap_version ? ` · ${scan.engine === 'native' ? '' : 'Nmap '}${scan.nmap_version}` : ''}
            </p>
            <p className="mt-1 text-xs text-slate-500">Authorized by {scan.auth_basis === 'verified_domain' ? 'verified domain ownership' : 'administrator-approved range'}</p>
          </div>
          <Badge tone={netTone(scan.status)}>{NET_STATUS_LABEL[scan.status]}</Badge>
        </div>
        {scan.error && <p className={`relative mt-4 rounded-lg border px-4 py-3 text-sm ${scan.status === 'partial' ? 'border-amber-400/30 bg-amber-400/10 text-amber-200' : 'border-rose-500/30 bg-rose-500/10 text-rose-200'}`}>{scan.error}</p>}
        {s.hosts_total != null && (
          <div className="relative mt-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
            <Stat label="Hosts responding" value={`${s.hosts_up ?? 0}/${s.hosts_total ?? 0}`} />
            <Stat label="Open" value={s.open ?? 0} tone="text-emerald-300" />
            <Stat label="Filtered" value={s.filtered ?? 0} tone="text-amber-300" />
            <Stat label="Closed" value={s.closed ?? 0} tone="text-slate-400" />
            <Stat label={s.planned != null ? 'Coverage' : 'Versions found'} value={s.planned != null ? `${s.checked ?? 0}/${s.planned}` : s.services ?? 0} tone="text-cyan-300" />
          </div>
        )}
        {s.coverage_note && (
          <p className={`relative mt-4 flex items-start gap-2 text-xs leading-relaxed ${s.complete ? 'text-slate-400' : 'text-amber-200'}`}>
            <AlertTriangle size={13} className="mt-0.5 shrink-0" />{s.coverage_note}
          </p>
        )}
      </Card>

      <div className="flex items-start gap-3 rounded-xl border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-xs leading-relaxed text-slate-300">
        <Info size={14} className="mt-0.5 shrink-0 text-cyan-300" />
        An open port means a service is reachable, not that it is vulnerable or breached. Version strings are reported by the service itself and can be inaccurate. No findings never means the target is secure.
      </div>

      {finished && (
        <Card className="p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100"><Bot size={16} className="text-cyan-300" />Proof-of-Breach AI analysis</h3>
            {ai.status !== 'pending' && <Button size="sm" variant={ai.status === 'ready' ? 'secondary' : 'primary'} onClick={analyze}><Sparkles size={13} />{ai.status === 'ready' ? 'Regenerate' : 'Explain these results'}</Button>}
          </div>
          {ai.status === 'pending' && <p className="mt-4 flex items-center gap-2 text-sm text-slate-400"><Spinner />Analyzing the scan results...</p>}
          {ai.status === 'failed' && <p className="mt-3 text-sm text-amber-200">{scan.ai_error ?? 'The analysis did not finish.'} Your results are saved.</p>}
          {ai.status === 'ready' && ai.analysis && (
            <div className="mt-5 grid gap-4 md:grid-cols-2">
              {NET_AI_SECTIONS.map(([k, label]) => ai.analysis?.[k] && (
                <div key={k} className={`rounded-xl border p-4 ${k === 'confirmed_facts' ? 'border-emerald-400/20 bg-emerald-400/5' : k === 'possibilities' ? 'border-amber-400/20 bg-amber-400/5' : 'border-slate-800 bg-veil-900/40'}`}>
                  <p className="text-[11px] uppercase tracking-widest text-slate-500">{label}</p>
                  <p className="mt-2 whitespace-pre-line text-sm leading-relaxed text-slate-300">{ai.analysis[k]}</p>
                </div>
              ))}
            </div>
          )}
          {ai.status === 'none' && <p className="mt-3 text-sm text-slate-400">Get a plain-language explanation, prioritized risks and remediation steps. Confirmed observations are kept separate from hypotheses.</p>}
        </Card>
      )}

      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-xs uppercase tracking-widest text-slate-500">Discovered hosts</h3>
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter address, port, service" className="w-56 pl-8" />
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} className="h-4 w-4 accent-cyan-400" />Open ports only
            </label>
          </div>
        </div>
        {hosts === null ? <Card className="flex justify-center p-6"><Spinner /></Card>
          : hosts.length === 0 ? <Card className="p-6 text-sm text-slate-400">No responsive hosts were recorded for this scan. That does not mean the target is secure; it may be offline, filtered by a firewall, or outside the checked ports.</Card>
          : shown.length === 0 ? <Card className="p-6 text-sm text-slate-400">No hosts match your filter.</Card>
          : shown.map((h) => <HostCard key={h.id} host={h} q={h.hostMatch ? '' : qn} />)}
      </section>
    </div>
  );
}
