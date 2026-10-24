import { useCallback, useEffect, useState } from 'react';
import { Cpu, History, Lock, Network, Radio, Settings2, Square } from 'lucide-react';
import { Badge, Button, Card, ErrorBanner, Spinner } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Route } from '@/components/AppShell';
import { callNet, isNetActive, NetScan, NetStatusResp, PROFILE_INFO } from '@/lib/network';
import { NetworkScanForm } from '@/components/network/NetworkScanForm';
import { NetworkReport } from '@/components/network/NetworkReport';
import { NetworkAdmin } from '@/components/network/NetworkAdmin';
import { ScanHistory } from '@/components/network/ScanHistory';
import { ScanCompare } from '@/components/network/ScanCompare';

type Tab = 'scan' | 'history' | 'setup';
const POLL_MS = 3000;

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);
  return now;
}

function LiveScan({ scan, onCancel, cancelling }: { scan: NetScan; onCancel: () => void; cancelling: boolean }) {
  const running = scan.status === 'running';
  const native = scan.engine === 'native';
  const now = useNow(native && running);
  const left = scan.deadline_at ? Math.max(0, Math.round((new Date(scan.deadline_at).getTime() - now) / 1000)) : null;
  const pct = Math.min(100, scan.progress ?? 0);
  const label = scan.cancel_requested ? 'Stopping the scan...'
    : native ? (pct >= 100 ? 'Finishing up and preparing the AI analysis' : 'The discovery engine is checking ports')
    : running ? 'Scanning' : 'Waiting for a free scanner';
  return (
    <Card className="relative overflow-hidden p-6">
      <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="relative flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-widest text-cyan-300/80">{PROFILE_INFO[scan.profile].label}</p>
          <p className="mt-1 truncate font-mono text-sm text-slate-100">{scan.target_input}</p>
          <p className="mt-1 flex items-center gap-2 text-sm text-slate-400"><Spinner />{label}</p>
        </div>
        <div className="flex items-center gap-4">
          {native && left != null && (
            <div className="text-right">
              <p className="text-2xl font-semibold tabular-nums text-slate-100">{pct}%</p>
              <p className="text-xs text-slate-500">{left}s left</p>
            </div>
          )}
          <Button variant="danger" size="sm" onClick={onCancel} loading={cancelling} disabled={scan.cancel_requested}><Square size={12} />Cancel scan</Button>
        </div>
      </div>
      <div className="relative mt-5 h-1.5 overflow-hidden rounded-full bg-veil-800">
        {native
          ? <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-[width] duration-700 ease-out" style={{ width: `${Math.max(3, pct)}%` }} />
          : <div className={`h-full w-1/3 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400 ${running ? 'sweep-x' : 'opacity-40'}`} />}
      </div>
      <p className="relative mt-3 text-xs text-slate-500">
        Targets {scan.targets.join(', ')} · time limit {scan.timeout_seconds < 120 ? `${scan.timeout_seconds}s` : `${Math.round(scan.timeout_seconds / 60)} min`}{scan.started_at ? ` · started ${new Date(scan.started_at).toLocaleTimeString()}` : ''}
      </p>
      {native && <p className="relative mt-1 text-xs text-slate-500">If the time limit is reached, the results found so far are saved and marked partial.</p>}
    </Card>
  );
}

export function NetworkScan({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [status, setStatus] = useState<NetStatusResp | null>(null);
  const [scans, setScans] = useState<NetScan[]>([]);
  const [tab, setTab] = useState<Tab>('scan');
  const [openId, setOpenId] = useState<string | null>(null);
  const [compare, setCompare] = useState<[NetScan, NetScan] | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState('');

  const loadStatus = useCallback(async () => {
    const r = await callNet<NetStatusResp>(token, { action: 'status' });
    if (r.ok && typeof r.data?.elite === 'boolean') setStatus(r.data); else setError(r.ok ? 'Unexpected response.' : r.error);
  }, [token]);

  const loadScans = useCallback(async () => {
    const { data, error: e } = await supabase.from('nmap_scans').select('*').order('created_at', { ascending: false }).limit(100);
    if (e) setError('Could not load your network scans.');
    else setScans((data ?? []) as NetScan[]);
  }, []);

  useEffect(() => { if (token) { loadStatus(); loadScans(); } }, [token, loadStatus, loadScans]);

  const upsert = (s: NetScan) => setScans((l) => (l.some((x) => x.id === s.id) ? l.map((x) => (x.id === s.id ? s : x)) : [s, ...l]));

  const active = scans.find(isNetActive);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(async () => {
      const r = await callNet<{ scan: NetScan }>(token, { action: 'poll', scan_id: active.id });
      if (!r.ok || !r.data?.scan) { setError(r.ok ? 'Unexpected response from the scanner.' : r.error); return; }
      upsert(r.data.scan);
      if (!isNetActive(r.data.scan)) setOpenId(r.data.scan.id);
    }, POLL_MS);
    return () => clearInterval(id);
  }, [active?.id, token]); // eslint-disable-line react-hooks/exhaustive-deps

  const openScan = openId ? scans.find((s) => s.id === openId) : undefined;
  useEffect(() => {
    if (!openScan || openScan.ai_status !== 'pending') return;
    const id = setInterval(async () => {
      const { data } = await supabase.from('nmap_scans').select('*').eq('id', openScan.id).maybeSingle();
      if (data) upsert(data as NetScan);
    }, POLL_MS);
    return () => clearInterval(id);
  }, [openScan?.id, openScan?.ai_status]); // eslint-disable-line react-hooks/exhaustive-deps

  const cancel = async () => {
    if (!active) return;
    setCancelling(true);
    const r = await callNet<{ scan: NetScan | null }>(token, { action: 'cancel', scan_id: active.id });
    setCancelling(false);
    if (!r.ok) setError(r.error);
    else if (r.data?.scan) upsert(r.data.scan);
    else loadScans();
  };

  if (!status) return error ? <ErrorBanner message={error} /> : <div className="flex justify-center py-24"><Spinner /></div>;

  if (!status.elite) {
    return (
      <Card className="relative overflow-hidden p-10 text-center fade-up">
        <div className="pointer-events-none absolute inset-x-0 -top-20 mx-auto h-48 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
        <Lock size={32} className="relative mx-auto text-cyan-300" />
        <h1 className="relative mt-4 text-2xl font-semibold text-slate-100">Network scanning is an Elite feature</h1>
        <p className="relative mx-auto mt-2 max-w-lg text-sm leading-relaxed text-slate-400">Discover hosts, open ports and running services on networks you are authorized to test, with AI-guided remediation.</p>
        <Button className="relative mt-6" onClick={() => onNavigate('settings')}>View plans</Button>
      </Card>
    );
  }

  if (compare) return <ScanCompare a={compare[0]} b={compare[1]} onBack={() => setCompare(null)} />;

  if (openScan) {
    return <NetworkReport key={openScan.id} token={token} scan={openScan} onBack={() => { setOpenId(null); loadScans(); }}
      onRetried={(s) => { upsert(s); setOpenId(null); setTab('scan'); }} />;
  }

  const tabs: { id: Tab; label: string; icon: typeof Radio }[] = [
    { id: 'scan', label: 'New scan', icon: Radio },
    { id: 'history', label: 'Scan history', icon: History },
    ...(status.admin ? [{ id: 'setup' as Tab, label: 'Approved ranges', icon: Settings2 }] : []),
  ];

  return (
    <div className="space-y-6 fade-up">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-300/80">Elite</p>
          <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight text-slate-100"><Network className="text-cyan-300" size={24} />Network Scan</h1>
          <p className="mt-1 text-sm text-slate-400">Host, port and service discovery for networks you are authorized to test, analyzed by Proof-of-Breach AI.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {status.native && <Badge tone="green"><span className="flex items-center gap-1.5"><Cpu size={12} />{status.native.version} online</span></Badge>}
          {status.paused && <Badge tone="amber">Emergency stop active</Badge>}
        </div>
      </header>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      <nav className="flex gap-1 overflow-x-auto rounded-xl border border-slate-800 bg-veil-900/60 p-1 scrollbar-thin" role="tablist">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
            className={`flex shrink-0 items-center gap-2 rounded-lg px-4 py-2 text-sm transition focus:outline-none focus:ring-2 focus:ring-cyan-400/40 ${tab === id ? 'bg-cyan-400/10 text-cyan-200 shadow-glow-cyan' : 'text-slate-400 hover:bg-veil-800/60 hover:text-slate-200'}`}>
            <Icon size={15} />{label}
          </button>
        ))}
      </nav>

      {tab === 'scan' && (
        active ? <LiveScan scan={active} onCancel={cancel} cancelling={cancelling} />
          : <NetworkScanForm token={token} paused={!!status.paused} onStarted={upsert} />
      )}

      {tab === 'history' && <ScanHistory scans={scans} onOpen={setOpenId} onCompare={(a, b) => setCompare([a, b])} />}

      {tab === 'setup' && status.admin && <NetworkAdmin token={token} />}
    </div>
  );
}
