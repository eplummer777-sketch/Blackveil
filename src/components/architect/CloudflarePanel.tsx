import { useCallback, useEffect, useState } from 'react';
import { Cloud, Eye, Lock, Plug, Power, ShieldAlert, ShieldCheck, Unlock, Zap } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Badge, Button, Card, ErrorBanner, Spinner } from '@/components/ui';
import { CfIntegration, CfProposal, CfSetting, callCloudflare } from '@/lib/cloudflare';
import { CfConnectModal } from '@/components/architect/CfConnectModal';
import { CfSettingsView } from '@/components/architect/CfSettingsView';
import { CfProposals } from '@/components/architect/CfProposals';

export function CloudflarePanel() {
  const { session } = useAuth();
  const token = session?.access_token ?? '';
  const [integration, setIntegration] = useState<CfIntegration | null>(null);
  const [settings, setSettings] = useState<CfSetting[]>([]);
  const [proposals, setProposals] = useState<CfProposal[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [reading, setReading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [connectOpen, setConnectOpen] = useState(false);

  const load = useCallback(async () => {
    const { data } = await supabase.from('architect_integrations').select('*').eq('provider', 'cloudflare').order('created_at', { ascending: false });
    const active = (data ?? []).find((d) => d.status === 'connected') as CfIntegration | undefined;
    setIntegration(active ?? null);
    if (active) {
      const [s, p] = await Promise.all([
        supabase.from('architect_cf_settings_snapshots').select('settings').eq('integration_id', active.id).order('created_at', { ascending: false }).limit(1),
        supabase.from('architect_cf_proposals').select('*').eq('integration_id', active.id).order('created_at', { ascending: true }),
      ]);
      if (s.data?.[0]?.settings) setSettings(s.data[0].settings as CfSetting[]);
      setProposals((p.data ?? []) as CfProposal[]);
    } else {
      setSettings([]);
      setProposals([]);
    }
    setLoaded(true);
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!notice) return; const t = setTimeout(() => setNotice(null), 6000); return () => clearTimeout(t); }, [notice]);

  async function refreshSettings() {
    if (!integration) return;
    setReading(true);
    setError(null);
    const res = await callCloudflare<{ settings: CfSetting[]; errors: string[] }>(token, { action: 'read_settings', integration_id: integration.id });
    setReading(false);
    if (!res.ok) { setError(res.error); return; }
    setSettings(res.data?.settings ?? []);
    if (res.data?.errors?.length) setNotice(`Read ${res.data.settings.length} settings. ${res.data.errors.length} could not be read.`);
    else setNotice('Settings refreshed from Cloudflare.');
  }

  async function analyze() {
    if (!integration) return;
    setBusyId('analyze');
    setError(null);
    const res = await callCloudflare<{ settings: CfSetting[]; proposals: CfProposal[]; gaps: number }>(token, { action: 'analyze', integration_id: integration.id });
    setBusyId(null);
    if (!res.ok) { setError(res.error); return; }
    setSettings(res.data?.settings ?? []);
    setProposals(res.data?.proposals ?? []);
    const gaps = res.data?.gaps ?? 0;
    setNotice(gaps === 0 ? 'Analysis complete. No security gaps found.' : `Analysis complete. ${gaps} gap${gaps === 1 ? '' : 's'} found — review the recommendations below.`);
  }

  async function callAction(id: string, action: string, body: Record<string, unknown> = {}) {
    setBusyId(id);
    setError(null);
    const res = await callCloudflare<{ message: string; passed?: boolean }>(token, { action, proposal_id: id, ...body });
    setBusyId(null);
    if (!res.ok) { setError(res.error); return; }
    setNotice(res.data?.message ?? 'Done.');
    await load();
  }

  const onApprove = (id: string) => callAction(id, 'approve', { acknowledged_risks: true });
  const onReject = (id: string) => callAction(`reject-${id}`, 'reject');
  const onApply = (id: string) => callAction(id, 'apply', { confirmed: true });
  const onVerify = (id: string) => callAction(id, 'verify');
  const onRollback = (id: string) => callAction(`rb-${id}`, 'rollback', { confirmed: true });

  async function enableWrite() {
    if (!integration) return;
    setBusyId('write');
    setError(null);
    const res = await callCloudflare<{ message: string }>(token, { action: 'enable_write', integration_id: integration.id });
    setBusyId(null);
    if (!res.ok) { setError(res.error); return; }
    setNotice(res.data?.message ?? 'Write mode enabled.');
    await load();
  }

  async function disconnect() {
    if (!integration) return;
    if (!confirm('Disconnect from Cloudflare? Your API token will be deleted. Proposed changes will be kept for your records.')) return;
    setBusyId('disconnect');
    setError(null);
    const res = await callCloudflare<{ message: string }>(token, { action: 'disconnect', integration_id: integration.id });
    setBusyId(null);
    if (!res.ok) { setError(res.error); return; }
    setNotice(res.data?.message ?? 'Disconnected.');
    setIntegration(null);
    setSettings([]);
    setProposals([]);
    await load();
  }

  if (!loaded) return <div className="flex justify-center py-20"><Spinner /></div>;

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && (
        <div className="fade-in rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-4 py-2.5 text-sm text-cyan-100 flex items-start gap-2">
          <ShieldCheck size={15} className="mt-0.5 shrink-0" /> {notice}
        </div>
      )}

      {!integration ? (
        <Card className="p-8 sm:p-10 text-center relative overflow-hidden">
          <div className="pointer-events-none absolute -top-32 -right-32 h-64 w-64 rounded-full bg-orange-500/10 blur-3xl" />
          <div className="relative">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-xl bg-orange-500/10 border border-orange-500/30 mb-4">
              <Cloud size={28} className="text-orange-300" />
            </div>
            <h2 className="text-xl font-semibold text-slate-100">Connect Cloudflare</h2>
            <p className="mt-2 text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
              Connect a Cloudflare API token to let Architect read your zone's security settings, identify gaps, and apply approved hardening changes through the official API.
            </p>
            <Button className="mt-6" onClick={() => setConnectOpen(true)}>
              <Plug size={16} /> Connect Cloudflare
            </Button>
            <p className="mt-4 text-xs text-slate-500 max-w-sm mx-auto">
              Start in read-only mode — Architect will only read your settings. You can enable write mode after reviewing the recommendations.
            </p>
          </div>
        </Card>
      ) : (
        <>
          {/* Integration header */}
          <Card className="p-5">
            <div className="flex flex-col sm:flex-row sm:items-center gap-4">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-orange-500/10 border border-orange-500/30 shrink-0">
                  <Cloud size={20} className="text-orange-300" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-semibold text-slate-100 truncate">{integration.zone_name}</h2>
                    <Badge tone={integration.status === 'connected' ? 'green' : 'rose'}>
                      {integration.status === 'connected' ? 'Connected' : 'Disconnected'}
                    </Badge>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {integration.account_name ?? 'Cloudflare'} · Zone {integration.zone_id.slice(0, 8)}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {integration.mode === 'read_only' ? (
                  <Button size="sm" variant="secondary" onClick={enableWrite} loading={busyId === 'write'}>
                    <Unlock size={14} /> Enable write
                  </Button>
                ) : (
                  <Badge tone="cyan"><Zap size={11} /> Write enabled</Badge>
                )}
                <Button size="sm" variant="ghost" onClick={disconnect} loading={busyId === 'disconnect'}>
                  <Power size={14} /> Disconnect
                </Button>
              </div>
            </div>

            {integration.mode === 'read_only' && (
              <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
                <Eye size={15} className="mt-0.5 shrink-0 text-cyan-300" />
                <p className="text-sm text-cyan-100/90 leading-relaxed">
                  <span className="font-medium">Read-only mode.</span> Architect can read your settings and identify gaps, but cannot apply any changes. Review the recommendations, then enable write mode to approve and apply them.
                </p>
              </div>
            )}
            {integration.mode === 'write' && (
              <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
                <Lock size={15} className="mt-0.5 shrink-0 text-amber-300" />
                <p className="text-sm text-amber-100/90 leading-relaxed">
                  <span className="font-medium">Write mode is on.</span> Approved changes will be applied to your live Cloudflare zone through the API. Every change is verified by re-reading the setting afterward.
                </p>
              </div>
            )}
          </Card>

          {/* Settings */}
          {settings.length > 0 ? (
            <CfSettingsView settings={settings} loading={reading} onRefresh={refreshSettings} />
          ) : (
            <Card className="p-6 text-center">
              <ShieldAlert size={28} className="mx-auto text-slate-600 mb-2" />
              <p className="text-sm text-slate-400">No settings read yet. Click below to read your zone's current security settings from Cloudflare.</p>
              <Button className="mt-4" variant="secondary" onClick={refreshSettings} loading={reading}>
                <Cloud size={15} /> Read settings now
              </Button>
            </Card>
          )}

          {/* Proposals */}
          <CfProposals
            proposals={proposals}
            busyId={busyId}
            onAnalyze={analyze}
            onApprove={onApprove}
            onReject={onReject}
            onApply={onApply}
            onVerify={onVerify}
            onRollback={onRollback}
          />
        </>
      )}

      {connectOpen && (
        <CfConnectModal
          token={token}
          onClose={() => setConnectOpen(false)}
          onConnected={() => { setConnectOpen(false); load(); }}
        />
      )}
    </div>
  );
}
