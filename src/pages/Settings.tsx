import { useState, FormEvent } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase, edgeUrl } from '@/lib/supabase';
import { Card, SectionTitle, Button, Input, Label, Badge } from '@/components/ui';
import { PLAN_LABELS, PLAN_PRICES } from '@/lib/types';
import { UserCircle, Mail, Building2, Trash2, AlertTriangle, ShieldCheck, LogOut, Gauge, Bug, CreditCard, Crown, Sparkles, ExternalLink } from 'lucide-react';
import { Route } from '@/components/AppShell';

export function Settings({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { user, profile, refreshProfile, signOut, subscription, hasMalwareRemoval, plan, session } = useAuth();
  const [displayName, setDisplayName] = useState(profile?.display_name ?? '');
  const [company, setCompany] = useState(profile?.company ?? '');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);
  const [portalError, setPortalError] = useState<string | null>(null);

  async function openBillingPortal() {
    setPortalLoading(true);
    setPortalError(null);
    if (!session?.access_token) {
      setPortalError('You must be signed in.');
      setPortalLoading(false);
      return;
    }
    try {
      const resp = await fetch(edgeUrl('stripe-portal'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) {
        setPortalError(data?.error ?? `Could not open billing portal (${resp.status}).`);
        setPortalLoading(false);
        return;
      }
      if (data?.url) {
        window.location.href = data.url;
        return;
      }
      setPortalError('Billing portal could not be opened. Please try again.');
      setPortalLoading(false);
    } catch {
      setPortalError('Something went wrong. Please try again.');
      setPortalLoading(false);
    }
  }

  async function saveProfile(e: FormEvent) {
    e.preventDefault();
    if (!user) return;
    setSaving(true);
    setMsg(null);
    const { error } = await supabase
      .from('profiles')
      .update({ display_name: displayName, company })
      .eq('id', user.id);
    setSaving(false);
    if (error) { setMsg(error.message); return; }
    await refreshProfile();
    setMsg('Profile updated.');
  }

  async function deleteAccount() {
    if (!user) return;
    setDeleteError(null);
    // Best-effort: delete profile row and sign out. Supabase does not allow
    // self-deletion of auth.users from the client; this requires an admin or
    // an edge function with service role. We scope what we can from the client.
    await supabase.from('audit_logs').insert({
      user_id: user.id,
      action: 'account_closure_requested',
      detail: { email: user.email },
    });
    await signOut();
    setDeleteError(
      'Account closure request recorded. To fully delete your account and data, contact the account owner / admin who can run the closure workflow from the Supabase dashboard. You have been signed out.'
    );
  }

  return (
    <div className="space-y-6 fade-up max-w-3xl">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">Account & Settings</h1>
        <p className="text-slate-400 mt-1 text-sm">Manage your profile, subscription, and account data.</p>
      </div>

      <Card className="p-5">
        <SectionTitle title="Profile" icon={<UserCircle size={18} />} />
        <form onSubmit={saveProfile} className="space-y-4 max-w-md">
          <div>
            <Label>Email</Label>
            <div className="relative">
              <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <Input value={profile?.email ?? ''} disabled className="pl-9 opacity-70" />
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Email cannot be changed here. Use password reset to verify ownership.</p>
          </div>
          <div>
            <Label>Display name</Label>
            <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Your name" />
          </div>
          <div>
            <Label>Company (optional)</Label>
            <div className="relative">
              <Building2 size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <Input value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Company name" className="pl-9" />
            </div>
          </div>
          {msg && <p className="text-sm text-emerald-300">{msg}</p>}
          <Button type="submit" loading={saving}><ShieldCheck size={15} /> Save profile</Button>
        </form>
      </Card>

      <Card className="p-5">
        <SectionTitle title="Subscription" subtitle="Your current plan" icon={<Gauge size={18} />} />
        <div className="rounded-lg border border-slate-800/70 bg-veil-950/40 p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${plan === 'elite' ? 'bg-amber-500/15 text-amber-300' : plan === 'pro' ? 'bg-cyan-500/15 text-cyan-300' : hasMalwareRemoval ? 'bg-cyan-500/15 text-cyan-300' : 'bg-veil-800 text-slate-400'}`}>
              {plan === 'elite' ? <Crown size={18} /> : plan === 'pro' ? <Sparkles size={18} /> : hasMalwareRemoval ? <Bug size={18} /> : <Gauge size={18} />}
            </div>
            <div>
              <div className="text-sm font-medium text-slate-200">
                {PLAN_LABELS[plan]} · ${PLAN_PRICES[plan]}/mo
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {plan === 'free'
                  ? 'Upgrade to unlock the Malware Removal Guide and more AI messages.'
                  : plan === 'elite'
                    ? 'You have unlimited AI messages and exclusive protection.'
                    : `Active${subscription?.current_period_end ? ` · renews ${new Date(subscription.current_period_end).toLocaleDateString()}` : ''}`}
              </p>
            </div>
          </div>
          <Badge tone={plan === 'free' ? 'slate' : 'green'}>
            {plan === 'free' ? 'Free' : 'Active'}
          </Badge>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => onNavigate('malware')}>
            <CreditCard size={15} /> {plan === 'free' ? 'View plans & upgrade' : 'Change plan'}
          </Button>
          {plan !== 'free' && (
            <Button variant="ghost" loading={portalLoading} onClick={openBillingPortal}>
              <ExternalLink size={15} /> Manage billing & cancel
            </Button>
          )}
          {plan !== 'free' && (
            <p className="text-[11px] text-slate-500 self-center">Cancel anytime. You keep access until the end of your billing period.</p>
          )}
        </div>
        {portalError && (
          <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{portalError}</div>
        )}
      </Card>

      <Card className="p-5 border-rose-500/20">
        <SectionTitle title="Danger zone" subtitle="Account closure & data deletion" icon={<AlertTriangle size={18} />} />
        {!confirmDelete ? (
          <Button variant="danger" onClick={() => setConfirmDelete(true)}><Trash2 size={15} /> Close my account</Button>
        ) : deleteError ? (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">{deleteError}</div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-slate-300">This will sign you out and record a closure request. Full deletion is completed by the operator to protect against unauthorized deletion.</p>
            <div className="flex gap-2">
              <Button variant="danger" onClick={deleteAccount}><LogOut size={15} /> Confirm closure</Button>
              <Button variant="ghost" onClick={() => setConfirmDelete(false)}>Cancel</Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
