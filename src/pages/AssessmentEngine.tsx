import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, Ban, Check, CheckCircle2, Cloud, Eye, History, Lock,
  RotateCcw, ScanSearch, ShieldAlert, ShieldCheck, Sparkles, Zap,
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Badge, Button, Card, ErrorBanner, EmptyState, SectionTitle, SeverityPill, Spinner } from '@/components/ui';
import { SEVERITY_ORDER, Severity } from '@/lib/types';
import {
  RemediationAssessment, RemediationAuditEntry, RemediationFinding,
  callAssessment, FIX_STATUS_META, formatVal,
} from '@/lib/remediation';
import { CfIntegration } from '@/lib/cloudflare';

export function AssessmentEngine() {
  const { session, user } = useAuth();
  const token = session?.access_token ?? '';
  const [target, setTarget] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<RemediationAssessment | null>(null);
  const [findings, setFindings] = useState<RemediationFinding[]>([]);
  const [audit, setAudit] = useState<RemediationAuditEntry[]>([]);
  const [recent, setRecent] = useState<RemediationAssessment[]>([]);
  const [integration, setIntegration] = useState<CfIntegration | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [ackIds, setAckIds] = useState<Set<string>>(new Set());
  const [confirmIds, setConfirmIds] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    if (!user) return;
    const [a, i] = await Promise.all([
      supabase.from('remediation_assessments').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(10),
      supabase.from('architect_integrations').select('*').eq('provider', 'cloudflare').eq('status', 'connected').maybeSingle(),
    ]);
    setRecent((a.data ?? []) as RemediationAssessment[]);
    setIntegration((i.data as CfIntegration) ?? null);
  }, [user]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!notice) return; const t = setTimeout(() => setNotice(null), 6000); return () => clearTimeout(t); }, [notice]);

  const toggle = (set: Set<string>, id: string) => {
    const next = new Set(set);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  };

  async function runAssessment() {
    if (!target.trim()) { setError('Enter a domain to assess.'); return; }
    if (!confirmed) { setError('Confirm you own or have permission to assess this target.'); return; }
    setLoading(true);
    setError(null);
    setAssessment(null);
    setFindings([]);
    setAudit([]);
    const res = await callAssessment<{ assessment: RemediationAssessment; findings: RemediationFinding[] }>(token, {
      action: 'run_assessment',
      target,
      authorization_confirmed: confirmed,
      integration_id: integration?.id,
    });
    setLoading(false);
    if (!res.ok) { setError(res.error); return; }
    setAssessment(res.data?.assessment ?? null);
    setFindings(res.data?.findings ?? []);
    load();
    const summary = res.data?.assessment?.summary;
    const total = summary?.total ?? 0;
    const gaps = (res.data?.findings ?? []).filter((f) => f.severity !== 'info').length;
    setNotice(gaps === 0 ? 'Assessment complete. No security issues found.' : `Assessment complete. ${gaps} issue${gaps === 1 ? '' : 's'} found across ${total} checks.`);
  }

  async function loadAssessment(id: string) {
    const res = await callAssessment<{ assessment: RemediationAssessment; findings: RemediationFinding[]; audit: RemediationAuditEntry[] }>(token, {
      action: 'get_assessment', assessment_id: id,
    });
    if (!res.ok) { setError(res.error); return; }
    setAssessment(res.data?.assessment ?? null);
    setFindings(res.data?.findings ?? []);
    setAudit(res.data?.audit ?? []);
  }

  async function fixAction(id: string, action: string, body: Record<string, unknown> = {}) {
    setBusyId(id);
    setError(null);
    const res = await callAssessment<{ message: string; passed?: boolean }>(token, { action, finding_id: id, ...body });
    setBusyId(null);
    if (!res.ok) { setError(res.error); return; }
    setNotice(res.data?.message ?? 'Done.');
    if (assessment) await loadAssessment(assessment.id);
  }

  const onApprove = (id: string) => fixAction(id, 'approve_fix', { acknowledged_risks: true });
  const onReject = (id: string) => fixAction(`reject-${id}`, 'reject_fix');
  const onApply = (id: string) => fixAction(id, 'apply_fix', { confirmed: true });
  const onVerify = (id: string) => fixAction(id, 'verify_fix');

  // Group findings
  const grouped = useMemo(() => {
    const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    const map = new Map<Severity, RemediationFinding[]>();
    for (const f of sorted) {
      const arr = map.get(f.severity) ?? [];
      arr.push(f);
      map.set(f.severity, arr);
    }
    return Array.from(map.entries());
  }, [findings]);

  const pendingApprovals = findings.filter((f) => f.fix_status === 'proposed' && f.fixable);
  const verifiedCount = findings.filter((f) => f.fix_status === 'verified').length;

  return (
    <div className="space-y-6 fade-in">
      <header>
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-cyan-300/80 font-mono-tight">
          <ScanSearch size={13} /> Assessment & Remediation
        </div>
        <h1 className="mt-1 text-2xl md:text-3xl font-semibold tracking-tight">
          <span className="text-slate-50">Security </span><span className="text-gradient">Assessment Engine</span>
        </h1>
        <p className="mt-1 text-sm text-slate-400 max-w-2xl">
          Inspects your website with safe, non-intrusive checks and your connected Cloudflare zone. Identifies real weaknesses, prioritizes them, proposes fixes, and verifies each fix after it is applied.
        </p>
      </header>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && (
        <div className="fade-in rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-4 py-2.5 text-sm text-cyan-100 flex items-start gap-2">
          <ShieldCheck size={15} className="mt-0.5 shrink-0" /> {notice}
        </div>
      )}

      <div className="grid lg:grid-cols-5 gap-6">
        {/* Assessment form */}
        <Card className="lg:col-span-2 p-5 h-fit">
          <SectionTitle title="New assessment" subtitle="Enter a public domain" icon={<ScanSearch size={18} />} />
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Target domain</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                autoComplete="off"
                spellCheck={false}
                className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition"
              />
              <p className="text-[11px] text-slate-500 mt-1.5">Use a root domain. http:// or https:// prefixes are accepted.</p>
            </div>

            {integration ? (
              <div className="flex items-center gap-2.5 rounded-lg border border-orange-500/30 bg-orange-500/5 p-3">
                <Cloud size={15} className="text-orange-300 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-200">Cloudflare: {integration.zone_name}</p>
                  <p className="text-xs text-slate-500">
                    {integration.mode === 'write' ? 'Write mode — fixes can be applied' : 'Read-only — fixes will be proposed but not applied'}
                  </p>
                </div>
                <Badge tone={integration.mode === 'write' ? 'cyan' : 'slate'}>
                  {integration.mode === 'write' ? <><Zap size={10} /> Write</> : <><Eye size={10} /> Read</>}
                </Badge>
              </div>
            ) : (
              <div className="flex items-center gap-2.5 rounded-lg border border-slate-700/60 bg-veil-950/40 p-3">
                <Cloud size={15} className="text-slate-500 shrink-0" />
                <p className="text-xs text-slate-500">No Cloudflare zone connected. HTTP checks will run; connect Cloudflare in the Architect tab to also inspect zone settings and apply fixes.</p>
              </div>
            )}

            <label className="flex items-start gap-2.5 cursor-pointer text-sm">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-slate-600 bg-veil-950 accent-cyan-500 focus:ring-cyan-400/40"
              />
              <span className="text-slate-300">I own this domain or have <span className="text-cyan-300">explicit permission</span> to assess it.</span>
            </label>

            <Button full disabled={!target || !confirmed} loading={loading} onClick={runAssessment}>
              <ScanSearch size={16} /> {loading ? 'Running assessment...' : 'Run assessment'}
            </Button>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Rate-limited to 10 assessments per hour. Private, loopback, and cloud metadata destinations are blocked. No intrusive or exploit-based tests are performed.
            </p>
          </div>
        </Card>

        {/* Results */}
        <div className="lg:col-span-3 space-y-5">
          {loading && (
            <Card className="p-5 relative overflow-hidden">
              <div className="absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-cyan-400/10 to-transparent scanline pointer-events-none" />
              <div className="flex items-center gap-2 text-cyan-300">
                <Spinner className="text-cyan-300" />
                <span className="text-sm font-medium">Assessing {target || 'target'}...</span>
              </div>
              <ul className="mt-4 space-y-2">
                {['Resolving DNS', 'Checking HTTPS reachability', 'Inspecting security headers', 'Testing HTTP redirect', 'Reading Cloudflare settings', 'Prioritizing findings'].map((s, i) => (
                  <li key={s} className="flex items-center gap-2 text-sm text-slate-400 fade-up" style={{ animationDelay: `${i * 120}ms` }}>
                    <CheckCircle2 size={14} className="text-cyan-400/70" /> {s}
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {!loading && assessment && (
            <>
              {/* Summary */}
              <Card className="p-5 border-cyan-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-wider text-slate-500">Result</div>
                    <div className="text-xl font-semibold text-slate-100">{assessment.target}</div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      {new Date(assessment.created_at).toLocaleString()} · {assessment.sources.includes('cloudflare') ? 'HTTP + Cloudflare' : 'HTTP only'}
                    </div>
                  </div>
                  <Badge tone={assessment.overall_status === 'Critical' ? 'rose' : assessment.overall_status === 'Needs attention' ? 'amber' : 'green'}>
                    {assessment.overall_status}
                  </Badge>
                </div>
                <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 mt-4">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
                    <div key={s} className="rounded-lg bg-veil-950/60 border border-slate-800/70 p-2.5 text-center">
                      <div className={`text-lg font-semibold ${assessment.summary[s] ? 'text-slate-100' : 'text-slate-600'}`}>{assessment.summary[s] ?? 0}</div>
                      <div className="text-[10px] uppercase tracking-wider text-slate-500">{s}</div>
                    </div>
                  ))}
                </div>
                {verifiedCount > 0 && (
                  <div className="mt-3 flex items-center gap-2 text-xs text-emerald-300">
                    <CheckCircle2 size={13} /> {verifiedCount} fix{verifiedCount === 1 ? '' : 'es'} verified live
                  </div>
                )}
              </Card>

              {/* Pending approvals */}
              {pendingApprovals.length > 0 && (
                <Card className="p-4 border-amber-500/30">
                  <div className="flex items-center gap-2 text-amber-200 mb-2">
                    <AlertTriangle size={16} /> <span className="text-sm font-medium">{pendingApprovals.length} fix{pendingApprovals.length === 1 ? '' : 'es'} awaiting your approval</span>
                  </div>
                  <p className="text-xs text-slate-500">Review each finding below, then approve the ones you want to apply.</p>
                </Card>
              )}

              {/* Findings */}
              {grouped.map(([severity, items]) => (
                <div key={severity}>
                  <div className="flex items-center gap-2 mb-2">
                    <SeverityPill severity={severity} />
                    <span className="text-xs text-slate-500">{items.length} finding{items.length === 1 ? '' : 's'}</span>
                  </div>
                  <div className="space-y-2">
                    {items.map((f) => (
                      <FindingCard
                        key={f.id}
                        finding={f}
                        busyId={busyId}
                        acked={ackIds.has(f.id)}
                        confirmed={confirmIds.has(f.id)}
                        onToggleAck={() => setAckIds(toggle(ackIds, f.id))}
                        onToggleConfirm={() => setConfirmIds(toggle(confirmIds, f.id))}
                        onApprove={() => onApprove(f.id)}
                        onReject={() => onReject(f.id)}
                        onApply={() => onApply(f.id)}
                        onVerify={() => onVerify(f.id)}
                      />
                    ))}
                  </div>
                </div>
              ))}

              {findings.length === 0 && (
                <Card className="p-8 text-center">
                  <ShieldCheck size={32} className="mx-auto text-slate-600 mb-2" />
                  <p className="text-sm text-slate-400">No findings were recorded for this assessment.</p>
                </Card>
              )}

              {/* Audit history */}
              {audit.length > 0 && (
                <Card className="p-5">
                  <SectionTitle title="Audit history" subtitle="Every action on this assessment" icon={<History size={18} />} />
                  <div className="divide-y divide-slate-800/60">
                    {audit.map((a) => (
                      <div key={a.id} className="flex items-center gap-3 py-2.5">
                        <div className={`w-1.5 h-1.5 rounded-full ${AUDIT_TONE[a.action]?.dot ?? 'bg-slate-500'}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-300">{AUDIT_TONE[a.action]?.label ?? a.action}</p>
                          <p className="text-[11px] text-slate-500 font-mono-tight">{new Date(a.created_at).toLocaleString()}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </>
          )}

          {!loading && !assessment && (
            <Card className="p-5">
              <SectionTitle title="What we check" subtitle="Non-intrusive, evidence-backed" icon={<ShieldCheck size={18} />} />
              <div className="grid sm:grid-cols-2 gap-3">
                {CHECKS.map((c) => (
                  <div key={c.id} className="flex items-start gap-2.5 rounded-lg border border-slate-800/70 bg-veil-950/40 p-3">
                    <span className="mt-0.5 text-cyan-300">{c.icon}</span>
                    <div>
                      <div className="text-sm font-medium text-slate-200">{c.title}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{c.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Recent assessments */}
      <Card className="p-5">
        <SectionTitle title="Recent assessments" icon={<History size={18} />} />
        {recent.length === 0 ? (
          <EmptyState icon={<History size={26} />} title="No assessments yet" hint="Your completed assessments will appear here." />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {recent.map((a) => (
              <button key={a.id} onClick={() => loadAssessment(a.id)} className="flex items-center gap-3 py-3 w-full text-left hover:bg-veil-800/30 -mx-2 px-2 rounded-lg transition">
                <ScanSearch size={16} className="text-cyan-300 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-slate-200 truncate">{a.target}</div>
                  <div className="text-[11px] text-slate-500 font-mono-tight">{new Date(a.created_at).toLocaleString()}</div>
                </div>
                <Badge tone={a.status === 'completed' ? 'green' : a.status === 'failed' ? 'rose' : 'slate'}>{a.status}</Badge>
                {a.overall_status && <Badge tone={a.overall_status === 'Critical' ? 'rose' : a.overall_status === 'Needs attention' ? 'amber' : 'green'}>{a.overall_status}</Badge>}
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function FindingCard({ finding, busyId, acked, confirmed, onToggleAck, onToggleConfirm, onApprove, onReject, onApply, onVerify }: {
  finding: RemediationFinding;
  busyId: string | null;
  acked: boolean;
  confirmed: boolean;
  onToggleAck: () => void;
  onToggleConfirm: () => void;
  onApprove: () => void;
  onReject: () => void;
  onApply: () => void;
  onVerify: () => void;
}) {
  const [open, setOpen] = useState(false);
  const fixMeta = FIX_STATUS_META[finding.fix_status];

  return (
    <Card className={`overflow-hidden transition ${open ? 'border-cyan-500/30' : ''}`}>
      <button onClick={() => setOpen(!open)} className="w-full p-4 text-left">
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-1.5">
              <p className="text-sm font-medium text-slate-100">{finding.title}</p>
              <SeverityPill severity={finding.severity} />
              {finding.source === 'cloudflare' && <Badge tone="cyan"><Cloud size={9} /> CF</Badge>}
              {finding.fixable && <Badge tone={fixMeta.tone}>{fixMeta.label}</Badge>}
            </div>
            <p className="mt-1 text-xs text-slate-500">{finding.category}</p>
            {finding.fixable && finding.fix_status === 'proposed' && (
              <div className="mt-2 flex items-center gap-3 text-xs">
                <span className="text-slate-500">From <span className="font-mono-tight text-amber-200">{formatVal(finding.current_value)}</span></span>
                <span className="text-slate-600">→</span>
                <span className="text-slate-500">To <span className="font-mono-tight text-cyan-200">{formatVal(finding.proposed_value)}</span></span>
              </div>
            )}
          </div>
        </div>
      </button>

      {open && (
        <div className="border-t border-slate-800/80 px-4 py-4 space-y-4 fade-in">
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Evidence</p>
            <pre className="text-[12px] font-mono-tight text-slate-300 bg-veil-950/80 border border-slate-800/70 rounded-md p-2.5 overflow-x-auto whitespace-pre-wrap">{finding.evidence}</pre>
          </div>

          <div>
            <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Impact</p>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.impact}</p>
          </div>

          <div>
            <p className="text-xs uppercase tracking-wider text-cyan-400 mb-1">Recommended remediation</p>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.remediation}</p>
          </div>

          {finding.fixable && finding.risks.length > 0 && (
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">Risks of this change</p>
              <ul className="space-y-1.5">
                {finding.risks.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-400 leading-relaxed">
                    <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-300" /> {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {finding.rollback_supported && (
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">Rollback</p>
              <div className="flex items-start gap-2 rounded-lg border border-slate-800 bg-veil-950/50 p-3">
                <RotateCcw size={13} className="mt-0.5 shrink-0 text-cyan-300" />
                <p className="text-sm text-slate-300 leading-relaxed">{finding.rollback_instructions}</p>
              </div>
            </div>
          )}

          {finding.apply_error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3">
              <p className="text-sm text-rose-200">{finding.apply_error}</p>
            </div>
          )}

          {finding.verification_result && (
            <div className={`rounded-lg border p-3 ${finding.fix_status === 'verified' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}>
              <div className="flex items-center gap-2">
                {finding.fix_status === 'verified' ? <CheckCircle2 size={14} className="text-emerald-300" /> : <ShieldAlert size={14} className="text-amber-300" />}
                <span className="text-sm text-slate-200">{finding.fix_status === 'verified' ? 'Verified live' : 'Verification result'}</span>
              </div>
              {finding.verification_result.actual !== undefined && (
                <p className="mt-1 text-xs text-slate-400">Actual value now: <span className="font-mono-tight text-slate-300">{formatVal(finding.verification_result.actual)}</span></p>
              )}
              {finding.verification_result.error && <p className="mt-1 text-xs text-rose-300">{finding.verification_result.error}</p>}
            </div>
          )}

          {/* Actions */}
          {finding.fixable && (
            <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-800/60">
              {finding.fix_status === 'proposed' && (
                <>
                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer mr-auto">
                    <input type="checkbox" checked={acked} onChange={onToggleAck} className="accent-cyan-400" />
                    I've read the risks
                  </label>
                  <Button size="sm" disabled={!acked} loading={busyId === finding.id} onClick={onApprove}>
                    <Check size={14} /> Approve fix
                  </Button>
                  <Button size="sm" variant="ghost" loading={busyId === `reject-${finding.id}`} onClick={onReject}>
                    <Ban size={14} /> Reject
                  </Button>
                </>
              )}
              {finding.fix_status === 'approved' && (
                <>
                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer mr-auto">
                    <input type="checkbox" checked={confirmed} onChange={onToggleConfirm} className="accent-cyan-400" />
                    Apply to my live zone
                  </label>
                  <Button size="sm" disabled={!confirmed} loading={busyId === finding.id} onClick={onApply}>
                    <Zap size={14} /> Apply now
                  </Button>
                  <Button size="sm" variant="ghost" loading={busyId === `reject-${finding.id}`} onClick={onReject}>
                    <Ban size={14} /> Reject
                  </Button>
                </>
              )}
              {finding.fix_status === 'applied' && (
                <Button size="sm" loading={busyId === finding.id} onClick={onVerify}>
                  <ShieldCheck size={14} /> Verify
                </Button>
              )}
              {finding.fix_status === 'failed' && (
                <Button size="sm" variant="secondary" loading={busyId === finding.id} onClick={onApply}>
                  <Sparkles size={14} /> Retry
                </Button>
              )}
              {!['proposed', 'approved', 'applied', 'verified', 'failed'].includes(finding.fix_status) && finding.fix_status !== 'none' && (
                <p className="text-xs text-slate-500">{FIX_STATUS_META[finding.fix_status].hint}</p>
              )}
            </div>
          )}

          {!finding.fixable && finding.source === 'http' && (
            <p className="text-xs text-slate-500 pt-1 border-t border-slate-800/60">
              No automatic fix is available. Follow the remediation advice above to fix this manually.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

const AUDIT_TONE: Record<string, { label: string; dot: string }> = {
  assessment_completed: { label: 'Assessment completed', dot: 'bg-emerald-400' },
  assessment_failed: { label: 'Assessment failed', dot: 'bg-rose-400' },
  fix_approved: { label: 'Fix approved', dot: 'bg-amber-400' },
  fix_rejected: { label: 'Fix rejected', dot: 'bg-slate-400' },
  fix_applied: { label: 'Fix applied to Cloudflare', dot: 'bg-cyan-400' },
  fix_apply_failed: { label: 'Fix apply failed', dot: 'bg-rose-400' },
  fix_verified: { label: 'Fix verified live', dot: 'bg-emerald-400' },
  fix_verify_mismatch: { label: 'Fix verification mismatch', dot: 'bg-amber-400' },
};

const CHECKS = [
  { id: 'tls', title: 'TLS / HTTPS', desc: 'Handshake success and HTTPS availability', icon: <Lock size={16} /> },
  { id: 'redirect', title: 'HTTP→HTTPS redirect', desc: 'Plain HTTP should redirect', icon: <RotateCcw size={16} /> },
  { id: 'headers', title: 'Security headers', desc: 'HSTS, CSP, X-Frame-Options, etc.', icon: <ShieldCheck size={16} /> },
  { id: 'banner', title: 'Server banner', desc: 'Software version disclosure', icon: <Eye size={16} /> },
  { id: 'dns', title: 'DNS records', desc: 'A record resolution', icon: <ScanSearch size={16} /> },
  { id: 'cloudflare', title: 'Cloudflare zone', desc: 'Security settings and gaps', icon: <Cloud size={16} /> },
];
