import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Assessment, Finding } from '@/lib/types';
import { Card, SectionTitle, Button, Badge, SeverityPill, EmptyState, Spinner } from '@/components/ui';
import { SEVERITY_ORDER } from '@/lib/types';
import {
  FileText, Download, ArrowLeft, Globe, CheckCircle2, AlertTriangle, ShieldCheck, Filter,
} from 'lucide-react';

export function Reports() {
  const { user } = useAuth();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Assessment | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);

  async function load() {
    if (!user) return;
    setLoading(true);
    const { data } = await supabase
      .from('assessments')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });
    setAssessments((data as Assessment[]) ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, [user]);

  async function openAssessment(a: Assessment) {
    setSelected(a);
    setLoadingFindings(true);
    const { data } = await supabase
      .from('findings')
      .select('*')
      .eq('assessment_id', a.id)
      .order('severity', { ascending: true });
    setFindings((data as Finding[]) ?? []);
    setLoadingFindings(false);
  }

  if (selected) {
    return (
      <ReportDetail
        assessment={selected}
        findings={findings}
        loading={loadingFindings}
        onBack={() => { setSelected(null); setFindings([]); }}
      />
    );
  }

  return (
    <div className="space-y-6 fade-up">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">Reports & History</h1>
        <p className="text-slate-400 mt-1 text-sm">All assessments, downloadable as PDF, with remediation tracking.</p>
      </div>

      <Card className="p-5">
        <SectionTitle title="Assessment history" icon={<FileText size={18} />} />
        {loading ? (
          <div className="p-3"><Spinner className="text-slate-500" /></div>
        ) : assessments.length === 0 ? (
          <EmptyState icon={<FileText size={28} />} title="No reports yet" hint="Run an assessment to generate a report." />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {assessments.map((a) => {
              const summary = a.summary ?? {};
              return (
                <div key={a.id} className="flex items-center gap-3 py-3">
                  <Globe size={16} className="text-cyan-300 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-slate-200 truncate">{a.target}</div>
                    <div className="text-[11px] text-slate-500 font-mono-tight">{new Date(a.created_at).toLocaleString()}</div>
                  </div>
                  <div className="hidden md:flex items-center gap-1.5">
                    {(['critical', 'high', 'medium', 'low'] as const).map((s) => {
                      const c = summary[s] ?? 0;
                      if (!c) return null;
                      return <span key={s} className="text-xs text-slate-400"><b className={severityText(s)}>{c}</b> {s}</span>;
                    })}
                  </div>
                  <Badge tone={a.status === 'completed' ? 'green' : a.status === 'failed' ? 'rose' : 'slate'}>{a.status}</Badge>
                  <Button size="sm" variant="secondary" onClick={() => openAssessment(a)}>
                    Open <ArrowLeft size={13} className="rotate-180" />
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

function severityText(s: string) {
  return s === 'critical' ? 'text-rose-300' : s === 'high' ? 'text-orange-300' : s === 'medium' ? 'text-amber-300' : 'text-cyan-300';
}

function ReportDetail({ assessment, findings, loading, onBack }: {
  assessment: Assessment;
  findings: Finding[];
  loading: boolean;
  onBack: () => void;
}) {
  const sorted = findings.slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const summary = assessment.summary ?? {};

  function downloadPdf() {
    const win = window.open('', '_blank');
    if (!win) return;
    const checks = (assessment.summary as { checks?: { check_id: string; status: string; note?: string }[] })?.checks ?? [];
    const findingsHtml = sorted.map((f) => `
      <div class="finding ${f.severity}">
        <div class="fhead"><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span> ${escapeHtml(f.title)}</div>
        <p>${escapeHtml(f.description ?? '')}</p>
        <div class="label">Evidence</div><pre>${escapeHtml(f.evidence ?? 'N/A')}</pre>
        <div class="label">Remediation</div><p>${escapeHtml(f.remediation ?? '')}</p>
      </div>`).join('');
    const checksHtml = checks.map((c) => `<li><span class="dot ${c.status}"></span>${escapeHtml(c.check_id)} — ${c.status}${c.note ? ' · ' + escapeHtml(c.note) : ''}</li>`).join('');
    win.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>Blackveil Report — ${escapeHtml(assessment.target)}</title>
    <link rel="stylesheet" href="${window.location.origin}/report.css"></head><body>
    <div class="h"><div class="brand">BLACKVEIL <span>AI</span></div><div>Security Assessment Report</div></div>
    <div class="meta"><b>Target:</b> ${escapeHtml(assessment.target)}<br>
    <b>Assessed:</b> ${new Date(assessment.created_at).toLocaleString()}<br>
    <b>Status:</b> ${escapeHtml(assessment.status)} · ${escapeHtml(assessment.overall_status ?? 'N/A')}<br>
    <b>Authorization:</b> Confirmed by owner/operator</div>
    <div class="grid">
      ${['critical','high','medium','low','info'].map(s => `<div class="stat"><b>${summary[s] ?? 0}</b><small>${s}</small></div>`).join('')}
    </div>
    <h2>Checks performed</h2><ul>${checksHtml || '<li>No check metadata</li>'}</ul>
    <h2>Findings (${sorted.length})</h2>${findingsHtml || '<p>No findings.</p>'}
    <div class="foot">Generated by BLACKVEIL AI · Defensive, non-intrusive assessment. Untested systems are not labeled secure. This report is provided for defensive remediation purposes only.</div>
    </body></html>`);
    win.document.close();
    if (win.document.readyState === 'complete') win.print();
    else win.addEventListener('load', () => win.print());
  }

  return (
    <div className="space-y-5 fade-up">
      <button onClick={onBack} className="text-sm text-slate-400 hover:text-slate-200 flex items-center gap-1.5">
        <ArrowLeft size={14} /> Back to reports
      </button>

      <Card className="p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-500">Assessment report</div>
            <div className="text-xl font-semibold text-slate-100 flex items-center gap-2"><Globe size={18} className="text-cyan-300" /> {assessment.target}</div>
            <div className="text-[11px] text-slate-500 mt-1 font-mono-tight">{new Date(assessment.created_at).toLocaleString()}</div>
          </div>
          <div className="flex items-center gap-2">
            <Badge tone={assessment.status === 'completed' ? 'green' : 'rose'}>{assessment.status}</Badge>
            {assessment.overall_status && <Badge tone="cyan">{assessment.overall_status}</Badge>}
            <Button size="sm" onClick={downloadPdf}><Download size={14} /> Download PDF</Button>
          </div>
        </div>
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 mt-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
            <div key={s} className="rounded-lg bg-veil-950/60 border border-slate-800/70 p-2.5 text-center">
              <div className={`text-lg font-semibold ${summary[s] ? 'text-slate-100' : 'text-slate-600'}`}>{summary[s] ?? 0}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-500">{s}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-5">
        <SectionTitle title={`Findings (${sorted.length})`} subtitle="Sorted by severity. Each includes evidence and remediation." icon={<AlertTriangle size={18} />} />
        {loading ? <Spinner className="text-slate-500" /> : sorted.length === 0 ? (
          <EmptyState icon={<ShieldCheck size={28} />} title="No findings" hint="All completed checks passed." />
        ) : (
          <div className="space-y-3">
            {sorted.map((f) => (
              <div key={f.id} className="rounded-lg border border-slate-800/70 bg-veil-950/40 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{f.title}</div>
                    <div className="text-xs text-slate-500 mt-0.5 font-mono-tight">{f.check_id}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {f.verified ? <Badge tone="green">Verified</Badge> : <Badge tone="slate">Inferred</Badge>}
                    <SeverityPill severity={f.severity} />
                  </div>
                </div>
                {f.description && <p className="text-sm text-slate-400 mt-2">{f.description}</p>}
                {f.evidence && (
                  <div className="mt-2.5">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Evidence</div>
                    <pre className="text-[12px] font-mono-tight text-slate-300 bg-veil-950/80 border border-slate-800/70 rounded-md p-2.5 overflow-x-auto whitespace-pre-wrap">{f.evidence}</pre>
                  </div>
                )}
                {f.remediation && (
                  <div className="mt-2.5 text-sm">
                    <div className="text-[10px] uppercase tracking-wider text-cyan-400 mb-1">Remediation</div>
                    <p className="text-slate-300">{f.remediation}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

export { Filter, CheckCircle2 };
