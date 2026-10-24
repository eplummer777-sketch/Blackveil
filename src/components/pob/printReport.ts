import { isIssue, PobCheck, PobScan, PobTarget, RESULT_LABEL, RETEST_LABEL, SCORE_METHOD, AI_SECTIONS } from '@/lib/pob';

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

export function printReport(scan: PobScan, target: PobTarget | undefined, checks: PobCheck[]) {
  const win = window.open('', '_blank');
  if (!win) return false;
  const issues = checks.filter(isIssue);
  const others = checks.filter((c) => !isIssue(c));
  const sev = ['critical', 'high', 'medium', 'low'].map((s) => `<div class="stat"><b>${issues.filter((c) => c.severity === s).length}</b><small>${s}</small></div>`).join('');
  const duration = scan.finished_at ? Math.round((+new Date(scan.finished_at) - +new Date(scan.started_at)) / 1000) + 's' : 'n/a';
  const c = scan.counts;
  const findingHtml = issues.map((f) => {
    const fix = f.evidence.remediation;
    const { remediation: _r, ...ev } = f.evidence; void _r;
    const ai = f.ai_status === 'ready' && f.ai_analysis
      ? AI_SECTIONS.map(([k, l]) => `<div class="label">${esc(l)}</div><p>${esc(f.ai_analysis![k])}</p>`).join('')
      : '<p><i>No AI analysis was generated for this finding.</i></p>';
    return `<div class="finding ${esc(f.severity)}">
      <div class="fhead"><span class="sev ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span> ${esc(f.title)} — ${esc(RESULT_LABEL[f.result])}</div>
      <p>${esc(f.summary)}</p>
      <p><b>Asset:</b> ${esc(f.affected_asset)} · <b>Validation:</b> ${esc(f.validation)} · <b>Confidence:</b> ${esc(f.confidence)}</p>
      <p><b>Tool:</b> ${esc(f.tool)} v${esc(f.tool_version)} · <b>Operation:</b> ${esc(f.operation)}</p>
      <div class="label">Evidence (sanitized)</div><pre>${esc(JSON.stringify(ev, null, 2))}</pre>
      ${ai}
      ${fix ? `<div class="label">Recommended remediation</div><p>${esc(fix.why)}</p><ul>${fix.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>${fix.snippets.map((s) => `<pre>${esc(s.label)}:\n${esc(s.code)}</pre>`).join('')}` : ''}
      <div class="label">Repair history and retest</div>
      <p>Remediation: ${esc(f.remediation_status.replace(/_/g, ' '))} · Verification: ${esc(RETEST_LABEL[f.retest_status])}${f.retest_evidence ? ` (${esc(new Date(f.retest_evidence.at).toLocaleString())}: ${esc(f.retest_evidence.summary)})` : ''}</p>
    </div>`;
  }).join('');
  const checksHtml = others.map((x) => `<li><span class="dot ${x.result === 'passed' ? 'pass' : 'warn'}"></span>${esc(x.title)} — ${esc(RESULT_LABEL[x.result])}: ${esc(x.summary)}</li>`).join('');

  win.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>Blackveil Proof-of-Breach Report — ${esc(scan.hostname)}</title>
  <link rel="stylesheet" href="${window.location.origin}/report.css"></head><body>
  <div class="h"><div class="brand">BLACKVEIL <span>AI</span></div><div>Proof-of-Breach Security Report</div></div>
  <div class="meta"><b>Target:</b> ${esc(scan.hostname)} (${esc(target?.environment ?? 'n/a')})<br>
  <b>Authorization:</b> Domain ownership verified by DNS TXT record${target?.verified_at ? ' on ' + esc(new Date(target.verified_at).toLocaleDateString()) : ''}; scope paths ${esc(target?.allowed_paths.join(', ') ?? '/')}; categories ${esc(target?.allowed_categories.join(', ') ?? '')}<br>
  <b>Scan date:</b> ${esc(new Date(scan.started_at).toLocaleString())} · <b>Duration:</b> ${duration} · <b>Status:</b> ${esc(scan.status)}<br>
  <b>Methodology:</b> Passive, non-destructive HTTP/TLS/DNS checks within verified scope. No exploits, logins, or data modification were attempted.<br>
  <b>Tools:</b> Blackveil HTTP Probe v1.0.0 (built-in Blackveil engine).</div>
  <h2>Executive summary</h2>
  <p>Security score <b>${scan.score ?? 'n/a'}/100</b>. ${c.passed ?? 0} passed, ${c.failed ?? 0} failed, ${c.partial ?? 0} partially protected, ${c.validated ?? 0} validated findings, ${c.suspected ?? 0} detected/suspected, ${c.incomplete ?? 0} incomplete, ${c.not_performed ?? 0} not performed.</p>
  <div class="grid">${sev}</div>
  <h2>Scoring methodology</h2><ul>${SCORE_METHOD.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>
  <h2>Findings</h2>${findingHtml || '<p>No failed checks.</p>'}
  <h2>Other checks (passed, incomplete or not performed)</h2><ul class="checks">${checksHtml}</ul>
  <h2>Limitations and disclaimer</h2>
  <p>This report covers only the checks listed above at the time of the scan. A high score is not proof that the site is secure. Authenticated areas, application logic, server internals and network services were not tested. Incomplete and not-performed checks must not be treated as passing.</p>
  </body></html>`);
  win.document.close();
  if (win.document.readyState === 'complete') win.print();
  else win.addEventListener('load', () => win.print());
  return true;
}
