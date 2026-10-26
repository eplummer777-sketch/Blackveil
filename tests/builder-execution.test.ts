import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeRequest, parseCoverage } from '../supabase/functions/_lib/intent.ts';
import { buildIndex } from '../supabase/functions/_lib/projectIndex.ts';
import { mergeProposals } from '../supabase/functions/_lib/changeset.ts';
import { parseAiReply } from '../supabase/functions/_lib/webbuilder.ts';
import {
  appliedRequirementStates, completeStep, failStep, planSteps, progressOf, requirementStates, startStep,
  verificationReport, withRequirementFiles, type PlanStep,
} from '../supabase/functions/_lib/taskPlan.ts';

const SITE = { 'index.html': '<!doctype html><html><body><h1>Hi</h1></body></html>', 'styles.css': 'body{}' };
const idx = buildIndex(SITE);

const analyze = (prompt: string) => analyzeRequest(prompt, idx, SITE, 'code');

const checksOk = [{ name: 'Static checks', ok: true, detail: 'all good' }];
const checksBad = [{ name: 'Static checks', ok: false, detail: 'index.html -> missing.png' }];

describe('requirement tracking', () => {
  const a = analyze('Add a page\nAdd a form\nAdd a footer');

  it('starts every requirement as unresolved when the plan reports no coverage', () => {
    const states = requirementStates(a, []);
    assert.equal(states.length, 3);
    assert.deepEqual(states.map((s) => s.status), ['unresolved', 'unresolved', 'unresolved']);
    assert.ok(states.every((s) => s.steps.length === 0));
  });

  it('links a requirement to the steps the planner assigned, and keeps unresolved ones marked', () => {
    const coverage = parseCoverage([
      { requirement: 'R1', covered_by: '1' },
      { requirement: 'R2', covered_by: '2' },
      { requirement: 'R3', covered_by: 'none' },
    ]);
    const states = requirementStates(a, coverage);
    assert.deepEqual(states[0].steps, [1]);
    assert.equal(states[0].status, 'pending');
    assert.equal(states[2].status, 'unresolved');
  });

  it('marks a requirement unresolved when it never fitted in the prompt', () => {
    const coverage = parseCoverage([{ requirement: 'R1', covered_by: '1' }]);
    const states = requirementStates(a, coverage, ['R1']);
    assert.equal(states[0].status, 'unresolved');
    assert.match(states[0].note ?? '', /never saw it/);
  });

  it('never completes a requirement from a plan claim alone, only from applied files', () => {
    const coverage = parseCoverage([{ requirement: 'R1', covered_by: '1' }]);
    let states = withRequirementFiles(requirementStates(a, coverage), planSteps(['Add a page'], [['index.html']], requirementStates(a, coverage)));
    assert.equal(states[0].status, 'pending');
    const xs = completeStep(startStep(planSteps(['Add a page'], [['index.html']], states), 1), states, 1);
    states = xs.states;
    assert.equal(states[0].status, 'in_progress');

    const notApplied = appliedRequirementStates(states, xs.steps, []);
    assert.equal(notApplied[0].status, 'failed');

    const applied = appliedRequirementStates(states, xs.steps, ['index.html']);
    assert.equal(applied[0].status, 'completed');
    assert.match(applied[0].note ?? '', /static checks only|applied/i);
  });

  it('keeps a failed step and its requirements visible instead of marking them done', () => {
    const coverage = parseCoverage([{ requirement: 'R1', covered_by: '1' }]);
    const states = requirementStates(a, coverage);
    const failed = failStep(startStep(planSteps(['Add a page'], [['index.html']], states), 1), states, 1, 'the reply could not be read');
    assert.equal(failed.steps[0].status, 'failed');
    assert.equal(failed.steps[0].attempts, 1);
    assert.equal(failed.states[0].status, 'failed');
    assert.match(failed.states[0].note ?? '', /could not be read/);
  });
});

describe('execution planning beyond eight steps', () => {
  const batches = Array.from({ length: 12 }, (_, i) => [`file${i + 1}.html`]);
  const coverageRows = batches.map((_, i) => ({ requirement: `R${i + 1}`, covered_by: String(i + 1) }));
  const prompt = batches.map((_, i) => `Change file${i + 1}.html`).join('\n');
  const a = analyze(prompt);
  const states = withRequirementFiles(requirementStates(a, parseCoverage(coverageRows)), planSteps(batches.map((_, i) => `Step ${i + 1}`), batches, requirementStates(a, parseCoverage(coverageRows))));
  const steps = planSteps(batches.map((_, i) => `Step ${i + 1}`), batches, requirementStates(a, parseCoverage(coverageRows)));

  it('keeps all 12 steps and every step keeps its requirement ids', () => {
    assert.equal(steps.length, 12);
    assert.deepEqual(steps.map((s) => s.index), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert.deepEqual(steps.map((s) => s.requirements[0]), ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12']);
    assert.deepEqual(steps[11].dependsOn, [11]);
    assert.deepEqual(steps[11].files, ['file12.html']);
  });

  it('reports progress for steps past the old eight-step boundary', () => {
    let working = steps;
    for (let i = 1; i <= 9; i++) working = completeStep(working, states, i).steps;
    const p = progressOf(working, states);
    assert.equal(p.totalSteps, 12);
    assert.equal(p.doneSteps, 9);
    assert.equal(p.pendingSteps, 3);
  });

  it('no longer cuts the batch list at a fixed step count', () => {
    const src = readFileSync('supabase/functions/web-builder/agent.ts', 'utf8');
    assert.doesNotMatch(src, /batches\.slice\(0, MAX_STEPS\)/);
    assert.doesNotMatch(src, /Too large for one request; left out for a follow-up/);
    assert.match(src, /const totalSteps = batches\.length/);
    const ws = readFileSync('src/components/builder/Workspace.tsx', 'utf8');
    assert.match(ws, /written < MAX_STEPS_PER_RUN/);
  });
});

describe('safe file edits', () => {
  it('refuses a cut-off full-file update and leaves the existing file alone', () => {
    const r = mergeProposals(SITE, [], [{ path: 'index.html', action: 'update', content: '<!doctype html><html><body><h1>Hi</h1>' }], 'static');
    assert.equal(r.files.length, 0);
    assert.match(r.notes.join(' '), /cut off/i);
    assert.match(r.notes.join(' '), /left untouched/i);
  });

  it('refuses a patch that would leave a script unbalanced', () => {
    const site = { 'app.js': 'function a(){}\n' };
    const r = mergeProposals(site, [], [{ path: 'app.js', action: 'patch', edits: [{ find: 'function a(){}', replace: 'function a(){ if (x) {' }] }], 'static');
    assert.equal(r.files.length, 0);
    assert.match(r.notes.join(' '), /cut off/i);
  });

  it('reports a change with missing content instead of dropping it silently', () => {
    const r = parseAiReply(JSON.stringify({ reply: 'x', changes: [{ path: 'a.html', action: 'update' }] }));
    assert.equal(r.changes.length, 0);
    assert.equal(r.dropped.length, 1);
    assert.match(r.dropped[0], /no file content/);
  });

  it('refuses an oversized full-file rewrite and says to use targeted edits', () => {
    const r = parseAiReply(JSON.stringify({ reply: 'x', changes: [{ path: 'a.html', action: 'create', content: 'x'.repeat(8_001) }] }));
    assert.equal(r.changes.length, 0);
    assert.match(r.dropped[0], /targeted edits/);
  });

  it('still accepts a small complete file and a normal patch', () => {
    const r = parseAiReply(JSON.stringify({
      reply: 'x',
      changes: [
        { path: 'about.html', action: 'create', content: '<h1>About</h1>' },
        { path: 'index.html', action: 'patch', edits: [{ find: '<h1>Hi</h1>', replace: '<h1>Hello</h1>' }] },
      ],
    }));
    assert.equal(r.changes.length, 2);
    assert.deepEqual(r.dropped, []);
    const merged = mergeProposals(SITE, [], r.changes, 'static');
    assert.equal(merged.files.length, 2);
  });
});

describe('verification reporting', () => {
  const steps: PlanStep[] = [{ index: 1, text: 's', files: ['index.html'], dependsOn: [], requirements: ['R1'], acceptance: [], status: 'done', attempts: 0 }];
  const a = analyze('Add a page');
  const states = requirementStates(a, parseCoverage([{ requirement: 'R1', covered_by: '1' }]));

  it('lists what was really checked and what could not be', () => {
    const v = verificationReport(steps, states, checksOk, ['index.html']);
    assert.ok(v.performed.some((s) => /static check/i.test(s)));
    assert.ok(v.notPerformed.some((s) => /browser/i.test(s)));
    assert.ok(v.notPerformed.some((s) => /execution environment/i.test(s)));
    assert.deepEqual(v.failed, []);
  });

  it('reports a failing check instead of claiming success', () => {
    const v = verificationReport(steps, states, checksBad, ['index.html']);
    assert.ok(v.failed.length > 0);
    assert.match(v.failed[0], /missing\.png/);
  });
});

describe('approval workflow is still enforced', () => {
  it('still refuses to apply before every step finished', () => {
    const src = readFileSync('supabase/functions/web-builder/changes.ts', 'utf8');
    assert.match(src, /a\.batches && !a\.complete/);
    assert.match(src, /status !== "pending"/);
    assert.match(src, /confirm_risks !== true/);
  });

  it('records requirement completion only inside the apply path', () => {
    const src = readFileSync('supabase/functions/web-builder/changes.ts', 'utf8');
    assert.match(src, /appliedRequirementStates/);
    const agent = readFileSync('supabase/functions/web-builder/agent.ts', 'utf8');
    assert.doesNotMatch(agent, /status: "completed"/);
  });
});
