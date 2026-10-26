import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chat, continueChange } from '../supabase/functions/web-builder/agent.ts';
import { applyChange } from '../supabase/functions/web-builder/changes.ts';
import { NeedsLocalAi, type LocalAiRequest } from '../supabase/functions/web-builder/ai.ts';
import type { Svc } from '../supabase/functions/web-builder/store.ts';
import { LOCAL_MODEL_IDS } from '../supabase/functions/_lib/localModels.ts';
import { checkReply } from '../src/lib/localAi/completion.ts';
import { FakeDb } from './support/fakeDb.ts';
import type { Row } from './support/types.ts';

// Drives the real web-builder server code (chat → continue_change → apply_change) with an in-memory
// database and a scripted on-device model. Nothing here talks to Supabase or a real AI.

const FILES = ['index.html', ...Array.from({ length: 11 }, (_, i) => `page${i + 1}.html`)];
const PAD = 'x'.repeat(3_900); // > BUDGET.batch (3,000 chars), so each file gets its own step
const page = (name: string) => `<!doctype html>\n<html><body>\n<p>${name}</p>\n<p>${PAD}</p>\n</body></html>\n`;
const PAGES: Record<string, string> = Object.fromEntries(FILES.map((f) => [f, page(f)]));
const PROMPT = FILES.map((f) => `Change ${f}`).join('\n');

const planReply = () => JSON.stringify({
  reply: 'Updating every page.',
  goal: 'Update all twelve pages',
  understanding: 'Every page gets its marker paragraph updated.',
  files_to_change: FILES,
  files_to_create: [],
  plan: FILES.map((f) => `Edit ${f}`),
  requirement_coverage: FILES.map((_, i) => ({ requirement: `R${i + 1}`, covered_by: String(i + 1) })),
});

const patchReply = (file: string) => JSON.stringify({
  reply: `Updated ${file}.`,
  notes: '',
  changes: [{ path: file, action: 'patch', edits: [{ find: `<p>${file}</p>`, replace: `<p>done ${file}</p>` }] }],
});

// The model: a full plan, then one targeted patch per step, chosen by the file named in that step.
const model = (req: LocalAiRequest): string => {
  if (req.purpose.startsWith('agent:plan')) return planReply();
  if (req.purpose.startsWith('agent:edit')) {
    const text = req.messages.map((m) => m.content).join('\n');
    const file = /Files to change in this step: (\S+)/.exec(text)?.[1] ?? '';
    return file ? patchReply(file) : 'nothing to do';
  }
  return '';
};

async function viaPhone<T>(call: (body: Row) => Promise<T>, body: Row, m: (req: LocalAiRequest) => string): Promise<T> {
  const replies: Row[] = [];
  for (let round = 0; ; round++) {
    if (round > 8) throw new Error('the server kept asking for on-device replies; this test would otherwise hang');
    try {
      return await call(JSON.parse(JSON.stringify(replies.length ? { ...body, ai_replies: replies } : body)) as Row);
    } catch (e) {
      if (!(e instanceof NeedsLocalAi)) throw e;
      const content = checkReply(m(e.request), e.request.format ?? 'json');
      replies.push({
        content, model: LOCAL_MODEL_IDS[0], prompt_hash: e.request.prompt_hash,
        usage: { input_tokens: 10, output_tokens: 10, estimated: false, duration_ms: 5 },
      });
    }
  }
}

interface Change extends Row { id: string; status: string; files: Row[]; analysis: Row }

function setup() {
  const db = new FakeDb();
  const projectId = crypto.randomUUID();
  db.rows('wb_config').push({ id: 1, ai_provider: 'local' });
  db.rows('wb_projects').push({ id: projectId, name: 'Pages', kind: 'static', description: 'Twelve pages', created_at: db.stamp(), updated_at: db.stamp() });
  for (const [path, content] of Object.entries(PAGES)) {
    db.rows('wb_files').push({ id: crypto.randomUUID(), project_id: projectId, path, content, updated_at: db.stamp() });
  }
  return { db, svc: db as unknown as Svc, projectId };
}

async function start(svc: Svc, projectId: string, m = model): Promise<Change> {
  const r = await viaPhone((b) => chat(svc, b), { project_id: projectId, message: PROMPT, mode: 'code', focus: [] }, m) as { change: Change | null };
  assert.ok(r.change, 'a proposal was created');
  return r.change;
}

async function step(svc: Svc, changeId: string, m = model): Promise<Change> {
  const r = await viaPhone((b) => continueChange(svc, b), { change_id: changeId }, m) as { change: Change; complete: boolean; failed?: boolean };
  return r.change;
}

const analysisOf = (c: Change) => c.analysis as Change['analysis'] & {
  next: number; complete: boolean; batches: string[][]; plan_steps: Row[]; requirements_state: Row[];
  failed_steps?: number[]; awaiting_retry?: boolean; verification?: Row;
};

describe('12-step plan → write → continue → apply', () => {
  it('keeps every step, its requirement mapping and the step order', async () => {
    const { svc, projectId } = setup();
    let change = await start(svc, projectId);
    const planned = analysisOf(change);

    assert.equal(planned.batches.length, 12);
    assert.equal(planned.plan_steps.length, 12);
    assert.deepEqual(planned.plan_steps.map((s) => s.index), Array.from({ length: 12 }, (_, i) => i + 1));
    assert.deepEqual(planned.plan_steps.map((s) => (s.requirements as string[])[0]),
      Array.from({ length: 12 }, (_, i) => `R${i + 1}`));
    assert.equal(planned.requirements_state.length, 12);
    assert.ok(planned.requirements_state.every((r) => isStatus(r, 'pending')));
    assert.deepEqual(planned.plan_steps[11].dependsOn, [11]);

    const seen: number[] = [];
    for (let i = 1; i <= 12; i++) {
      change = await step(svc, change.id);
      const an = analysisOf(change);
      seen.push(an.next);
      assert.equal(an.plan_steps.filter((s) => status(s) === 'done').length, i, `done count after step ${i}`);
      for (const row of an.plan_steps) {
        const idx = Number(row.index);
        assert.equal(status(row), idx <= i ? 'done' : 'pending', `step ${idx} status after ${i}`);
      }
    }
    assert.deepEqual(seen, Array.from({ length: 12 }, (_, i) => i + 1), 'steps run once each, in order');

    const done = analysisOf(change);
    assert.equal(done.complete, true);
    assert.equal(done.plan_steps.filter((s) => status(s) === 'done').length, 12);
    assert.equal(done.requirements_state.filter((r) => isStatus(r, 'in_progress')).length, 12);
    assert.equal(change.files.length, 12);
    assert.equal(new Set(change.files.map((f) => f.path)).size, 12, 'no file proposed twice');
    assert.ok(done.verification && Array.isArray(done.verification.notPerformed));
  });

  it('records requirement completion only when the change is applied', async () => {
    const { db, svc, projectId } = setup();
    let change = await start(svc, projectId);
    while (!analysisOf(change).complete) change = await step(svc, change.id);

    assert.equal(analysisOf(change).requirements_state.filter((r) => isStatus(r, 'completed')).length, 0, 'nothing completed before apply');

    const applied = await applyChange(svc, { change_id: change.id }) as { verification: { checks: Row[] } };
    assert.ok(applied.verification.checks.length > 0);

    const stored = db.rows('wb_changes').find((r) => r.id === change.id) as Change;
    const after = analysisOf(stored);
    assert.equal(after.requirements_state.filter((r) => isStatus(r, 'completed')).length, 12);
    assert.equal(stored.status, 'applied');
    assert.ok(after.requirements_state.every((r) => /static checks only/i.test(String(r.note ?? ''))));

    await assert.rejects(() => applyChange(svc, { change_id: change.id }), /already applied/);
  });
});

describe('failure and retry', () => {
  it('keeps the failed step pending, blocks apply, and retries without duplicating work', async () => {
    const { svc, projectId } = setup();
    let change = await start(svc, projectId);
    for (let i = 1; i <= 4; i++) change = await step(svc, change.id);

    // Both the first attempt and its repair answer in prose: step 5 cannot be read.
    const failing = (req: LocalAiRequest) => req.purpose.startsWith('agent:edit 5/') ? 'I already updated it.' : model(req);
    const failed = await step(svc, change.id, failing);
    const fa = analysisOf(failed);
    assert.equal(fa.next, 4, 'the failed step is not advanced past');
    assert.equal(fa.awaiting_retry, true);
    assert.deepEqual(fa.failed_steps, [5]);
    assert.equal(status(fa.plan_steps[4]), 'failed');
    assert.ok(fa.plan_steps.slice(5).every((s) => status(s) === 'pending'));
    assert.equal(failed.files.length, 4, 'no change from the failed step was kept');

    await assert.rejects(() => applyChange(svc, { change_id: change.id }), /has not finished writing/);

    const retried = await step(svc, change.id);
    const ra = analysisOf(retried);
    assert.equal(ra.next, 5, 'the retry runs the same step');
    assert.equal(ra.awaiting_retry, false);
    assert.equal(status(ra.plan_steps[4]), 'done');
    assert.equal(Number(ra.plan_steps[4].attempts), 1);
    assert.equal(retried.files.length, 5);
    assert.equal(new Set(retried.files.map((f) => f.path)).size, 5, 'retry did not duplicate earlier work');

    let c = retried;
    while (!analysisOf(c).complete) c = await step(svc, c.id);
    assert.equal(c.files.length, 12);
    await applyChange(svc, { change_id: c.id, confirm_risks: true });
    await assert.rejects(() => applyChange(svc, { change_id: c.id }), /already applied/);
  });

  it('resumes from persisted state after a refresh', async () => {
    const { db, svc, projectId } = setup();
    const change = await start(svc, projectId);
    await step(svc, change.id);

    // A fresh page load only reads the stored row.
    const stored = db.rows('wb_changes').find((r) => r.id === change.id) as Change;
    assert.equal(analysisOf(stored).next, 1);
    assert.equal(status(analysisOf(stored).plan_steps[0]), 'done');

    const resumed = await step(svc, stored.id);
    assert.equal(analysisOf(resumed).next, 2);
  });

  it('a broken reply fails the step and never touches the project files', async () => {
    const { db, svc, projectId } = setup();
    const change = await start(svc, projectId);
    const broken = await step(svc, change.id, () => '{"reply":"oops","changes":[');
    assert.equal(analysisOf(broken).awaiting_retry, true);

    const storedFiles = db.rows('wb_files').filter((r) => r.project_id === projectId);
    assert.equal(storedFiles.some((r) => String(r.content).includes('done ')), false, 'no file was written');
    await assert.rejects(() => applyChange(svc, { change_id: change.id }), /has not finished writing/);
  });
});

// Small helpers so the assertions read clearly against loosely typed rows.
function status(row: Row): string { return String(row.status ?? ''); }
function isStatus(row: Row, want: string): boolean { return row.status === want; }
