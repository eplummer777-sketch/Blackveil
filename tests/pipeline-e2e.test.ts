import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chat, continueChange } from '../supabase/functions/web-builder/agent.ts';
import { applyChange } from '../supabase/functions/web-builder/changes.ts';
import { publishProject } from '../supabase/functions/web-builder/publish.ts';
import { NeedsLocalAi, type LocalAiRequest } from '../supabase/functions/web-builder/ai.ts';
import type { Svc } from '../supabase/functions/web-builder/store.ts';
import { LOCAL_MODEL_IDS } from '../supabase/functions/_lib/localModels.ts';
import { checkReply } from '../src/lib/localAi/completion.ts';

type Row = Record<string, unknown>;

// Minimal in-memory stand-in for the Supabase query builder, covering only what the web-builder uses.
class FakeDb {
  tables: Record<string, Row[]> = {};
  tick = 0;
  rows(t: string) { return (this.tables[t] ??= []); }
  stamp() { return new Date(Date.UTC(2026, 9, 24) + ++this.tick * 1000).toISOString(); }
  from(t: string) { return new Query(this, t); }
}

class Query implements PromiseLike<{ data: unknown; error: { message: string } | null; count?: number }> {
  private op: 'select' | 'insert' | 'update' | 'upsert' | 'delete' = 'select';
  private cols = '*';
  private head = false;
  private filters: ((r: Row) => boolean)[] = [];
  private sort: { col: string; asc: boolean } | null = null;
  private window: [number, number] | null = null;
  private mode: 'many' | 'single' | 'maybe' = 'many';
  private payload: Row | Row[] = [];
  private conflict: string[] = [];
  private db: FakeDb;
  private table: string;
  constructor(db: FakeDb, table: string) { this.db = db; this.table = table; }

  select(cols = '*', opts?: { head?: boolean }) { this.cols = cols; this.head = !!opts?.head; return this; }
  insert(p: Row | Row[]) { this.op = 'insert'; this.payload = p; return this; }
  update(p: Row) { this.op = 'update'; this.payload = p; return this; }
  upsert(p: Row | Row[], o?: { onConflict?: string }) { this.op = 'upsert'; this.payload = p; this.conflict = (o?.onConflict ?? 'id').split(',').map((s) => s.trim()); return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c: string, v: unknown) { this.filters.push((r) => r[c] === v); return this; }
  neq(c: string, v: unknown) { this.filters.push((r) => r[c] !== v); return this; }
  in(c: string, vs: unknown[]) { this.filters.push((r) => vs.includes(r[c])); return this; }
  gte(c: string, v: string) { this.filters.push((r) => String(r[c]) >= v); return this; }
  filter(c: string, _op: string, v: unknown) { return this.eq(c, v); }
  order(col: string, o?: { ascending?: boolean }) { this.sort = { col, asc: o?.ascending !== false }; return this; }
  limit(n: number) { this.window = [0, n - 1]; return this; }
  range(a: number, b: number) { this.window = [a, b]; return this; }
  single() { this.mode = 'single'; return this; }
  maybeSingle() { this.mode = 'maybe'; return this; }

  then<A, B>(ok?: ((v: { data: unknown; error: { message: string } | null; count?: number }) => A) | null, bad?: ((e: unknown) => B) | null) {
    return Promise.resolve().then(() => this.run()).then(ok, bad);
  }

  private defaults(): Row {
    const now = this.db.stamp();
    const base: Row = { id: crypto.randomUUID(), created_at: now, updated_at: now };
    if (this.table === 'wb_changes') Object.assign(base, { status: 'pending', snapshot_id: null, decided_at: null });
    if (this.table === 'wb_messages') Object.assign(base, { model: null });
    return base;
  }

  private run() {
    const all = this.db.rows(this.table);
    let hit: Row[];
    if (this.op === 'insert') {
      hit = (Array.isArray(this.payload) ? this.payload : [this.payload]).map((p) => ({ ...this.defaults(), ...structuredClone(p) }));
      all.push(...hit);
    } else if (this.op === 'upsert') {
      hit = (Array.isArray(this.payload) ? this.payload : [this.payload]).map((p) => {
        const found = all.find((r) => this.conflict.every((k) => r[k] === p[k]));
        if (found) return Object.assign(found, structuredClone(p));
        const row = { ...this.defaults(), ...structuredClone(p) };
        all.push(row);
        return row;
      });
    } else {
      hit = all.filter((r) => this.filters.every((f) => f(r)));
      if (this.op === 'update') hit.forEach((r) => Object.assign(r, structuredClone(this.payload as Row)));
      if (this.op === 'delete') this.db.tables[this.table] = all.filter((r) => !hit.includes(r));
    }
    if (this.sort) {
      const { col, asc } = this.sort;
      hit = [...hit].sort((a, b) => (String(a[col]) < String(b[col]) ? -1 : String(a[col]) > String(b[col]) ? 1 : 0) * (asc ? 1 : -1));
    }
    if (this.window) hit = hit.slice(this.window[0], this.window[1] + 1);
    if (this.head) return { data: null, error: null, count: hit.length };
    const pick = (r: Row) => (this.cols === '*' ? structuredClone(r) : Object.fromEntries(this.cols.split(',').map((c) => c.trim()).map((c) => [c, structuredClone(r[c])])));
    const data = hit.map(pick);
    if (this.mode === 'single') return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: `expected 1 row, got ${data.length}` } };
    if (this.mode === 'maybe') return { data: data[0] ?? null, error: null };
    return { data, error: null };
  }
}

const SITE = {
  'index.html': '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8" />\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <title>New site</title>\n  <link rel="stylesheet" href="styles.css" />\n</head>\n<body>\n  <main class="hero">\n    <h1>Hello from Blackveil Web Builder</h1>\n    <p>Describe what you want in the chat, or edit these files directly.</p>\n    <button id="cta">Click me</button>\n  </main>\n  <script src="script.js"></script>\n</body>\n</html>\n',
  'script.js': "document.getElementById('cta')?.addEventListener('click', () => {\n  document.querySelector('p').textContent = 'JavaScript is running in the preview.';\n});\n",
  'styles.css': '* { box-sizing: border-box; }\nbody { margin: 0; font-family: system-ui, sans-serif; background: #0b1220; color: #e2e8f0; }\n.hero { min-height: 100vh; display: grid; place-content: center; text-align: center; gap: 16px; padding: 24px; }\nh1 { margin: 0; font-size: 2.5rem; line-height: 1.2; }\nbutton { padding: 12px 20px; border: 0; border-radius: 8px; background: #22d3ee; color: #0b1220; font-weight: 600; cursor: pointer; }\n',
};

function setup() {
  const db = new FakeDb();
  const projectId = crypto.randomUUID();
  db.rows('wb_config').push({ id: 1, ai_provider: 'local' });
  db.rows('wb_projects').push({ id: projectId, name: 'Blackveil OS', kind: 'static', description: 'Owner site', created_at: db.stamp(), updated_at: db.stamp() });
  for (const [path, content] of Object.entries(SITE)) db.rows('wb_files').push({ id: crypto.randomUUID(), project_id: projectId, path, content, updated_at: db.stamp() });
  return { db, svc: db as unknown as Svc, projectId };
}

type Model = (req: LocalAiRequest) => string;

// Mirrors wbWithAi in the browser: answer each on-device request, pass the reply through the phone-side check, call again.
async function viaPhone<T>(call: (body: Row) => Promise<T>, body: Row, model: Model, seen: string[] = []): Promise<T> {
  const replies: Row[] = [];
  for (;;) {
    try {
      return await call(JSON.parse(JSON.stringify(replies.length ? { ...body, ai_replies: replies } : body)));
    } catch (e) {
      if (!(e instanceof NeedsLocalAi)) throw e;
      seen.push(e.request.purpose);
      const content = checkReply(model(e.request), e.request.format ?? 'json');
      replies.push({ content, model: LOCAL_MODEL_IDS[0], prompt_hash: e.request.prompt_hash, usage: { input_tokens: 10, output_tokens: 10, estimated: false, duration_ms: 5 } });
    }
  }
}

const plan = (title: string) => JSON.stringify({
  reply: `I will rename the heading to ${title} and restyle the button.`,
  understanding: `Heading becomes ${title}; button gets a new colour.`,
  files_to_inspect: ['index.html', 'styles.css'], files_to_change: ['index.html', 'styles.css'], files_to_create: [],
  plan: ['Change the h1 text', 'Change the button colour'],
});

const edit = (from: string, to: string, colourFrom: string, colourTo: string) => JSON.stringify({
  reply: 'Updated the heading and button colour.', notes: '',
  changes: [
    { path: 'index.html', action: 'patch', edits: [{ find: `<h1>${from}</h1>`, replace: `<h1>${to}</h1>` }] },
    { path: 'styles.css', action: 'patch', edits: [{ find: `background: ${colourFrom};`, replace: `background: ${colourTo};` }] },
  ],
});

async function runEdit(svc: Svc, projectId: string, model: Model, message: string, seen: string[]) {
  const r = await viaPhone((b) => chat(svc, b), { project_id: projectId, message, mode: 'code', focus: [] }, model, seen) as { change: Row | null; messages: Row[] };
  assert.ok(r.change, 'a proposal was created');
  let change = r.change as Row & { id: string; analysis: { complete: boolean; risks?: string[] }; status: string; files: unknown[] };
  for (let guard = 0; !change.analysis.complete; guard++) {
    assert.ok(guard < 10, 'writing steps must finish');
    change = (await viaPhone((b) => continueChange(svc, b), { change_id: change.id }, model, seen) as { change: typeof change }).change;
  }
  assert.equal(change.status, 'pending');
  assert.ok(change.files.length > 0, 'files were proposed');
  await applyChange(svc, { change_id: change.id, confirm_risks: true });
  return r;
}

const files = (db: FakeDb, projectId: string) => Object.fromEntries(db.rows('wb_files').filter((r) => r.project_id === projectId).map((r) => [r.path, r.content as string]));

describe('End-to-end: message, plan, write, apply and publish with the real server code', () => {
  it('runs the full cycle three times in a row on the owner site and publishes each result', async () => {
    const { db, svc, projectId } = setup();
    const rounds = [
      { from: 'Hello from Blackveil Web Builder', to: 'Blackveil OS Studio', c1: '#22d3ee', c2: '#10b981' },
      { from: 'Blackveil OS Studio', to: 'Blackveil OS Studio v2', c1: '#10b981', c2: '#f59e0b' },
      { from: 'Blackveil OS Studio v2', to: 'Blackveil OS Studio v3', c1: '#f59e0b', c2: '#0ea5e9' },
    ];
    for (const [i, x] of rounds.entries()) {
      const seen: string[] = [];
      const model: Model = (req) => (req.purpose.startsWith('agent:plan') ? plan(x.to) : edit(x.from, x.to, x.c1, x.c2));
      await runEdit(svc, projectId, model, `Change the heading to ${x.to} and make the button ${x.c2}`, seen);
      assert.deepEqual(seen, ['agent:plan', 'agent:edit 1/1'], `round ${i + 1} AI steps`);

      const now = files(db, projectId);
      assert.match(now['index.html'], new RegExp(`<h1>${x.to}</h1>`));
      assert.match(now['styles.css'], new RegExp(`background: ${x.c2};`));

      const pub = await publishProject(svc, { project_id: projectId, slug: 'blackveil-os', confirm: true }) as { pages: string[]; publication: Row };
      assert.deepEqual(pub.pages, ['index.html']);
      const stored = db.rows('wb_publications')[0] as { slug: string; pages: Record<string, string> };
      assert.equal(db.rows('wb_publications').length, 1, 'republishing replaces the same site');
      assert.equal(stored.slug, 'blackveil-os');
      assert.match(stored.pages['index.html'], new RegExp(`<h1>${x.to}</h1>`));
      assert.match(stored.pages['index.html'], new RegExp(`background: ${x.c2}`), 'published page includes the new styles');
    }
    const msgs = db.rows('wb_messages') as { role: string; content: string }[];
    assert.equal(msgs.filter((m) => m.role === 'user').length, 3);
    assert.equal(msgs.filter((m) => /failed/i.test(m.content)).length, 0, 'no failures recorded');
    assert.ok(db.rows('wb_ai_calls').length >= 6, 'every on-device reply was logged');
  });

  it('recovers when the small model answers the plan in plain prose first (the "nothing sent" bug)', async () => {
    const { db, svc, projectId } = setup();
    const seen: string[] = [];
    const model: Model = (req) => req.purpose === 'agent:plan' ? 'Sure! I will change the heading and the button colour for you.'
      : req.purpose === 'agent:plan (repair)' ? plan('Blackveil OS Studio')
      : edit('Hello from Blackveil Web Builder', 'Blackveil OS Studio', '#22d3ee', '#10b981');
    await runEdit(svc, projectId, model, 'Change the heading to Blackveil OS Studio and make the button green', seen);
    assert.deepEqual(seen, ['agent:plan', 'agent:plan (repair)', 'agent:edit 1/1']);
    assert.match(files(db, projectId)['index.html'], /<h1>Blackveil OS Studio<\/h1>/);
    const calls = db.rows('wb_ai_calls');
    assert.equal(calls.find((c) => c.purpose === 'agent:plan')?.parse_ok, false, 'the bad first reply is recorded as unparsed');
  });

  it('shows a plain-prose answer as written instead of dropping it', async () => {
    const { db, svc, projectId } = setup();
    const r = await viaPhone((b) => chat(svc, b), { project_id: projectId, message: 'What does my site do?', mode: 'ask', focus: [] },
      () => 'Your site shows a heading, a short line of text and a button that changes the text when clicked.') as { messages: Row[] };
    const answer = r.messages[1] as { role: string; content: string };
    assert.equal(answer.role, 'assistant');
    assert.match(answer.content, /button that changes the text/);
    assert.equal(db.rows('wb_messages').length, 2);
  });

  it('reports a clear error, stores no half-finished proposal, and allows a clean retry when the plan stays unreadable', async () => {
    const { db, svc, projectId } = setup();
    await assert.rejects(
      viaPhone((b) => chat(svc, b), { project_id: projectId, message: 'Make the button green', mode: 'code', focus: [] }, () => 'I cannot do that.'),
      /could not produce a readable plan/,
    );
    assert.equal(db.rows('wb_changes').length, 0);
    assert.equal(db.rows('wb_messages').filter((m) => m.role === 'user').length, 0, 'nothing stored, so Try again cannot duplicate the message');
    await runEdit(svc, projectId, (req) => (req.purpose.startsWith('agent:plan') ? plan('Blackveil OS Studio') : edit('Hello from Blackveil Web Builder', 'Blackveil OS Studio', '#22d3ee', '#10b981')), 'Make the button green', []);
    assert.match(files(db, projectId)['styles.css'], /#10b981/);
  });
});
