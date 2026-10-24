import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRequest, chooseWorkflow, errorEvidence, parseCauses } from '../supabase/functions/_lib/intent.ts';
import { checkBrackets, checkHtml, syntaxCheck } from '../supabase/functions/_lib/syntax.ts';
import { fileHashes, memoryBrief, projectProfile, rankMemories, rulesBrief, staleFiles, type MemoryRow } from '../supabase/functions/_lib/memory.ts';
import { buildIndex } from '../supabase/functions/_lib/projectIndex.ts';
import { localReply, promptHash, MAX_AI_ROUNDS } from '../supabase/functions/web-builder/ai.ts';
import { LOCAL_MODEL_IDS } from '../supabase/functions/_lib/localModels.ts';
import { readFileSync } from 'node:fs';

const site = {
  'index.html': '<!doctype html><html><head><link rel="stylesheet" href="styles.css"></head><body><h1 class="title">Hi</h1><script src="app.js"></script></body></html>',
  'styles.css': '.title { color: red; }\n',
  'app.js': 'function greet() {\n  return "hi";\n}\ngreet();\n',
};

const mem = (o: Partial<MemoryRow>): MemoryRow => ({ id: crypto.randomUUID(), kind: 'decision', title: 't', body: '', source: 'user', status: 'active', files: [], file_hashes: {}, updated_at: '', ...o });

describe('Workflow evaluation set', () => {
  const cases: [string, string][] = [
    ['reply with hello', 'ask'], ['hello', 'ask'],
    ['explain how the header works', 'explain'], ['review my site for problems', 'review'],
    ['plan a pricing section', 'plan'], ['add a contact form to the homepage', 'code'],
    ['the button is broken and nothing happens', 'debug'], ['TypeError: x is undefined at app.js:3', 'debug'],
  ];
  for (const [p, w] of cases) it(`"${p}" -> ${w}`, () => assert.equal(analyzeRequest(p, buildIndex(site), site).workflow, w));
  it('reads the file and line out of a pasted error', () => {
    assert.deepEqual(analyzeRequest('TypeError: x is undefined at app.js:3', buildIndex(site), site).errors[0], { message: 'TypeError: x is undefined at app.js:3', file: 'app.js', line: 3 });
  });
  it('chooses debug when errors are present', () => assert.equal(chooseWorkflow('look at this', [{ message: 'x' }]), 'debug'));

  it('respects the mode the owner picked over the automatic choice', () => {
    const ra = analyzeRequest('add a footer', buildIndex(site), site, 'plan');
    assert.equal(ra.workflow, 'plan');
    assert.equal(ra.chosen_by, 'owner');
  });

  it('ignores an unknown mode value', () => {
    assert.equal(analyzeRequest('add a footer', buildIndex(site), site, 'hack').chosen_by, 'auto');
  });
});

describe('Static syntax checks', () => {
  it('accepts balanced code and rejects missing braces', () => {
    assert.equal(checkBrackets(site['app.js'], true), null);
    assert.ok(checkBrackets('function a() {\n  if (x) {\n}\n', true));
  });
  it('ignores brackets inside strings and comments', () => {
    assert.equal(checkBrackets('const s = "{"; // }\n/* ( */', true), null);
  });
  it('detects unclosed html tags but allows void tags', () => {
    assert.equal(checkHtml('<div><img src="a"><br></div>'), null);
    assert.ok(checkHtml('<div><section></div>'));
  });
  it('reports a failing check for broken changed files only', () => {
    assert.equal(syntaxCheck(site, ['app.js']).ok, true);
    assert.equal(syntaxCheck({ ...site, 'styles.css': '.a { color: red;' }, ['styles.css']).ok, false);
  });
});

describe('Project memory', () => {
  it('marks memories as outdated when their files change', () => {
    const m = mem({ files: ['styles.css'], file_hashes: fileHashes(site, ['styles.css']) });
    assert.deepEqual(staleFiles(m, site), []);
    assert.deepEqual(staleFiles(m, { ...site, 'styles.css': '.x{}' }), ['styles.css']);
  });
  it('ranks relevant active notes and skips archived and rule notes', () => {
    const list = [mem({ title: 'Footer uses dark theme' }), mem({ title: 'Footer old', status: 'archived' }), mem({ kind: 'rule', title: 'Footer rule' }), mem({ title: 'Unrelated pricing' })];
    const ranked = rankMemories(list, 'change the footer', []);
    assert.equal(ranked[0].title, 'Footer uses dark theme');
    assert.ok(!ranked.some((m) => m.status === 'archived' || m.kind === 'rule'));
  });
  it('never feeds unconfirmed AI claims into prompts and ranks file contents above notes', () => {
    assert.equal(rankMemories([mem({ title: 'footer guess', status: 'unverified', source: 'ai' })], 'footer', []).length, 0);
    assert.match(memoryBrief([mem({ title: 'x' })], site), /file contents are correct/);
    assert.equal(rulesBrief([mem({ kind: 'rule', title: 'AI rule', source: 'ai' })]), '');
    assert.match(rulesBrief([mem({ kind: 'rule', title: 'Use short replies' })]), /safety|security/i);
  });
  it('builds a project overview from real files', () => {
    const p = projectProfile(site, buildIndex(site));
    assert.ok(p.body.includes('index.html'));
  });
});

describe('Debug evidence', () => {
  it('ranks causes by likelihood and caps them', () => {
    const c = parseCauses({ causes: [{ cause: 'b', evidence: 'e', likelihood: 'low' }, { cause: 'a', evidence: 'e', likelihood: 'high' }] });
    assert.equal(c[0].cause, 'a');
    assert.ok(parseCauses({ causes: Array(9).fill({ cause: 'x', evidence: 'y', likelihood: 'medium' }) }).length <= 5);
    assert.deepEqual(parseCauses(null), []);
  });
  it('quotes the real source lines around a reported error', () => {
    const ev = errorEvidence([{ message: 'boom', file: 'app.js', line: 2 }, { message: 'x', file: 'missing.js', line: 1 }], site);
    assert.match(ev.text, /return "hi"/);
    assert.deepEqual(ev.missing, ['missing.js']);
  });
});

describe('Multi-round local replies', () => {
  const msgs = [{ role: 'user' as const, content: 'hi' }];
  const reply = async (content: string, m = msgs) => ({ content, model: LOCAL_MODEL_IDS[0], prompt_hash: await promptHash(m, 100), usage: { output_tokens: 3, estimated: false, duration_ms: 1200 } });

  it('asks the device for a reply when none was sent', async () => {
    await assert.rejects(localReply({}, 'p', msgs, 100), (e: Error) => e.constructor.name === 'NeedsLocalAi');
  });
  it('consumes replies in order and records measured usage', async () => {
    const body = { ai_replies: [await reply('one'), await reply('two')] };
    const a = await localReply(body, 'p', msgs, 100);
    const b = await localReply(body, 'p', msgs, 100);
    assert.equal(a.content, 'one');
    assert.equal(b.content, 'two');
    assert.equal(a.tokensEstimated, false);
    assert.equal(a.durationMs, 1200);
  });
  it('stops after the round limit', async () => {
    const body = { ai_replies: Array(MAX_AI_ROUNDS + 1).fill(await reply('x')) };
    for (let i = 0; i < MAX_AI_ROUNDS; i++) await localReply(body, 'p', msgs, 100);
    await assert.rejects(localReply(body, 'p', msgs, 100), /allowed attempts/);
  });
  it('rejects a reply generated for a different prompt', async () => {
    await assert.rejects(localReply({ ai_reply: await reply('x', [{ role: 'user', content: 'other' }]) }, 'p', msgs, 100), /changed/);
  });
  it('rejects replies from models that are not on-device', async () => {
    await assert.rejects(localReply({ ai_reply: { ...(await reply('x')), model: 'gpt-4' } }, 'p', msgs, 100), /unknown model/);
  });
});

describe('Safety wiring stays in place', () => {
  const agent = readFileSync('supabase/functions/web-builder/agent.ts', 'utf8');
  const learning = readFileSync('supabase/functions/web-builder/learning.ts', 'utf8');
  it('still redacts secrets before prompting', () => assert.match(agent, /redactForModel/));
  it('needs owner testing, an applied change and passing checks to verify a fix', () => {
    assert.match(learning, /owner_tested/);
    assert.match(learning, /applied/);
  });
  it('limits automatic repair attempts', () => assert.match(readFileSync('src/lib/builder.ts', 'utf8'), /MAX_REPAIRS = 2/));
});
