import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildContext, checkProjectSize, isOwner, parseAiReply, parseInspectReply, validatePath, verifyAppliedFiles } from '../supabase/functions/_lib/webbuilder.ts';
import { buildIndex, checkConsistency, expandSelection, findSecrets, kindOf, planBatches, redactForModel, REDACTED } from '../supabase/functions/_lib/projectIndex.ts';
import { applyPatch, applyToMap, mergeProposals, riskNotes } from '../supabase/functions/_lib/changeset.ts';
import { localReply, NeedsLocalAi, promptHash } from '../supabase/functions/web-builder/ai.ts';
import { LOCAL_MODEL_IDS, LOCAL_MODELS } from '../supabase/functions/_lib/localModels.ts';
import { readdirSync, readFileSync } from 'node:fs';
import { buildCompletion, checkReply, extractJsonObject, firstJsonObject, LocalAiError, normalizeMessages, runCompletion, type CompletionEngine } from '../src/lib/localAi/completion.ts';
import { prebuiltAppConfig } from '@mlc-ai/web-llm';
import { buildPreview, highlight, lineDiff, resolveLocal } from '../src/lib/builderTools.ts';

const CFG = { owner_email: 'eplummer777@gmail.com', owner_user_id: 'u-owner' };
const confirmed = '2026-01-01T00:00:00Z';

describe('web builder owner check', () => {
  it('accepts the pinned owner, ignoring email case', () => {
    assert.equal(isOwner({ id: 'u-owner', email: 'EPlummer777@Gmail.com', email_confirmed_at: confirmed }, CFG), true);
  });
  it('rejects other users, even with the owner email', () => {
    assert.equal(isOwner({ id: 'u-other', email: 'eplummer777@gmail.com', email_confirmed_at: confirmed }, CFG), false);
    assert.equal(isOwner({ id: 'u-other', email: 'customer@example.com', email_confirmed_at: confirmed }, CFG), false);
  });
  it('rejects the owner id with a different or unconfirmed email', () => {
    assert.equal(isOwner({ id: 'u-owner', email: 'changed@example.com', email_confirmed_at: confirmed }, CFG), false);
    assert.equal(isOwner({ id: 'u-owner', email: 'eplummer777@gmail.com', email_confirmed_at: null }, CFG), false);
  });
  it('denies when the user or configuration is missing', () => {
    assert.equal(isOwner(null, CFG), false);
    assert.equal(isOwner({ id: 'u-owner', email: 'eplummer777@gmail.com', email_confirmed_at: confirmed }, null), false);
    assert.equal(isOwner({ id: '', email: '', email_confirmed_at: confirmed }, { owner_email: '', owner_user_id: '' }), false);
  });
});

describe('web builder path validation', () => {
  it('accepts normal relative paths', () => {
    for (const p of ['index.html', 'src/app.js', 'assets/img/logo.svg', '.gitignore']) assert.equal(validatePath(p).ok, true, p);
  });
  it('rejects traversal, absolute and odd paths', () => {
    for (const p of ['../secret', 'a/../../b', '/etc/passwd', 'a\\b', 'a//b', './a', '', 'a b', 'x'.repeat(201), 42, 'a/b/c/d/e/f/g/h/i']) {
      assert.equal(validatePath(p).ok, false, String(p));
    }
  });
});

describe('web builder limits and context', () => {
  it('rejects oversized projects', () => {
    assert.match(checkProjectSize({ a: 'x'.repeat(200_001) }) ?? '', /larger/);
    assert.equal(checkProjectSize({ a: 'ok' }), null);
  });
  it('includes files in the given order and reports what did not fit', () => {
    const ctx = buildContext({ 'big.js': 'x'.repeat(500), 'a.css': 'b{}', 'index.html': '<p>' }, ['index.html', 'big.js', 'a.css'], 120);
    assert.deepEqual(ctx.included, ['index.html', 'a.css']);
    assert.deepEqual(ctx.omitted, ['big.js']);
    assert.match(ctx.text, /--- FILE: index\.html\n<p>\n--- END FILE: index\.html/);
  });
});

describe('web builder AI reply parsing', () => {
  it('parses a fenced JSON change set and drops unsafe paths', () => {
    const raw = '```json\n{"reply":"Done","changes":[{"path":"index.html","action":"update","content":"<h1>"},{"path":"../x","action":"create","content":"bad"},{"path":"old.js","action":"delete"},{"path":"n.js","action":"update"}]}\n```';
    const r = parseAiReply(raw);
    assert.equal(r.reply, 'Done');
    assert.deepEqual(r.changes, [{ path: 'index.html', action: 'update', content: '<h1>' }, { path: 'old.js', action: 'delete' }]);
  });
  it('keeps plain text replies without inventing changes', () => {
    const r = parseAiReply('I cannot help with that.');
    assert.equal(r.changes.length, 0);
    assert.ok(r.error);
  });
});

describe('web builder client tools', () => {
  it('produces a line diff', () => {
    const d = lineDiff('a\nb\nc', 'a\nB\nc\nd');
    assert.deepEqual(d.map((l) => l.kind + l.text), ['samea', 'delb', 'addB', 'samec', 'addd']);
    assert.deepEqual(lineDiff(null, 'x'), [{ kind: 'add', text: 'x' }]);
  });
  it('inlines local CSS and JS and reports missing files', () => {
    const p = buildPreview({
      'index.html': '<link rel="stylesheet" href="./s.css"><script src="app.js"></script><script src="gone.js"></script><script src="https://cdn.example/x.js"></script>',
      's.css': 'p{}', 'app.js': 'if (a </script>) {}',
    })!;
    assert.match(p.html, /<style data-file="s.css">\np\{\}/);
    assert.match(p.html, /<\\\/script>/);
    assert.match(p.html, /src="https:\/\/cdn\.example\/x\.js"/);
    assert.deepEqual(p.missing, ['gone.js']);
    assert.equal(buildPreview({ 'a.js': '' }), null);
  });
  it('escapes markup when highlighting', () => {
    const h = highlight('<img src=x onerror=alert(1)>', 'html');
    assert.ok(!h.includes('<img'));
    assert.match(highlight('const a = "<b>"', 'js'), /&lt;b&gt;/);
  });
});

describe('on-device Blackveil AI protocol', () => {
  const msgs = [{ role: 'system' as const, content: 'rules' }, { role: 'user' as const, content: 'make it blue' }];
  const model = LOCAL_MODEL_IDS[0];

  it('asks the browser for a reply instead of calling any AI service', async () => {
    await assert.rejects(localReply({}, 'agent:plan', msgs, 500), (e: unknown) => {
      assert.ok(e instanceof NeedsLocalAi);
      assert.equal(e.request.max_tokens, 500);
      assert.deepEqual(e.request.messages, msgs);
      assert.match(e.request.prompt_hash, /^[0-9a-f]{64}$/);
      return true;
    });
  });

  it('accepts a reply bound to the same prompt from an allowed model', async () => {
    const hash = await promptHash(msgs, 500);
    const r = await localReply({ ai_reply: { content: '{"x":1}', model, prompt_hash: hash, usage: { input_tokens: 9, output_tokens: 4 } } }, 'p', msgs, 500);
    assert.equal(r.content, '{"x":1}');
    assert.equal(r.model, model);
    assert.equal(r.outputTokens, 4);
  });

  it('rejects stale prompts, unknown models and empty replies', async () => {
    const hash = await promptHash(msgs, 500);
    await assert.rejects(localReply({ ai_reply: { content: 'x', model, prompt_hash: 'other' } }, 'p', msgs, 500), (e: { status: number }) => e.status === 409);
    await assert.rejects(localReply({ ai_reply: { content: 'x', model: 'gemini-3.8-flash', prompt_hash: hash } }, 'p', msgs, 500), (e: { status: number }) => e.status === 400);
    await assert.rejects(localReply({ ai_reply: { content: '  ', model, prompt_hash: hash } }, 'p', msgs, 500), (e: { status: number }) => e.status === 422);
  });

  it('only lists models that exist in the installed WebLLM catalog', () => {
    const known = new Set(prebuiltAppConfig.model_list.map((m) => m.model_id));
    assert.ok(LOCAL_MODELS.length > 0);
    for (const id of LOCAL_MODEL_IDS) assert.ok(known.has(id), id);
  });

  it('has no hosted AI endpoints left in the web builder or its client code', () => {
    const dirs = ['supabase/functions/web-builder', 'src/lib/localAi', 'src/components/builder'];
    const hosted = /generativelanguage\.googleapis|api\.openai\.com|pollinations|GEMINI_API_KEY|OPENAI_API_KEY|anthropic\.com/i;
    for (const d of dirs) for (const f of readdirSync(d)) assert.doesNotMatch(readFileSync(`${d}/${f}`, 'utf8'), hosted, `${d}/${f}`);
  });
});

describe('Blackveil AI grammar matcher fix', () => {
  const localAiSrc = () => readdirSync('src/lib/localAi').map((f) => readFileSync(`src/lib/localAi/${f}`, 'utf8').replace(/^\s*\/\/.*$/gm, '')).join('\n');

  it('loads the model and builds requests without a grammar-constrained response format', () => {
    const src = localAiSrc();
    assert.doesNotMatch(src, /response_format\s*:|json_object['"]|json_schema|grammar\s*:/);
    const req = buildCompletion({ messages: [{ role: 'system', content: 's' }, { role: 'user', content: 'u' }], max_tokens: 50 });
    assert.equal('response_format' in req, false);
    assert.deepEqual(Object.keys(req).sort(), ['max_tokens', 'messages', 'stream', 'stream_options', 'temperature']);
  });

  it('builds a simple text request and accepts the plain reply as-is', () => {
    const req = buildCompletion({ messages: [{ role: 'user', content: 'Reply exactly: BLACKVEIL LOCAL AI ONLINE' }], max_tokens: 96, format: 'text' });
    assert.deepEqual(req.messages, [{ role: 'user', content: 'Reply exactly: BLACKVEIL LOCAL AI ONLINE' }]);
    assert.equal(checkReply('BLACKVEIL LOCAL AI ONLINE', 'text'), 'BLACKVEIL LOCAL AI ONLINE');
    assert.throws(() => checkReply('   ', 'text'), /empty reply/);
  });

  it('merges system and repeated turns into a shape small models accept', () => {
    const msgs = normalizeMessages([
      { role: 'system', content: 'a' }, { role: 'assistant', content: 'x' }, { role: 'system', content: 'b' },
      { role: 'user', content: 'u1' }, { role: 'user', content: 'u2' },
    ]);
    assert.deepEqual(msgs, [{ role: 'system', content: 'a\n\nb' }, { role: 'user', content: 'u1\n\nu2' }]);
  });

  it('accepts valid JSON replies, including fenced ones', () => {
    const raw = '```json\n{"reply":"ok","changes":[{"path":"index.html","action":"update","content":"<h1>Hi</h1>"}]}\n```';
    const clean = checkReply(raw);
    assert.equal(clean, raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1));
    assert.deepEqual(extractJsonObject(raw)?.reply, 'ok');
    assert.equal(parseAiReply(clean).changes.length, 1);
  });

  it('reads only the first complete object, even when braces appear inside strings or junk follows', () => {
    assert.equal(firstJsonObject('x {"a":"}{\\"","b":{"c":1}} then {"again":2}'), '{"a":"}{\\"","b":{"c":1}}');
    assert.equal(firstJsonObject('{"a":{"b":1}'), null);
    assert.deepEqual(extractJsonObject('{"plan":["a"]}\n{"plan":["a"]}'), { plan: ['a'] });
  });

  it('hands malformed JSON to the server unchanged so its repair round can run', () => {
    for (const bad of ['Sure! Here is your change.', '{"reply": "ok", "changes": [', '["not","an","object"]']) {
      assert.equal(checkReply(bad), bad);
    }
  });

  it('never turns malformed structured replies into project edits', () => {
    const site = { 'index.html': '<h1>Old</h1>' };
    const malformed = [
      '{"reply":"done","changes":"index.html"}',
      '{"changes":[{"path":"../etc/passwd","action":"update","content":"x"}]}',
      '{"changes":[{"path":"index.html","action":"update"}]}',
      '{"changes":[{"path":"index.html","action":"patch","edits":[{"find":"","replace":"x"}]}]}',
      '{"changes":[{"path":"index.html","action":"explode","content":"x"}]}',
      'not json at all',
    ];
    for (const raw of malformed) {
      const parsed = parseAiReply(raw);
      assert.equal(parsed.changes.length, 0, raw);
      assert.deepEqual(mergeProposals(site, [], parsed.changes, 'static').files, [], raw);
    }
    assert.ok(parseAiReply('not json at all').error);
  });

  it('keeps the local-only server protocol: no hosted fallback, allowlisted models, stale replies refused', async () => {
    const ai = readFileSync('supabase/functions/web-builder/ai.ts', 'utf8');
    assert.doesNotMatch(ai, /fetch\(|gemini|openai|pollinations/i);
    assert.doesNotMatch(localAiSrc(), /gemini|openai|pollinations|https?:\/\/(?!huggingface|raw\.githubusercontent)/i);
    const messages = [{ role: 'user' as const, content: 'hi' }];
    const hash = await promptHash(messages, 100);
    await assert.rejects(localReply({ ai_reply: { content: '{}', model: 'gemini-2.5-flash', prompt_hash: hash } }, 'p', messages, 100), (e: { status?: number }) => e.status === 400);
    await assert.rejects(localReply({ ai_reply: { content: '{}', model: LOCAL_MODEL_IDS[0], prompt_hash: 'stale' } }, 'p', messages, 100), (e: { status?: number }) => e.status === 409);
  });

  it('keeps approval, risk confirmation, checkpoints and undo in the change flow', () => {
    const src = readFileSync('supabase/functions/web-builder/changes.ts', 'utf8');
    assert.match(src, /status !== "pending"/);
    assert.match(src, /confirm_risks !== true/);
    assert.match(src, /snapshot\(svc, ch\.project_id, "Before AI change"\)/);
    assert.match(src, /status !== "applied"\) throw new HttpError\(409, "Only applied changes can be undone\."/);
    assert.match(src, /snapshot\(svc, ch\.project_id, "Before undoing an AI change"\)/);
    const site = { 'index.html': '<h1>Old</h1>', 'about.html': '<p>About</p>' };
    const { files } = mergeProposals(site, [], parseAiReply('{"changes":[{"path":"index.html","action":"update","content":"<h1>New</h1>"},{"path":"about.html","action":"delete"}]}').changes, 'static');
    const applied = applyToMap(site, files);
    assert.deepEqual(applied, { 'index.html': '<h1>New</h1>' });
    const undone = { ...applied };
    for (const f of files) { if (f.before === null) delete undone[f.path]; else undone[f.path] = f.before; }
    assert.deepEqual(undone, site);
  });
});

describe('Blackveil AI edit-chat generation', () => {
  function fakeEngine(pieces: (string | { finish: string } | Error)[], endless = false) {
    const calls = { interrupts: 0, requests: [] as unknown[], yielded: 0 };
    let interrupted = false;
    const engine: CompletionEngine = {
      interruptGenerate: () => { calls.interrupts++; interrupted = true; },
      chat: { completions: { create: async (req) => {
        calls.requests.push(req);
        interrupted = false;
        return (async function* () {
          let i = 0;
          while (!interrupted && (i < pieces.length || endless)) {
            const p = i < pieces.length ? pieces[i] : ' {"again": true}';
            i++;
            calls.yielded++;
            if (p instanceof Error) throw p;
            if (typeof p === 'object') yield { choices: [{ delta: { content: '' }, finish_reason: p.finish }] };
            else yield { choices: [{ delta: { content: p } }] };
            if (calls.yielded > 5000) throw new Error('runaway');
          }
        })();
      } } },
    };
    return { engine, calls };
  }
  const planReq = { messages: [{ role: 'system' as const, content: 'PLANNING STEP. Respond with ONLY JSON' }, { role: 'user' as const, content: 'Make the heading blue' }], max_tokens: 1800 };

  it('stops generating as soon as the edit-chat JSON is complete, instead of running to the token limit', async () => {
    const { engine, calls } = fakeEngine(['```json\n{"understanding":"Blue heading",', '"files_to_change":["index.html"],', '"plan":["Set h1 colour"]}', '\n```\nHere is another version:'], true);
    const seen: number[] = [];
    const r = await runCompletion(engine, planReq, (n) => seen.push(n));
    assert.equal(calls.interrupts, 1);
    assert.ok(calls.yielded <= 3, `kept generating: ${calls.yielded}`);
    assert.equal(r.content, '{"understanding":"Blue heading","files_to_change":["index.html"],"plan":["Set h1 colour"]}');
    assert.deepEqual(parseInspectReply(r.content, { 'index.html': '<h1>x</h1>' }).targets, ['index.html']);
    assert.deepEqual(seen, [1, 2, 3]);
    assert.equal(r.usage.output_tokens, 3);
    assert.equal('response_format' in (calls.requests[0] as object), false);
  });

  it('returns a reply cut off at the token limit so the server can ask for a repair', async () => {
    const { engine, calls } = fakeEngine(['I will now explain', ' the plan {', '"understanding": "', 'blue', { finish: 'length' }]);
    const r = await runCompletion(engine, planReq);
    assert.equal(r.content, 'I will now explain the plan {"understanding": "blue');
    assert.equal(calls.interrupts, 0);
  });

  it('fails cleanly on prose-only replies and on engine errors mid-stream', async () => {
    assert.equal((await runCompletion(fakeEngine(['Sure, I changed it.', { finish: 'stop' }]).engine, planReq)).content, 'Sure, I changed it.');
    const seen: number[] = [];
    await assert.rejects(runCompletion(fakeEngine(['{"understanding":', new Error('Device lost')]).engine, planReq, (n) => seen.push(n)), /Device lost/);
    assert.deepEqual(seen, [1]);
  });

  it('reports a cancelled run as stopped, not as a model failure', async () => {
    let cancelled = false;
    const { engine } = fakeEngine(['{"plan":', '["a"]}']);
    await assert.rejects(runCompletion(engine, planReq, () => { cancelled = true; }, () => cancelled), /Stopped\. Nothing was saved\./);
  });

  it('lets plain-text device tests finish normally without early stopping', async () => {
    const { engine, calls } = fakeEngine(['BLACKVEIL LOCAL ', 'AI ONLINE', { finish: 'stop' }]);
    const r = await runCompletion(engine, { ...planReq, format: 'text' });
    assert.equal(r.content, 'BLACKVEIL LOCAL AI ONLINE');
    assert.equal(calls.interrupts, 0);
  });

  function stuckEngine(firstPieces: string[]) {
    const calls = { interrupts: 0 };
    const engine: CompletionEngine = {
      interruptGenerate: () => { calls.interrupts++; },
      chat: { completions: { create: async () => (async function* () {
        for (const p of firstPieces) yield { choices: [{ delta: { content: p } }] };
        await new Promise(() => {});
      })() } },
    };
    return { engine, calls };
  }
  const fast = { firstTokenMs: 60, idleMs: 60, pollMs: 5 };

  it('stops with a clear error when the device never produces the first word (stuck prefill)', async () => {
    const { engine, calls } = stuckEngine([]);
    const seen: number[] = [];
    const err = await runCompletion(engine, planReq, (n) => seen.push(n), () => false, fast).catch((e) => e);
    assert.ok(err instanceof LocalAiError);
    assert.match(err.message, /did not start answering in time.*Nothing was changed/);
    assert.equal(err.release, true);
    assert.equal(calls.interrupts, 1);
    assert.deepEqual(seen, []);
  });

  it('stops with a clear error when the reply stalls partway through', async () => {
    const { engine } = stuckEngine(['{"reply":', '"hel']);
    const err = await runCompletion(engine, planReq, undefined, () => false, { ...fast, firstTokenMs: 5000 }).catch((e) => e);
    assert.match(err.message, /stopped responding partway through/);
  });

  it('Stop works even while the device is stuck before the first word', async () => {
    let cancelled = false;
    setTimeout(() => { cancelled = true; }, 20);
    const err = await runCompletion(stuckEngine([]).engine, planReq, undefined, () => cancelled, { ...fast, firstTokenMs: 10_000 }).catch((e) => e);
    assert.match(err.message, /Stopped\. Nothing was saved\./);
    assert.equal(err.release, false);
  });

  it('a chat message like "reply with hello" gets a direct reply and no file edits', () => {
    const plan = parseInspectReply('{"reply":"hello","understanding":"Say hello","files_to_inspect":[],"files_to_change":[],"files_to_create":[],"plan":[]}', { 'index.html': '' });
    assert.equal(plan.reply, 'hello');
    assert.deepEqual(plan.targets, []);
    assert.equal(parseInspectReply('{"plan":[]}', {}).reply, '');
  });

  it('the Thinking card shows which stage the device is in', () => {
    const src = readFileSync('src/components/builder/ChatPanel.tsx', 'utf8');
    assert.match(src, /Reading your request on your device/);
    assert.match(src, /Writing a reply/);
  });

  it('sends the cleaned reply through the same on-device protocol the server validates', async () => {
    const messages = [{ role: 'user' as const, content: 'plan' }];
    const hash = await promptHash(messages, 1800);
    const { engine } = fakeEngine(['{"plan":["a"]}', ' trailing {junk'], true);
    const r = await runCompletion(engine, { messages, max_tokens: 1800 });
    const accepted = await localReply({ ai_reply: { content: r.content, model: LOCAL_MODEL_IDS[0], prompt_hash: hash, usage: r.usage } }, 'agent:plan', messages, 1800);
    assert.equal(accepted.content, '{"plan":["a"]}');
    assert.equal(accepted.model, LOCAL_MODEL_IDS[0]);
  });

  it('blocks duplicate submissions and overlapping generations', () => {
    const ws = readFileSync('src/components/builder/Workspace.tsx', 'utf8');
    assert.match(ws, /async function send\(text: string, mode\?: WbWorkflow, repairOf\?: string\) \{\n\s+if \(inFlight\.current\) return false;\n\s+inFlight\.current = true;/);
    assert.match(ws, /async function continueChange\(change: WbChange\) \{\n\s+if \(inFlight\.current\) return/);
    assert.equal((ws.match(/inFlight\.current = false;/g) ?? []).length, 2);
    const ctx = readFileSync('src/lib/localAi/LocalAiContext.tsx', 'utf8');
    assert.match(ctx, /if \(generating\.current\) throw new Error\('Blackveil AI is already working on a reply\.'\);/);
    assert.match(ctx, /finally \{\n\s+generating\.current = false;\n\s+setStatus\(engine\.current \? 'ready' : 'idle'\);/);
  });

  it('clears the Thinking token counter whenever a generation ends, including failures', () => {
    const ws = readFileSync('src/components/builder/Workspace.tsx', 'utf8');
    assert.match(ws, /async function think\(req: LocalAiRequest\) \{\n\s+setAiTokens\(0\);\n\s+try \{\n\s+return await ai\.generate\(req, setAiTokens\);\n\s+\} finally \{\n\s+setAiTokens\(null\);/);
    assert.match(ws, /\} finally \{\n\s+inFlight\.current = false;\n\s+setPending\(null\);\n\s+setSending\(false\);/);
  });
});

describe('agent workflow helpers', () => {
  it('keeps only existing files from the inspect step', () => {
    const p = parseInspectReply('```json\n{"understanding":"edit title","files_to_inspect":["index.html","../etc","nope.js","index.html"],"files_to_change":["index.html","ghost.css"],"files_to_create":["about.html","index.html","../x.html"],"plan":["change h1",""]}\n```', { 'index.html': '' });
    assert.deepEqual(p.files, ['index.html']);
    assert.deepEqual(p.targets, ['index.html']);
    assert.deepEqual(p.creates, ['about.html']);
    assert.deepEqual(p.plan, ['change h1']);
    assert.equal(p.understanding, 'edit title');
    assert.deepEqual(parseInspectReply('garbage', {}), { reply: '', understanding: '', files: [], targets: [], creates: [], plan: [] });
  });

  it('verifies applied files against the proposal', () => {
    const stored = { 'index.html': '<h1>', 'data.json': '{}' };
    const checks = verifyAppliedFiles(stored, [
      { path: 'index.html', after: '<h1>' },
      { path: 'data.json', after: '{}' },
      { path: 'old.js', after: null },
    ]);
    assert.equal(checks[0].ok, true);
    const mismatch = verifyAppliedFiles({ 'index.html': 'changed' }, [{ path: 'index.html', after: 'expected' }]);
    assert.equal(mismatch[0].ok, false);
  });
});

describe('project index and change engine', () => {
  const site = {
    'index.html': '<link rel="stylesheet" href="styles.css"><nav><a href="about.html">About</a></nav><script src="app.js"></script>',
    'about.html': '<link rel="stylesheet" href="styles.css"><img src="img/logo.png">',
    'styles.css': '@import "theme.css"; body{}',
    'theme.css': ':root{}',
    'app.js': "import { x } from './util'; fetch('data.json')",
    'util.js': 'export const x = 1',
    'data.json': '{}',
    'lost.html': '<p>',
    'supabase/migrations/1_init.sql': 'create table t();',
  };

  it('classifies files and builds a dependency graph with broken refs and orphan pages', () => {
    assert.equal(kindOf('src/pages/Home.tsx'), 'page');
    assert.equal(kindOf('supabase/migrations/1_init.sql'), 'database');
    assert.equal(kindOf('.env.local'), 'env');
    const idx = buildIndex(site);
    assert.deepEqual(idx.entries['styles.css'].dependents.sort(), ['about.html', 'index.html']);
    assert.ok(idx.entries['app.js'].refs.includes('util.js'));
    assert.ok(idx.entries['app.js'].refs.includes('data.json'));
    assert.deepEqual(idx.entries['about.html'].missing, ['img/logo.png']);
    assert.deepEqual(idx.orphanPages, ['lost.html']);
  });

  it('expands a selection to dependencies and dependents, and batches by size', () => {
    const sel = expandSelection(buildIndex(site), ['styles.css']);
    assert.deepEqual(sel.sort(), ['about.html', 'index.html', 'styles.css', 'theme.css']);
    assert.deepEqual(planBatches({ a: 50, b: 60, c: 10 }, ['a', 'b', 'c'], 100), [['a'], ['b', 'c']]);
  });

  it('redacts secrets before anything is sent to the model', () => {
    const key = 'AIza' + 'x'.repeat(35);
    assert.deepEqual(findSecrets(`const k = "${key}"`), ['Google API key']);
    assert.equal(redactForModel('.env', 'API_KEY=abc\nURL=x'), `API_KEY=${REDACTED}\nURL=${REDACTED}`);
    assert.ok(!redactForModel('app.js', `k="${key}"`).includes(key));
  });

  it('runs cross-file consistency checks', () => {
    const byName = Object.fromEntries(checkConsistency({ ...site, 'bad.json': '{', 'empty.css': '' }, 'static').map((c) => [c.name, c]));
    assert.match(byName['Every local link, import and asset reference resolves'].detail, /img\/logo\.png/);
    assert.match(byName['JSON files parse'].detail, /bad\.json/);
    assert.equal(byName['No empty files'].ok, false);
    assert.equal(byName['Every page is linked from somewhere'].warn, true);
  });

  it('applies exact patches and refuses ambiguous ones', () => {
    assert.deepEqual(applyPatch('a b c', [{ find: 'b', replace: 'B' }]), { content: 'a B c' });
    assert.ok('error' in applyPatch('a a', [{ find: 'a', replace: 'x' }]));
    assert.ok('error' in applyPatch('abc', [{ find: 'z', replace: 'x' }]));
  });

  it('merges multi-step proposals with renames, patches and safety skips', () => {
    const step1 = mergeProposals(site, [], [
      { path: 'contact.html', action: 'create', content: '<h1>Contact</h1>' },
      { path: 'index.html', action: 'patch', edits: [{ find: '<a href="about.html">About</a>', replace: '<a href="about.html">About</a><a href="contact.html">Contact</a>' }] },
      { path: '.env', action: 'update', content: 'X=1' },
      { path: 'theme.css', action: 'update', content: `:root{--k:"${REDACTED}"}` },
    ], 'static');
    assert.equal(step1.notes.length, 2);
    const step2 = mergeProposals(site, step1.files, [
      { path: 'helpers.js', action: 'rename', from: 'util.js' },
      { path: 'app.js', action: 'patch', edits: [{ find: './util', replace: './helpers' }] },
      { path: 'index.html', action: 'delete' },
    ], 'static');
    const next = applyToMap(site, step2.files);
    assert.match(next['index.html'], /contact\.html/);
    assert.equal(next['util.js'], undefined);
    assert.equal(next['helpers.js'], 'export const x = 1');
    assert.match(next['app.js'], /\.\/helpers/);
    assert.ok(step2.notes.some((n) => /index\.html/.test(n)));
    const risks = riskNotes(step2.files, 'static');
    assert.ok(risks.some((r) => /util\.js/.test(r)));
  });

  it('flags destructive database statements as risks without running them', () => {
    const r = riskNotes([{ path: 'supabase/migrations/2_drop.sql', action: 'create', before: null, after: 'drop table users;' }], 'other');
    assert.match(r.join(' '), /destructive/);
  });
});

describe('multi-page preview', () => {
  it('resolves links relative to the current page and injects the error bridge', () => {
    assert.equal(resolveLocal('../styles.css', 'blog/post.html'), 'styles.css');
    assert.equal(resolveLocal('/about.html', 'blog/post.html'), 'about.html');
    assert.equal(resolveLocal('https://x.y/a.css', 'index.html'), null);
    const p = buildPreview({ 'blog/post.html': '<head></head><link rel="stylesheet" href="../s.css">', 's.css': 'b{}' }, 'blog/post.html');
    assert.match(p!.html, /data-file="s\.css"/);
    assert.match(p!.html, /<head><script>\(function\(\)\{/);
    assert.deepEqual(p!.missing, []);
  });
});
