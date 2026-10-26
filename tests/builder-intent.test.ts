import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  analysisBrief, analyzeRequest, estTokens, packSections, parseCoverage, requirementLines, unresolvedRequirements,
} from '../supabase/functions/_lib/intent.ts';
import { buildIndex } from '../supabase/functions/_lib/projectIndex.ts';
import { parseInspectReply } from '../supabase/functions/_lib/webbuilder.ts';

const SITE = { 'index.html': '<h1>Hi</h1>', 'styles.css': 'body{}' };
const idx = buildIndex(SITE);
const analyze = (prompt: string, mode?: string) => analyzeRequest(prompt, idx, SITE, mode);

const MANY = [
  'Add an About page',
  'Add a Contact page',
  'Add a Blog page',
  'Link every new page from the navigation',
  'Make the header sticky',
  'Make the footer dark',
  'Add a newsletter form',
  'Add email validation to the newsletter form',
  'Add a cookie banner',
  'Add a 404 page',
  'Make every page responsive',
  'Add a favicon',
  'Add Open Graph tags',
  'Add a sitemap.xml',
  'Add a robots.txt',
  'Add a privacy policy page',
].join('\n');

describe('request understanding', () => {
  it('keeps the original request exactly as written', () => {
    const prompt = 'Add an About page and link it from the nav.';
    const a = analyze(prompt);
    assert.equal(a.original, prompt);
    assert.ok(a.goal.length > 0);
  });

  it('understands a short request', () => {
    const a = analyze('Make the heading blue');
    assert.equal(a.workflow, 'code');
    assert.deepEqual(a.requirements, ['Make the heading blue']);
  });

  it('keeps all 16 requirements instead of stopping at a fixed limit', () => {
    const a = analyze(MANY);
    assert.equal(a.requirements.length, 16);
    assert.equal(requirementLines(a).length, 16);
    assert.match(requirementLines(a)[15], /^R16: /);
    assert.equal(a.unresolved.length, 0);
  });

  it('sends every one of the 16 numbered requirements to the planner when the budget allows', () => {
    const brief = analysisBrief(analyze(MANY), 8_000);
    for (let i = 1; i <= 16; i++) assert.match(brief.text, new RegExp(`R${i}:`), `R${i}`);
    assert.deepEqual(brief.omitted, []);
  });

  it('names every requirement it cannot fit instead of dropping it', () => {
    const a = analyze(MANY);
    const tight = analysisBrief(a, 60);
    for (const line of requirementLines(a)) {
      const id = line.split(':')[0];
      assert.ok(tight.text.includes(`${id}:`) || tight.omitted.includes(id), `${id} silently lost`);
    }
  });

  it('keeps every constraint in a long request that contains a conflict', () => {
    const parts = [
      'Redesign the homepage',
      "Don't change the pricing page",
      'Never remove the login link',
      'Keep the existing footer',
      'Do not touch the checkout flow',
      "Don't edit the analytics script",
      'Must keep the current colour palette',
      'Only change the hero section',
      'Avoid changing any database migration',
      'Leave the API routes alone',
      'Make the hero full width',
      'Change the pricing page layout',
    ];
    const a = analyze(parts.join('\n'));
    assert.ok(a.constraints.length >= 8, a.constraints.join(' | '));
    assert.ok(a.conflicts.length > 0);
    const brief = analysisBrief(a, 4_000);
    assert.match(brief.text, /pricing page/i);
  });

  it('refuses an oversized request with a clear message instead of slicing it', () => {
    const src = readFileSync('supabase/functions/web-builder/agent.ts', 'utf8');
    assert.match(src, /maxPromptChars/);
    assert.match(src, /Nothing was changed\. Send it in two parts/);
    assert.doesNotMatch(src, /str\(body\.message/);
  });
});

describe('context budget', () => {
  it('keeps the request and reports what does not fit instead of cutting silently', () => {
    const request = 'x'.repeat(2_000);
    const packed = packSections([
      { name: 'request', text: request, priority: 0, keep: true },
      { name: 'files', text: 'y'.repeat(20_000), priority: 5 },
    ], 100);
    assert.match(packed.text, /x{2000}/);
    assert.deepEqual(packed.omitted, ['files']);
    assert.equal(packed.overBudget, true);
  });

  it('estimates tokens above raw character count for code', () => {
    assert.equal(estTokens('x'.repeat(350)), 100);
  });
});

describe('requirement coverage', () => {
  const a = analyze('Add a page\nAdd a form\nAdd a footer');

  it('treats a plan with no coverage rows as unconfirmed, never done', () => {
    assert.equal(unresolvedRequirements(a, parseCoverage(null)).length, a.requirements.length);
  });

  it('flags only the requirements the planner marked as not covered', () => {
    const rows = parseCoverage([
      { requirement: 'R1', covered_by: '1' },
      { requirement: 'R2', covered_by: 'none' },
      { requirement: 'R3', covered_by: '3' },
    ]);
    const unresolved = unresolvedRequirements(a, rows);
    assert.equal(unresolved.length, 1);
    assert.match(unresolved[0], /^R2:/);
  });

  it('matches coverage by requirement id, not by the model saying anything', () => {
    const rows = parseCoverage([
      { requirement: 'step one', covered_by: '1' },
      { requirement: 'anything', covered_by: 'done' },
    ]);
    assert.equal(unresolvedRequirements(a, rows).length, a.requirements.length);
  });

  it('reads goal and coverage from the planner reply and reports shortening', () => {
    const raw = JSON.stringify({
      reply: 'ok', goal: 'Add three sections', understanding: 'Adds a page, a form and a footer',
      files_to_change: ['index.html'], plan: ['page', 'form', 'footer'],
      requirement_coverage: [{ requirement: 'R1', covered_by: '1' }],
    });
    const p = parseInspectReply(raw, SITE);
    assert.equal(p.goal, 'Add three sections');
    assert.equal(p.coverage.length, 1);
    assert.deepEqual(p.trimmed, []);
  });
});
