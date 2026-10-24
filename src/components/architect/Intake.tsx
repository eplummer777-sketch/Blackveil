import { useState } from 'react';
import { ArrowRight, ChevronRight, FolderKanban, Sparkles, Wand2 } from 'lucide-react';
import { Badge, Button, Card, EmptyState } from '@/components/ui';
import type { ArchitectProject } from '@/lib/architect';

const EXAMPLES = [
  'I run a small online shop on an Nginx server and want to stop bots and harden the site.',
  'My family shares a home Wi-Fi router, two Windows laptops and some phones. I want them safer.',
  'I have a Linux VPS that I log into over SSH. I keep seeing failed login attempts.',
  'Our startup uses AWS and I want to lock down who can access the account.',
];

const PROJECT_STATUS: Record<ArchitectProject['status'], { label: string; tone: 'cyan' | 'amber' | 'rose' }> = {
  needs_answers: { label: 'Needs answers', tone: 'amber' },
  planned: { label: 'Plan ready', tone: 'cyan' },
  failed: { label: 'Failed', tone: 'rose' },
};

export function Intake({ projects, creating, onCreate, onOpen }: {
  projects: ArchitectProject[];
  creating: boolean;
  onCreate: (description: string) => void;
  onOpen: (id: string) => void;
}) {
  const [text, setText] = useState('');
  const trimmed = text.trim();
  const valid = trimmed.length >= 10 && trimmed.length <= 4000;

  return (
    <div className="grid gap-6 lg:grid-cols-5">
      <Card className="lg:col-span-3 p-6 sm:p-8 relative overflow-hidden">
        <div className="pointer-events-none absolute -top-24 -right-24 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="relative">
          <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-cyan-300/80">
            <Sparkles size={14} /> New project
          </div>
          <h2 className="mt-3 text-2xl font-semibold text-slate-100 leading-tight">What do you want to protect?</h2>
          <p className="mt-2 text-sm text-slate-400 leading-relaxed">
            Describe it in your own words. Architect will ask a few follow-up questions, then draft a plan with the exact settings and rules to apply.
          </p>
          <form
            className="mt-6"
            onSubmit={(e) => { e.preventDefault(); if (valid) onCreate(trimmed); }}
          >
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={6}
              maxLength={4000}
              placeholder="For example: I host a WordPress site on Apache and want to stop brute-force logins..."
              className="w-full resize-none rounded-xl border border-slate-700/80 bg-veil-950/70 px-4 py-3.5 text-sm text-slate-100 leading-relaxed placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition"
            />
            <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
              <span>{trimmed.length < 10 ? 'At least a sentence, please.' : 'Do not include passwords or secret keys.'}</span>
              <span className="font-mono-tight">{text.length}/4000</span>
            </div>
            <div className="mt-5 flex flex-wrap gap-2">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => setText(ex)}
                  className="rounded-full border border-slate-700/70 bg-veil-800/60 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-200 transition text-left"
                >
                  {ex.length > 52 ? ex.slice(0, 52) + '...' : ex}
                </button>
              ))}
            </div>
            <div className="mt-6 flex items-center gap-3">
              <Button type="submit" loading={creating} disabled={!valid}>
                <Wand2 size={16} /> Start planning
              </Button>
              {creating && <span className="text-xs text-slate-400">Preparing questions...</span>}
            </div>
          </form>
        </div>
      </Card>

      <Card className="lg:col-span-2 p-5">
        <div className="flex items-center gap-2 mb-4">
          <FolderKanban size={16} className="text-cyan-300" />
          <h3 className="text-sm font-semibold text-slate-200">Your projects</h3>
          <span className="ml-auto text-xs text-slate-500">{projects.length}</span>
        </div>
        {projects.length === 0 ? (
          <EmptyState icon={<FolderKanban size={28} />} title="No projects yet" hint="Your security plans will appear here." />
        ) : (
          <ul className="space-y-2 max-h-[460px] overflow-y-auto scrollbar-thin pr-1">
            {projects.map((p) => (
              <li key={p.id}>
                <button
                  onClick={() => onOpen(p.id)}
                  className="group w-full rounded-lg border border-slate-800 bg-veil-950/40 px-4 py-3 text-left hover:border-cyan-500/40 hover:bg-veil-800/60 transition"
                >
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-slate-200">{p.title}</span>
                    <ChevronRight size={14} className="ml-auto shrink-0 text-slate-600 group-hover:text-cyan-300 group-hover:translate-x-0.5 transition" />
                  </div>
                  <div className="mt-1.5 flex items-center gap-2">
                    <Badge tone={PROJECT_STATUS[p.status].tone}>{PROJECT_STATUS[p.status].label}</Badge>
                    <span className="text-xs text-slate-500">{new Date(p.created_at).toLocaleDateString()}</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-4 flex items-start gap-2 text-xs text-slate-500 leading-relaxed">
          <ArrowRight size={12} className="mt-0.5 shrink-0" />
          Architect writes plans and settings. It never connects to or runs anything on your devices.
        </p>
      </Card>
    </div>
  );
}
