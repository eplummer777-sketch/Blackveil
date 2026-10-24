import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, FlaskConical, KanbanSquare, RefreshCw, ScrollText, ShieldCheck, Map as MapIcon } from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { Button, Card, ErrorBanner, Spinner } from '@/components/ui';
import { Answers, ArchitectChange, ArchitectEvent, ArchitectProject, ChangeAction, callArchitect } from '@/lib/architect';
import { QuestionsForm } from '@/components/architect/QuestionsForm';
import { PlanView } from '@/components/architect/PlanView';
import { StatusBoard } from '@/components/architect/StatusBoard';
import { ChangeDrawer } from '@/components/architect/ChangeDrawer';
import { ActivityLog } from '@/components/architect/ActivityLog';
import type { ActionPayload } from '@/components/architect/ChangeActions';

type Tab = 'board' | 'plan' | 'activity';
const TABS: { id: Tab; label: string; icon: typeof MapIcon }[] = [
  { id: 'board', label: 'Changes', icon: KanbanSquare },
  { id: 'plan', label: 'Plan', icon: MapIcon },
  { id: 'activity', label: 'Audit log', icon: ScrollText },
];

export function Workspace({ project, token, onBack, onProjectUpdated }: {
  project: ArchitectProject;
  token: string;
  onBack: () => void;
  onProjectUpdated: (p: ArchitectProject) => void;
}) {
  const [tab, setTab] = useState<Tab>('board');
  const [changes, setChanges] = useState<ArchitectChange[]>([]);
  const [events, setEvents] = useState<ArchitectEvent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setRefreshing(true);
    const [c, e] = await Promise.all([
      supabase.from('architect_changes').select('*').eq('project_id', project.id).order('position'),
      supabase.from('architect_events').select('*').eq('project_id', project.id).order('created_at', { ascending: false }).limit(200),
    ]);
    setRefreshing(false);
    setLoaded(true);
    if (c.error || e.error) {
      setError('Could not load this project. Check your connection and try refreshing.');
      return;
    }
    setChanges((c.data ?? []) as ArchitectChange[]);
    setEvents((e.data ?? []) as ArchitectEvent[]);
  }, [project.id]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(null), 6000);
    return () => clearTimeout(t);
  }, [notice]);

  async function submitAnswers(answers: Answers) {
    setBusy('answers');
    setError(null);
    const res = await callArchitect<{ project: ArchitectProject }>(token, { action: 'submit_answers', project_id: project.id, answers });
    setBusy(null);
    if (!res.ok) { setError(res.error); return; }
    if (!res.data?.project) { setError('The plan was created but could not be loaded. Try refreshing.'); return; }
    onProjectUpdated(res.data.project);
    setTab('board');
    setNotice('Plan ready. Every change starts as Proposed. Run the sandbox test, then review and approve.');
    await load();
  }

  async function run(key: string, body: Record<string, unknown>, success: (d: Record<string, unknown>) => string) {
    setBusy(key);
    setError(null);
    const res = await callArchitect<Record<string, unknown>>(token, body);
    setBusy(null);
    if (!res.ok) { setError(res.error); return; }
    setNotice(success(res.data ?? {}));
    await load();
  }

  const testAll = () => run('test_all', { action: 'test_all', project_id: project.id }, (d) =>
    Number(d.tested) ? `Sandbox tested ${d.tested} change(s): ${d.passed} passed, ${Number(d.tested) - Number(d.passed)} failed.` : 'Nothing left to test.');
  const testOne = (id: string) => run('test', { action: 'test_change', change_id: id }, (d) => String(d.summary ?? 'Test complete.'));
  const act = (id: string, action: ChangeAction, payload: ActionPayload) =>
    run(action, { action, change_id: id, ...payload }, (d) => String(d.message ?? 'Done.'));

  const openChange = changes.find((c) => c.id === openId) ?? null;
  const untested = changes.filter((c) => c.status === 'proposed' || c.status === 'test_failed').length;
  const count = (s: ArchitectChange['status'][]) => changes.filter((c) => s.includes(c.status)).length;

  return (
    <div className="space-y-6 fade-in">
      <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
        <div className="min-w-0">
          <button onClick={onBack} className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-200 transition">
            <ArrowLeft size={13} /> All projects
          </button>
          <h2 className="mt-2 text-xl md:text-2xl font-semibold text-slate-50 tracking-tight truncate">{project.title}</h2>
        </div>
        {project.status === 'planned' && (
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={load} loading={refreshing}>{!refreshing && <RefreshCw size={14} />} Refresh</Button>
            <Button size="sm" onClick={testAll} loading={busy === 'test_all'} disabled={untested === 0}>
              <FlaskConical size={14} /> Test all proposed{untested ? ` (${untested})` : ''}
            </Button>
          </div>
        )}
      </div>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && (
        <div className="fade-in rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-4 py-2.5 text-sm text-cyan-100 flex items-start gap-2">
          <ShieldCheck size={15} className="mt-0.5 shrink-0" /> {notice}
        </div>
      )}

      {project.status === 'needs_answers' ? (
        <div className="max-w-3xl">
          <Card className="p-5 mb-4">
            <p className="text-sm text-slate-300 leading-relaxed">
              A few questions so the plan fits your setup and skill level. Only the first question is required.
            </p>
          </Card>
          <QuestionsForm questions={project.questions} submitting={busy === 'answers'} onSubmit={submitAnswers} />
        </div>
      ) : !loaded ? (
        <div className="flex justify-center py-20"><Spinner /></div>
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Stat label="Proposed" value={count(['proposed', 'test_failed'])} />
            <Stat label="Tested" value={count(['tested', 'approved'])} />
            <Stat label="Applied by you" value={count(['deployed'])} />
            <Stat label="Verified" value={count(['verified'])} accent />
          </div>

          <nav className="flex gap-1 overflow-x-auto rounded-xl border border-slate-800 bg-veil-900/60 p-1">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm whitespace-nowrap transition-colors ${tab === t.id ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/30' : 'text-slate-400 hover:text-slate-200 hover:bg-veil-800/60'}`}
              >
                <t.icon size={15} /> {t.label}
              </button>
            ))}
          </nav>

          <div key={tab} className="fade-in">
            {tab === 'board' && <StatusBoard changes={changes} onOpen={setOpenId} />}
            {tab === 'plan' && project.plan && <PlanView project={project} plan={project.plan} />}
            {tab === 'activity' && <ActivityLog events={events} changes={changes} />}
          </div>
        </>
      )}

      {openChange && (
        <ChangeDrawer
          change={openChange}
          busy={busy}
          onClose={() => setOpenId(null)}
          onTest={() => testOne(openChange.id)}
          onAction={(action, payload) => act(openChange.id, action, payload)}
        />
      )}
    </div>
  );
}

function Stat({ label, value, accent = false }: { label: string; value: number; accent?: boolean }) {
  return (
    <Card className="p-4">
      <p className="text-[11px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold font-mono-tight ${accent ? 'text-emerald-300' : 'text-slate-100'}`}>{value}</p>
    </Card>
  );
}
