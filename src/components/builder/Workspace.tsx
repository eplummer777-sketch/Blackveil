import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, ErrorBanner, Spinner } from '@/components/ui';
import { useLocalAi, type LocalAiRequest } from '@/lib/localAi/LocalAiContext';
import { wb, wbWithAi, errText, changeInProgress, WbApplyResult, WbChange, WbCheck, WbProjectData, type WbRating, type WbWorkflow } from '@/lib/builder';
import { MemoryDrawer } from '@/components/builder/MemoryDrawer';
import { Preview } from '@/components/builder/Preview';
import { ChatPanel } from '@/components/builder/ChatPanel';
import { ChangeReview } from '@/components/builder/ChangeReview';
import { HistoryDrawer } from '@/components/builder/HistoryDrawer';
import { PublishDialog } from '@/components/builder/PublishDialog';
import { BookOpen, Download, Eye, EyeOff, Globe, History, Rocket } from 'lucide-react';

interface Attempt { text: string; mode?: WbWorkflow; repairOf?: string }

export function Workspace({ projectId, onAiSettings }: {
  projectId: string;
  onAiSettings: () => void;
}) {
  const ai = useLocalAi();
  const [aiTokens, setAiTokens] = useState<number | null>(null);
  const [data, setData] = useState<WbProjectData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const inFlight = useRef(false);
  const [showPreview, setShowPreview] = useState(false);
  const [review, setReview] = useState<WbChange | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [showPublish, setShowPublish] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [writingId, setWritingId] = useState<string | null>(null);
  const [retry, setRetry] = useState<Attempt | null>(null);
  const [showMemory, setShowMemory] = useState(false);
  const [exporting, setExporting] = useState(false);

  const reload = useCallback(async () => {
    try {
      const d = await wb<WbProjectData>('get_project', { project_id: projectId });
      setData(d);
      return d;
    } catch (e) {
      setError(errText(e));
      return null;
    }
  }, [projectId]);

  useEffect(() => { reload(); }, [reload]);

  async function act(action: string, payload: Record<string, unknown>): Promise<string | null> {
    setError(null);
    try {
      await wb(action, { project_id: projectId, ...payload });
      await reload();
      return null;
    } catch (e) {
      return errText(e);
    }
  }

  async function think(req: LocalAiRequest) {
    setAiTokens(0);
    try {
      return await ai.generate(req, setAiTokens);
    } finally {
      setAiTokens(null);
    }
  }

  async function writeSteps(start: WbChange) {
    let ch = start;
    setWritingId(ch.id);
    try {
      while (changeInProgress(ch)) {
        const total = ch.analysis?.batches?.length ?? 0;
        setProgress(`Writing step ${(ch.analysis?.next ?? 0) + 1} of ${total}…`);
        const cur = ch;
        setData((d) => (d ? { ...d, changes: d.changes.map((c) => (c.id === cur.id ? cur : c)) } : d));
        setReview((r) => (r && r.id === cur.id ? cur : r));
        const r = await wbWithAi<{ change: WbChange }>('continue_change', { change_id: ch.id }, think);
        ch = r.change;
      }
    } finally {
      setWritingId(null);
      setProgress(null);
    }
    await reload();
    setReview(ch.status === 'pending' ? ch : null);
  }

  async function send(text: string, mode?: WbWorkflow, repairOf?: string) {
    if (inFlight.current) return false;
    inFlight.current = true;
    setSending(true);
    setError(null);
    setRetry(null);
    setPending(text);
    const known = new Set(data?.messages.map((m) => m.id));
    try {
      const r = await wbWithAi<{ change: WbChange | null }>('chat', {
        project_id: projectId, message: text, focus: [], ...(mode ? { mode } : {}), ...(repairOf ? { repair_of: repairOf } : {}),
      }, think);
      await reload();
      setPending(null);
      if (r.change && !r.change.analysis?.awaiting_go) await writeSteps(r.change);
      return true;
    } catch (e) {
      setError(errText(e));
      const d = await reload();
      // Offer a retry only when the server stored nothing, so a retry can never duplicate the message.
      const saved = !!d?.messages.some((m) => !known.has(m.id) && m.role === 'user' && m.content === text);
      if (!saved) setRetry({ text, mode, repairOf });
      return saved;
    } finally {
      inFlight.current = false;
      setPending(null);
      setSending(false);
    }
  }

  async function continueChange(change: WbChange) {
    if (inFlight.current) return 'Blackveil AI is already working on a request.';
    inFlight.current = true;
    setSending(true);
    try {
      await writeSteps(change);
      return null;
    } catch (e) {
      const d = await reload();
      const latest = d?.changes.find((c) => c.id === change.id);
      if (latest) setReview(latest);
      return errText(e);
    } finally {
      inFlight.current = false;
      setSending(false);
    }
  }

  function fixWithAi(change: WbChange, checks: WbCheck[]) {
    setReview(null);
    send(`Fix these problems found by the project checks, updating every affected file:\n${checks.map((c) => `- ${c.name}: ${c.detail}`).join('\n')}`, 'code', change.id);
  }

  async function rate(messageId: string, rating: WbRating) {
    try {
      await wb('rate_message', { project_id: projectId, message_id: messageId, rating });
      setData((d) => (d ? { ...d, feedback: [{ message_id: messageId, rating }, ...(d.feedback ?? []).filter((f) => f.message_id !== messageId)] } : d));
    } catch (e) {
      setError(errText(e));
    }
  }

  async function applyChange(change: WbChange, force: boolean, confirmRisks: boolean) {
    setError(null);
    try {
      const r = await wb<WbApplyResult>('apply_change', { change_id: change.id, force, confirm_risks: confirmRisks });
      await reload();
      return { error: null, checks: r.verification.checks };
    } catch (e) {
      return { error: errText(e) };
    }
  }

  async function undoChange(change: WbChange, force: boolean) {
    const err = await act('revert_change', { change_id: change.id, force });
    if (!err) setReview(null);
    return err;
  }

  async function rejectChange(change: WbChange) {
    const err = await act('reject_change', { change_id: change.id });
    if (!err) setReview(null);
    return err;
  }

  async function restore(id: string) {
    const err = await act('restore_snapshot', { snapshot_id: id });
    if (!err) setShowHistory(false);
    return err;
  }

  async function exportProject() {
    if (!window.confirm('Download all saved website files as JSON to this device? The file may contain sensitive content; keep it private.')) return;
    setExporting(true);
    setError(null);
    try {
      const exported = await wb<{
        format: string;
        name: string;
        description: string;
        kind: string;
        files: Record<string, string>;
      }>('export_project', { project_id: projectId });
      const safeName = exported.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'website';
      const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `${safeName}.json`;
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setError(errText(e));
    } finally {
      setExporting(false);
    }
  }

  if (!data) {
    return error ? <ErrorBanner message={error} />
      : <div className="flex items-center gap-2 text-sm text-slate-400"><Spinner /> Opening your website…</div>;
  }

  return (
    <div className="flex flex-col gap-3 h-[calc(100vh-7rem)] min-h-[560px] fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <div className="h-8 w-8 rounded-lg bg-cyan-500/10 text-cyan-300 grid place-content-center"><Globe size={16} /></div>
        <div className="min-w-0">
          <h1 className="text-base font-semibold leading-tight text-slate-100 truncate max-w-[40ch]">{data.project.name}</h1>
          <p className="text-[11px] text-slate-500">{data.publication ? 'Live' : 'Not published yet'}</p>
        </div>
        <div className="ml-auto flex flex-wrap gap-1.5">
          <Button variant="ghost" size="sm" onClick={() => { void exportProject(); }} loading={exporting} title="Download all website files as JSON">
            <Download size={14} /> Export JSON
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setShowPreview(!showPreview)}>
            {showPreview ? <EyeOff size={14} /> : <Eye size={14} />} {showPreview ? 'Hide preview' : 'Preview'}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setShowMemory(true)}><BookOpen size={14} /> Memory</Button>
          <Button variant="ghost" size="sm" onClick={() => setShowHistory(true)}><History size={14} /> History</Button>
          <Button size="sm" onClick={() => setShowPublish(true)}>
            {data.publication ? <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> : <Rocket size={14} />}
            {data.publication ? 'Published' : 'Publish'}
          </Button>
        </div>
      </div>

      <div className={`flex-1 min-h-0 grid gap-3 ${showPreview ? 'lg:grid-cols-[minmax(380px,460px)_minmax(0,1fr)]' : ''}`}>
        <section className={`${showPreview ? 'hidden lg:block' : 'block w-full max-w-3xl mx-auto'} rounded-xl border border-slate-800 bg-veil-900/60 overflow-hidden min-h-0`}>
          <ChatPanel messages={data.messages} changes={data.changes} aiTokens={aiTokens} pending={pending} writingId={writingId} busy={sending}
            feedback={data.feedback ?? []} onRate={rate}
            error={error} onDismissError={() => { setError(null); setRetry(null); }}
            onRetry={retry && !sending ? () => send(retry.text, retry.mode, retry.repairOf) : undefined}
            onSend={(t, mode) => send(t, mode)} onReview={setReview} onAiSettings={onAiSettings}
            onContinue={(c) => { continueChange(c).then((err) => { if (err) setError(err); }); }} />
        </section>
        {showPreview && (
          <section className="rounded-xl border border-slate-800 bg-veil-900/60 overflow-hidden min-h-0 fade-up">
            <Preview files={data.files} onFix={(msg) => { setShowPreview(false); send(msg); }} />
          </section>
        )}
      </div>

      {review && (
        <ChangeReview key={review.id} change={review} progress={progress} onClose={() => { if (!progress) setReview(null); }}
          onApply={(force, confirmRisks) => applyChange(review, force, confirmRisks)}
          onReject={() => rejectChange(review)}
          onContinue={() => continueChange(review)}
          onUndo={(force) => undoChange(review, force)}
          onFix={(checks) => fixWithAi(review, checks)} />
      )}
      {showMemory && <MemoryDrawer projectId={projectId} onClose={() => setShowMemory(false)} />}
      {showPublish && <PublishDialog data={data} onClose={() => setShowPublish(false)} onChanged={reload} />}
      {showHistory && (
        <HistoryDrawer snapshots={data.snapshots} onClose={() => setShowHistory(false)} onRestore={restore}
          onCheckpoint={() => act('create_snapshot', {})} />
      )}
    </div>
  );
}
