import { useCallback, useEffect, useState } from 'react';
import { Drawer, Button, Badge, ErrorBanner, Spinner } from '@/components/ui';
import { wb, errText, type WbFix, type WbMemory, type WbMetrics, type WbAiStats } from '@/lib/builder';
import { Archive, BadgeCheck, Check, Pencil, Plus, Trash2, X } from 'lucide-react';

const KINDS = ['requirement', 'convention', 'decision', 'rule', 'bug', 'limitation', 'milestone', 'session'];
const KIND_HINT: Record<string, string> = { rule: 'A workflow preference Blackveil AI follows. It can never override safety rules.' };
type Tab = 'memory' | 'fixes' | 'quality';

function MemoryForm({ initial, onSave, onCancel }: { initial?: WbMemory; onSave: (v: { kind: string; title: string; body: string }) => Promise<void>; onCancel: () => void }) {
  const [kind, setKind] = useState(initial?.kind ?? 'requirement');
  const [title, setTitle] = useState(initial?.title ?? '');
  const [body, setBody] = useState(initial?.body ?? '');
  const [saving, setSaving] = useState(false);
  return (
    <div className="space-y-2 rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-3">
      <select value={kind} onChange={(e) => setKind(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-veil-950 px-2 py-1.5 text-sm text-slate-200">
        {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
      </select>
      {KIND_HINT[kind] && <p className="text-[11px] text-slate-400">{KIND_HINT[kind]}</p>}
      <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} placeholder="Short title"
        className="w-full rounded-lg border border-slate-700 bg-veil-950 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-500" />
      <textarea value={body} onChange={(e) => setBody(e.target.value)} maxLength={4000} rows={3} placeholder="Details (optional)"
        className="w-full resize-y rounded-lg border border-slate-700 bg-veil-950 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-500" />
      <div className="flex gap-2">
        <Button size="sm" disabled={!title.trim() || saving} onClick={async () => { setSaving(true); try { await onSave({ kind, title, body }); } finally { setSaving(false); } }}>
          {saving ? <Spinner /> : <Check size={14} />} Save
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

function MemoryItem({ m, onEdit, onStatus, onDelete }: { m: WbMemory; onEdit: () => void; onStatus: (s: 'active' | 'archived') => void; onDelete: () => void }) {
  const generated = m.kind === 'architecture' && m.source === 'system';
  return (
    <li className="rounded-xl border border-slate-800 bg-veil-950/40 p-3 space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone="cyan">{m.kind}</Badge>
        {m.status === 'unverified' && <Badge tone="amber">AI claim, not confirmed</Badge>}
        {m.source === 'system' && <Badge tone="slate">recorded by the app</Badge>}
        {m.stale.length > 0 && <Badge tone="rose">may be outdated</Badge>}
        {!generated && (
          <div className="ml-auto flex gap-0.5">
            {m.status === 'unverified' && <button title="Confirm this is true" onClick={() => onStatus('active')} className="h-6 w-6 grid place-content-center rounded-md text-emerald-300 hover:bg-emerald-500/10"><Check size={12} /></button>}
            <button title="Edit" onClick={onEdit} className="h-6 w-6 grid place-content-center rounded-md text-slate-400 hover:bg-slate-800"><Pencil size={12} /></button>
            <button title="Archive (Blackveil AI stops using it)" onClick={() => onStatus('archived')} className="h-6 w-6 grid place-content-center rounded-md text-slate-400 hover:bg-slate-800"><Archive size={12} /></button>
            <button title="Delete" onClick={onDelete} className="h-6 w-6 grid place-content-center rounded-md text-rose-300 hover:bg-rose-500/10"><Trash2 size={12} /></button>
          </div>
        )}
      </div>
      <p className="text-sm font-medium text-slate-100">{m.title}</p>
      {m.body && <p className="text-xs leading-relaxed text-slate-400 whitespace-pre-wrap break-words">{m.body}</p>}
      {m.stale.length > 0 && <p className="text-[11px] text-rose-300/80">Changed since this was saved: {m.stale.filter((p) => !p.startsWith('__')).join(', ') || 'the list of files'}</p>}
    </li>
  );
}

function FixItem({ f, onVerify }: { f: WbFix; onVerify: (cause: string, outcome: 'verified' | 'failed') => Promise<void> }) {
  const [cause, setCause] = useState(f.root_cause);
  const [tested, setTested] = useState(false);
  const [busy, setBusy] = useState(false);
  const tone = f.status === 'verified' ? 'green' : f.status === 'failed' ? 'rose' : 'amber';
  const run = async (o: 'verified' | 'failed') => { setBusy(true); try { await onVerify(cause, o); } finally { setBusy(false); } };
  return (
    <li className="rounded-xl border border-slate-800 bg-veil-950/40 p-3 space-y-2 text-xs">
      <div className="flex items-center gap-1.5"><Badge tone={tone}>{f.status === 'hypothesis' ? 'not verified' : f.status}</Badge><span className="text-slate-500">confidence: {f.confidence}</span></div>
      <p className="text-sm text-slate-100">{f.problem}</p>
      {f.fix_summary && <p className="text-slate-400">Fix: {f.fix_summary}</p>}
      {f.evidence && <p className="text-slate-500">Evidence: {f.evidence}</p>}
      {f.limitations && <p className="text-slate-500">{f.limitations}</p>}
      {f.status === 'hypothesis' && (
        <div className="space-y-2 border-t border-slate-800 pt-2">
          <input value={cause} onChange={(e) => setCause(e.target.value)} maxLength={1000} placeholder="Root cause (required to verify)"
            className="w-full rounded-lg border border-slate-700 bg-veil-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-500" />
          <label className="flex items-start gap-2 text-slate-300">
            <input type="checkbox" checked={tested} onChange={(e) => setTested(e.target.checked)} className="mt-0.5" />
            I tested this in the preview and the problem is gone.
          </label>
          <div className="flex gap-2">
            <Button size="sm" disabled={!tested || !cause.trim() || busy} onClick={() => run('verified')}><BadgeCheck size={13} /> Mark verified</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => run('failed')}><X size={13} /> It did not work</Button>
          </div>
        </div>
      )}
    </li>
  );
}

const fmt = (v: number | null, unit = '') => (v === null ? 'not recorded' : `${v}${unit}`);

function StatsColumn({ title, ai, changes }: { title: string; ai: WbAiStats; changes: Record<string, number> }) {
  const rows: [string, string][] = [
    ['AI calls', String(ai.calls)], ['Readable on first try or after repair', fmt(ai.readable_rate, '%')], ['Repair attempts', String(ai.repairs)],
    ['Average time on device', fmt(ai.avg_seconds, 's')], ['Average reply length', fmt(ai.avg_output_tokens, ' tokens')],
    ['Token counts that are estimates', fmt(ai.estimated_token_share, '%')],
    ['Changes applied / rejected / undone', `${changes.applied ?? 0} / ${changes.rejected ?? 0} / ${changes.reverted ?? 0}`],
  ];
  return (
    <div className="rounded-xl border border-slate-800 bg-veil-950/40 p-3">
      <h4 className="mb-2 text-xs uppercase tracking-wider text-slate-500">{title}</h4>
      <dl className="space-y-1.5 text-xs">{rows.map(([k, v]) => <div key={k} className="flex justify-between gap-3"><dt className="text-slate-400">{k}</dt><dd className="text-slate-100 tabular-nums text-right">{v}</dd></div>)}</dl>
    </div>
  );
}

export function MemoryDrawer({ projectId, onClose }: { projectId: string; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>('memory');
  const [memories, setMemories] = useState<WbMemory[] | null>(null);
  const [fixes, setFixes] = useState<WbFix[]>([]);
  const [metrics, setMetrics] = useState<WbMetrics | null>(null);
  const [editing, setEditing] = useState<WbMemory | 'new' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [m, q] = await Promise.all([
        wb<{ memories: WbMemory[]; fixes: WbFix[] }>('list_memories', { project_id: projectId }),
        wb<WbMetrics>('get_ai_metrics', { project_id: projectId }),
      ]);
      setMemories(m.memories); setFixes(m.fixes); setMetrics(q);
    } catch (e) { setError(errText(e)); }
  }, [projectId]);
  useEffect(() => { load(); }, [load]);

  async function call(action: string, payload: Record<string, unknown>) {
    setError(null);
    try { await wb(action, { project_id: projectId, ...payload }); setEditing(null); await load(); } catch (e) { setError(errText(e)); }
  }

  return (
    <Drawer title="Project memory" onClose={onClose} subtitle={<span className="text-xs text-slate-400">What Blackveil AI remembers about your website</span>}>
      <div className="space-y-4">
        <p className="text-xs leading-relaxed text-slate-400">
          These notes are added to Blackveil AI's instructions when they match your request. This is saved memory, not training: the model itself does not change.
          Notes marked as AI claims are ignored until you confirm them.
        </p>
        <div className="flex gap-1 rounded-lg bg-slate-900 p-1">
          {(['memory', 'fixes', 'quality'] as Tab[]).map((t) => (
            <button key={t} onClick={() => setTab(t)} className={`flex-1 rounded-md py-1 text-xs capitalize transition ${tab === t ? 'bg-slate-700 text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>
              {t === 'fixes' ? 'Fix library' : t}
            </button>
          ))}
        </div>
        {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
        {!memories && !error && <div className="flex items-center gap-2 text-sm text-slate-400"><Spinner /> Loading…</div>}

        {memories && tab === 'memory' && (
          <div className="space-y-3">
            {editing === 'new' ? <MemoryForm onCancel={() => setEditing(null)} onSave={(v) => call('save_memory', v)} />
              : <Button size="sm" onClick={() => setEditing('new')}><Plus size={14} /> Add a note</Button>}
            <ul className="space-y-2">
              {memories.map((m) => editing !== 'new' && editing?.id === m.id
                ? <li key={m.id}><MemoryForm initial={m} onCancel={() => setEditing(null)} onSave={(v) => call('update_memory', { memory_id: m.id, ...v })} /></li>
                : <MemoryItem key={m.id} m={m} onEdit={() => setEditing(m)} onStatus={(status) => call('update_memory', { memory_id: m.id, status })}
                    onDelete={() => { if (window.confirm('Delete this note?')) call('delete_memory', { memory_id: m.id }); }} />)}
            </ul>
          </div>
        )}

        {memories && tab === 'fixes' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">Fixes from Debug requests start as not verified. A fix becomes verified only when its change is still applied, the checks pass, a root cause is given, and you confirm you tested it. Rating a message does not verify a fix.</p>
            {fixes.length === 0 && <p className="text-sm text-slate-500">No fixes yet. Apply a change from a Debug request to start the library.</p>}
            <ul className="space-y-2">
              {fixes.map((f) => <FixItem key={f.id} f={f} onVerify={(root_cause, outcome) => call('verify_fix', { fix_id: f.id, root_cause, outcome, owner_tested: outcome === 'verified' })} />)}
            </ul>
          </div>
        )}

        {metrics && tab === 'quality' && (
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <StatsColumn title="Before the upgrade" ai={metrics.baseline.ai} changes={metrics.baseline.changes} />
              <StatsColumn title="Since the upgrade" ai={metrics.current.ai} changes={metrics.current.changes} />
            </div>
            <div className="rounded-xl border border-slate-800 bg-veil-950/40 p-3 text-xs text-slate-400">
              Your ratings: {Object.entries(metrics.feedback).map(([k, v]) => `${k} ${v}`).join(', ') || 'none yet'}. Fix library: {Object.entries(metrics.fixes).map(([k, v]) => `${k === 'hypothesis' ? 'not verified' : k} ${v}`).join(', ') || 'empty'}.
            </div>
            <p className="text-[11px] text-slate-500">{metrics.note}</p>
          </div>
        )}
      </div>
    </Drawer>
  );
}
