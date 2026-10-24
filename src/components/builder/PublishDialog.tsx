import { useState } from 'react';
import { Button, Drawer, ErrorBanner, Input } from '@/components/ui';
import { wb, errText, publicSiteUrl, WbProjectData, WbPublishResult } from '@/lib/builder';
import { CheckList } from '@/components/builder/ChangeReview';
import { AlertTriangle, Check, Copy, ExternalLink, Globe, Rocket } from 'lucide-react';

export function PublishDialog({ data, onClose, onChanged }: {
  data: WbProjectData;
  onClose: () => void;
  onChanged: () => Promise<unknown>;
}) {
  const live = data.publication;
  const [slug, setSlug] = useState(live?.slug ?? data.suggested_slug);
  const [agree, setAgree] = useState(false);
  const [busy, setBusy] = useState<'publish' | 'unpublish' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WbPublishResult | null>(null);
  const [copied, setCopied] = useState(false);
  const hasHome = 'index.html' in data.files;
  const url = live ? publicSiteUrl(live.slug) : null;

  async function publish() {
    setBusy('publish');
    setError(null);
    try {
      const r = await wb<WbPublishResult>('publish_project', { project_id: data.project.id, slug, confirm: true });
      setResult(r);
      setAgree(false);
      await onChanged();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(null);
    }
  }

  async function unpublish() {
    if (!window.confirm('Take this website offline? The public link will stop working until you publish again.')) return;
    setBusy('unpublish');
    setError(null);
    try {
      await wb('unpublish_project', { project_id: data.project.id });
      setResult(null);
      await onChanged();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(null);
    }
  }

  async function copy() {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError('Could not copy the link. Select it and copy it manually.');
    }
  }

  const problems = result?.checks.filter((c) => !c.ok && !c.warn) ?? [];

  return (
    <Drawer title="Publish website" subtitle="Put your website online at a public link" onClose={onClose}>
      <div className="space-y-5">
        {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

        {live && url ? (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-3">
            <div className="flex items-center gap-2 text-sm font-medium text-emerald-200">
              <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60 animate-ping" /><span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" /></span>
              Live
              <span className="ml-auto text-[11px] font-normal text-slate-400">Updated {new Date(live.published_at).toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-veil-950/70 border border-slate-800 px-3 py-2">
              <Globe size={14} className="text-slate-500 shrink-0" />
              <span className="font-mono text-xs text-slate-200 truncate select-all">{url}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-sm font-medium text-veil-950 hover:bg-emerald-400 transition"><ExternalLink size={14} /> Open website</a>
              <Button size="sm" variant="secondary" onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy link'}</Button>
              <Button size="sm" variant="ghost" onClick={unpublish} loading={busy === 'unpublish'}>Unpublish</Button>
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-800 bg-veil-950/40 p-4 flex items-start gap-3">
            <div className="h-9 w-9 rounded-lg bg-cyan-500/10 text-cyan-300 grid place-content-center shrink-0"><Rocket size={17} /></div>
            <p className="text-sm leading-relaxed text-slate-300">Your website is not published yet. Choose an address below and publish to get a link anyone can visit.</p>
          </div>
        )}

        {result && (
          <div className="space-y-3 fade-up">
            <p className="text-sm text-slate-300">Published {result.pages.length} page{result.pages.length === 1 ? '' : 's'}: <span className="font-mono text-xs text-slate-400">{result.pages.join(', ')}</span></p>
            {result.missing.length > 0 && (
              <p className="text-xs text-amber-200">Some referenced files do not exist and will not load: <span className="font-mono">{result.missing.join(', ')}</span></p>
            )}
            {problems.length > 0 && <CheckList checks={result.checks} title="Site checks" />}
          </div>
        )}

        <div className="space-y-3">
          <label className="block text-xs font-medium uppercase tracking-wider text-slate-500">Website address</label>
          <Input value={slug} maxLength={48} onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-'))} />
          <p className="font-mono text-[11px] text-slate-500 break-all">{publicSiteUrl(slug || 'your-site')}</p>
        </div>

        {!hasHome && <p className="flex items-start gap-2 text-sm text-amber-200"><AlertTriangle size={15} className="mt-0.5 shrink-0" /> Add an index.html home page before publishing.</p>}

        <ul className="space-y-1.5 text-xs leading-relaxed text-slate-400 list-disc pl-4">
          <li>Publishing copies your saved pages. Later edits stay private until you publish again.</li>
          <li>Every HTML page with its styles and scripts goes live. Server code and databases are not run.</li>
          <li>For visitor safety, published pages run in a protected frame, so features that rely on browser storage or cookies may not work.</li>
          <li>A restore point is saved each time you publish.</li>
        </ul>

        <label className="flex items-start gap-2.5 text-sm text-slate-300 cursor-pointer">
          <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} className="mt-1 accent-cyan-400" />
          I understand this website will be visible to anyone with the link.
        </label>

        <Button full onClick={publish} loading={busy === 'publish'} disabled={!agree || !hasHome || slug.length < 3 || busy !== null}>
          <Rocket size={15} /> {live ? 'Publish latest changes' : 'Publish website'}
        </Button>
      </div>
    </Drawer>
  );
}
