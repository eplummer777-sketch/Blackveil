import { resolveLocal } from '@/lib/builderTools';

type Site = { title: string; entry: string; pages: Record<string, string> };

const status = document.getElementById('status') as HTMLDivElement;
const params = new URLSearchParams(location.search);
const slug = params.get('s') ?? '';

function fail(title: string, detail: string) {
  document.title = title;
  status.replaceChildren();
  const box = document.createElement('div');
  const h = document.createElement('h1');
  h.textContent = title;
  const p = document.createElement('p');
  p.textContent = detail;
  box.append(h, p);
  status.append(box);
  status.style.display = 'flex';
}

function isSite(v: unknown): v is Site {
  const s = v as Site;
  return !!s && typeof s.entry === 'string' && typeof s.pages === 'object' && s.pages !== null && typeof s.pages[s.entry] === 'string';
}

async function load(): Promise<Site | null> {
  if (!/^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(slug)) return null;
  const res = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/web-publish?slug=${encodeURIComponent(slug)}`, {
    headers: { apikey: import.meta.env.VITE_SUPABASE_ANON_KEY },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(String(res.status));
  const data: unknown = await res.json();
  if (!isSite(data)) throw new Error('bad response');
  return data;
}

function start(site: Site) {
  const frame = document.createElement('iframe');
  frame.id = 'site';
  frame.title = site.title || 'Website';
  frame.setAttribute('sandbox', 'allow-scripts allow-forms allow-popups allow-modals allow-popups-to-escape-sandbox');
  document.body.append(frame);
  status.style.display = 'none';

  const show = (page: string) => {
    const html = site.pages[page];
    frame.srcdoc = html;
    const t = /<title[^>]*>([^<]*)<\/title>/i.exec(html)?.[1]?.trim();
    document.title = t || site.title || 'Website';
  };
  const pageFromUrl = () => {
    const p = new URLSearchParams(location.search).get('p');
    return p && p in site.pages ? p : site.entry;
  };
  let current = pageFromUrl();
  show(current);

  window.addEventListener('message', (e) => {
    if (e.source !== frame.contentWindow || !e.data || e.data.bv !== 1 || e.data.type !== 'nav') return;
    const target = resolveLocal(String(e.data.href), current);
    if (!target) return;
    const page = target in site.pages ? target : `${target.replace(/\/$/, '')}/index.html` in site.pages ? `${target.replace(/\/$/, '')}/index.html` : null;
    if (!page) return;
    current = page;
    const url = new URL(location.href);
    if (page === site.entry) url.searchParams.delete('p'); else url.searchParams.set('p', page);
    history.pushState(null, '', url);
    show(page);
  });
  window.addEventListener('popstate', () => { current = pageFromUrl(); show(current); });
}

load().then(
  (site) => (site ? start(site) : fail('Site not found', 'This website is not published, or the address is wrong.')),
  () => fail('Site unavailable', 'This website could not be loaded right now. Please try again in a moment.'),
);
