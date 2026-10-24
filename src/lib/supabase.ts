import { createClient } from '@supabase/supabase-js';

const url = import.meta.env.VITE_SUPABASE_URL as string;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

if (!url || !anonKey) {
  // eslint-disable-next-line no-console
  console.error('Supabase env missing. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env');
}

export const supabase = createClient(url, anonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});

export const edgeUrl = (slug: string) => `${url}/functions/v1/${slug}`;

export async function callEdge<T = unknown>(
  slug: string,
  body: unknown,
  token: string
): Promise<{ ok: true; data: T } | { ok: false; status: number; error: string }> {
  const resp = await fetch(edgeUrl(slug), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  let parsed: unknown = null;
  try {
    parsed = await resp.json();
  } catch {
    /* ignore */
  }
  if (!resp.ok) {
    const errVal = parsed && typeof parsed === 'object' && 'error' in parsed
      ? String((parsed as Record<string, unknown>).error)
      : null;
    const msg = errVal ?? `Request failed (${resp.status})`;
    return { ok: false, status: resp.status, error: msg };
  }
  return { ok: true, data: parsed as T };
}
