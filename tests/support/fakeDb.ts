import type { Row } from './types.ts';

// Minimal in-memory stand-in for the Supabase query builder, covering only what the web-builder
// uses. Copied from tests/pipeline-e2e.test.ts so the execution tests can drive the real server
// code without a database.

export class FakeDb {
  tables: Record<string, Row[]> = {};
  tick = 0;
  rows(t: string) { return (this.tables[t] ??= []); }
  stamp() { return new Date(Date.UTC(2026, 9, 24) + ++this.tick * 1000).toISOString(); }
  from(t: string) { return new Query(this, t); }
}

export class Query implements PromiseLike<{ data: unknown; error: { message: string } | null; count?: number }> {
  private op: 'select' | 'insert' | 'update' | 'upsert' | 'delete' = 'select';
  private cols = '*';
  private head = false;
  private filters: ((r: Row) => boolean)[] = [];
  private sort: { col: string; asc: boolean } | null = null;
  private window: [number, number] | null = null;
  private mode: 'many' | 'single' | 'maybe' = 'many';
  private payload: Row | Row[] = [];
  private conflict: string[] = [];
  private db: FakeDb;
  private table: string;
  constructor(db: FakeDb, table: string) { this.db = db; this.table = table; }

  select(cols = '*', opts?: { head?: boolean }) { this.cols = cols; this.head = !!opts?.head; return this; }
  insert(p: Row | Row[]) { this.op = 'insert'; this.payload = p; return this; }
  update(p: Row) { this.op = 'update'; this.payload = p; return this; }
  upsert(p: Row | Row[], o?: { onConflict?: string }) { this.op = 'upsert'; this.payload = p; this.conflict = (o?.onConflict ?? 'id').split(',').map((s) => s.trim()); return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c: string, v: unknown) { this.filters.push((r) => r[c] === v); return this; }
  neq(c: string, v: unknown) { this.filters.push((r) => r[c] !== v); return this; }
  in(c: string, vs: unknown[]) { this.filters.push((r) => vs.includes(r[c])); return this; }
  gte(c: string, v: string) { this.filters.push((r) => String(r[c]) >= v); return this; }
  filter(c: string, _op: string, v: unknown) { return this.eq(c, v); }
  order(col: string, o?: { ascending?: boolean }) { this.sort = { col, asc: o?.ascending !== false }; return this; }
  limit(n: number) { this.window = [0, n - 1]; return this; }
  range(a: number, b: number) { this.window = [a, b]; return this; }
  single() { this.mode = 'single'; return this; }
  maybeSingle() { this.mode = 'maybe'; return this; }

  then<A, B>(ok?: ((v: { data: unknown; error: { message: string } | null; count?: number }) => A) | null, bad?: ((e: unknown) => B) | null) {
    return Promise.resolve().then(() => this.run()).then(ok, bad);
  }

  private defaults(): Row {
    const now = this.db.stamp();
    const base: Row = { id: crypto.randomUUID(), created_at: now, updated_at: now };
    if (this.table === 'wb_changes') Object.assign(base, { status: 'pending', snapshot_id: null, decided_at: null });
    if (this.table === 'wb_messages') Object.assign(base, { model: null });
    return base;
  }

  private run() {
    const all = this.db.rows(this.table);
    let hit: Row[];
    if (this.op === 'insert') {
      hit = (Array.isArray(this.payload) ? this.payload : [this.payload]).map((p) => ({ ...this.defaults(), ...structuredClone(p) }));
      all.push(...hit);
    } else if (this.op === 'upsert') {
      hit = (Array.isArray(this.payload) ? this.payload : [this.payload]).map((p) => {
        const found = all.find((r) => this.conflict.every((k) => r[k] === p[k]));
        if (found) return Object.assign(found, structuredClone(p));
        const row = { ...this.defaults(), ...structuredClone(p) };
        all.push(row);
        return row;
      });
    } else {
      hit = all.filter((r) => this.filters.every((f) => f(r)));
      if (this.op === 'update') hit.forEach((r) => Object.assign(r, structuredClone(this.payload as Row)));
      if (this.op === 'delete') this.db.tables[this.table] = all.filter((r) => !hit.includes(r));
    }
    if (this.sort) {
      const { col, asc } = this.sort;
      hit = [...hit].sort((a, b) => (String(a[col]) < String(b[col]) ? -1 : String(a[col]) > String(b[col]) ? 1 : 0) * (asc ? 1 : -1));
    }
    if (this.window) hit = hit.slice(this.window[0], this.window[1] + 1);
    if (this.head) return { data: null, error: null, count: hit.length };
    const pick = (r: Row) => (this.cols === '*' ? structuredClone(r) : Object.fromEntries(this.cols.split(',').map((c) => c.trim()).map((c) => [c, structuredClone(r[c])])));
    const data = hit.map(pick);
    if (this.mode === 'single') return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: `expected 1 row, got ${data.length}` } };
    if (this.mode === 'maybe') return { data: data[0] ?? null, error: null };
    return { data, error: null };
  }
}
