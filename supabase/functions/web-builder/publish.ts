import { checkConsistency, findSecrets } from "../_lib/projectIndex.ts";
import { buildPreview } from "../_lib/sitebuild.ts";
import { HttpError, loadFiles, loadProject, must, snapshot, str, uuid, type Body, type Svc } from "./store.ts";

const SLUG = /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/;
const MAX_BYTES = 5_000_000;
const COLUMNS = "project_id, slug, entry, title, published_at";

export function slugify(name: string): string {
  const s = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  return s.length >= 3 ? s : `site-${s || "web"}`;
}

export async function getPublication(svc: Svc, projectId: string) {
  return await must(svc.from("wb_publications").select(COLUMNS).eq("project_id", projectId).maybeSingle());
}

export async function publishProject(svc: Svc, body: Body) {
  const id = uuid(body.project_id);
  const project = await loadProject(svc, id);
  if (body.confirm !== true) throw new HttpError(400, "Confirm that you want this website to be public.");
  const slug = str(body.slug, 48).trim().toLowerCase();
  if (!SLUG.test(slug)) throw new HttpError(400, "The address must be 3-48 characters: lowercase letters, numbers and dashes, not starting or ending with a dash.");

  const files = await loadFiles(svc, id);
  if (!("index.html" in files)) throw new HttpError(422, "Your project needs an index.html home page before it can be published.");

  const pages: Record<string, string> = {};
  const missing = new Set<string>();
  let bytes = 0;
  for (const p of Object.keys(files).filter((f) => /\.html?$/i.test(f)).sort()) {
    const built = buildPreview(files, p);
    if (!built) continue;
    const secrets = findSecrets(built.html);
    if (secrets.length) throw new HttpError(422, `Publishing stopped: ${p} contains what looks like a secret (${secrets.join(", ")}). Remove it first, because published pages are public.`);
    built.missing.forEach((m) => missing.add(m));
    pages[p] = built.html;
    bytes += built.html.length;
  }
  if (bytes > MAX_BYTES) throw new HttpError(413, "The website is too large to publish (over 5 MB of pages).");

  const taken = await must(svc.from("wb_publications").select("project_id").eq("slug", slug).maybeSingle()) as { project_id: string } | null;
  if (taken && taken.project_id !== id) throw new HttpError(409, "That address is already used by another of your websites.");

  const snapshotId = await snapshot(svc, id, "Before publishing");
  const publication = await must(svc.from("wb_publications").upsert(
    { project_id: id, slug, pages, entry: "index.html", title: project.name, published_at: new Date().toISOString() },
    { onConflict: "project_id" },
  ).select(COLUMNS).single());

  return {
    publication,
    snapshot_id: snapshotId,
    pages: Object.keys(pages),
    missing: [...missing],
    checks: checkConsistency(files, project.kind),
  };
}

export async function unpublishProject(svc: Svc, body: Body) {
  const id = uuid(body.project_id);
  await loadProject(svc, id);
  await must(svc.from("wb_publications").delete().eq("project_id", id));
  return { unpublished: true };
}
