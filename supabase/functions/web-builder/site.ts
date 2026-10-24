import { HttpError, uuid, type Body, type Svc } from "./store.ts";

type Run = (action: string, body: Body) => Promise<unknown>;

const BLOCKED = new Set(["create_project", "delete_project", "import_project"]);

async function siteId(svc: Svc, run: Run): Promise<string> {
  const { data, error } = await svc.from("wb_config").select("site_project_id").eq("id", 1).maybeSingle();
  if (error) throw error;
  const id = (data as { site_project_id: string | null } | null)?.site_project_id;
  if (id) return id;
  const created = await run("create_project", { name: "My Website" }) as { project: { id: string } };
  const { error: pinErr } = await svc.from("wb_config").update({ site_project_id: created.project.id }).eq("id", 1);
  if (pinErr) throw pinErr;
  return created.project.id;
}

// Every request from the browser is confined to the owner's single website.
export async function runForSite(svc: Svc, action: string, body: Body, run: Run): Promise<unknown> {
  if (BLOCKED.has(action)) throw new HttpError(403, "The Web Builder only edits your website.");
  const site = await siteId(svc, run);

  if (action === "list_projects") {
    const { data, error } = await svc.from("wb_projects").select("*").eq("id", site);
    if (error) throw error;
    return { projects: data ?? [] };
  }

  if (body.project_id !== undefined && uuid(body.project_id) !== site) {
    throw new HttpError(403, "The Web Builder only edits your website.");
  }
  if (body.change_id !== undefined) {
    const { data, error } = await svc.from("wb_changes").select("project_id").eq("id", uuid(body.change_id)).maybeSingle();
    if (error) throw error;
    if (!data || (data as { project_id: string }).project_id !== site) throw new HttpError(404, "Change not found.");
  }
  return await run(action, body);
}
