import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { isOwner, STATIC_STARTER, type FileMap, type OwnerConfig } from "../_lib/webbuilder.ts";
import { LOCAL_PROVIDER, NeedsLocalAi } from "./ai.ts";
import { chat, continueChange, usageToday } from "./agent.ts";
import { applyChange, checkProject, projectIndex, renameFolder, revertChange } from "./changes.ts";
import { getPublication, publishProject, slugify, unpublishProject } from "./publish.ts";
import { runForSite } from "./site.ts";
import { aiMetrics, deleteMemory, listMemories, rateMessage, saveMemory, updateMemory, verifyFix } from "./learning.ts";
import {
  createProject, ensureSize, HttpError, loadFiles, loadProject, must, path, replaceAllFiles, snapshot, str, uuid, writeFiles,
  type Body, type Svc,
} from "./store.ts";

const CAPABILITIES = {
  preview: "static",
  execution: false,
  execution_reason: "No isolated execution environment is connected, so installs, builds, tests and a terminal are unavailable. Missing dependency: an isolated sandbox runner (for example a container service with resource limits and no access to your secrets). Static cross-file checks still run.",
  deploy: false,
};

async function handle(svc: Svc, action: string, body: Body): Promise<unknown> {
  switch (action) {
    case "access":
      return { owner: true, capabilities: CAPABILITIES };

    case "list_projects":
      return { projects: await must(svc.from("wb_projects").select("*").order("updated_at", { ascending: false })) };

    case "create_project": {
      const starter = body.template === "blank" ? { "index.html": "<!doctype html>\n<html>\n<body>\n</body>\n</html>\n" } : STATIC_STARTER;
      return { project: await createProject(svc, str(body.name, 80), str(body.description, 2000), str(body.kind, 10), starter) };
    }

    case "get_project": {
      const id = uuid(body.project_id);
      const project = await loadProject(svc, id);
      const [files, messages, changes, snapshots, publication, feedback] = await Promise.all([
        loadFiles(svc, id),
        must(svc.from("wb_messages").select("*").eq("project_id", id).order("created_at", { ascending: false }).limit(200)).then((rows) => (rows as unknown[]).reverse()),
        must(svc.from("wb_changes").select("*").eq("project_id", id).order("created_at", { ascending: false }).limit(30)),
        must(svc.from("wb_snapshots").select("id, label, created_at").eq("project_id", id).order("created_at", { ascending: false })),
        getPublication(svc, id),
        must(svc.from("wb_feedback").select("message_id, rating").eq("project_id", id).order("created_at", { ascending: false }).limit(300)),
      ]);
      return { project, files, messages, changes, snapshots, publication, feedback, suggested_slug: slugify(project.name) };
    }

    case "update_project": {
      const id = uuid(body.project_id);
      await loadProject(svc, id);
      const name = str(body.name, 80).trim();
      if (!name) throw new HttpError(400, "Project name is required.");
      return { project: await must(svc.from("wb_projects").update({ name, description: str(body.description, 2000), updated_at: new Date().toISOString() }).eq("id", id).select("*").single()) };
    }

    case "delete_project": {
      const id = uuid(body.project_id);
      const p = await loadProject(svc, id);
      if (body.confirm_name !== p.name) throw new HttpError(400, "Type the project name exactly to confirm deletion.");
      await must(svc.from("wb_projects").delete().eq("id", id));
      return { deleted: true };
    }

    case "write_file": {
      const id = uuid(body.project_id);
      const p = path(body.path);
      if (typeof body.content !== "string") throw new HttpError(400, "Content must be text.");
      const files = await loadFiles(svc, id);
      if (body.create === true && p in files) throw new HttpError(409, "A file with that name already exists.");
      if (files[p] === body.content) return { saved: true, unchanged: true };
      ensureSize({ ...files, [p]: body.content });
      if (p in files) await snapshot(svc, id, `Before editing ${p}`);
      await writeFiles(svc, id, { [p]: body.content });
      return { saved: true };
    }

    case "rename_file": {
      const id = uuid(body.project_id);
      const from = path(body.from);
      const to = path(body.to);
      const files = await loadFiles(svc, id);
      if (!(from in files)) throw new HttpError(404, "File not found.");
      if (to in files) throw new HttpError(409, "A file with that name already exists.");
      await snapshot(svc, id, `Before renaming ${from}`);
      await writeFiles(svc, id, { [to]: files[from] }, [from]);
      return { renamed: true };
    }

    case "delete_file": {
      const id = uuid(body.project_id);
      const p = path(body.path);
      const files = await loadFiles(svc, id);
      if (!(p in files)) throw new HttpError(404, "File not found.");
      await snapshot(svc, id, `Before deleting ${p}`);
      await writeFiles(svc, id, {}, [p]);
      return { deleted: true };
    }

    case "create_snapshot": {
      const id = uuid(body.project_id);
      await loadProject(svc, id);
      return { snapshot_id: await snapshot(svc, id, str(body.label, 120) || "Manual checkpoint") };
    }

    case "restore_snapshot": {
      const id = uuid(body.project_id);
      const snapId = uuid(body.snapshot_id);
      const snap = await must(svc.from("wb_snapshots").select("files").eq("id", snapId).eq("project_id", id).maybeSingle()) as { files: FileMap } | null;
      if (!snap) throw new HttpError(404, "Snapshot not found.");
      await snapshot(svc, id, "Before restoring a snapshot");
      await replaceAllFiles(svc, id, snap.files);
      return { restored: true, files: await loadFiles(svc, id) };
    }

    case "chat":
      return await chat(svc, body);

    case "continue_change":
      return await continueChange(svc, body);

    case "apply_change":
      return await applyChange(svc, body);

    case "revert_change":
      return await revertChange(svc, body);

    case "check_project":
      return await checkProject(svc, body);

    case "get_project_index":
      return await projectIndex(svc, body);

    case "rename_folder":
      return await renameFolder(svc, body);

    case "publish_project":
      return await publishProject(svc, body);

    case "unpublish_project":
      return await unpublishProject(svc, body);

    case "reject_change": {
      const id = uuid(body.change_id);
      const ch = await must(svc.from("wb_changes").select("status").eq("id", id).maybeSingle()) as { status: string } | null;
      if (!ch) throw new HttpError(404, "Change not found.");
      if (ch.status !== "pending") throw new HttpError(409, `Change is already ${ch.status}.`);
      await must(svc.from("wb_changes").update({ status: "rejected", decided_at: new Date().toISOString() }).eq("id", id));
      return { rejected: true };
    }

    case "export_project": {
      const id = uuid(body.project_id);
      const p = await loadProject(svc, id);
      return { format: "blackveil-web-builder/v1", name: p.name, description: p.description, kind: p.kind, files: await loadFiles(svc, id) };
    }

    case "import_project": {
      const raw = body.files;
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new HttpError(400, "Import must contain a files object.");
      const files: FileMap = {};
      for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof v !== "string") throw new HttpError(400, `File ${k} is not text.`);
        files[path(k)] = v;
      }
      return { project: await createProject(svc, str(body.name, 80) || "Imported project", str(body.description, 2000), str(body.kind, 10), files) };
    }

    case "get_ai_settings": {
      const cfg = await must(svc.from("wb_config").select("ai_provider").eq("id", 1).single()) as { ai_provider: string };
      return { settings: cfg, usage: { today: await usageToday(svc, LOCAL_PROVIDER) } };
    }

    case "set_ai_settings": {
      const choice = body.provider;
      if (choice !== "none" && choice !== "local") throw new HttpError(400, "Unknown provider.");
      await must(svc.from("wb_config").update({ ai_provider: choice, paid_ai_approved: false, updated_at: new Date().toISOString() }).eq("id", 1));
      return { settings: { ai_provider: choice } };
    }

    case "list_memories":
      return await listMemories(svc, body);

    case "save_memory":
      return await saveMemory(svc, body);

    case "update_memory":
      return await updateMemory(svc, body);

    case "delete_memory":
      return await deleteMemory(svc, body);

    case "verify_fix":
      return await verifyFix(svc, body);

    case "rate_message":
      return await rateMessage(svc, body);

    case "get_ai_metrics":
      return await aiMetrics(svc, body);

    case "run_command":
    case "build":
    case "deploy":
      throw new HttpError(501, CAPABILITIES.execution_reason);

    default:
      throw new HttpError(400, "Unknown action.");
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  try {
    if (req.method !== "POST") return errorResponse("Method not allowed.", 405);
    const { user } = await getAuthenticatedUser(req);
    if (!user) return errorResponse("Authentication required.", 401);
    const svc = getServiceClient();
    const { data: cfg, error } = await svc.from("wb_config").select("owner_email, owner_user_id").eq("id", 1).maybeSingle();
    if (error || !isOwner(user, cfg as OwnerConfig | null)) return errorResponse("Access denied.", 403);

    let body: Body;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid request body.", 400);
    }
    if (!body || typeof body !== "object") return errorResponse("Invalid request body.", 400);
    return json(await runForSite(svc, str(body.action, 40), body, (a, b) => handle(svc, a, b)));
  } catch (e) {
    if (e instanceof NeedsLocalAi) return json({ needs_local_ai: e.request });
    if (e instanceof HttpError) return errorResponse(e.message, e.status);
    console.error("web-builder error", e);
    return errorResponse("Internal error.", 500);
  }
});
