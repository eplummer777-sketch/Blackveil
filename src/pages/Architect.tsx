import { useCallback, useEffect, useState } from 'react';
import { Cloud, EyeOff, FlaskConical, FolderKanban, ShieldAlert, UserCheck, Wand2 } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { ErrorBanner, Spinner } from '@/components/ui';
import { ArchitectProject, callArchitect } from '@/lib/architect';
import { Intake } from '@/components/architect/Intake';
import { Workspace } from '@/components/architect/Workspace';
import { CloudflarePanel } from '@/components/architect/CloudflarePanel';

const PRINCIPLES = [
  { icon: EyeOff, title: 'Never runs anything', text: 'Architect only writes proposals. It cannot connect to or execute commands on your devices.' },
  { icon: FlaskConical, title: 'Sandbox = static checks', text: '"Tested" means the file passed safety and syntax analysis. It was not run on a real system.' },
  { icon: UserCheck, title: 'You stay in control', text: 'Every change needs your approval, and you apply it yourself. Statuses reflect only what really happened.' },
  { icon: ShieldAlert, title: 'Not complete protection', text: 'A plan reduces specific risks. No tool can make a device or account fully secure.' },
];

export function Architect() {
  const { session, user } = useAuth();
  const token = session?.access_token ?? '';
  const [projects, setProjects] = useState<ArchitectProject[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [view, setView] = useState<'projects' | 'cloudflare'>('projects');

  const load = useCallback(async () => {
    if (!user) return;
    const { data, error: err } = await supabase
      .from('architect_projects')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });
    setLoaded(true);
    if (err) { setError('Could not load your Architect projects. Try refreshing the page.'); return; }
    setProjects((data ?? []) as ArchitectProject[]);
  }, [user]);

  useEffect(() => { load(); }, [load]);

  async function create(description: string) {
    setCreating(true);
    setError(null);
    const res = await callArchitect<{ project: ArchitectProject }>(token, { action: 'create_project', description });
    setCreating(false);
    if (!res.ok) { setError(res.error); return; }
    const project = res.data?.project;
    if (!project?.id) { setError('The project was created but could not be opened. Try refreshing.'); return; }
    setProjects((p) => [project, ...p]);
    setOpenId(project.id);
  }

  const open = projects.find((p) => p.id === openId) ?? null;
  const showCloudflare = view === 'cloudflare' && !open;

  return (
    <div className="space-y-6 fade-in">
      <header>
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-cyan-300/80 font-mono-tight">
          <Wand2 size={13} /> AI security builder
        </div>
        <h1 className="mt-1 text-2xl md:text-3xl font-semibold tracking-tight">
          <span className="text-slate-50">Blackveil </span><span className="text-gradient">Architect</span>
        </h1>
        <p className="mt-1 text-sm text-slate-400 max-w-2xl">
          Describe what you want to protect. Get a tailored plan with ready-to-use settings, firewall rules and scripts, each tested in a safe sandbox and released only with your approval.
        </p>
      </header>

      {!open && (
        <nav className="flex gap-1 rounded-xl border border-slate-800 bg-veil-900/60 p-1 w-fit">
          <button
            onClick={() => setView('projects')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm transition ${view === 'projects' ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/30' : 'text-slate-400 hover:text-slate-200 hover:bg-veil-800/60'}`}
          >
            <FolderKanban size={15} /> Projects
          </button>
          <button
            onClick={() => setView('cloudflare')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm transition ${view === 'cloudflare' ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/30' : 'text-slate-400 hover:text-slate-200 hover:bg-veil-800/60'}`}
          >
            <Cloud size={15} /> Cloudflare
          </button>
        </nav>
      )}

      {view === 'projects' && !open && (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {PRINCIPLES.map((p) => (
            <div key={p.title} className="rounded-xl border border-slate-800/80 bg-veil-900/40 p-4 hover:border-cyan-500/30 transition">
              <p.icon size={16} className="text-cyan-300" />
              <p className="mt-2 text-sm font-medium text-slate-200">{p.title}</p>
              <p className="mt-1 text-xs text-slate-500 leading-relaxed">{p.text}</p>
            </div>
          ))}
        </div>
      )}

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {showCloudflare ? (
        <CloudflarePanel />
      ) : !loaded ? (
        <div className="flex justify-center py-20"><Spinner /></div>
      ) : open ? (
        <Workspace
          key={open.id}
          project={open}
          token={token}
          onBack={() => { setOpenId(null); load(); }}
          onProjectUpdated={(p) => setProjects((list) => list.map((x) => (x.id === p.id ? p : x)))}
        />
      ) : (
        <Intake projects={projects} creating={creating} onCreate={create} onOpen={setOpenId} />
      )}
    </div>
  );
}
