import { useEffect, useState } from 'react';
import { wb, errText, WbProject } from '@/lib/builder';
import { LocalAiProvider } from '@/lib/localAi/LocalAiContext';
import { Workspace } from '@/components/builder/Workspace';
import { BlackveilAiPanel } from '@/components/builder/BlackveilAiPanel';
import { ErrorBanner, ErrorBoundary, Spinner } from '@/components/ui';

async function openWebsite(): Promise<string> {
  const { projects } = await wb<{ projects: WbProject[] }>('list_projects');
  if (!projects?.length) throw new Error('Your website could not be found.');
  return projects[0].id;
}

export default function WebBuilder() {
  const [projectId, setProjectId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAi, setShowAi] = useState(false);

  useEffect(() => {
    openWebsite().then(setProjectId, (e) => setError(errText(e)));
  }, []);

  return (
    <LocalAiProvider>
      {projectId ? <ErrorBoundary label="Web Builder"><Workspace projectId={projectId} onAiSettings={() => setShowAi(true)} /></ErrorBoundary>
        : error ? <ErrorBanner message={error} />
        : <div className="flex items-center gap-2 text-sm text-slate-400"><Spinner /> Opening your website…</div>}
      {showAi && <ErrorBoundary label="Blackveil AI settings"><BlackveilAiPanel onClose={() => setShowAi(false)} /></ErrorBoundary>}
    </LocalAiProvider>
  );
}
