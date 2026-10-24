import { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { AuthProvider, useAuth } from '@/lib/auth';
import { AuthPage } from '@/pages/AuthPage';
import { AppShell, Route } from '@/components/AppShell';
import { Dashboard } from '@/pages/Dashboard';
import { Assessments } from '@/pages/Assessments';
import { Assistant } from '@/pages/Assistant';
import { Reports } from '@/pages/Reports';
import { Device } from '@/pages/Device';
import { Settings } from '@/pages/Settings';
import { Admin } from '@/pages/Admin';
import { Malware } from '@/pages/Malware';
import { Tools } from '@/pages/Tools';
import { Sentinel } from '@/pages/Sentinel';
import { Architect } from '@/pages/Architect';
import { AssessmentEngine } from '@/pages/AssessmentEngine';
import { ProofOfBreach } from '@/pages/ProofOfBreach';
import { Limitations } from '@/pages/Limitations';
import { NetworkScan } from '@/pages/NetworkScan';
import { Pentest } from '@/pages/Pentest';
import { BlackveilOS } from '@/pages/BlackveilOS';
import { Logo, Spinner } from '@/components/ui';
import { Plan } from '@/lib/types';
import { OpenTarget, openTargetFrom } from '@/lib/push';
import { CheckCircle2, Loader2, AlertCircle } from 'lucide-react';
import { wb, WbCapabilities } from '@/lib/builder';

const WebBuilder = lazy(() => import('@/pages/WebBuilder'));

function Gate() {
  const { user, loading, refreshSubscription, plan, isAdmin } = useAuth();
  const [builder, setBuilder] = useState<WbCapabilities | null>(null);
  const [route, setRoute] = useState<Route>('dashboard');
  const [notice, setNotice] = useState<string | null>(null);
  const [activated, setActivated] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const initialPlanRef = useRef<Plan | null>(null);
  const [deepLink, setDeepLink] = useState<{ target: OpenTarget; at: number } | null>(() => {
    const target = openTargetFrom(window.location.href);
    return target ? { target, at: Date.now() } : null;
  });

  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;
    const onMessage = (e: MessageEvent) => {
      if (e.data?.type !== 'blackveil-open') return;
      const target = openTargetFrom(e.data.url);
      if (target) setDeepLink({ target, at: Date.now() });
    };
    navigator.serviceWorker.addEventListener('message', onMessage);
    return () => navigator.serviceWorker.removeEventListener('message', onMessage);
  }, []);

  useEffect(() => {
    if (!user || !deepLink) return;
    const params = new URLSearchParams(window.location.search);
    if (params.has('open')) {
      params.delete('open');
      const qs = params.toString();
      window.history.replaceState({}, document.title, window.location.pathname + (qs ? `?${qs}` : '') + window.location.hash);
    }
    setRoute('malware');
  }, [user, deepLink]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const status = params.get('checkout');
    if (!status) return;

    const cleanUrl = window.location.pathname + window.location.hash;
    window.history.replaceState({}, document.title, cleanUrl);

    if (status === 'success') {
      setNotice('Payment received — activating your subscription…');
      initialPlanRef.current = plan;
    } else if (status === 'returned') {
      setNotice('Checking your subscription status…');
    } else if (status === 'canceled') {
      setNotice('Checkout was canceled. No charge was made.');
      setTimeout(() => setNotice(null), 5000);
      return;
    }

    let attempts = 0;
    const maxAttempts = 10;
    const poll = async () => {
      attempts++;
      await refreshSubscription();
      if (attempts >= maxAttempts) {
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        setNotice(null);
      }
    };
    poll();
    pollRef.current = setInterval(poll, 2500);
    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshSubscription]);

  // When the plan changes after checkout, confirm activation and stop polling.
  useEffect(() => {
    if (notice && initialPlanRef.current !== null && plan !== initialPlanRef.current && plan !== 'free') {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      setNotice(`Your ${plan === 'elite' ? 'Elite' : plan === 'pro' ? 'Pro' : 'Malware Removal'} subscription is now active. All premium features are unlocked.`);
      setActivated(true);
      setTimeout(() => { setNotice(null); setActivated(false); }, 6000);
    }
  }, [plan, notice]);

  useEffect(() => {
    setBuilder(null);
    if (!user || !isAdmin) return;
    let live = true;
    wb<{ owner: boolean; capabilities: WbCapabilities }>('access')
      .then((d) => { if (live && d.owner === true) setBuilder(d.capabilities); })
      .catch(() => {});
    return () => { live = false; };
  }, [user, isAdmin]);

  useEffect(() => {
    if (route === 'web-builder' && !builder) setRoute('dashboard');
  }, [route, builder]);

  if (loading) {
    return (
      <div className="min-h-screen grid-bg flex flex-col items-center justify-center gap-3">
        <div className="radial-fade absolute inset-0 pointer-events-none" />
        <Logo size={40} />
        <div className="flex items-center gap-2 text-slate-400 text-sm">
          <Spinner className="text-cyan-300" /> Initializing secure workspace…
        </div>
      </div>
    );
  }

  if (!user) return <AuthPage initial="signin" />;

  return (
    <AppShell route={route} onNavigate={setRoute} showBuilder={!!builder}>
      {notice && (
        <div className={`mb-4 rounded-lg border p-3.5 flex items-center gap-3 fade-up ${
          activated
            ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
            : notice.includes('canceled')
              ? 'border-amber-500/40 bg-amber-500/10 text-amber-200'
              : 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
        }`}>
          {activated ? <CheckCircle2 size={18} className="shrink-0" /> :
           notice.includes('canceled') ? <AlertCircle size={18} className="shrink-0" /> :
           <Loader2 size={18} className="shrink-0 animate-spin" />}
          <span className="text-sm">{notice}</span>
        </div>
      )}
      {route === 'dashboard'   && <Dashboard onNavigate={setRoute} />}
      {route === 'assessments' && <Assessments />}
      {route === 'assistant'   && <Assistant onNavigate={setRoute} />}
      {route === 'reports'     && <Reports />}
      {route === 'device'      && <Device />}
      {route === 'malware'     && <Malware key={deepLink?.at} open={deepLink?.target} />}
      {route === 'tools'       && <Tools onNavigate={setRoute} />}
      {route === 'settings'    && <Settings onNavigate={setRoute} />}
      {route === 'admin'       && <Admin />}
      {route === 'architect'   && <Architect />}
      {route === 'assessment-engine' && <AssessmentEngine />}
      {route === 'proof-of-breach' && <ProofOfBreach onNavigate={setRoute} />}
      {route === 'network-scan' && <NetworkScan onNavigate={setRoute} />}
      {route === 'pentest' && <Pentest onNavigate={setRoute} />}
      {route === 'sentinel'    && <Sentinel onNavigate={setRoute} />}
      {route === 'limitations' && <Limitations onNavigate={setRoute} />}
      {route === 'blackveil-os' && <BlackveilOS onNavigate={setRoute} />}
      {route === 'web-builder' && builder && (
        <Suspense fallback={<div className="flex items-center gap-2 text-sm text-slate-400"><Spinner className="text-cyan-300" /> Loading Web Builder…</div>}>
          <WebBuilder />
        </Suspense>
      )}
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  );
}
