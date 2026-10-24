import { ReactNode } from 'react';
import { FlaskConical, Radar, ShieldCheck, ShieldAlert, ShieldQuestion } from 'lucide-react';
import { Honeypot } from '@/lib/sentinel';

export function SimulatedBadge({ simulated }: { simulated: boolean }) {
  return simulated ? (
    <span className="inline-flex items-center gap-1 rounded-md border border-amber-400/30 bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-300">
      <FlaskConical size={11} /> Simulated
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-md border border-rose-400/40 bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-rose-200">
      <Radar size={11} /> Real detection
    </span>
  );
}

/** Never shows a protective/verified state unless the server recorded a passing health check. */
export function HealthBadge({ hp }: { hp: Honeypot }) {
  if (hp.status === 'retired') {
    return <Pill className="border-slate-600/50 bg-slate-700/30 text-slate-400" icon={<ShieldQuestion size={12} />}>Retired</Pill>;
  }
  if (hp.status === 'stopped') {
    return <Pill className="border-slate-600/50 bg-slate-700/30 text-slate-300" icon={<ShieldQuestion size={12} />}>Stopped</Pill>;
  }
  if (hp.status === 'active' && hp.last_health_status === 'healthy' && hp.verified_at) {
    return <Pill className="border-emerald-500/40 bg-emerald-500/10 text-emerald-300" icon={<ShieldCheck size={12} />}>Verified healthy</Pill>;
  }
  if (hp.status === 'failed') {
    return <Pill className="border-rose-500/40 bg-rose-500/10 text-rose-300" icon={<ShieldAlert size={12} />}>Failed</Pill>;
  }
  if (hp.last_health_status === 'unhealthy') {
    return <Pill className="border-rose-500/40 bg-rose-500/10 text-rose-300" icon={<ShieldAlert size={12} />}>Health check failed</Pill>;
  }
  if (hp.status === 'deploying') {
    return <Pill className="border-cyan-400/30 bg-cyan-400/10 text-cyan-300" icon={<ShieldQuestion size={12} />}>Deploying</Pill>;
  }
  return <Pill className="border-slate-600/50 bg-slate-700/30 text-slate-300" icon={<ShieldQuestion size={12} />}>Unverified</Pill>;
}

function Pill({ children, icon, className }: { children: ReactNode; icon: ReactNode; className: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${className}`}>
      {icon}
      {children}
    </span>
  );
}
