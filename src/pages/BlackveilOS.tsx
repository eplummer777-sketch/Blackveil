import { useEffect, useRef, useState } from 'react';
import {
  AppWindow, TerminalSquare, Gauge, ShieldCheck, Crosshair, Network, ScanSearch,
  Swords, LayoutGrid, X, Minus, Power, Bot, HardDrive,
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { callBv, BvStatus } from '@/lib/bvos';
import { Route } from '@/components/AppShell';
import { OsTerminal } from '@/components/os/Terminal';
import { OsSystemStatus } from '@/components/os/SystemStatus';

type WindowId = 'terminal' | 'status';

interface AppDef {
  id: string;
  label: string;
  desc: string;
  icon: typeof Gauge;
  route: Route;
  accent: string;
  tier?: 'Pro' | 'Elite';
}

const APPS: AppDef[] = [
  { id: 'network', label: 'Network Scanner', desc: 'Host & port discovery', icon: Network, route: 'network-scan', accent: 'text-cyan-300', tier: 'Elite' },
  { id: 'tls', label: 'TLS / Web Audit', desc: 'HTTPS, headers & DNS checks', icon: ShieldCheck, route: 'assessments', accent: 'text-emerald-300' },
  { id: 'webscan', label: 'Web Security', desc: 'Proof-of-Breach scanner', icon: Crosshair, route: 'proof-of-breach', accent: 'text-amber-300', tier: 'Elite' },
  { id: 'pentest', label: 'Penetration Test', desc: 'Native pentest engine', icon: Swords, route: 'pentest', accent: 'text-rose-300', tier: 'Elite' },
  { id: 'assistant', label: 'AI Assistant', desc: 'Ask a security expert', icon: Bot, route: 'assistant', accent: 'text-cyan-200' },
  { id: 'tools', label: 'Security Tools', desc: 'Link, message & QR checks', icon: ScanSearch, route: 'tools', accent: 'text-slate-300' },
];

const TIER_PILL: Record<'Pro' | 'Elite', string> = {
  Pro: 'border-emerald-400/25 bg-emerald-400/10 text-emerald-200',
  Elite: 'border-amber-400/25 bg-amber-400/10 text-amber-200',
};

interface Win {
  id: WindowId;
  title: string;
  icon: typeof Gauge;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  minimized: boolean;
}

export function BlackveilOS({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { session, isAdmin, plan } = useAuth();
  const token = session?.access_token ?? '';
  const [launcherOpen, setLauncherOpen] = useState(true);
  const [status, setStatus] = useState<BvStatus | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [windows, setWindows] = useState<Win[]>(() => [
    { id: 'terminal', title: 'Terminal', icon: TerminalSquare, x: 60, y: 60, w: 720, h: 480, z: 20, minimized: false },
    { id: 'status', title: 'System Status', icon: Gauge, x: 820, y: 80, w: 460, h: 520, z: 10, minimized: true },
  ]);
  const [focus, setFocus] = useState<WindowId | null>('terminal');
  const [drag, setDrag] = useState<{ id: WindowId; offsetX: number; offsetY: number } | null>(null);
  const desktopRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!token) return;
    callBv<BvStatus>(token, { action: 'status' }).then((r) => { if (r.ok) setStatus(r.data ?? null); });
  }, [token]);

  useEffect(() => {
    if (sessionId) {
      setWindows((ws) => ws.map((w) => (w.id === 'terminal' ? { ...w } : w)));
    }
  }, [sessionId]);

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!drag) return;
      setWindows((ws) => ws.map((w) => (w.id === drag.id ? { ...w, x: e.clientX - drag.offsetX, y: e.clientY - drag.offsetY } : w)));
    }
    function onUp() { setDrag(null); }
    if (drag) {
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
      return () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); };
    }
  }, [drag]);

  function focusWindow(id: WindowId) {
    const z = Math.max(...windows.map((w) => w.z)) + 1;
    setWindows((ws) => ws.map((w) => (w.id === id ? { ...w, z, minimized: false } : w)));
    setFocus(id);
  }

  function toggleMinimize(id: WindowId) {
    setWindows((ws) => ws.map((w) => (w.id === id ? { ...w, minimized: !w.minimized } : w)));
    if (focus === id) setFocus(windows.find((w) => w.id !== id && !w.minimized)?.id ?? null);
  }

  function closeWindow(id: WindowId) {
    setWindows((ws) => ws.filter((w) => w.id !== id));
    if (focus === id) setFocus(null);
  }

  const openApp = (route: Route) => {
    setLauncherOpen(false);
    onNavigate(route);
  };

  const workersOnline = status?.workersOnline ?? 0;

  return (
    <div ref={desktopRef} className="relative h-[calc(100vh-7rem)] min-h-[520px] overflow-hidden rounded-2xl border border-slate-800 bg-[#04060a] shadow-2xl select-none">
      {/* desktop backdrop */}
      <div className="pointer-events-none absolute inset-0 opacity-40" style={{
        backgroundImage: 'radial-gradient(circle at 20% 20%, rgba(34,211,238,.08), transparent 40%), radial-gradient(circle at 80% 70%, rgba(148,163,184,.06), transparent 45%)',
      }} />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-cyan-500/[0.04] to-transparent" />

      {/* desktop icons area */}
      <div className="absolute left-4 top-4 grid grid-cols-1 gap-1.5">
        {APPS.slice(0, 5).map((app) => (
          <DesktopIcon key={app.id} app={app} onDouble={() => openApp(app.route)} />
        ))}
      </div>

      {/* windows */}
      {windows.map((w) => (
        <Window
          key={w.id}
          win={w}
          focus={focus === w.id}
          onFocus={() => focusWindow(w.id)}
          onMinimize={() => toggleMinimize(w.id)}
          onClose={() => closeWindow(w.id)}
          onDragStart={(offX, offY) => setDrag({ id: w.id, offsetX: offX, offsetY: offY })}
        >
          {w.id === 'terminal' && <OsTerminal sessionId={sessionId} onSession={setSessionId} />}
          {w.id === 'status' && <OsSystemStatus />}
        </Window>
      ))}

      {/* launcher */}
      {launcherOpen && (
        <div className="absolute bottom-16 left-4 z-50 w-80 rounded-xl border border-slate-700/80 bg-veil-900/95 backdrop-blur-md shadow-2xl overflow-hidden fade-up">
          <div className="border-b border-slate-800 px-4 py-2.5 text-[10px] uppercase tracking-widest text-slate-500">Blackveil OS — Applications</div>
          <div className="p-2 grid grid-cols-3 gap-1.5">
            {APPS.map((app) => {
              const Icon = app.icon;
              return (
                <button
                  key={app.id}
                  onClick={() => openApp(app.route)}
                  className="group flex flex-col items-center gap-1.5 rounded-lg p-2.5 text-center transition hover:bg-cyan-400/10"
                >
                  <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-700 bg-veil-950 text-slate-300 transition group-hover:border-cyan-400/40 group-hover:text-cyan-200">
                    <Icon size={20} />
                  </span>
                  <span className="text-[10px] text-slate-300 leading-tight">{app.label}</span>
                  {app.tier && <span className={`text-[8px] font-semibold uppercase tracking-wider border rounded px-1 py-px ${TIER_PILL[app.tier]}`}>{app.tier}</span>}
                </button>
              );
            })}
          </div>
          <div className="flex items-center gap-2 border-t border-slate-800 px-4 py-2.5">
            <button onClick={() => focusWindow('terminal')} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-700 px-2 py-1.5 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-200 transition">
              <TerminalSquare size={13} /> Terminal
            </button>
            <button onClick={() => focusWindow('status')} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-700 px-2 py-1.5 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-200 transition">
              <Gauge size={13} /> Status
            </button>
          </div>
        </div>
      )}

      {/* taskbar */}
      <div className="absolute inset-x-0 bottom-0 flex h-12 items-center gap-2 border-t border-slate-800 bg-[#090c12]/95 px-3 backdrop-blur-md">
        <button onClick={() => setLauncherOpen(!launcherOpen)} className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition ${launcherOpen ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-slate-700 text-slate-300 hover:border-cyan-400/40 hover:text-cyan-200'}`}>
          <LayoutGrid size={14} /> OS
        </button>

        <div className="mx-1 h-6 w-px bg-slate-800" />

        <div className="flex flex-1 items-center gap-1.5 overflow-x-auto scrollbar-thin">
          {windows.map((w) => {
            const Icon = w.icon;
            const active = focus === w.id && !w.minimized;
            return (
              <button
                key={w.id}
                onClick={() => focusWindow(w.id)}
                className={`flex shrink-0 items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition ${active ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-slate-800 text-slate-400 hover:text-slate-200'}`}
              >
                <Icon size={13} /> {w.title}
                <span className={`ml-1 h-1.5 w-1.5 rounded-full ${w.minimized ? 'bg-slate-600' : 'bg-emerald-400'}`} />
              </button>
            );
          })}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <span className="hidden sm:flex items-center gap-1.5 rounded-lg border border-slate-800 px-2 py-1 text-[10px] text-slate-400">
            <HardDrive size={11} />
            <span className={workersOnline ? 'text-emerald-300' : 'text-amber-300'}>{workersOnline ? `${workersOnline} worker${workersOnline === 1 ? '' : 's'}` : 'offline'}</span>
          </span>
          <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 px-2 py-1 text-[10px] text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> {plan === 'free' ? 'Free' : plan}
          </div>
          <span className="hidden sm:block text-[10px] text-slate-600 font-mono-tight">BV-OS 1.0</span>
          <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-800 text-slate-400">
            <Power size={13} />
          </span>
        </div>
      </div>

      {isAdmin && windows.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="rounded-xl border border-slate-800 bg-veil-900/80 p-6 text-center">
            <AppWindow size={28} className="mx-auto text-cyan-300" />
            <p className="mt-3 text-sm text-slate-200">No windows open</p>
            <p className="mt-1 text-xs text-slate-500">Open Terminal or System Status from the launcher.</p>
          </div>
        </div>
      )}
    </div>
  );
}

function DesktopIcon({ app, onDouble }: { app: AppDef; onDouble: () => void }) {
  const Icon = app.icon;
  return (
    <button
      onDoubleClick={onDouble}
      className="group flex w-24 flex-col items-center gap-1.5 rounded-lg p-2 text-center transition hover:bg-white/5"
      title={`${app.label} — ${app.desc}`}
    >
      <span className="flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-veil-900/70 shadow-lg transition group-hover:border-cyan-400/40">
        <Icon size={22} className={app.accent} />
      </span>
      <span className="text-[10px] leading-tight text-slate-300">{app.label}</span>
    </button>
  );
}

function Window({
  win, focus, onFocus, onMinimize, onClose, onDragStart, children,
}: {
  win: Win;
  focus: boolean;
  onFocus: () => void;
  onMinimize: () => void;
  onClose: () => void;
  onDragStart: (x: number, y: number) => void;
  children: React.ReactNode;
}) {
  const Icon = win.icon;
  if (win.minimized) return null;
  return (
    <div
      className={`absolute flex flex-col overflow-hidden rounded-xl border bg-veil-950 shadow-2xl ${focus ? 'border-cyan-500/30' : 'border-slate-800'}`}
      style={{ left: win.x, top: win.y, width: win.w, height: win.h, zIndex: win.z, maxWidth: 'calc(100% - 24px)', maxHeight: 'calc(100% - 76px)' }}
      onMouseDown={onFocus}
    >
      <div
        className={`flex shrink-0 items-center justify-between gap-2 border-b px-3 py-2 ${focus ? 'border-slate-700 bg-[#0c1017]' : 'border-slate-800 bg-[#0a0e15]'}`}
        onMouseDown={(e) => {
          if (e.target instanceof HTMLElement && e.target.closest('button')) return;
          onDragStart(e.clientX - win.x, e.clientY - win.y);
        }}
        style={{ cursor: 'move' }}
      >
        <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
          <Icon size={13} className="text-cyan-300" /> {win.title}
        </div>
        <div className="flex items-center gap-0.5">
          <button onClick={onMinimize} className="rounded-md p-1.5 text-slate-500 hover:bg-slate-800 hover:text-slate-200 transition" aria-label="Minimize"><Minus size={12} /></button>
          <button onClick={onClose} className="rounded-md p-1.5 text-slate-500 hover:bg-rose-500/20 hover:text-rose-200 transition" aria-label="Close"><X size={12} /></button>
        </div>
      </div>
      <div className="min-h-0 flex-1">{children}</div>
    </div>
  );
}
