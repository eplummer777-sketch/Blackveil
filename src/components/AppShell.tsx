import { ReactNode, useState, useEffect, useRef } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { Logo, Button } from '@/components/ui';
import { CommandPalette } from '@/components/CommandPalette';
import { Notification } from '@/lib/types';
import {
  LayoutDashboard, ScanSearch, Bot, FileText, ShieldCheck, Gauge, Search,
  LogOut, Menu, UserCircle, Bug, Wrench, Bell, Radar, Wand2, Stethoscope, Crosshair, Network, Swords, MoreHorizontal, Lock, Monitor, Code2,
} from 'lucide-react';

export type Route = 'dashboard' | 'assessments' | 'assessment-engine' | 'assistant' | 'reports' | 'device' | 'malware' | 'tools' | 'admin' | 'settings' | 'sentinel' | 'architect' | 'limitations' | 'proof-of-breach' | 'network-scan' | 'pentest' | 'blackveil-os' | 'web-builder';

type Group = 'Overview' | 'Scan & test' | 'Protect' | 'Assist' | 'Operations';

export type NavItem = { id: Route; label: string; icon: typeof LayoutDashboard; desc: string; group: Group; tier?: 'Pro' | 'Elite' };

const NAV: NavItem[] = [
  { id: 'dashboard',         label: 'Dashboard',          icon: LayoutDashboard, desc: 'Your security at a glance', group: 'Overview' },
  { id: 'reports',           label: 'Reports',            icon: FileText,        desc: 'History & PDF exports',     group: 'Overview' },
  { id: 'assessments',       label: 'Assessments',        icon: ScanSearch,      desc: 'Website scans',             group: 'Scan & test' },
  { id: 'assessment-engine', label: 'Assessment Engine',  icon: Stethoscope,     desc: 'Assess & remediate',        group: 'Scan & test' },
  { id: 'proof-of-breach',   label: 'Proof-of-Breach AI', icon: Crosshair,       desc: 'Test & verify findings',    group: 'Scan & test', tier: 'Elite' },
  { id: 'network-scan',      label: 'Network Scan',       icon: Network,         desc: 'Host & port discovery',     group: 'Scan & test', tier: 'Elite' },
  { id: 'pentest',           label: 'Penetration Test',   icon: Swords,          desc: 'Native pentest engine',     group: 'Scan & test', tier: 'Elite' },
  { id: 'sentinel',          label: 'Sentinel',           icon: Radar,           desc: 'Honeypots & decoys',        group: 'Protect', tier: 'Pro' },
  { id: 'architect',         label: 'Architect',          icon: Wand2,           desc: 'AI security builder',       group: 'Protect' },
  { id: 'device',            label: 'Device',             icon: ShieldCheck,     desc: 'Endpoint protection',       group: 'Protect' },
  { id: 'malware',           label: 'Malware Removal',    icon: Bug,             desc: 'Step-by-step cleanup',      group: 'Protect' },
  { id: 'assistant',         label: 'AI Assistant',       icon: Bot,             desc: 'Ask a security expert',     group: 'Assist' },
  { id: 'tools',             label: 'Security Tools',     icon: Wrench,          desc: 'Link & password checks',    group: 'Assist' },
  { id: 'blackveil-os',      label: 'Blackveil OS',       icon: Monitor,         desc: 'Isolated Linux workspace',  group: 'Operations' },
];

const ADMIN_ITEM: NavItem = { id: 'admin', label: 'Admin', icon: Gauge, desc: 'Platform operations', group: 'Operations' };
const BUILDER_ITEM: NavItem = { id: 'web-builder', label: 'Web Builder', icon: Code2, desc: 'Private AI coding workspace', group: 'Operations' };
const ACCOUNT_ITEM: NavItem = { id: 'settings', label: 'Account', icon: UserCircle, desc: 'Profile, plan & alerts', group: 'Operations' };

const TIER_STYLE = {
  Elite: 'text-amber-200 bg-amber-400/10 border-amber-400/25',
  Pro: 'text-emerald-200 bg-emerald-400/10 border-emerald-400/25',
};

export function AppShell({
  route, onNavigate, children, showBuilder = false,
}: {
  showBuilder?: boolean;
  route: Route;
  onNavigate: (r: Route) => void;
  children: ReactNode;
}) {
  const { profile, signOut, isAdmin, user } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showNotifs, setShowNotifs] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!user) return;
    let mounted = true;
    const load = async () => {
      const { data } = await supabase
        .from('notifications')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(20);
      if (!mounted) return;
      const notifs = (data as Notification[]) ?? [];
      setNotifications(notifs);
      setUnreadCount(notifs.filter((n) => !n.read).length);
    };
    load();

    const channel = supabase
      .channel('notifications:' + user.id)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'notifications', filter: `user_id=eq.${user.id}` }, load)
      .subscribe();

    return () => { mounted = false; supabase.removeChannel(channel); };
  }, [user]);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifs(false);
      }
    }
    if (showNotifs) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [showNotifs]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  async function markAllRead() {
    if (!user || unreadCount === 0) return;
    const unread = notifications.filter((n) => !n.read);
    for (const n of unread) {
      await supabase.from('notifications').update({ read: true }).eq('id', n.id);
    }
    setNotifications(notifications.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);
  }

  function go(r: Route) {
    onNavigate(r);
    setMobileOpen(false);
    setPaletteOpen(false);
  }

  const navItems = [...NAV, ...(isAdmin ? [ADMIN_ITEM] : []), ...(showBuilder ? [BUILDER_ITEM] : [])];
  const groups = navItems.reduce<{ name: Group; items: NavItem[] }[]>((acc, item) => {
    const g = acc.find((x) => x.name === item.group);
    if (g) g.items.push(item); else acc.push({ name: item.group, items: [item] });
    return acc;
  }, []);
  const current = [...navItems, ACCOUNT_ITEM].find((i) => i.id === route);
  const CurrentIcon = current?.icon ?? LayoutDashboard;
  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="min-h-screen bg-veil-950 text-slate-200 grid-bg">
      <div className="min-h-screen flex">
        <aside
          className={`fixed lg:sticky lg:top-0 lg:h-screen z-40 inset-y-0 left-0 w-72 border-r border-slate-800/80 bg-veil-900/90 backdrop-blur-md flex flex-col transition-transform duration-300 ${
            mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
          }`}
        >
          <div className="px-5 h-16 flex items-center gap-3 border-b border-slate-800/70 shrink-0">
            <Logo size={30} />
            <div className="leading-tight">
              <div className="text-base font-semibold tracking-tight text-slate-100">BLACKVEIL <span className="text-gradient">AI</span></div>
              <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Security Ops</div>
            </div>
          </div>

          <div className="px-4 pt-4 shrink-0">
            <button
              onClick={() => setPaletteOpen(true)}
              className="w-full flex items-center gap-2.5 rounded-lg border border-slate-800 bg-veil-950/70 px-3 py-2 text-sm text-slate-500 hover:border-slate-700 hover:text-slate-300 transition"
            >
              <Search size={15} />
              <span className="flex-1 text-left">Find a page</span>
              <kbd className="hidden lg:inline text-[10px] border border-slate-700 rounded px-1.5 py-0.5">{isMac ? '⌘' : 'Ctrl'} K</kbd>
            </button>
          </div>

          <nav className="flex-1 px-3 py-4 overflow-y-auto scrollbar-thin space-y-5">
            {groups.map((group) => (
              <div key={group.name}>
                <div className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{group.name}</div>
                <div className="space-y-0.5">
                  {group.items.map((item) => (
                    <NavButton key={item.id} item={item} active={route === item.id} onClick={() => go(item.id)} />
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="px-3 py-3 border-t border-slate-800/70 space-y-2 shrink-0">
            <NavButton item={ACCOUNT_ITEM} active={route === 'settings'} onClick={() => go('settings')} />
            <div className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl bg-veil-950/60 border border-slate-800/60">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-400/30 to-slate-700 flex items-center justify-center text-xs font-semibold text-cyan-200">
                {(profile?.display_name || profile?.email || '?').charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-slate-200 truncate">{profile?.display_name || 'User'}</div>
                <div className="text-[10px] text-slate-500 truncate">{profile?.email}</div>
              </div>
              <button onClick={() => signOut()} title="Sign out" aria-label="Sign out" className="p-1.5 rounded-md text-slate-500 hover:text-rose-300 hover:bg-rose-500/10 transition">
                <LogOut size={15} />
              </button>
            </div>
          </div>
        </aside>

        {mobileOpen && (
          <div className="fixed inset-0 z-30 bg-black/60 lg:hidden fade-in" onClick={() => setMobileOpen(false)} />
        )}

        <div className="flex-1 flex flex-col min-w-0">
          <header className="sticky top-0 z-20 backdrop-blur-md bg-veil-950/80 border-b border-slate-800/70">
            <div className="flex items-center gap-3 px-4 lg:px-8 h-16">
              <button onClick={() => setMobileOpen(true)} aria-label="Open menu" className="lg:hidden -ml-1 p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-veil-800/60">
                <Menu size={20} />
              </button>
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <span className="hidden sm:flex w-9 h-9 rounded-lg items-center justify-center border border-cyan-400/20 bg-cyan-400/10 text-cyan-300 shrink-0">
                  <CurrentIcon size={17} />
                </span>
                <div className="min-w-0">
                  <div className="hidden sm:flex items-center gap-1.5 text-[11px] text-slate-500">
                    <span>{current?.group ?? 'Overview'}</span>
                    <span className="text-slate-700">/</span>
                    <span className="flex items-center gap-1 text-emerald-400/80"><Lock size={10} /> Encrypted session</span>
                  </div>
                  <div className="text-sm sm:text-base font-semibold text-slate-100 truncate">{current?.label ?? 'BLACKVEIL'}</div>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <button onClick={() => setPaletteOpen(true)} aria-label="Search pages" className="lg:hidden rounded-lg p-2 text-slate-400 hover:text-slate-200 hover:bg-veil-800/60 transition">
                  <Search size={18} />
                </button>
                <div className="relative" ref={notifRef}>
                  <button
                    onClick={() => { setShowNotifs(!showNotifs); if (!showNotifs) markAllRead(); }}
                    className="relative rounded-lg p-2 text-slate-400 hover:text-slate-200 hover:bg-veil-800/60 transition"
                    title="Notifications"
                    aria-label="Notifications"
                  >
                    <Bell size={18} />
                    {unreadCount > 0 && (
                      <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-rose-500 text-white text-[10px] font-semibold flex items-center justify-center">
                        {unreadCount > 9 ? '9+' : unreadCount}
                      </span>
                    )}
                  </button>
                  {showNotifs && (
                    <div className="absolute right-0 top-full mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-xl border border-slate-800 bg-veil-900 shadow-xl z-50 overflow-hidden fade-up">
                      <div className="px-4 py-3 border-b border-slate-800/70 flex items-center justify-between">
                        <span className="text-sm font-medium text-slate-200">Notifications</span>
                        {notifications.length > 0 && (
                          <button onClick={markAllRead} className="text-[11px] text-cyan-300 hover:text-cyan-200">Mark all read</button>
                        )}
                      </div>
                      <div className="max-h-80 overflow-y-auto scrollbar-thin">
                        {notifications.length === 0 ? (
                          <div className="py-8 text-center">
                            <Bell size={24} className="text-slate-600 mx-auto mb-2" />
                            <p className="text-sm text-slate-500">No notifications yet</p>
                          </div>
                        ) : (
                          notifications.map((n) => (
                            <button
                              key={n.id}
                              onClick={() => { if (n.link) onNavigate(n.link as Route); setShowNotifs(false); }}
                              className={`w-full flex items-start gap-2.5 px-4 py-3 text-left border-b border-slate-800/40 hover:bg-veil-800/40 transition ${!n.read ? 'bg-cyan-500/5' : ''}`}
                            >
                              <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${n.kind === 'security_alert' ? 'bg-rose-400' : n.kind === 'subscription' ? 'bg-emerald-400' : 'bg-cyan-400'}`} />
                              <div className="flex-1 min-w-0">
                                <div className="text-sm text-slate-200 truncate">{n.title}</div>
                                {n.body && <div className="text-xs text-slate-500 mt-0.5 line-clamp-2">{n.body}</div>}
                                <div className="text-[10px] text-slate-600 font-mono-tight mt-1">{new Date(n.created_at).toLocaleString()}</div>
                              </div>
                            </button>
                          ))
                        )}
                      </div>
                    </div>
                  )}
                </div>
                <button
                  onClick={() => go('assistant')}
                  className={`hidden sm:inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                    route === 'assistant' ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-slate-700 text-slate-300 hover:border-cyan-400/40 hover:text-cyan-200'
                  }`}
                >
                  <Bot size={14} /> Ask AI
                </button>
                <div className="hidden sm:block">
                  <Button size="sm" variant="primary" onClick={() => go('assessments')}>
                    <ScanSearch size={14} /> New assessment
                  </Button>
                </div>
              </div>
            </div>
          </header>

          <main key={route} className="flex-1 px-4 lg:px-8 py-6 lg:py-8 pb-28 lg:pb-8 max-w-7xl w-full mx-auto fade-up">
            {children}
          </main>

          <footer className="hidden lg:flex px-8 py-4 text-[11px] text-slate-600 border-t border-slate-800/60 flex-wrap items-center justify-between gap-2">
            <span>BLACKVEIL AI · Defensive cybersecurity. Authorized assessments only.</span>
            <span className="font-mono-tight">v1.0 · SOC-style operations</span>
          </footer>
        </div>
      </div>

      <div className="lg:hidden fixed bottom-0 inset-x-0 z-30 border-t border-slate-800/80 bg-veil-900/95 backdrop-blur-md pb-[env(safe-area-inset-bottom)]">
        <div className="grid grid-cols-5">
          <MobileTab icon={<LayoutDashboard size={19} />} label="Home" active={route === 'dashboard'} onClick={() => go('dashboard')} />
          <MobileTab icon={<ScanSearch size={19} />} label="Scan" active={route === 'assessments'} onClick={() => go('assessments')} />
          <MobileTab icon={<Bot size={19} />} label="AI" active={route === 'assistant'} onClick={() => go('assistant')} />
          <MobileTab icon={<Wrench size={19} />} label="Tools" active={route === 'tools'} onClick={() => go('tools')} />
          <MobileTab
            icon={<MoreHorizontal size={19} />}
            label="More"
            active={!['dashboard', 'assessments', 'assistant', 'tools'].includes(route)}
            onClick={() => setMobileOpen(true)}
          />
        </div>
      </div>

      {paletteOpen && <CommandPalette items={[...navItems, ACCOUNT_ITEM]} onSelect={go} onClose={() => setPaletteOpen(false)} />}
    </div>
  );
}

function NavButton({ item, active, onClick }: { item: NavItem; active: boolean; onClick: () => void }) {
  const Icon = item.icon;
  return (
    <button
      onClick={onClick}
      aria-current={active ? 'page' : undefined}
      className={`group relative w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all ${
        active ? 'bg-cyan-400/10 text-cyan-100' : 'text-slate-400 hover:text-slate-100 hover:bg-veil-800/70'
      }`}
    >
      <span className={`absolute left-0 top-1/2 -translate-y-1/2 w-[3px] rounded-r-full bg-cyan-300 transition-all ${active ? 'h-5 opacity-100' : 'h-0 opacity-0'}`} />
      <Icon size={17} className={`shrink-0 transition-colors ${active ? 'text-cyan-300' : 'text-slate-500 group-hover:text-slate-300'}`} />
      <span className="flex-1 min-w-0 text-left">
        <span className="block font-medium truncate">{item.label}</span>
        <span className={`block text-[11px] truncate transition-colors ${active ? 'text-cyan-200/60' : 'text-slate-600 group-hover:text-slate-500'}`}>{item.desc}</span>
      </span>
      {item.tier && (
        <span className={`text-[9px] font-semibold uppercase tracking-wider border rounded px-1.5 py-0.5 ${TIER_STYLE[item.tier]}`}>{item.tier}</span>
      )}
    </button>
  );
}

function MobileTab({ icon, label, active, onClick }: { icon: ReactNode; label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`relative flex flex-col items-center gap-1 py-2.5 transition ${active ? 'text-cyan-300' : 'text-slate-500 hover:text-slate-300'}`}
    >
      <span className={`absolute top-0 h-0.5 rounded-b-full bg-cyan-300 transition-all ${active ? 'w-8 opacity-100' : 'w-0 opacity-0'}`} />
      {icon}
      <span className="text-[10px] font-medium">{label}</span>
    </button>
  );
}
