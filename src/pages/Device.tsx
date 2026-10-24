import { useState } from 'react';
import { Card, SectionTitle, Badge, Button } from '@/components/ui';
import {
  ShieldCheck, Smartphone, Laptop, Lock, KeyRound, RefreshCw, UserCheck,
  CheckCircle2, Circle, Info, AlertTriangle,
} from 'lucide-react';

interface ChecklistItem {
  id: string;
  label: string;
  hint?: string;
}

const DEVICE_CHECKLIST: ChecklistItem[] = [
  { id: 'os', label: 'Operating system is up to date', hint: 'Install all pending OS updates to patch known vulnerabilities.' },
  { id: 'autolock', label: 'Auto-lock / screen lock enabled', hint: 'Set the device to lock after a short period of inactivity.' },
  { id: 'disk', label: 'Disk encryption enabled (FileVault / BitLocker)', hint: 'Encrypt the disk so data is protected if the device is stolen.' },
  { id: 'mfa', label: 'Multi-factor authentication on important accounts', hint: 'Use an authenticator app or hardware key, not just SMS.' },
  { id: 'passwords', label: 'Strong unique passwords in a password manager', hint: 'Never reuse passwords across accounts.' },
  { id: 'findmy', label: 'Find My / remote-wipe enabled', hint: 'Lets you locate or erase a lost device.' },
  { id: 'firewall', label: 'System firewall enabled', hint: 'Blocks unsolicited inbound connections.' },
  { id: 'guest', label: 'Guest accounts disabled', hint: 'Remove unused user accounts.' },
  { id: 'backups', label: 'Regular encrypted backups', hint: 'Follow 3-2-1: three copies, two media, one offsite.' },
  { id: 'apps', label: 'Unused apps removed, remaining apps updated', hint: 'Old apps can carry unpatched vulnerabilities.' },
];

const DEVICE_GUIDES = [
  { icon: <Laptop size={18} />, title: 'Windows & macOS', body: 'Enable built-in disk encryption (BitLocker / FileVault), keep the OS patched, turn on the firewall, and use an authenticator app for MFA.' },
  { icon: <Smartphone size={18} />, title: 'iOS & Android', body: 'Install OS updates promptly, enable auto-lock with biometrics, turn on Find My / Find My Device, and review app permissions regularly.' },
  { icon: <KeyRound size={18} />, title: 'Accounts & MFA', body: 'Use a password manager, unique passwords per site, and MFA on email, banking, and work accounts. Prefer authenticator apps over SMS.' },
  { icon: <RefreshCw size={18} />, title: 'Software updates', body: 'Patch operating systems, browsers, and plugins immediately. Enable automatic updates wherever possible.' },
];

export function Device() {
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const completed = Object.values(checked).filter(Boolean).length;
  const pct = Math.round((completed / DEVICE_CHECKLIST.length) * 100);

  return (
    <div className="space-y-6 fade-up">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100">Device Security</h1>
        <p className="text-slate-400 mt-1 text-sm">A guided, defensive checklist for your laptops and phones.</p>
      </div>

      <Card className="p-5 border-amber-500/20 bg-amber-500/5">
        <div className="flex items-start gap-3">
          <Info size={18} className="text-amber-300 mt-0.5 shrink-0" />
          <div className="text-sm text-slate-300">
            <p className="font-medium text-amber-200">What a website can and cannot check</p>
            <p className="mt-1 text-slate-400 leading-relaxed">
              A browser cannot scan your computer or phone for malware, installed apps, or system settings — that requires a native security agent with permissions.
              This page gives you a guided checklist and expert recommendations you apply on your device. The architecture supports adding a legitimate desktop/mobile agent later.
            </p>
          </div>
        </div>
      </Card>

      <div className="grid lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-5">
          <SectionTitle title="Security checklist" subtitle="Work through these on your device" icon={<ShieldCheck size={18} />} action={<Badge tone="cyan">{pct}% complete</Badge>} />
          <div className="h-1.5 rounded-full bg-veil-800 overflow-hidden mb-4">
            <div className="h-full bg-cyan-400 transition-all duration-500" style={{ width: `${pct}%` }} />
          </div>
          <ul className="space-y-2">
            {DEVICE_CHECKLIST.map((item) => {
              const done = !!checked[item.id];
              return (
                <li key={item.id}>
                  <button
                    onClick={() => setChecked((c) => ({ ...c, [item.id]: !c[item.id] }))}
                    className="w-full flex items-start gap-3 rounded-lg border border-slate-800/70 bg-veil-950/40 px-3.5 py-3 text-left hover:border-cyan-500/30 transition"
                  >
                    {done ? <CheckCircle2 size={18} className="text-emerald-400 mt-0.5 shrink-0" /> : <Circle size={18} className="text-slate-600 mt-0.5 shrink-0" />}
                    <div className="flex-1">
                      <div className={`text-sm font-medium ${done ? 'text-slate-400 line-through' : 'text-slate-200'}`}>{item.label}</div>
                      {item.hint && <div className="text-[11px] text-slate-500 mt-0.5">{item.hint}</div>}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="mt-4 flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => setChecked({})}>Reset</Button>
            <Button size="sm" variant="ghost" onClick={() => setChecked(Object.fromEntries(DEVICE_CHECKLIST.map((i) => [i.id, true])))}>Mark all done</Button>
          </div>
        </Card>

        <div className="space-y-6">
          <Card className="p-5">
            <SectionTitle title="Guides" icon={<Lock size={18} />} />
            <div className="space-y-3">
              {DEVICE_GUIDES.map((g) => (
                <div key={g.title} className="flex items-start gap-3">
                  <span className="rounded-lg bg-cyan-500/10 p-2 text-cyan-300 shrink-0">{g.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-slate-200">{g.title}</div>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{g.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-5">
            <SectionTitle title="Need deeper analysis?" icon={<AlertTriangle size={18} />} />
            <p className="text-sm text-slate-400">
              For log analysis, paste sanitized security logs into the AI assistant. Remove real credentials, tokens, and personal data first.
            </p>
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
              <UserCheck size={14} /> Designed so a native agent can be added later.
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
