import { Component, ReactNode, useEffect, type ErrorInfo } from 'react';
import { Loader2, ShieldAlert, X } from 'lucide-react';

export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Blackveil AI logo">
      <defs>
        <linearGradient id="bv-g" x1="0" y1="0" x2="48" y2="48">
          <stop offset="0" stopColor="#67e8f9" />
          <stop offset="1" stopColor="#0ea5b7" />
        </linearGradient>
      </defs>
      <path d="M24 2 L42 11 V27 C42 37 34 44 24 46 C14 44 6 37 6 27 V11 Z" fill="#0b1018" stroke="url(#bv-g)" strokeWidth="1.5" />
      <path d="M16 16 H30 C32 16 33 17.5 33 19.5 C33 21.5 32 23 30 23 H20 V26 H30 C32 26 33 27.5 33 29.5 C33 31.5 32 33 30 33 H16 Z" fill="url(#bv-g)" opacity="0.95" />
      <circle cx="24" cy="24" r="3" fill="#0b1018" />
      <path d="M24 9 V14 M24 34 V39 M9 24 H14 M34 24 H39" stroke="url(#bv-g)" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

export function Spinner({ className = '' }: { className?: string }) {
  return <Loader2 className={`animate-spin ${className}`} size={16} />;
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-slate-800/80 bg-veil-900/60 backdrop-blur-sm shadow-card ${className}`}>
      {children}
    </div>
  );
}

export function SectionTitle({ title, subtitle, icon, action }: { title: string; subtitle?: string; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 mb-4">
      <div className="flex items-start gap-3">
        {icon && <div className="mt-0.5 text-cyan-300">{icon}</div>}
        <div>
          <h2 className="text-lg font-semibold text-slate-100 tracking-tight">{title}</h2>
          {subtitle && <p className="text-sm text-slate-400 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

type ButtonProps = {
  children: ReactNode;
  onClick?: () => void;
  type?: 'button' | 'submit';
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
  disabled?: boolean;
  loading?: boolean;
  className?: string;
  full?: boolean;
};

export function Button({
  children, onClick, type = 'button', variant = 'primary', size = 'md',
  disabled, loading, className = '', full,
}: ButtonProps) {
  const base = 'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-400/40 disabled:opacity-50 disabled:cursor-not-allowed';
  const sizes = { sm: 'text-xs px-3 py-1.5', md: 'text-sm px-4 py-2.5' };
  const variants = {
    primary: 'bg-cyan-400 text-veil-950 hover:bg-cyan-300 shadow-glow-cyan',
    secondary: 'bg-veil-800 text-slate-200 hover:bg-veil-700 border border-slate-700',
    ghost: 'text-slate-300 hover:bg-veil-800/70',
    danger: 'bg-rose-500/90 text-white hover:bg-rose-500',
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={`${base} ${sizes[size]} ${variants[variant]} ${full ? 'w-full' : ''} ${className}`}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: 'cyan' | 'rose' | 'amber' | 'slate' | 'green' }) {
  const tones = {
    cyan: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
    rose: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
    amber: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    green: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    slate: 'bg-slate-700/30 text-slate-300 border-slate-600/40',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className = '', ...rest } = props;
  return (
    <input
      {...rest}
      className={`w-full rounded-lg border border-slate-700/80 bg-veil-950/60 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition ${className}`}
    />
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">{children}</label>;
}

export function EmptyState({ icon, title, hint, action }: { icon?: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      {icon && <div className="text-slate-600 mb-3">{icon}</div>}
      <p className="text-slate-300 font-medium">{title}</p>
      {hint && <p className="text-sm text-slate-500 mt-1 max-w-sm">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function SeverityPill({ severity }: { severity: 'critical' | 'high' | 'medium' | 'low' | 'info' }) {
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-amber-300 bg-amber-500/10 border-amber-500/40',
    low: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/40',
    info: 'text-slate-300 bg-slate-700/30 border-slate-600/40',
  };
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize ${map[severity]}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}

export function Drawer({ title, subtitle, onClose, children, wide = false }: { title: string; subtitle?: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm fade-in" onClick={onClose} />
      <aside className={`relative w-full ${wide ? 'max-w-3xl' : 'max-w-xl'} h-full bg-veil-900 border-l border-slate-800 shadow-2xl flex flex-col drawer-in`}>
        <header className="flex items-start justify-between gap-4 px-6 py-5 border-b border-slate-800/80">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-slate-100 truncate">{title}</h2>
            {subtitle && <div className="mt-1.5">{subtitle}</div>}
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-slate-500 hover:text-slate-200 hover:bg-veil-800 transition" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto scrollbar-thin px-6 py-5">{children}</div>
      </aside>
    </div>
  );
}

export class ErrorBoundary extends Component<{ children: ReactNode; label: string; compact?: boolean }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error(`[${this.props.label}]`, error, info.componentStack); }
  render() {
    if (!this.state.failed) return this.props.children;
    const text = this.props.compact
      ? `This ${this.props.label} could not be displayed. The rest of the conversation is unaffected.`
      : `The ${this.props.label} hit a display problem. Your conversation and files are safe.`;
    return <ErrorBanner message={text} action={{ label: 'Try again', onClick: () => this.setState({ failed: false }) }} />;
  }
}

export function ErrorBanner({ message, onDismiss, action }: { message: string; onDismiss?: () => void; action?: { label: string; onClick: () => void } }) {
  return (
    <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-200 flex items-start gap-2.5">
      <ShieldAlert size={16} className="mt-0.5 shrink-0" />
      <span className="flex-1">{message}</span>
      {action && <button onClick={action.onClick} className="shrink-0 rounded-md border border-rose-400/40 px-2 py-0.5 text-xs font-medium text-rose-100 hover:bg-rose-500/20 transition">{action.label}</button>}
      {onDismiss && <button onClick={onDismiss} className="text-rose-300 hover:text-rose-100"><X size={14} /></button>}
    </div>
  );
}

export function Toggle({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled} onClick={() => onChange(!on)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors duration-200 disabled:opacity-50 ${on ? 'bg-cyan-400' : 'bg-veil-700 border border-slate-700'}`}>
      <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ${on ? 'translate-x-[22px]' : 'translate-x-0.5'}`} />
    </button>
  );
}
