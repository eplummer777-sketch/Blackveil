import { useState, FormEvent } from 'react';
import { supabase } from '@/lib/supabase';
import { Logo, Button, Input, Label } from '@/components/ui';
import { ShieldCheck, Mail, Lock, User, AlertCircle, ArrowLeft } from 'lucide-react';

type Mode = 'signin' | 'signup' | 'reset';

export function AuthPage({ initial = 'signin' }: { initial?: Mode }) {
  const [mode, setMode] = useState<Mode>(initial);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setLoading(true);
    try {
      if (mode === 'signup') {
        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: { data: { display_name: displayName } },
        });
        if (error) throw error;
        setInfo('Account created. You are now signed in.');
      } else if (mode === 'signin') {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
      } else {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: window.location.origin,
        });
        if (error) throw error;
        setInfo('Password reset link sent. Check your email.');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Something went wrong';
      setError(humanizeAuthError(msg));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen grid-bg relative overflow-hidden">
      <div className="absolute inset-0 radial-fade pointer-events-none" />
      <div className="relative min-h-screen flex flex-col items-center justify-center px-4 py-10">
        <div className="flex items-center gap-2.5 mb-8">
          <Logo size={34} />
          <div className="leading-tight">
            <div className="text-xl font-semibold tracking-tight text-slate-100">BLACKVEIL <span className="text-gradient">AI</span></div>
            <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">Cybersecurity Platform</div>
          </div>
        </div>

        <div className="w-full max-w-md rounded-2xl border border-slate-800/80 bg-veil-900/70 backdrop-blur-sm shadow-card p-7 fade-up">
          <div className="flex items-center gap-2 text-cyan-300 mb-1">
            <ShieldCheck size={18} />
            <span className="text-xs uppercase tracking-widest">Secure access</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            {mode === 'signin' && 'Welcome back'}
            {mode === 'signup' && 'Create your account'}
            {mode === 'reset' && 'Reset your password'}
          </h1>
          <p className="text-sm text-slate-400 mt-1 mb-6">
            {mode === 'signin' && 'Sign in to your Blackveil security workspace.'}
            {mode === 'signup' && 'Start running authorized security assessments in minutes.'}
            {mode === 'reset' && 'We will email you a secure link to set a new password.'}
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'signup' && (
              <div>
                <Label>Display name</Label>
                <div className="relative">
                  <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <Input
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Alex Morgan"
                    className="pl-9"
                    autoComplete="name"
                  />
                </div>
              </div>
            )}
            <div>
              <Label>Email</Label>
              <div className="relative">
                <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <Input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="pl-9"
                  autoComplete="email"
                />
              </div>
            </div>
            {mode !== 'reset' && (
              <div>
                <Label>Password</Label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <Input
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    className="pl-9"
                    autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
                  />
                </div>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 text-sm text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">
                <AlertCircle size={15} className="mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            {info && (
              <div className="text-sm text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2">
                {info}
              </div>
            )}

            <Button type="submit" loading={loading} full size="md">
              {mode === 'signin' && 'Sign in'}
              {mode === 'signup' && 'Create account'}
              {mode === 'reset' && 'Send reset link'}
            </Button>
          </form>

          <div className="mt-6 flex flex-col gap-2 text-sm">
            {mode === 'signin' && (
              <>
                <button onClick={() => { setMode('signup'); setError(null); setInfo(null); }} className="text-cyan-300 hover:text-cyan-200 text-left">
                  Don't have an account? Create one →
                </button>
                <button onClick={() => { setMode('reset'); setError(null); setInfo(null); }} className="text-slate-400 hover:text-slate-300 text-left flex items-center gap-1">
                  <ArrowLeft size={13} /> Forgot password?
                </button>
              </>
            )}
            {mode !== 'signin' && (
              <button onClick={() => { setMode('signin'); setError(null); setInfo(null); }} className="text-slate-400 hover:text-slate-300 text-left flex items-center gap-1">
                <ArrowLeft size={13} /> Back to sign in
              </button>
            )}
          </div>
        </div>

        <p className="text-[11px] text-slate-600 mt-6 max-w-md text-center">
          By signing in you agree to use Blackveil AI only against systems you own or are authorized to assess. Defensive use only.
        </p>
      </div>
    </div>
  );
}

function humanizeAuthError(msg: string): string {
  const m = msg.toLowerCase();
  if (m.includes('invalid login')) return 'Incorrect email or password.';
  if (m.includes('user already registered')) return 'An account with this email already exists. Try signing in.';
  if (m.includes('rate limit')) return 'Too many attempts. Please wait a moment and try again.';
  if (m.includes('password') && m.includes('weak')) return 'Please choose a stronger password (at least 8 characters).';
  return msg;
}
