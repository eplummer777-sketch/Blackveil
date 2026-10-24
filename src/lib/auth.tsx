import { createContext, useContext, useEffect, useState, ReactNode, useCallback } from 'react';
import { Session, User } from '@supabase/supabase-js';
import { supabase } from './supabase';
import { Profile, Subscription, Plan } from './types';

interface AuthState {
  session: Session | null;
  user: User | null;
  profile: Profile | null;
  subscription: Subscription | null;
  loading: boolean;
  isAdmin: boolean;
  plan: Plan;
  hasMalwareRemoval: boolean;
  isPro: boolean;
  isElite: boolean;
  refreshProfile: () => Promise<void>;
  refreshSubscription: () => Promise<void>;
  signOut: () => Promise<void>;
}

const Ctx = createContext<AuthState>({
  session: null,
  user: null,
  profile: null,
  subscription: null,
  loading: true,
  isAdmin: false,
  plan: 'free',
  hasMalwareRemoval: false,
  isPro: false,
  isElite: false,
  refreshProfile: async () => {},
  refreshSubscription: async () => {},
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);

  const loadProfile = useCallback(async (uid: string) => {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', uid)
      .maybeSingle();
    if (error) {
      // eslint-disable-next-line no-console
      console.warn('profile load error', error.message);
      return;
    }
    if (data) setProfile(data as Profile);
  }, []);

  const loadSubscription = useCallback(async (uid: string) => {
    const { data, error } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', uid)
      .maybeSingle();
    if (error) {
      // eslint-disable-next-line no-console
      console.warn('subscription load error', error.message);
      return;
    }
    if (data) setSubscription(data as Subscription);
  }, []);

  useEffect(() => {
    let mounted = true;
    let settled = false;

    const fail = () => {
      if (mounted && !settled) {
        settled = true;
        setLoading(false);
      }
    };

    // Safety net: never block the UI longer than 6s waiting for auth init.
    const timeout = setTimeout(fail, 6000);

    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      settled = true;
      clearTimeout(timeout);
      setSession(data.session);
      setUser(data.session?.user ?? null);
      if (data.session?.user) {
        Promise.all([
          loadProfile(data.session.user.id),
          loadSubscription(data.session.user.id),
        ]).finally(() => mounted && setLoading(false));
      } else {
        setLoading(false);
      }
    }).catch(() => {
      clearTimeout(timeout);
      fail();
    });

    const { data: sub } = supabase.auth.onAuthStateChange((_event, sess) => {
      (async () => {
        setSession(sess);
        setUser(sess?.user ?? null);
        if (sess?.user) {
          await Promise.all([loadProfile(sess.user.id), loadSubscription(sess.user.id)]);
        } else {
          setProfile(null);
          setSubscription(null);
        }
        setLoading(false);
      })();
    });

    return () => {
      mounted = false;
      clearTimeout(timeout);
      sub.subscription.unsubscribe();
    };
  }, [loadProfile]);

  const refreshProfile = useCallback(async () => {
    if (user) await loadProfile(user.id);
  }, [user, loadProfile]);

  const refreshSubscription = useCallback(async () => {
    if (user) await loadSubscription(user.id);
  }, [user, loadSubscription]);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    setProfile(null);
    setSubscription(null);
  }, []);

  const isAdmin = (user?.app_metadata as Record<string, unknown> | undefined)?.role === 'admin';
  const isActive =
    subscription?.status === 'active' || subscription?.status === 'trialing';
  const subPlan: Plan =
    subscription && isActive && (subscription.plan === 'malware_removal' || subscription.plan === 'pro' || subscription.plan === 'elite')
      ? subscription.plan
      : 'free';
  const plan: Plan = isAdmin ? 'elite' : subPlan;
  const hasMalwareRemoval = isAdmin || plan === 'malware_removal' || plan === 'pro' || plan === 'elite';
  const isPro = isAdmin || plan === 'pro' || plan === 'elite';
  const isElite = isAdmin || plan === 'elite';

  return (
    <Ctx.Provider value={{ session, user, profile, subscription, loading, isAdmin, plan, hasMalwareRemoval, isPro, isElite, refreshProfile, refreshSubscription, signOut }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  return useContext(Ctx);
}
