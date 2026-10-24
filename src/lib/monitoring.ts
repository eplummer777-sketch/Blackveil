import { supabase, callEdge } from '@/lib/supabase';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface MonitoringSettings {
  enabled: boolean;
  email_alerts: boolean;
  push_alerts: boolean;
  min_severity: Severity;
  daily_report: boolean;
  report_hour_utc: number;
  last_report_on: string | null;
  enabled_at: string | null;
}

export interface AlertDelivery {
  id: string;
  channel: 'email' | 'sms' | 'push';
  kind: 'incident' | 'daily_report' | 'test';
  subject: string;
  status: 'pending' | 'sending' | 'sent' | 'failed' | 'not_configured';
  error: string | null;
  created_at: string;
  sent_at: string | null;
}

export interface MonitoringReport {
  id: string;
  report_date: string;
  summary: Record<string, unknown>;
  body: string;
  created_at: string;
}

export interface MonitoringStatus {
  eligible: boolean;
  channels: { email: boolean; push: boolean };
  pushKey?: string | null;
}

export const DEFAULT_SETTINGS: MonitoringSettings = {
  enabled: false, email_alerts: true, push_alerts: false, min_severity: 'medium',
  daily_report: true, report_hour_utc: 13, last_report_on: null, enabled_at: null,
};

export async function loadMonitoringData() {
  const [s, d, r] = await Promise.all([
    supabase.from('monitoring_settings').select('enabled, email_alerts, push_alerts, min_severity, daily_report, report_hour_utc, last_report_on, enabled_at').maybeSingle(),
    supabase.from('alert_deliveries').select('id, channel, kind, subject, status, error, created_at, sent_at').order('created_at', { ascending: false }).limit(25),
    supabase.from('monitoring_reports').select('id, report_date, summary, body, created_at').order('created_at', { ascending: false }).limit(14),
  ]);
  const error = s.error || d.error || r.error;
  if (error) return { ok: false as const, error: 'Could not load monitoring data.' };
  return {
    ok: true as const,
    settings: (s.data as MonitoringSettings | null) ?? DEFAULT_SETTINGS,
    deliveries: (d.data ?? []) as AlertDelivery[],
    reports: (r.data ?? []) as MonitoringReport[],
  };
}

export async function monitoringCall<T = Record<string, unknown>>(token: string, body: Record<string, unknown>) {
  try {
    return await callEdge<T>('monitoring', body, token);
  } catch {
    return { ok: false as const, status: 0, error: 'Could not reach Blackveil. Check your connection.' };
  }
}

export function localHourLabel(utcHour: number) {
  const d = new Date();
  d.setUTCHours(utcHour, 0, 0, 0);
  return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}
