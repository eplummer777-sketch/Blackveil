import { CheckCircle2, XCircle, AlertTriangle, MinusCircle } from 'lucide-react';
import { CheckResult } from '@/lib/pob';

export const RESULT_ICON: Record<CheckResult, JSX.Element> = {
  passed: <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />,
  failed: <XCircle size={16} className="text-rose-400 shrink-0" />,
  partial: <AlertTriangle size={16} className="text-amber-400 shrink-0" />,
  incomplete: <MinusCircle size={16} className="text-slate-400 shrink-0" />,
  not_performed: <MinusCircle size={16} className="text-slate-500 shrink-0" />,
};
