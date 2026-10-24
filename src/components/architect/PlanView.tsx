import { AlertTriangle, Bot, FileCog, Info, ListChecks } from 'lucide-react';
import { Badge, Card } from '@/components/ui';
import type { ArchitectProject, Plan } from '@/lib/architect';

export function PlanView({ project, plan }: { project: ArchitectProject; plan: Plan }) {
  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-2 p-6">
        <div className="flex flex-wrap items-center gap-2">
          {project.plan_source === 'ai' ? (
            <Badge tone="cyan"><Bot size={12} /> Drafted by AI</Badge>
          ) : (
            <Badge tone="slate"><FileCog size={12} /> Built from safe templates</Badge>
          )}
          <span className="text-xs text-slate-500">Review every step before applying anything.</span>
        </div>
        <h3 className="mt-4 text-xl font-semibold text-slate-100 leading-tight">{plan.title}</h3>
        <p className="mt-2 text-sm text-slate-300 leading-relaxed">{plan.summary}</p>

        <ol className="mt-6 space-y-4">
          {plan.steps.map((s, i) => (
            <li key={i} className="flex gap-4">
              <div className="flex flex-col items-center">
                <span className="flex h-7 w-7 items-center justify-center rounded-full border border-cyan-500/30 bg-veil-950 text-xs font-semibold text-cyan-300 font-mono-tight">
                  {i + 1}
                </span>
                {i < plan.steps.length - 1 && <span className="mt-1 w-px flex-1 bg-gradient-to-b from-cyan-500/30 to-transparent" />}
              </div>
              <div className="pb-2">
                <p className="text-sm font-medium text-slate-100">{s.title}</p>
                <p className="mt-1 text-sm text-slate-400 leading-relaxed">{s.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      <div className="space-y-6">
        <Card className="p-5 border-amber-500/20">
          <h4 className="flex items-center gap-2 text-sm font-semibold text-amber-200">
            <AlertTriangle size={15} /> What this plan does not cover
          </h4>
          <ul className="mt-3 space-y-2">
            {plan.not_covered.map((n, i) => (
              <li key={i} className="text-sm text-slate-400 leading-relaxed pl-3 border-l border-amber-500/30">{n}</li>
            ))}
          </ul>
        </Card>
        {plan.assumptions.length > 0 && (
          <Card className="p-5">
            <h4 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
              <Info size={15} className="text-cyan-300" /> Assumptions
            </h4>
            <ul className="mt-3 space-y-2">
              {plan.assumptions.map((a, i) => (
                <li key={i} className="text-sm text-slate-400 leading-relaxed pl-3 border-l border-slate-700">{a}</li>
              ))}
            </ul>
          </Card>
        )}
        <Card className="p-5">
          <h4 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <ListChecks size={15} className="text-cyan-300" /> Your request
          </h4>
          <p className="mt-3 text-sm text-slate-400 leading-relaxed whitespace-pre-wrap">{project.description}</p>
        </Card>
      </div>
    </div>
  );
}
