import { useState } from 'react';
import { Check, HelpCircle, Send } from 'lucide-react';
import { Button, Card, Input } from '@/components/ui';
import type { Answers, Question } from '@/lib/architect';

export function QuestionsForm({ questions, submitting, onSubmit }: {
  questions: Question[];
  submitting: boolean;
  onSubmit: (answers: Answers) => void;
}) {
  const [answers, setAnswers] = useState<Answers>({});
  const systems = answers.systems;
  const ready = Array.isArray(systems) && systems.length > 0;

  const toggle = (q: Question, opt: string) => {
    setAnswers((prev) => {
      if (q.type === 'single') return { ...prev, [q.id]: prev[q.id] === opt ? '' : opt };
      const cur = Array.isArray(prev[q.id]) ? (prev[q.id] as string[]) : [];
      return { ...prev, [q.id]: cur.includes(opt) ? cur.filter((x) => x !== opt) : [...cur, opt] };
    });
  };

  const isSelected = (q: Question, opt: string) => {
    const v = answers[q.id];
    return Array.isArray(v) ? v.includes(opt) : v === opt;
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); if (ready) onSubmit(answers); }} className="space-y-4">
      {questions.map((q, i) => (
        <Card key={q.id} className="p-5 sm:p-6 fade-up" >
          <div className="flex items-start gap-3">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-xs font-semibold text-cyan-300 font-mono-tight">
              {i + 1}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-100 leading-snug">
                {q.question}
                {q.id === 'systems' && <span className="text-cyan-300"> *</span>}
              </p>
              {q.why && (
                <p className="mt-1 flex items-start gap-1.5 text-xs text-slate-500 leading-relaxed">
                  <HelpCircle size={12} className="mt-0.5 shrink-0" /> {q.why}
                </p>
              )}
              <div className="mt-4">
                {q.type === 'text' ? (
                  <Input
                    value={typeof answers[q.id] === 'string' ? (answers[q.id] as string) : ''}
                    onChange={(e) => setAnswers((p) => ({ ...p, [q.id]: e.target.value }))}
                    maxLength={500}
                    placeholder={q.id === 'website_url' ? 'https://example.com' : 'Optional'}
                  />
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {q.options.map((opt) => {
                      const on = isSelected(q, opt);
                      return (
                        <button
                          key={opt}
                          type="button"
                          onClick={() => toggle(q, opt)}
                          aria-pressed={on}
                          className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm transition ${
                            on
                              ? 'border-cyan-400/60 bg-cyan-500/15 text-cyan-100 shadow-glow-cyan'
                              : 'border-slate-700/80 bg-veil-950/50 text-slate-300 hover:border-slate-500 hover:text-slate-100'
                          }`}
                        >
                          {on && <Check size={14} />}
                          {opt}
                        </button>
                      );
                    })}
                  </div>
                )}
                {q.type === 'multi' && <p className="mt-2 text-xs text-slate-600">Choose all that apply.</p>}
              </div>
            </div>
          </div>
        </Card>
      ))}
      <div className="sticky bottom-20 lg:bottom-4 z-10">
        <Card className="p-4 flex flex-col sm:flex-row sm:items-center gap-3 bg-veil-900/95">
          <p className="text-xs text-slate-400 flex-1">
            {ready ? 'Architect will draft a plan and proposed changes. Nothing is applied automatically.' : 'Choose at least one thing you want to protect (question marked *).'}
          </p>
          <Button type="submit" loading={submitting} disabled={!ready}>
            <Send size={16} /> {submitting ? 'Drafting plan...' : 'Generate plan'}
          </Button>
        </Card>
      </div>
    </form>
  );
}
