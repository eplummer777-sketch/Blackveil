import { LOCAL_PROVIDER, localReply, type AiMessage, type AiResult } from "./ai.ts";
import { must, type Body, type Svc } from "./store.ts";

const REPAIR_PROMPT = `Your previous answer could not be read because it was not one valid JSON object in the required shape. Reply again with ONLY that JSON object: no text before or after it, no code fences, double-quoted keys and strings, and every bracket closed. Keep it short.`;

interface CallLog { purpose: string; r: AiResult; ok: boolean }

// One action's AI calls. Logs are written only when the action finishes, so a round that stops to wait
// for the device's answer is not counted twice.
export class AiRun {
  private logs: CallLog[] = [];
  constructor(private svc: Svc, private body: Body, private projectId: string) {}

  async ask(purpose: string, messages: AiMessage[], maxTokens: number, valid: (content: string) => boolean): Promise<{ r: AiResult; ok: boolean; repaired: boolean }> {
    const first = await localReply(this.body, purpose, messages, maxTokens);
    const ok = valid(first.content);
    this.logs.push({ purpose, r: first, ok });
    if (ok) return { r: first, ok, repaired: false };
    const retry = [...messages, { role: "assistant" as const, content: first.content.slice(0, 1500) }, { role: "user" as const, content: REPAIR_PROMPT }];
    const second = await localReply(this.body, `${purpose} (repair)`, retry, maxTokens);
    const ok2 = valid(second.content);
    this.logs.push({ purpose: `${purpose} (repair)`, r: second, ok: ok2 });
    return { r: second, ok: ok2, repaired: true };
  }

  get usage() {
    return this.logs.reduce((t, l) => ({ input: t.input + l.r.inputTokens, output: t.output + l.r.outputTokens }), { input: 0, output: 0 });
  }

  async flush(): Promise<void> {
    if (!this.logs.length) return;
    await must(this.svc.from("wb_ai_calls").insert(this.logs.map(({ purpose, r, ok }) => ({
      provider: LOCAL_PROVIDER, model: r.model, purpose, project_id: this.projectId, ok: true, status: 200,
      input_tokens: r.inputTokens, output_tokens: r.outputTokens, duration_ms: r.durationMs, parse_ok: ok,
      tokens_estimated: r.tokensEstimated, pipeline: "v2",
    }))));
    this.logs = [];
  }
}
