export interface ChatResult {
  content: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
}

interface ChatOptions {
  messages: { role: "system" | "user" | "assistant"; content: string }[];
  temperature: number;
  maxTokens: number;
  jsonMode?: boolean;
  timeoutMs: number;
}

export async function chatCompletion(opts: ChatOptions): Promise<ChatResult> {
  const apiKey = Deno.env.get("OPENAI_API_KEY");
  const providers = [
    ...(apiKey ? [{ url: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini", auth: "Bearer " + apiKey }] : []),
    { url: "https://text.pollinations.ai/openai", model: "openai", auth: "" },
  ];
  const failures: string[] = [];
  for (const p of providers) {
    try {
      const resp = await fetch(p.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(p.auth ? { Authorization: p.auth } : {}) },
        body: JSON.stringify({
          model: p.model,
          temperature: opts.temperature,
          max_tokens: opts.maxTokens,
          ...(opts.jsonMode && p.auth ? { response_format: { type: "json_object" } } : {}),
          messages: opts.messages,
        }),
        signal: AbortSignal.timeout(opts.timeoutMs),
      });
      if (!resp.ok) {
        failures.push(`${p.model} ${resp.status}`);
        continue;
      }
      const data = await resp.json();
      const content = String(data?.choices?.[0]?.message?.content ?? "");
      if (!content.trim()) {
        failures.push(`${p.model} empty`);
        continue;
      }
      return {
        content,
        model: p.model,
        inputTokens: Number(data?.usage?.prompt_tokens) || 0,
        outputTokens: Number(data?.usage?.completion_tokens) || 0,
      };
    } catch (err) {
      failures.push(`${p.model} ${err instanceof Error ? err.message : "error"}`);
    }
  }
  throw new Error("AI provider error: " + failures.join(" | "));
}
