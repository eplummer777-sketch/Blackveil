import { getAuthenticatedUser, getServiceClient } from "../_lib/auth.ts";
import { corsHeaders, errorResponse, json } from "../_lib/cors.ts";
import { quotaMessage, resolveQuota } from "../_lib/ai-quota.ts";
import {
  actionPrompt, extractActions, loadActionContext, MAX_ACTIONS_PER_REPLY, validateAction,
} from "../_lib/assistant-actions.ts";

const SYSTEM_PROMPT = [
  "You are BLACKVEIL AI, a senior defensive cybersecurity assistant built into a premium",
  "cybersecurity platform for individuals and small businesses. You are knowledgeable, precise,",
  "and genuinely helpful — like having a senior security engineer on call.",
  "",
  "VOICE:",
  "- Warm, expert, and confident. Clear and well-structured with short sections, bullet",
  "  points, and plain language. Use markdown (bold, lists, short inline code spans, and",
  "  fenced code blocks for commands/config).",
  "- Be thorough but never bloated. Lead with the direct answer in one or two sentences,",
  "  then add context.",
  "- When a user asks a follow-up, stay in context and build on the conversation.",
  "",
  "ANSWER STRUCTURE (use it whenever a question needs more than a one-line answer):",
  "1. **Direct answer** — one or two sentences that directly answer the question.",
  "2. **Why it matters** — a short paragraph explaining the security impact or context.",
  "3. **What to do** — concrete, numbered steps the user can follow right now.",
  "4. **How to verify** — one or two sentences describing how the user can confirm it worked.",
  "Skip sections that don't apply. Keep each section tight. Do not use the literal section",
  "headers as labels if a one-line answer is enough — apply this structure only when it helps.",
  "",
  "PRINCIPLES:",
  "- Defensive only. Never provide instructions, steps, payloads, or code for attacking,",
  "  exploiting, bypassing authentication, scanning systems without authorization, or any",
  "  offensive activity. If a request is offensive, decline and offer a defensive alternative.",
  "- Never ask for or accept real passwords, credential dumps, private keys, or other",
  "  secrets. If a user pastes one, tell them to rotate it immediately and do not store it.",
  "- You may analyze security logs, configuration files, and headers the user is authorized",
  "  to share. Focus on explaining what you see and recommending defensive fixes.",
  "- Clearly separate what you OBSERVED (present in provided data) from what you INFER",
  "  (your reasoning or hypothesis). Use phrases like 'Based on the headers you shared…'",
  "  versus 'This likely means…'. When you are uncertain, say so explicitly and never",
  "  present estimates as confirmed findings.",
  "- Recommend practical, prioritized remediation. Prefer the simplest reliable fix.",
  "- You are not a substitute for incident response retainers or law enforcement. For",
  "  active breaches, recommend isolating affected systems and contacting qualified",
  "  professionals.",
  "- Never invent product capabilities. If something requires a tool the user does not",
  "  have, say so.",
  "- You can answer general technology questions too, but always bring it back to security",
  "  when relevant.",
  "",
  "CLARIFICATION:",
  "- If a question is too vague to answer usefully (e.g. 'is my site secure?' with no",
  "  further detail), ask ONE focused clarifying question before answering. Do not ask",
  "  multiple questions and do not refuse — offer your best general guidance alongside the",
  "  question.",
  "",
  "URGENCY:",
  "- If the user describes an active attack (ransomware, ongoing breach, account takeover",
  "  in progress, someone actively in their system), begin your answer with a clearly",
  "  marked urgent line in this exact format:",
  "    [URGENT] <one sentence describing the immediate protective action>",
  "  Then continue with the rest of your structured answer.",
].join("\n");

interface ChatMsg {
  role: "user" | "assistant";
  content: string;
}

const MAX_HISTORY = 30;
const MAX_INPUT_CHARS = 16000;

const URGENT_RE = /(\bactive\b|on-?going|\bright now\b|\bbeing attacked\b|ransomware|\bencrypted\b|\bhacked\b|account takeover|unauthorized access|breach in progress|malware right now|currently infected)/i;

function detectSeverity(content: string): "urgent" | "normal" {
  return URGENT_RE.test(content) ? "urgent" : "normal";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  const { user, client, error } = await getAuthenticatedUser(req);
  if (!user) return errorResponse(error ?? "Unauthorized", 401);

  let body: {
    threadId?: string;
    message?: string;
    regenerate?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON", 400);
  }
  const message = (body.message ?? "").trim();
  const isRegenerate = !!body.regenerate;

  if (!isRegenerate) {
    if (!message) return errorResponse("Message is required", 400);
    if (message.length > MAX_INPUT_CHARS) {
      return errorResponse(`Message too long (max ${MAX_INPUT_CHARS} chars)`, 413);
    }
  } else {
    if (!body.threadId) return errorResponse("threadId is required to regenerate", 400);
  }

  const serviceClient = getServiceClient();

  const q = await resolveQuota(serviceClient, user);
  const { plan, remaining } = q;
  if (q.limit > 0 && remaining <= 0) {
    return json({
      error: "quota_reached", plan, limit: q.limit, window: q.window, used: q.used, message: quotaMessage(q),
    }, 429);
  }

  // Resolve or create thread
  let threadId = body.threadId;
  let regenerateUserMessage: string | null = null;

  if (threadId) {
    const { data: owned, error: e } = await client
      .from("chat_threads")
      .select("id")
      .eq("id", threadId)
      .maybeSingle();
    if (e || !owned) return errorResponse("Thread not found", 404);

    if (isRegenerate) {
      // Find the last user message in this thread to re-send
      const { data: lastUser } = await client
        .from("chat_messages")
        .select("content")
        .eq("thread_id", threadId)
        .eq("role", "user")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (!lastUser?.content) {
        return errorResponse("No user message found to regenerate", 400);
      }
      regenerateUserMessage = lastUser.content;
      // Remove the most recent assistant message (the one we're regenerating)
      const { data: lastAssistant } = await client
        .from("chat_messages")
        .select("id")
        .eq("thread_id", threadId)
        .eq("role", "assistant")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (lastAssistant?.id) {
        await client.from("chat_messages").delete().eq("id", lastAssistant.id);
      }
    }
  } else if (!isRegenerate) {
    const title = message.slice(0, 60);
    const { data: thread, error: e } = await client
      .from("chat_threads")
      .insert({ user_id: user.id, title })
      .select("id")
      .single();
    if (e || !thread) return errorResponse("Could not create thread", 500);
    threadId = thread.id;
  } else {
    return errorResponse("Thread not found", 404);
  }

  // Save user message (skip on regenerate — the user message already exists)
  if (!isRegenerate) {
    const { error: insertErr } = await client
      .from("chat_messages")
      .insert({ thread_id: threadId, role: "user", content: message });
    if (insertErr) return errorResponse("Could not store message", 500);
  }

  // Load recent history
  const { data: history } = await client
    .from("chat_messages")
    .select("role, content")
    .eq("thread_id", threadId)
    .order("created_at", { ascending: true })
    .limit(MAX_HISTORY);

  let messages: ChatMsg[] = (history ?? []).map((m) => ({
    role: m.role as "user" | "assistant",
    content: m.content,
  }));

  // If the history is long, fold older messages into a compact summary so the
  // AI stays on-topic without exceeding the context window.
  if (messages.length > 20) {
    const recent = messages.slice(-16);
    const older = messages.slice(0, -16);
    const olderSummary = older
      .map((m) => `${m.role === "user" ? "User" : "Assistant"}: ${m.content.slice(0, 240)}`)
      .join("\n");
    messages = [
      {
        role: "user",
        content:
          "Earlier in this conversation:\n" + olderSummary +
          "\n\n(Pick up the thread from here.)",
      },
      { role: "assistant", content: "Understood — I have the prior context. How can I help next?" },
      ...recent,
    ];
  }

  const apiKey = Deno.env.get("OPENAI_API_KEY");
  const providers = [
    ...(apiKey ? [{
      name: "openai", url: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini",
      headers: { Authorization: "Bearer " + apiKey } as Record<string, string>,
    }] : []),
    { name: "pollinations", url: "https://text.pollinations.ai/openai", model: "openai", headers: {} as Record<string, string> },
  ];
  let provider = providers[0].name;
  let apiUrl = providers[0].url;
  let model = providers[0].model;
  let authHeaders = providers[0].headers;

  const actionCtx = await loadActionContext(serviceClient, user.id, plan);
  const systemContent = SYSTEM_PROMPT + "\n" + actionPrompt(actionCtx);

  const severity = detectSeverity(
    isRegenerate ? (regenerateUserMessage ?? "") : message
  );

  // Stream the response back to the client as SSE
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const emit = (obj: unknown) =>
        controller.enqueue(encoder.encode("data: " + JSON.stringify(obj) + "\n\n"));

      emit({
        type: "meta",
        threadId,
        remaining,
        limit: q.limit,
        plan,
        window: q.window,
        severity,
        regenerate: isRegenerate,
      });

      try {
        let resp: Response | null = null;
        const failures: string[] = [];
        for (const p of providers) {
          const r = await fetch(p.url, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...p.headers },
            body: JSON.stringify({
              model: p.model,
              messages: [{ role: "system", content: systemContent }, ...messages],
              temperature: 0.3,
              max_tokens: 2200,
              stream: true,
              ...(p.name === "openai" ? { stream_options: { include_usage: true } } : {}),
            }),
          });
          if (r.ok) {
            resp = r;
            provider = p.name; apiUrl = p.url; model = p.model; authHeaders = p.headers;
            break;
          }
          failures.push(p.name + " " + r.status + ": " + (await r.text()).slice(0, 300));
        }
        if (failures.length) {
          await serviceClient.from("admin_events").insert({
            kind: "ai_error",
            detail: { user_id: user.id, error: failures.join(" | "), provider: resp ? "fallback:" + provider : "none" },
          });
        }
        if (!resp) throw new Error("All AI providers failed");
        if (!resp.body) throw new Error("No response body");

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let fullContent = "";
        let usage: { prompt_tokens?: number; completion_tokens?: number } | null = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || !trimmed.startsWith("data:")) continue;
            const data = trimmed.slice(5).trim();
            if (data === "[DONE]") continue;
            try {
              const parsed = JSON.parse(data);
              const delta = parsed?.choices?.[0]?.delta?.content;
              if (delta) {
                fullContent += delta;
                emit({ type: "delta", delta });
              }
              if (parsed?.usage) usage = parsed.usage;
            } catch {
              // ignore malformed keep-alive
            }
          }
        }

        // Non-streaming fallback if the provider didn't stream
        if (!fullContent) {
          const fbResp = await fetch(apiUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...authHeaders,
            },
            body: JSON.stringify({
              model,
              messages: [{ role: "system", content: systemContent }, ...messages],
              temperature: 0.3,
              max_tokens: 2200,
            }),
          });
          if (fbResp.ok) {
            const fbData = await fbResp.json();
            fullContent = String(fbData?.choices?.[0]?.message?.content ?? "").trim();
            usage = fbData?.usage ?? null;
            if (fullContent) emit({ type: "delta", delta: fullContent });
          }
        }

        const { clean: content, raw: rawActions } = extractActions(fullContent);
        if (!content && !rawActions.length) {
          throw new Error("AI provider returned an empty response.");
        }
        const uncertain =
          /uncertain|not enough (info|information)|cannot (verify|confirm)|i (can't|cannot) (know|confirm)/i
            .test(content);

        const { data: savedMsg, error: saveErr } = await client.from("chat_messages").insert({
          thread_id: threadId,
          role: "assistant",
          content: content || "Here is what I can do for you. Review the action below and confirm it if you want me to go ahead.",
          uncertain,
        }).select("id").single();
        if (saveErr || !savedMsg) throw new Error("Could not store reply");

        const valid = rawActions
          .map((r) => validateAction(r, actionCtx))
          .filter((a): a is NonNullable<typeof a> => a !== null)
          .slice(0, MAX_ACTIONS_PER_REPLY);
        let actions: unknown[] = [];
        if (valid.length) {
          const { data: inserted } = await serviceClient.from("assistant_actions").insert(
            valid.map((v) => ({
              user_id: user.id, thread_id: threadId, message_id: savedMsg.id,
              kind: v.kind, params: v.params, summary: v.summary,
            })),
          ).select("id, message_id, kind, summary, status, result, created_at, expires_at");
          actions = inserted ?? [];
        }

        await client.from("chat_threads")
          .update({ updated_at: new Date().toISOString() })
          .eq("id", threadId);

        await serviceClient.from("ai_usage").insert({
          user_id: user.id,
          feature: "assistant",
          model,
          input_tokens: usage?.prompt_tokens ?? 0,
          output_tokens: usage?.completion_tokens ?? 0,
          cost_usd: estimateCost(usage, model),
        });

        await serviceClient.from("audit_logs").insert({
          user_id: user.id,
          action: "ai_assistant_message",
          detail: {
            thread_id: threadId,
            provider,
            regenerate: isRegenerate,
            severity,
          },
        });

        emit({
          type: "done",
          threadId,
          messageId: savedMsg.id,
          content,
          actions,
          uncertain,
          severity,
          remaining: remaining === -1 ? -1 : remaining - 1,
          limit: q.limit,
          plan,
          window: q.window,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        await serviceClient.from("admin_events").insert({
          kind: "ai_error",
          detail: { user_id: user.id, error: msg, provider },
        });
        emit({ type: "error", message: "The AI service could not be reached. Please try again in a moment." });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      ...corsHeaders,
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
});

function estimateCost(usage: unknown, model: string): number {
  const u = usage as { prompt_tokens?: number; completion_tokens?: number } | null;
  if (!u) return 0;
  // gpt-4o-mini pricing: $0.15 / 1M input, $0.60 / 1M output (per 1k tokens)
  const inputRate = model === "gpt-4o-mini" ? 0.15 : 0.15;
  const outputRate = model === "gpt-4o-mini" ? 0.6 : 0.6;
  const inp = (u.prompt_tokens ?? 0) / 1_000_000 * inputRate;
  const out = (u.completion_tokens ?? 0) / 1_000_000 * outputRate;
  return Number((inp + out).toFixed(6));
}
