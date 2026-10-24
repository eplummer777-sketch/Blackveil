import { normalizeHostname } from "../_lib/net.ts";

const ALLOWED_PORTS = new Set(["", "443", "8080", "8443", "8090"]);

export type Result<T> = { value: T } | { error: string };

export function validateInstanceUrl(input: unknown): Result<string> {
  const raw = typeof input === "string" ? input.trim() : "";
  if (!raw) return { error: "Enter the scanner address." };
  if (raw.length > 300) return { error: "The address is too long." };
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { error: "Enter a full address starting with https://" };
  }
  if (u.protocol !== "https:") return { error: "The scanner address must use https:// so the API key is encrypted in transit." };
  if (u.username || u.password) return { error: "The address must not contain a username or password." };
  if (u.search || u.hash) return { error: "Use only the server address, without ? or # parts." };
  if (u.pathname !== "/" && u.pathname !== "") return { error: "Use only the server root (for example https://zap.example.com), without a path." };
  if (!ALLOWED_PORTS.has(u.port)) return { error: "Only ports 443, 8080, 8443 and 8090 are allowed." };
  const host = normalizeHostname(u.hostname);
  if (!host) return { error: "Use a public host name. IP addresses, localhost and internal names are not allowed." };
  return { value: `https://${host}${u.port ? `:${u.port}` : ""}` };
}

export function validateInstanceName(input: unknown): Result<string> {
  const name = typeof input === "string" ? input.trim().replace(/\s+/g, " ") : "";
  if (!name) return { error: "Give the scanner a name." };
  if (name.length > 60) return { error: "Keep the name under 60 characters." };
  return { value: name };
}

export function validateApiKey(input: unknown): Result<string> {
  const key = typeof input === "string" ? input.trim() : "";
  if (key.length < 16) return { error: "The API key must be at least 16 characters." };
  if (key.length > 200) return { error: "The API key is too long." };
  if (!/^[\x21-\x7e]+$/.test(key)) return { error: "The API key must not contain spaces or special characters." };
  return { value: key };
}

export const keyHint = (key: string) => key.slice(-4);
