export function requireEnv(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`Missing required secret: ${name}`);
  return value;
}

export function getFrontendUrl(): string {
  const raw = requireEnv("FRONTEND_URL");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("FRONTEND_URL is not a valid URL");
  }
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(isLocal && url.protocol === "http:")) {
    throw new Error("FRONTEND_URL must use https");
  }
  return url.origin;
}
