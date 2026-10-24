import { SimulatorProvider } from "./simulator.ts";
import { CloudflareWorkerProvider } from "./cloudflare-provider.ts";
import type { HoneypotProvider, ProviderId } from "./types.ts";

/**
 * Returns the simulator provider (no credentials needed).
 */
export function getSimulatorProvider(): HoneypotProvider {
  return new SimulatorProvider();
}

/**
 * Returns the cloud honeypot provider backed by Cloudflare Workers.
 * Requires the user's Cloudflare API token and account ID.
 */
export function getCloudProvider(apiToken: string, accountId: string, ingestUrl: string): CloudflareWorkerProvider {
  return new CloudflareWorkerProvider(apiToken, accountId, ingestUrl);
}

/**
 * Returns a provider for a given honeypot row.
 * For the simulator, no credentials are needed.
 * For cloud honeypots, the caller must supply Cloudflare credentials.
 */
export function getProvider(id: ProviderId, cloudCreds?: { apiToken: string; accountId: string; ingestUrl: string }): HoneypotProvider {
  if (id === "simulator") return new SimulatorProvider();
  if (id === "cloud" && cloudCreds) {
    return new CloudflareWorkerProvider(cloudCreds.apiToken, cloudCreds.accountId, cloudCreds.ingestUrl);
  }
  if (id === "cloud") {
    throw new Error("Cloud deployment requires Cloudflare credentials. Connect a Cloudflare integration in Architect first.");
  }
  throw new Error(`Provider "${id}" is not configured. Only the simulator and cloud (Cloudflare) providers are available.`);
}
