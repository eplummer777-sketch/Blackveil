export type PaidPlan = "malware_removal" | "pro" | "elite";

export const PRICE_BY_PLAN: Record<PaidPlan, string> = {
  malware_removal: "price_1UTQ5SLVKDpqUpmAdEYp2mX0",
  pro: "price_1USQJ2LVKDpqUpmADMBODhuL",
  elite: "price_1UTQ7NLVKDpqUpmABVSZq4NR",
};

export function planForPrice(priceId: string | undefined | null): PaidPlan | null {
  const hit = (Object.keys(PRICE_BY_PLAN) as PaidPlan[]).find((p) => PRICE_BY_PLAN[p] === priceId);
  return hit ?? null;
}

export function isLiveKey(key: string): boolean {
  return /^(sk|rk)_live_/.test(key.trim());
}
