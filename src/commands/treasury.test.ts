import { describe, expect, it } from "vitest";
import {
  DEFAULT_GAS_TOPUP_ETH,
  MIN_SOURCE_GAS_WEI,
  formatEthWei,
  formatUsdcUnits,
  parseEthAmount,
  parseUsdcAmount,
  planRefill,
  refillAuthReason,
} from "./treasury.js";

describe("amount parsing/formatting", () => {
  it("parses USDC to 6-decimal base units", () => {
    expect(parseUsdcAmount("0.008")).toBe(8000n);
    expect(parseUsdcAmount("1")).toBe(1_000_000n);
    expect(() => parseUsdcAmount("0.0000001")).toThrow(/decimal places/);
    expect(() => parseUsdcAmount("0")).toThrow(/greater than zero/);
    expect(() => parseUsdcAmount("abc")).toThrow(/Invalid USDC/);
  });

  it("parses ETH to wei", () => {
    expect(parseEthAmount(DEFAULT_GAS_TOPUP_ETH)).toBe(20_000_000_000_000n);
    expect(parseEthAmount("1")).toBe(10n ** 18n);
  });

  it("formats round-trip", () => {
    expect(formatUsdcUnits(246000n)).toBe("0.246");
    expect(formatUsdcUnits(0n)).toBe("0.0");
    expect(formatEthWei(MIN_SOURCE_GAS_WEI)).toBe("0.000005");
  });
});

describe("planRefill", () => {
  const eth = (s: string) => parseEthAmount(s);

  it("sweeps the full balance without a top-up when source has gas", () => {
    const plan = planRefill({
      sourceUsdc: 10_000n,
      sourceEthWei: eth("0.00002"),
      treasuryEthWei: eth("0.001"),
      gasTopupEth: DEFAULT_GAS_TOPUP_ETH,
    });
    expect(plan).toEqual({ amountUnits: 10_000n, needsTopup: false, topupWei: 0n });
  });

  it("schedules a top-up when source ETH is below the floor", () => {
    const plan = planRefill({
      sourceUsdc: 246_000n,
      sourceEthWei: 0n,
      treasuryEthWei: eth("0.001"),
      gasTopupEth: DEFAULT_GAS_TOPUP_ETH,
    });
    expect(plan).toEqual({ amountUnits: 246_000n, needsTopup: true, topupWei: eth("0.00002") });
  });

  it("honours an explicit partial amount", () => {
    const plan = planRefill({
      sourceUsdc: 246_000n,
      sourceEthWei: eth("0.00002"),
      treasuryEthWei: 0n,
      amountUsdc: "0.1",
    });
    expect(plan.amountUnits).toBe(100_000n);
  });

  it("rejects amounts above the source balance", () => {
    expect(() =>
      planRefill({ sourceUsdc: 1000n, sourceEthWei: eth("1"), treasuryEthWei: 0n, amountUsdc: "1" }),
    ).toThrow(/cannot refill/);
  });

  it("fails when top-up is needed but disabled", () => {
    expect(() =>
      planRefill({ sourceUsdc: 1000n, sourceEthWei: 0n, treasuryEthWei: eth("1") }),
    ).toThrow(/top-up is disabled/);
  });

  it("fails when the treasury cannot afford the top-up plus its own gas", () => {
    expect(() =>
      planRefill({
        sourceUsdc: 1000n,
        sourceEthWei: 0n,
        treasuryEthWei: eth("0.00003"),
        gasTopupEth: DEFAULT_GAS_TOPUP_ETH,
      }),
    ).toThrow(/not enough to send/);
  });
});

describe("refillAuthReason", () => {
  it("mentions project, amount and optional top-up", () => {
    const base = { project: "myproj", from: "0xabc", amountUsdc: "0.246" };
    expect(refillAuthReason(base)).toBe(
      "abracadabra treasury: refill 0.246 USDC from myproj 0xabc",
    );
    expect(refillAuthReason({ ...base, topupEth: "0.00002" })).toContain(
      "(+0.00002 ETH gas top-up from treasury)",
    );
  });
});
