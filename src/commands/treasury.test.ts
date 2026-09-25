import { describe, expect, it } from "vitest";
import {
  DEFAULT_GAS_TOPUP_ETH,
  ETH_PAY_GAS_RESERVE_WEI,
  MIN_SOURCE_GAS_WEI,
  castSend,
  formatEthWei,
  formatUsdcUnits,
  parseEthAmount,
  parseUsdcAmount,
  paymentAuthReason,
  planRefill,
  planTreasuryPayment,
  refillAuthReason,
} from "./treasury.js";

const TREASURY = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";

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
    expect(parseEthAmount("0.0006")).toBe(600_000_000_000_000n);
    expect(() => parseEthAmount("0.0000000000000000001")).toThrow(/decimal places/);
    expect(() => parseEthAmount("0")).toThrow(/greater than zero/);
  });

  it("formats round-trip", () => {
    expect(formatUsdcUnits(246000n)).toBe("0.246");
    expect(formatUsdcUnits(0n)).toBe("0.0");
    expect(formatEthWei(MIN_SOURCE_GAS_WEI)).toBe("0.000005");
    expect(ETH_PAY_GAS_RESERVE_WEI).toBe(MIN_SOURCE_GAS_WEI);
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

describe("paymentAuthReason", () => {
  it("keeps the USDC reason string identical (default asset)", () => {
    expect(
      paymentAuthReason({ to: OTHER, amount: "0.008", reason: "cron402 bazaar settle" }),
    ).toBe(`abracadabra treasury: pay 0.008 USDC to ${OTHER} — cron402 bazaar settle`);
  });

  it("formats the ETH auth reason", () => {
    expect(
      paymentAuthReason({
        to: OTHER,
        amount: "0.0006",
        reason: "gas top-up",
        asset: "eth",
      }),
    ).toBe(`abracadabra treasury: pay 0.0006 ETH to ${OTHER} — gas top-up`);
  });
});

describe("planTreasuryPayment", () => {
  const eth = (s: string) => parseEthAmount(s);

  it("defaults asset to usdc", () => {
    const plan = planTreasuryPayment({
      to: OTHER,
      amount: "0.008",
      reason: "test",
      treasuryAddress: TREASURY,
      ethBalanceWei: eth("0.001"),
      usdcBalanceUnits: 10_000n,
    });
    expect(plan.asset).toBe("usdc");
    expect(plan.amountUnits).toBe(8000n);
    expect(plan.reserveWei).toBe(0n);
  });

  it("rejects invalid assets", () => {
    expect(() =>
      planTreasuryPayment({
        asset: "btc" as "usdc",
        to: OTHER,
        amount: "1",
        reason: "x",
        treasuryAddress: TREASURY,
        ethBalanceWei: 0n,
      }),
    ).toThrow(/Unsupported asset/);
  });

  it("rejects missing reason", () => {
    expect(() =>
      planTreasuryPayment({
        to: OTHER,
        amount: "0.008",
        reason: "  ",
        treasuryAddress: TREASURY,
        ethBalanceWei: eth("1"),
      }),
    ).toThrow(/--reason is required/);
  });

  it("rejects invalid --to", () => {
    expect(() =>
      planTreasuryPayment({
        to: "not-an-address",
        amount: "0.008",
        reason: "x",
        treasuryAddress: TREASURY,
        ethBalanceWei: eth("1"),
      }),
    ).toThrow(/Invalid destination/);
  });

  it("rejects self-address (mixed case)", () => {
    expect(() =>
      planTreasuryPayment({
        to: "0x1111111111111111111111111111111111111111".toUpperCase().replace("0X", "0x"),
        amount: "0.008",
        reason: "x",
        treasuryAddress: TREASURY,
        ethBalanceWei: eth("1"),
        usdcBalanceUnits: 1_000_000n,
      }),
    ).toThrow(/own address/);

    expect(() =>
      planTreasuryPayment({
        asset: "eth",
        to: "0xAbCdEf1111111111111111111111111111111111",
        amount: "0.0001",
        reason: "x",
        treasuryAddress: "0xabcdef1111111111111111111111111111111111",
        ethBalanceWei: eth("1"),
      }),
    ).toThrow(/own address/);
  });

  it("ETH reserve: exactly balance - reserve passes; 1 wei over fails", () => {
    const reserve = ETH_PAY_GAS_RESERVE_WEI;
    const balance = eth("0.001");
    const exact = balance - reserve;
    const plan = planTreasuryPayment({
      asset: "eth",
      to: OTHER,
      amount: formatEthWei(exact),
      reason: "exact",
      treasuryAddress: TREASURY,
      ethBalanceWei: balance,
    });
    expect(plan.amountUnits).toBe(exact);
    expect(plan.ethBalanceAfterWei).toBe(reserve);

    expect(() =>
      planTreasuryPayment({
        asset: "eth",
        to: OTHER,
        amount: formatEthWei(exact + 1n),
        reason: "over",
        treasuryAddress: TREASURY,
        ethBalanceWei: balance,
      }),
    ).toThrow(/gas reserve/);
  });

  it("rejects USDC when balance is insufficient", () => {
    expect(() =>
      planTreasuryPayment({
        to: OTHER,
        amount: "1",
        reason: "x",
        treasuryAddress: TREASURY,
        ethBalanceWei: eth("1"),
        usdcBalanceUnits: 100n,
      }),
    ).toThrow(/cannot pay/);
  });
});

describe("castSend keystore env (mocked exec)", () => {
  const throwawayKey = "0x" + "ab".repeat(32);

  it("never puts key or password on argv; sets ETH_KEYSTORE/ETH_PASSWORD; strips inherited signer env", async () => {
    let captured: { args: readonly string[]; env: NodeJS.ProcessEnv } | null = null;
    const tx = {
      transactionHash: "0x" + "cd".repeat(32),
      status: 1,
    };
    const hash = await castSend(["0x2222222222222222222222222222222222222222", "--value", "1"], throwawayKey, {
      exec: async (_cmd, args, options) => {
        captured = { args, env: options.env };
        return { stdout: JSON.stringify(tx), stderr: "" };
      },
    });
    expect(hash).toBe(tx.transactionHash);
    expect(captured).not.toBeNull();
    const argvJoined = captured!.args.join(" ");
    expect(argvJoined).not.toMatch(/private-key/i);
    expect(argvJoined).not.toContain(throwawayKey);
    expect(argvJoined).not.toContain(throwawayKey.slice(2));
    expect(captured!.args).toContain("send");
    expect(captured!.args).toContain("--json");
    expect(captured!.env.ETH_KEYSTORE).toBeTruthy();
    expect(captured!.env.ETH_PASSWORD).toBeTruthy();
    expect(captured!.env.ETH_FROM).toBeUndefined();
    expect(captured!.env.ETH_PRIVATE_KEY).toBeUndefined();
    expect(captured!.env.ETH_KEYSTORE_ACCOUNT).toBeUndefined();
    // password must not appear as argv value
    for (const a of captured!.args) {
      expect(a).not.toBe(captured!.env.ETH_PASSWORD);
    }
  });

  it("removes the temp dir after success and after failure", async () => {
    const { promises: fs } = await import("node:fs");
    let keystorePath = "";
    await castSend(["0x2222222222222222222222222222222222222222", "--value", "1"], throwawayKey, {
      exec: async (_cmd, _args, options) => {
        keystorePath = options.env.ETH_KEYSTORE!;
        await fs.access(keystorePath);
        return {
          stdout: JSON.stringify({ transactionHash: "0x" + "11".repeat(32), status: 1 }),
          stderr: "",
        };
      },
    });
    await expect(fs.access(keystorePath)).rejects.toThrow();

    let failPath = "";
    await expect(
      castSend(["0x2222222222222222222222222222222222222222", "--value", "1"], throwawayKey, {
        exec: async (_cmd, _args, options) => {
          failPath = options.env.ETH_KEYSTORE!;
          await fs.access(failPath);
          const err = new Error(`boom key=${throwawayKey} path=${failPath}`) as Error & {
            stderr: string;
          };
          err.stderr = `revert ${throwawayKey} @ ${failPath}`;
          throw err;
        },
      }),
    ).rejects.toThrow(/\[redacted/);
    await expect(fs.access(failPath)).rejects.toThrow();
  });

  it("scrubs secrets from castSend errors", async () => {
    await expect(
      castSend(["0x2222222222222222222222222222222222222222", "--value", "1"], throwawayKey, {
        exec: async (_cmd, _args, options) => {
          const err = new Error("x") as Error & { stderr: string };
          err.stderr = `failed key=${throwawayKey} bare=${throwawayKey.slice(2)} ks=${options.env.ETH_KEYSTORE}`;
          throw err;
        },
      }),
    ).rejects.toSatisfy((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      expect(msg).not.toContain(throwawayKey);
      expect(msg).not.toContain(throwawayKey.slice(2));
      expect(msg).toMatch(/\[redacted-key\]/);
      expect(msg).toMatch(/\[redacted-path\]/);
      return true;
    });
  });
});
