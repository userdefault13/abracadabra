import { describe, expect, it } from "vitest";
import { detectWalletPairs } from "./rotate-wallet.js";
import type { Project } from "../core/vault.js";

function proj(vars: Record<string, string>): Project {
  const now = Date.now();
  return {
    createdAt: now,
    vars: Object.fromEntries(
      Object.entries(vars).map(([k, value]) => [
        k,
        { value, secret: /KEY/i.test(k), updatedAt: now },
      ]),
    ),
  };
}

describe("detectWalletPairs", () => {
  it("finds canonical EVM pair", () => {
    const pairs = detectWalletPairs(
      proj({
        EVM_ADDRESS: "0xabc",
        EVM_PRIVATE_KEY: "0xdead",
      }),
    );
    expect(pairs).toHaveLength(1);
    expect(pairs[0].privateKeyVar).toBe("EVM_PRIVATE_KEY");
    expect(pairs[0].legacyPrivateKeyVar).toBe("EVM_PRIVATE_KEY_LEGACY");
  });

  it("finds Aarcade-style prefixed pair", () => {
    const pairs = detectWalletPairs(
      proj({
        AARCADEGHST_PRIVATE_KEY: "0xdead",
        AARCADEGHST_WALLET_ADDRESS: "0x8842",
      }),
    );
    expect(pairs.some((p) => p.privateKeyVar === "AARCADEGHST_PRIVATE_KEY")).toBe(true);
    const p = pairs.find((x) => x.privateKeyVar === "AARCADEGHST_PRIVATE_KEY")!;
    expect(p.addressVar).toBe("AARCADEGHST_WALLET_ADDRESS");
    expect(p.legacyPrivateKeyVar).toBe("AARCADEGHST_PRIVATE_KEY_LEGACY");
  });

  it("skips SSH and treasury", () => {
    const pairs = detectWalletPairs(
      proj({
        SSH_PRIVATE_KEY: "x",
        TREASURY_PRIVATE_KEY: "y",
      }),
    );
    expect(pairs).toHaveLength(0);
  });
});
