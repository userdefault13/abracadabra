import { describe, expect, it } from "vitest";
import {
  buildSafeTx,
  decodeErc20Transfer,
  describeSafeTx,
  encodeErc20Transfer,
  packSignatures,
  parseAddressArray,
  parseUintOutput,
  planSafePayment,
  safeAppUrl,
  safePayAuthReason,
  serviceTxToSafeTx,
  ZERO_ADDRESS,
} from "./safe.js";
import { BASE_USDC } from "./treasury.js";

const A = "0x000000000000000000000000000000000000000a";
const B = "0x000000000000000000000000000000000000000B";
const C = "0x00000000000000000000000000000000000000c0";
const sig = (n: number) => `0x${n.toString(16).padStart(130, "0")}`;

describe("erc20 transfer calldata", () => {
  it("encodes and decodes round-trip", () => {
    const data = encodeErc20Transfer("0xc015Be7C1ba2618E6A0bc2bB76a4B805aF53121F", 8000n);
    expect(data).toBe(
      "0xa9059cbb000000000000000000000000c015be7c1ba2618e6a0bc2bb76a4b805af53121f0000000000000000000000000000000000000000000000000000000000001f40",
    );
    expect(decodeErc20Transfer(data)).toEqual({
      to: "0xc015be7c1ba2618e6a0bc2bb76a4b805af53121f",
      units: 8000n,
    });
  });

  it("returns null for other calldata", () => {
    expect(decodeErc20Transfer("0x")).toBeNull();
    expect(decodeErc20Transfer("0x095ea7b3" + "0".repeat(128))).toBeNull();
    expect(decodeErc20Transfer("0xa9059cbb" + "0".repeat(100))).toBeNull();
  });
});

describe("cast output parsing", () => {
  it("parses address arrays", () => {
    expect(parseAddressArray(`[${A}, ${B}]\n`)).toEqual([A, B]);
    expect(parseAddressArray("[]")).toEqual([]);
  });
  it("parses uints with scientific suffix and hex", () => {
    expect(parseUintOutput("123 [1.23e2]")).toBe(123n);
    expect(parseUintOutput("0x10")).toBe(16n);
    expect(parseUintOutput("7\n")).toBe(7n);
  });
});

describe("packSignatures", () => {
  it("sorts by owner address ascending and concatenates", () => {
    const packed = packSignatures([
      { owner: C, signature: sig(3) },
      { owner: A, signature: sig(1) },
      { owner: B, signature: sig(2) },
    ]);
    expect(packed).toBe(`0x${sig(1).slice(2)}${sig(2).slice(2)}${sig(3).slice(2)}`);
    expect(packed.length).toBe(2 + 3 * 130);
  });
  it("rejects duplicates and non-EOA signatures", () => {
    expect(() => packSignatures([{ owner: A, signature: sig(1) }, { owner: A.toUpperCase().replace("0X", "0x"), signature: sig(2) }])).toThrow(/Duplicate/);
    expect(() => packSignatures([{ owner: A, signature: "0x1234" }])).toThrow(/Unsupported signature/);
  });
});

describe("planSafePayment", () => {
  it("executes at threshold 1, proposes otherwise", () => {
    expect(planSafePayment(1)).toBe("execute");
    expect(planSafePayment(2)).toBe("propose");
    expect(() => planSafePayment(0)).toThrow(/threshold/);
  });
});

describe("describeSafeTx", () => {
  it("summarises USDC transfers in human units", () => {
    const tx = buildSafeTx({ to: BASE_USDC, data: encodeErc20Transfer(A, 246000n), nonce: 3n });
    expect(describeSafeTx(tx)).toBe(`send 0.246 USDC to ${A}`);
  });
  it("falls back to a generic call description", () => {
    expect(describeSafeTx({ to: B, value: 10n ** 18n, data: "0x", operation: 0 })).toBe(`call ${B} with 1.0 ETH`);
    expect(describeSafeTx({ to: B, value: 0n, data: "0xdeadbeef", operation: 1 })).toBe(`DELEGATECALL ${B} (4 bytes calldata)`);
  });
});

describe("serviceTxToSafeTx", () => {
  it("normalises nulls and numeric strings", () => {
    const tx = serviceTxToSafeTx({
      safe: A, to: BASE_USDC, value: "0", data: null, operation: 0, gasToken: ZERO_ADDRESS,
      safeTxGas: 0, baseGas: "0", gasPrice: "0", refundReceiver: null, nonce: "12",
      safeTxHash: "0x" + "1".repeat(64), isExecuted: false, confirmationsRequired: 2,
    });
    expect(tx).toEqual(buildSafeTx({ to: BASE_USDC, data: "0x", nonce: 12n }));
  });
});

describe("prompts and links", () => {
  it("builds the Safe app queue URL", () => {
    expect(safeAppUrl(A)).toBe(`https://app.safe.global/transactions/queue?safe=base:${A}`);
  });
  it("explains propose mode in the Touch ID reason", () => {
    const r = safePayAuthReason({ safe: A, to: B, amountUsdc: "1.5", reason: "invoice", mode: "propose", threshold: 2 });
    expect(r).toContain("pay 1.5 USDC to");
    expect(r).toContain("sign 1 of 2");
    expect(safePayAuthReason({ safe: A, to: B, amountUsdc: "1.5", reason: "invoice", mode: "execute", threshold: 1 })).not.toContain("sign 1 of");
  });
});
