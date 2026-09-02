import { describe, it, expect } from "vitest";
import { stableStringify, hashGameState, buildCheckpointSignMessage } from "./checkpoint-crypto.js";

describe("cartridge checkpoint crypto", () => {
  it("stableStringify sorts top-level keys like cartridge sim", () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("builds deterministic sign message", () => {
    const gameState = { schemaVersion: 1, abraVersion: "1.0.2" };
    const hash = hashGameState(gameState);
    const msg = buildCheckpointSignMessage({
      cartridgeId: "sim-deadbeef",
      nonce: 1,
      gameState,
    });
    expect(msg).toContain("sim-deadbeef");
    expect(msg).toContain(`stateHash: ${hash}`);
  });
});
