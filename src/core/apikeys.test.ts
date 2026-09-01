import { describe, it, expect } from "vitest";
import { emptyVault } from "./vault.js";
import {
  generateApiKey,
  findValidApiKey,
  apiKeyHasAccess,
  hashKey,
} from "./apikeys.js";

describe("apikeys", () => {
  it("generates keys with abra prefix and stores only hash", () => {
    const { record, fullKey } = generateApiKey("test-agent", ["proj-a"]);
    expect(fullKey).toMatch(/^abra_[0-9a-f]{8}_[A-Za-z0-9_-]+$/);
    expect(record.keyHash).toBe(hashKey(fullKey));
    expect(record.keyHash).not.toBe(fullKey);
    expect(record.projects).toEqual(["proj-a"]);
  });

  it("validates a stored key", () => {
    const vault = emptyVault();
    const { record, fullKey } = generateApiKey("agent", null);
    vault.apiKeys = { [record.id]: record };

    expect(findValidApiKey(vault, fullKey)?.name).toBe("agent");
    expect(findValidApiKey(vault, "abra_deadbeef_notreal")).toBeUndefined();
  });

  it("rejects expired keys", () => {
    const vault = emptyVault();
    const { record, fullKey } = generateApiKey("expired", ["p"], { expiresInDays: -1 });
    record.expiresAt = Date.now() - 1000;
    vault.apiKeys = { [record.id]: record };

    expect(findValidApiKey(vault, fullKey)).toBeUndefined();
  });

  it("enforces project scope", () => {
    const { record } = generateApiKey("scoped", ["allowed"]);
    expect(apiKeyHasAccess(record, "allowed")).toBe(true);
    expect(apiKeyHasAccess(record, "denied")).toBe(false);
    const global = generateApiKey("global", null).record;
    expect(apiKeyHasAccess(global, "anything")).toBe(true);
  });
});
