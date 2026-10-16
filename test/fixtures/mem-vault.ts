import { vi } from "vitest";
import { VAULT_UNCHANGED, type Vault, type VaultMutator } from "../../src/core/vault.js";

/**
 * In-memory stand-in for loadVault/updateVault with updateVault's semantics
 * (fresh copy per mutation, VAULT_UNCHANGED skips the write). `writes` counts
 * persisted vaults so tests can assert "no write" / "one write".
 */
export function memVault(initial: Vault = { version: 1, projects: {}, connections: {} }) {
  let stored: Vault = structuredClone(initial);
  const writes = vi.fn((v: Vault) => {
    stored = structuredClone(v);
  });
  const updateVault = vi.fn(async (mutator: VaultMutator): Promise<Vault> => {
    const draft = structuredClone(stored);
    const out = await mutator(draft);
    if (out === VAULT_UNCHANGED) return structuredClone(stored);
    writes(out ?? draft);
    return structuredClone(stored);
  });
  return {
    loadVault: async () => structuredClone(stored),
    updateVault,
    writes,
    stored: () => stored,
    set: (v: Vault) => {
      stored = structuredClone(v);
    },
  };
}
