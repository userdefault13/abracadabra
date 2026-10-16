/**
 * Test-only harness for src/core/vault-concurrency.test.ts: one writer process
 * adding `count` vars named `<prefix>_<i>` to project "race" in its ABRA_DIR.
 *
 *   node --import tsx test/fixtures/vault-writer.ts <locked|naive> <prefix> <count> <syncDir>
 *
 * locked — updateVault (read-modify-write under the vault lock).
 * naive  — the pre-lock pattern: loadVault, a short gap (a prompt or network
 *          wait in real commands), then save the stale copy. The write itself
 *          is still under the lock; only the read is outside it.
 *
 * Writers report "ready-<prefix>" in syncDir after unlocking, then wait for
 * "go" so all of them contend at once.
 */
import fs from "node:fs";
import path from "node:path";
import { loadVault, saveVault, updateVault, withVaultLock, type Vault } from "../../src/core/vault.js";

const [mode, prefix, countArg, syncDir] = process.argv.slice(2);
const count = Number(countArg);
const LOCK = { timeoutMs: 120_000 };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function addVar(v: Vault, name: string): void {
  v.projects.race ??= { createdAt: Date.now(), vars: {} };
  v.projects.race.vars[name] = { value: `v-${name}`, secret: false, updatedAt: Date.now() };
}

if ((mode !== "locked" && mode !== "naive") || !prefix || !(count > 0) || !syncDir) {
  process.stderr.write("usage: vault-writer.ts <locked|naive> <prefix> <count> <syncDir>\n");
  process.exit(2);
}

await loadVault();
fs.writeFileSync(path.join(syncDir, `ready-${prefix}`), "");
while (!fs.existsSync(path.join(syncDir, "go"))) await sleep(5);

for (let i = 0; i < count; i++) {
  const name = `${prefix}_${i}`;
  if (mode === "locked") {
    await updateVault((v) => addVar(v, name), LOCK);
  } else {
    const v = await loadVault();
    addVar(v, name);
    await sleep(5 + Math.random() * 10);
    await withVaultLock(() => saveVault(v), LOCK);
  }
}
process.exit(0);
