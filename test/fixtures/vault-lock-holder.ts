/**
 * Test-only harness for src/core/vault-concurrency.test.ts: takes the vault
 * lock in `dir`, prints "held", then either exits without releasing (the
 * process 'exit' hook must clean up) or hangs until the parent kills it.
 *
 *   node --import tsx test/fixtures/vault-lock-holder.ts <dir> <exit|hang>
 */
import { acquireVaultLock } from "../../src/core/vault-lock.js";

const [dir, mode] = process.argv.slice(2);
await acquireVaultLock({ dir });
process.stdout.write("held\n");
if (mode === "exit") process.exit(0);
setInterval(() => {}, 1_000);
