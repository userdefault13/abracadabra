import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Every vault.enc write must go through updateVault()/withVaultLock(). This
 * scans non-test sources for the low-level writers outside the files that
 * implement them.
 */

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Low-level writer → files (relative to src/) allowed to reference it. */
const ALLOWED: Record<string, string[]> = {
  saveVault: ["core/vault.ts"],
  saveVaultDirect: ["core/vault.ts"],
  writeEncryptedVaultFile: ["core/vault.ts"],
  writeEncryptedFile: ["core/vault.ts"],
  saveVaultViaAgent: ["core/vault.ts", "agent/client.ts", "agent/index.ts"],
  agentVaultSave: ["agent/client.ts", "agent/index.ts"],
  // abra-agent's vault.save / inbox writes; both take or verify the lock themselves.
  saveVaultFileForClient: ["core/vault.ts", "agent/server.ts"],
  updateVaultFile: ["core/vault.ts", "agent/server.ts"],
};

/** Allowed anywhere, but only lexically inside a withVaultLock(…) callback. */
const NEEDS_WITH_LOCK = ["writeRestoredVault"];

const RAW_FS_WRITE = /\b(?:writeFileSync|writeFile|renameSync|rename|copyFileSync|copyFile|appendFileSync|appendFile|createWriteStream|rmSync|unlinkSync)\s*\(/;
const VAULT_PATH_REF = /\bvaultFile\s*\(|\bvaultPath\s*\(|["'`][^"'`]*vault\.enc["'`]/;

function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");
}

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return sourceFiles(full);
    if (!/\.(ts|tsx)$/.test(e.name) || /\.test\.tsx?$/.test(e.name)) return [];
    return [full];
  });
}

/** Index of the `(` that opens the innermost unclosed call before `pos`, if its callee is `name`. */
function insideCallTo(code: string, pos: number, name: string): boolean {
  let depth = 0;
  for (let i = pos - 1; i >= 0; i--) {
    const c = code[i];
    if (c === ")") depth++;
    else if (c === "(") {
      if (depth === 0) {
        if (code.slice(0, i).trimEnd().endsWith(name)) return true;
      } else depth--;
    }
  }
  return false;
}

export function findViolations(rel: string, source: string): string[] {
  const code = stripComments(source);
  const out: string[] = [];
  const lineOf = (i: number) => code.slice(0, i).split("\n").length;
  for (const [name, files] of Object.entries(ALLOWED)) {
    if (files.includes(rel)) continue;
    for (const m of code.matchAll(new RegExp(`\\b${name}\\b`, "g"))) {
      out.push(`${rel}:${lineOf(m.index!)} references ${name} — use updateVault()/withVaultLock()`);
    }
  }
  if (rel !== "core/vault.ts") {
    for (const name of NEEDS_WITH_LOCK) {
      for (const m of code.matchAll(new RegExp(`\\b${name}\\s*\\(`, "g"))) {
        if (!insideCallTo(code, m.index!, "withVaultLock")) {
          out.push(`${rel}:${lineOf(m.index!)} calls ${name} outside withVaultLock()`);
        }
      }
    }
    code.split("\n").forEach((line, i) => {
      if (RAW_FS_WRITE.test(line) && VAULT_PATH_REF.test(line)) {
        out.push(`${rel}:${i + 1} raw fs write to vault.enc`);
      }
    });
  }
  return out;
}

describe("vault write guard", () => {
  it("no source file writes vault.enc outside updateVault/withVaultLock", () => {
    const violations = sourceFiles(SRC).flatMap((f) =>
      findViolations(path.relative(SRC, f).split(path.sep).join("/"), fs.readFileSync(f, "utf8")),
    );
    expect(violations).toEqual([]);
  });

  it("the scanner catches each kind of violation (self-check)", () => {
    const bad = [
      `import { saveVault } from "../core/vault.js";`,
      `await saveVault(v);`,
      `writeEncryptedVaultFile(enc);`,
      `const restored = writeRestoredVault(v, key);`,
      `fs.writeFileSync(vaultFile(), data);`,
      `fs.renameSync(tmp, path.join(dir, "vault.enc"));`,
    ].join("\n");
    const found = findViolations("commands/evil.ts", bad);
    expect(found).toEqual([
      expect.stringContaining(":1 references saveVault"),
      expect.stringContaining(":2 references saveVault"),
      expect.stringContaining(":3 references writeEncryptedVaultFile"),
      expect.stringContaining(":4 calls writeRestoredVault outside withVaultLock"),
      expect.stringContaining(":5 raw fs write"),
      expect.stringContaining(":6 raw fs write"),
    ]);

    const ok = [
      `// saveVault(v) in a comment is fine`,
      `await withVaultLock(async () => {`,
      `  await restoreMasterKey(k);`,
      `  const restored = writeRestoredVault(v, key);`,
      `});`,
      `await updateVault((v) => { v.projects.x = p; });`,
    ].join("\n");
    expect(findViolations("commands/fine.ts", ok)).toEqual([]);
  });
});
