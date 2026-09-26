import { describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SRC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function collectSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...(await collectSourceFiles(full)));
      continue;
    }
    if (!ent.isFile()) continue;
    if (!/\.(ts|js|mjs)$/.test(ent.name)) continue;
    if (/\.test\.(ts|js|mjs)$/.test(ent.name)) continue;
    out.push(full);
  }
  return out;
}

describe("no private key on cast argv (source scan)", () => {
  it('fails if any non-test file under src/ contains "--private-key"', async () => {
    const files = await collectSourceFiles(SRC_ROOT);
    const hits: string[] = [];
    for (const file of files) {
      const text = await fs.readFile(file, "utf8");
      if (text.includes('"--private-key"')) {
        hits.push(path.relative(SRC_ROOT, file));
      }
    }
    expect(hits).toEqual([]);
  });
});
