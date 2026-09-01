import { loadVault, assertProject } from "../core/vault.js";
import { authenticate } from "../platform/index.js";

function shQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

export async function printEnv(
  projectName: string,
  opts: { keys?: string },
): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);

    const filter = opts.keys
      ? new Set(opts.keys.split(",").map((k) => k.trim()).filter(Boolean))
      : null;

    const selected = Object.keys(project.vars).filter(
      (k) => !filter || filter.has(k),
    );
    if (filter) {
      for (const k of filter) {
        if (!(k in project.vars)) throw new Error(`Var not found in ${projectName}: ${k}`);
      }
    }
    if (selected.length === 0) return;

    // dumping secrets into the shell deserves the same gate as `get`
    await authenticate(`abracadabra: export ${selected.length} var(s) from "${projectName}"`);

    for (const key of selected) {
      console.log(`export ${key}=${shQuote(project.vars[key].value)}`);
    }
  } catch (err) {
    console.error(`✗ ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
