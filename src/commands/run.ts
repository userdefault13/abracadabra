import { spawn } from "node:child_process";
import { loadVault, assertProject } from "../core/vault.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

interface RunOptions {
  project?: string;
  keys?: string;
}

export async function runCommand(options: RunOptions, command: { args: string[] }): Promise<void> {
  const args = command.args;
  // first operand is the project unless given via --project
  let projectName = options.project;
  let cmdArgs = args;
  if (!projectName) {
    if (args.length === 0) {
      console.error("Usage: abra run <project> [--keys K1,K2] -- <cmd> [args...]");
      process.exit(1);
    }
    projectName = args[0];
    cmdArgs = args.slice(1);
  }

  if (cmdArgs[0] === "--") cmdArgs = cmdArgs.slice(1);
  if (cmdArgs.length === 0) {
    console.error("No command given. Usage: abra run <project> -- <cmd> [args...]");
    process.exit(1);
  }

  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);

    const filter = options.keys
      ? new Set(options.keys.split(",").map((k) => k.trim()).filter(Boolean))
      : null;

    const injected: Record<string, string> = {};
    for (const [key, entry] of Object.entries(project.vars)) {
      if (filter && !filter.has(key)) continue;
      injected[key] = entry.value;
    }
    if (filter) {
      for (const key of filter) {
        if (!(key in project.vars)) {
          console.error(`✗ Var not found in ${projectName}: ${key}`);
          process.exit(1);
        }
      }
    }

    console.error(dim(`▸ injecting ${Object.keys(injected).length} var(s) from ${projectName}`));

    const child = spawn(cmdArgs[0], cmdArgs.slice(1), {
      stdio: "inherit",
      env: { ...process.env, ...injected },
    });

    child.on("error", (err) => {
      console.error(`✗ Failed to start command: ${err.message}`);
      process.exit(127);
    });

    child.on("exit", (code, signal) => {
      if (signal) process.kill(process.pid, signal);
      else process.exit(code ?? 0);
    });
  } catch (err) {
    console.error(`✗ ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
