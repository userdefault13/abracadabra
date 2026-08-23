import { Command } from "commander";
import { loadVault, saveVault, assertProject } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { prompt, promptHidden } from "../core/prompt.js";
import { authenticate, biometricsSkipped } from "../auth/touchid.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

function mask(value: string): string {
  if (value.length <= 4) return "••••";
  return `${value.slice(0, 2)}${"•".repeat(8)}${value.slice(-2)}`;
}

export async function listProjects(): Promise<void> {
  try {
    const vault = await loadVault();
    const names = Object.keys(vault.projects).sort();
    if (names.length === 0) {
      console.log(dim("No projects yet. Try: abra project new <name>"));
      return;
    }
    for (const name of names) {
      const count = Object.keys(vault.projects[name].vars).length;
      console.log(`${bold(name)} ${dim(`(${count} var${count === 1 ? "" : "s"})`)}`);
    }
  } catch (err) {
    fail(err);
  }
}

export function registerProjectCommands(program: Command): void {
  const project = program
    .command("project")
    .description("Manage projects");

  project
    .command("new <name>")
    .description("Create a new project")
    .action(async (name: string) => {
      try {
        const vault = await loadVault();
        if (vault.projects[name]) fail(`Project already exists: ${name}`);
        vault.projects[name] = { createdAt: Date.now(), vars: {} };
        await saveVault(vault);
        console.log(green(`✓ Created project ${bold(name)}`));
      } catch (err) {
        fail(err);
      }
    });

  project
    .command("rm <name>")
    .description("Delete a project and all its variables")
    .action(async (name: string) => {
      try {
        const vault = await loadVault();
        assertProject(vault, name);
        const answer = await prompt(
          `Delete project "${name}" and all its vars? [y/N] `,
        );
        if (answer.trim().toLowerCase() !== "y") {
          console.log(dim("Aborted"));
          return;
        }
        delete vault.projects[name];
        await saveVault(vault);
        console.log(green(`✓ Deleted project ${name}`));
      } catch (err) {
        fail(err);
      }
    });

  project
    .command("ls")
    .description("List projects")
    .action(listProjects);
}

export async function listVars(name: string): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, name);
    const keys = Object.keys(project.vars).sort();
    if (keys.length === 0) {
      console.log(dim(`No vars in ${name}. Try: abra set ${name} KEY`));
      return;
    }
    const width = Math.max(...keys.map((k) => k.length));
    for (const key of keys) {
      const entry = project.vars[key];
      const value = entry.secret ? mask(entry.value) : entry.value;
      console.log(
        `${key.padEnd(width)}  ${value}  ${entry.secret ? dim("[secret]") : ""}`,
      );
    }
  } catch (err) {
    fail(err);
  }
}

interface SetOptions {
  visible?: boolean;
  secret?: boolean;
  stdin?: boolean;
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (c) => chunks.push(c));
    process.stdin.on("end", () =>
      resolve(Buffer.concat(chunks).toString("utf8").replace(/\n$/, "")),
    );
    process.stdin.on("error", reject);
  });
}

export async function setVar(projectName: string, key: string, opts: SetOptions): Promise<void> {
  try {
    const vault: Vault = await loadVault();
    let project = vault.projects[projectName];
    if (!project) {
      project = { createdAt: Date.now(), vars: {} };
      vault.projects[projectName] = project;
      console.log(green(`✓ Created project ${bold(projectName)}`));
    }
    const existing = project.vars[key];
    const isSecret = existing ? existing.secret : opts.secret !== false;
    const value = opts.stdin
      ? await readStdin()
      : isSecret && !opts.visible
        ? await promptHidden(`Value for ${key} ${dim("(hidden input)")}: `)
        : await prompt(`Value for ${key}: `);
    if (!value) fail("Empty value");
    project.vars[key] = { value, secret: isSecret, updatedAt: Date.now() };
    await saveVault(vault);
    console.log(green(`✓ ${existing ? "Updated" : "Added"} ${key} in ${projectName}`));
  } catch (err) {
    fail(err);
  }
}

export async function getVar(projectName: string, key: string): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);
    const entry = project.vars[key];
    if (!entry) fail(`Var not found: ${key} in ${projectName}`);
    await authenticate(`abracadabra: reveal ${projectName}/${key}`);
    process.stdout.write(entry.value);
  } catch (err) {
    fail(err);
  }
}

export async function removeVar(projectName: string, key: string): Promise<void> {
  try {
    const vault = await loadVault();
    const project = assertProject(vault, projectName);
    if (!project.vars[key]) fail(`Var not found: ${key} in ${projectName}`);
    delete project.vars[key];
    await saveVault(vault);
    console.log(green(`✓ Deleted ${key} from ${projectName}`));
  } catch (err) {
    fail(err);
  }
}
