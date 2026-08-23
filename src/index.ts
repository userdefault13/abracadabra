#!/usr/bin/env node
import { Command } from "commander";
import { registerProjectCommands, listProjects, listVars, setVar, getVar, removeVar } from "./commands/crud.js";
import { runCommand } from "./commands/run.js";
import { printEnv } from "./commands/env.js";
import { registerConnectCommands } from "./commands/connect.js";
import { keygen } from "./commands/keygen.js";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { name: pkgName, version } = require("../package.json") as {
  name: string;
  version: string;
};

const program = new Command();

program
  .name(pkgName)
  .description("Terminal vault for env vars & passwords")
  .version(version);

registerProjectCommands(program);
registerConnectCommands(program);

program
  .command("ls [project]")
  .description("List projects, or vars within a project")
  .action(async (project?: string) => {
    if (!project) {
      await listProjects();
    } else {
      await listVars(project);
    }
  });

program
  .command("set <project> <key>")
  .description("Add or update a var (hidden input for secrets)")
  .option("--visible", "echo the value while typing / show in ls")
  .option("--no-secret", "store as a non-secret (plain) var")
  .option("--stdin", "read the value from stdin (for scripts)")
  .action(setVar);

program
  .command("get <project> <key>")
  .description("Print a var value to stdout")
  .action(getVar);

program
  .command("rm <project> <key>")
  .description("Delete a var")
  .action(removeVar);

program
  .command("run")
  .description("Run a command with project vars injected into its environment")
  .option("-p, --project <name>", "project (otherwise first argument)")
  .option("-k, --keys <keys>", "comma-separated subset of keys to inject")
  .allowUnknownOption()
  .action(runCommand);

program
  .command("serve")
  .description("Start the local biometric-gated API server + web dash")
  .option("--port <number>", "port to listen on", "7331")
  .option("--open", "open the web dash in your browser")
  .action(async (opts: { port: string; open?: boolean }) => {
    const { startServer } = await import("./api/server.js");
    await startServer(Number(opts.port), opts.open);
  });

program
  .command("env <project>")
  .description("Print export statements for eval: eval $(abra env myproj). Touch ID gated.")
  .option("-k, --keys <keys>", "comma-separated subset of keys to export")
  .action(printEnv);

program
  .command("keygen <provider> <project>")
  .description("Generate credentials locally (providers: foundry); stores them in the project")
  .option("--pay-to", "also set PAY_TO_ADDRESS to the first generated address")
  .option("-n, --count <number>", "number of wallets to generate", "1")
  .action(keygen);

program
  .command("mcp")
  .description("Run the abracadabra MCP server (stdio) for AI agents")
  .action(async () => {
    const { startMcpServer } = await import("./mcp/server.js");
    await startMcpServer();
  });

// no subcommand → launch TUI
if (process.argv.length <= 2) {
  const { startTui } = await import("./tui/start.js");
  startTui();
} else {
  await program.parseAsync().catch((err: unknown) => {
    console.error(`✗ ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
