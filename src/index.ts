#!/usr/bin/env node
import { Command } from "commander";
import { registerProjectCommands, listProjects, listVars, setVar, getVar, removeVar } from "./commands/crud.js";
import { runCommand } from "./commands/run.js";
import { printEnv } from "./commands/env.js";
import { registerConnectCommands } from "./commands/connect.js";
import { registerUsbCommands } from "./commands/usb.js";
import { registerKeyCommands } from "./commands/keys.js";
import { keygen } from "./commands/keygen.js";
import { updateCommand } from "./commands/update.js";
import { cmdDoctor } from "./commands/doctor.js";
import { cmdActivate, cmdLicenseStatus, cmdLicenseClear } from "./commands/activate.js";
import {
  cmdCartridgeEnsure,
  cmdCartridgeStatus,
  cmdCartridgeCheckpoint,
  cmdCartridgeRules,
} from "./commands/cartridge.js";
import { cmdLock, cmdUnlock, cmdUnlockStatus } from "./commands/unlock.js";
import { maybePromptForUpdate } from "./core/update.js";
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
registerUsbCommands(program);
registerKeyCommands(program);

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
    await maybePromptForUpdate(version);
    const { assertLicensed } = await import("./license/index.js");
    await assertLicensed();
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
  .description("Generate credentials locally (providers: foundry, cloudflare, ssh); stores them in the project")
  .option("--pay-to", "also set PAY_TO_ADDRESS to the first generated address")
  .option("-n, --count <number>", "number of wallets/keys to generate", "1")
  .option("--comment <text>", "ssh: key comment (default: project@hostname)")
  .option("--perms <list>", "cloudflare: comma-separated permission groups", "Workers Scripts Edit,Account Settings Read")
  .option("--expires-in <days>", "cloudflare: expire the token after N days", "0")
  .option("--account <id>", "cloudflare: account ID (default: from connection)")
  .action(keygen);

program
  .command("mcp")
  .description("Run the abracadabra MCP server (stdio) for AI agents")
  .action(async () => {
    const { assertLicensed } = await import("./license/index.js");
    await assertLicensed();
    const { startMcpServer } = await import("./mcp/server.js");
    await startMcpServer();
  });

program
  .command("activate [wallet]")
  .description("Activate abracadabra with a wallet holding an Abra License NFT on Base")
  .option("--challenge", "print a sign-in message for future wallet-proof flow")
  .action(async (wallet: string | undefined, opts: { challenge?: boolean }) => {
    await cmdActivate(wallet, opts);
  });

const license = program.command("license").description("Abra License NFT activation status");

license
  .command("status")
  .description("Show license activation and on-chain verification")
  .option("--json", "JSON output")
  .action(async (opts: { json?: boolean }) => {
    await cmdLicenseStatus(opts.json);
  });

license
  .command("clear")
  .description("Remove local activation (requires ABRA_SKIP_LICENSE=1)")
  .action(cmdLicenseClear);

const cartridge = program.command("cartridge").description("Aarcade cartridge — cloud metadata checkpoints");

cartridge
  .command("rules")
  .description("Fetch abracadabra cartridge rules manifest from Aarcade")
  .action(cmdCartridgeRules);

cartridge
  .command("ensure [wallet]")
  .description("Mint or fetch your abracadabra cartridge (Abra License NFT when enforced)")
  .action(async (wallet?: string) => {
    await cmdCartridgeEnsure(wallet);
  });

cartridge
  .command("status")
  .description("Show local + remote cartridge snapshot")
  .action(cmdCartridgeStatus);

cartridge
  .command("checkpoint")
  .description("Sign and save a vault metadata checkpoint (no secret values)")
  .option("--wallet <0x>", "license wallet (default: activated wallet)")
  .option("--label <text>", "checkpoint label")
  .option("--signature <0x>", "pre-signed checkpoint message")
  .option("--dry-run", "print gameState + sign message only")
  .action(async (opts: { wallet?: string; label?: string; signature?: string; dryRun?: boolean }) => {
    await cmdCartridgeCheckpoint(opts);
  });

program
  .command("doctor")
  .description("Environment checklist (platform, keystore, vault)")
  .action(cmdDoctor);

program
  .command("unlock")
  .description("Unlock passphrase-file keystore (ABRA_KEYSTORE=passphrase-file)")
  .action(cmdUnlock);

program
  .command("lock")
  .description("Clear in-memory unlock session (passphrase-file keystore)")
  .action(cmdLock);

program
  .command("unlock-status")
  .description("Exit 0 if passphrase vault session is active")
  .action(cmdUnlockStatus);

program
  .command("update")
  .description("Check for or install abracadabra updates (CDN or npm)")
  .option("--check", "print current vs latest only")
  .option("--apply", "install without prompting")
  .option("--force", "bypass the 24h update cache")
  .action(async (opts: { check?: boolean; apply?: boolean; force?: boolean }) => {
    await updateCommand(opts, version);
  });

// no subcommand → launch TUI (fall back to the API server when stdin
// isn't a terminal, e.g. backgrounded via `npm run dev:all` or piped)
if (process.argv.length <= 2) {
  if (!process.stdin.isTTY) {
    console.error("⚠ no TTY — skipping interactive TUI, starting the API server instead");
    const { startServer } = await import("./api/server.js");
    await startServer();
  } else {
    await maybePromptForUpdate(version);
    const { assertLicensed } = await import("./license/index.js");
    await assertLicensed();
    const { startTui } = await import("./tui/start.js");
    startTui();
  }
} else {
  await program.parseAsync().catch((err: unknown) => {
    console.error(`✗ ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
