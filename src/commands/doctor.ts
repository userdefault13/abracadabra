import { existsSync } from "node:fs";
import { vaultFile } from "../core/paths.js";
import { platformHealth, platformInfo } from "../platform/index.js";

const ok = (msg: string) => console.log(`ok    ${msg}`);
const warn = (msg: string) => console.log(`warn  ${msg}`);
const fail = (msg: string) => console.log(`fail  ${msg}`);

export async function cmdDoctor(): Promise<void> {
  let fails = 0;
  const info = platformInfo();

  ok(`platform ${info.platform}`);
  ok(`keystore backend ${info.keystore}`);
  ok(`auth backend ${info.auth}`);
  if (info.biometricsSkipped) warn("ABRA_SKIP_BIOMETRICS / ABRA_AUTH=none — no approval prompts");

  const vault = vaultFile();
  if (existsSync(vault)) {
    ok(`vault ${vault}`);
  } else {
    warn(`no vault yet (${vault}) — run: abra project new <name>`);
  }

  if (info.keystore === "passphrase-file") {
    if (info.vaultLocked) {
      warn("passphrase vault locked — run: abra unlock");
    } else {
      ok("passphrase vault session unlocked");
    }
  }

  if (info.keystore === "keytar") {
    const health = await platformHealth();
    if (health.keytar?.ok) {
      ok("keytar credential store reachable");
    } else {
      warn(`keytar unavailable: ${health.keytar?.detail ?? "unknown"}`);
      warn("fallback: export ABRA_KEYSTORE=passphrase-file");
      fails++;
    }
  }

  if (info.keystore === "macos-keychain" && process.platform !== "darwin") {
    fail("macos-keychain selected on non-macOS");
    fails++;
  }

  if (fails > 0) process.exit(1);
}
