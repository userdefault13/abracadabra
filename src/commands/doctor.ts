import { existsSync } from "node:fs";
import { vaultFile } from "../core/paths.js";
import { platformHealth, platformInfo } from "../platform/index.js";
import { getLicenseStatus, licenseContractAddress } from "../license/index.js";

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

  const licContract = licenseContractAddress();
  if (licContract) {
    ok(`license contract ${licContract}`);
    const lic = await getLicenseStatus();
    if (lic.skip) warn("ABRA_SKIP_LICENSE=1 — NFT gate disabled");
    else if (!lic.activated) warn("license not activated — run: abra activate <wallet>");
    else if (lic.onChainOk) ok(`license activated ${lic.wallet}`);
    else if (lic.onChainOk === false) {
      warn(`license invalid on-chain for ${lic.wallet}`);
      fails++;
    } else warn("license on-chain check failed (RPC)");
  } else {
    warn("ABRA_LICENSE_NFT unset — commercial license gate off");
  }

  if (fails > 0) process.exit(1);
}
