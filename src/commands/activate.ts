import { prompt } from "../core/prompt.js";
import { isEthAddress } from "../license/config.js";
import {
  getLicenseStatus,
  licenseContractAddress,
  licenseEnforcementSkipped,
  fetchNftBalance,
  writeActivation,
  clearActivation,
  createActivationChallenge,
} from "../license/index.js";

const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(msg: string): never {
  console.error(red(`✗ ${msg}`));
  process.exit(1);
}

export async function cmdActivate(walletArg?: string, opts?: { challenge?: boolean }): Promise<void> {
  const contract = licenseContractAddress();
  if (!contract) {
    fail(
      "ABRA_LICENSE_NFT is not configured — set env to the deployed AbraLicense contract on Base",
    );
  }

  let wallet = walletArg?.trim();
  if (!wallet) {
    wallet = await prompt("Wallet holding Abra License NFT (0x…): ");
    wallet = wallet.trim();
  }
  if (!isEthAddress(wallet)) fail("Invalid wallet address");

  if (opts?.challenge) {
    const challenge = createActivationChallenge(wallet);
    console.log(dim("Sign this message in your wallet (verification in a future release):"));
    console.log(challenge.message);
    console.log("");
  }

  console.error(dim(`▸ checking balanceOf on ${contract} (Base)…`));
  try {
    const balance = await fetchNftBalance(wallet);
    if (balance <= 0n) {
      fail(
        `No Abra License NFT for ${wallet} — mint: https://www.aarcadeghst.com/concierge/terminal`,
      );
    }
    const record = writeActivation({ wallet, balance });
    console.log(green(`✓ Activated for ${record.wallet} (${balance} license NFT(s))`));
    console.log(dim(`  saved ${record.activatedAt}`));
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
}

export async function cmdLicenseStatus(json = false): Promise<void> {
  const status = await getLicenseStatus();
  if (json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  if (status.skip) console.log(dim("license enforcement skipped (ABRA_SKIP_LICENSE=1)"));
  if (!status.contract) {
    console.log(dim("license contract not configured (ABRA_LICENSE_NFT unset) — gate off"));
    return;
  }
  console.log(`license contract: ${status.contract}`);
  console.log(`enforcement: ${status.enforcement ? "on" : "off"}`);
  if (!status.activated) {
    console.log(dim("not activated — run: abra activate <wallet>"));
    process.exit(status.enforcement ? 1 : 0);
  }
  console.log(`wallet: ${status.wallet}`);
  console.log(`activated: ${status.activatedAt}`);
  if (status.onChainOk === true) console.log(green("on-chain: valid"));
  else if (status.onChainOk === false) {
    console.log(red("on-chain: no NFT for stored wallet"));
    process.exit(1);
  } else console.log(dim("on-chain: could not verify (RPC)"));
}

export function cmdLicenseClear(): void {
  if (!licenseEnforcementSkipped()) {
    console.error(red("✗ Refusing to clear license without ABRA_SKIP_LICENSE=1"));
    process.exit(1);
  }
  clearActivation();
  console.log(green("✓ Cleared local license activation"));
}
