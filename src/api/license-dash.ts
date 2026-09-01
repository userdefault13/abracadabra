import type { ServerResponse } from "node:http";
import { send } from "./http-utils.js";
import { isEthAddress } from "../license/config.js";
import {
  getLicenseStatus,
  fetchNftBalance,
  writeActivation,
} from "../license/index.js";

/** GET /api/license/status — public (pre passkey auth). */
export async function licenseStatus(res: ServerResponse): Promise<void> {
  const status = await getLicenseStatus();
  send(res, 200, status);
}

/** POST /api/license/activate { wallet } — public; verifies NFT on Base. */
export async function licenseActivate(
  body: Record<string, unknown>,
  res: ServerResponse,
): Promise<void> {
  const wallet = String(body.wallet ?? "").trim();
  if (!isEthAddress(wallet)) {
    send(res, 400, { error: "invalid wallet address" });
    return;
  }
  try {
    const balance = await fetchNftBalance(wallet);
    if (balance <= 0n) {
      send(res, 403, {
        error: "no Abra License NFT for this wallet",
        mintUrl: "https://www.aarcadeghst.com/concierge/terminal",
      });
      return;
    }
    const record = writeActivation({ wallet, balance });
    send(res, 200, { ok: true, activation: record, balance: balance.toString() });
  } catch (err) {
    send(res, 502, {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
