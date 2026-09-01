import {
  ERC721_BALANCE_OF_SELECTOR,
  licenseContractAddress,
  licenseRpcUrl,
  normalizeAddress,
} from "./config.js";

function encodeBalanceOf(owner: string): string {
  const addr = normalizeAddress(owner).slice(2);
  return ERC721_BALANCE_OF_SELECTOR + addr.padStart(64, "0");
}

function parseUint256Hex(hex: string): bigint {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!h || h === "0") return 0n;
  return BigInt(`0x${h}`);
}

export async function fetchNftBalance(
  wallet: string,
  opts?: { contract?: string; rpcUrl?: string },
): Promise<bigint> {
  const contract = opts?.contract ?? licenseContractAddress();
  if (!contract) {
    throw new Error("ABRA_LICENSE_NFT is not set — license verification unavailable");
  }
  const rpc = opts?.rpcUrl ?? licenseRpcUrl();
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_call",
    params: [{ to: contract, data: encodeBalanceOf(wallet) }, "latest"],
  };
  const res = await fetch(rpc, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const json = (await res.json()) as { result?: string; error?: { message?: string } };
  if (json.error?.message) throw new Error(`RPC error: ${json.error.message}`);
  if (!json.result) throw new Error("RPC returned empty result");
  return parseUint256Hex(json.result);
}

export async function walletHoldsLicense(wallet: string): Promise<boolean> {
  const balance = await fetchNftBalance(wallet);
  return balance > 0n;
}
