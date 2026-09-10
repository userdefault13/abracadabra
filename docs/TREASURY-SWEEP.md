# Runbook: sweep USDC from a project wallet into the abra treasury

**Chain:** Base mainnet (8453) · **Token:** USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (6 decimals)

`abra treasury pay` only sends *out of* the treasury. When a project wallet created with
`abra keygen foundry <project>` has accumulated USDC (x402 refunds, leftover top-ups, revenue)
and the treasury is running low, move it back with two `cast` transactions signed by keys
that never leave the vault except as a process argument.

## Wallets involved

| Role | Vault project · var | Key in vault? |
|------|---------------------|---------------|
| Destination: abra treasury | `__abra_treasury__` · `TREASURY_ADDRESS` / `TREASURY_PRIVATE_KEY` | yes |
| Source: project signer | `<project>` · `EVM_ADDRESS` / `EVM_PRIVATE_KEY` (or `_1`, `_2`, … suffixes) | yes |
| Project receiver | `<project>` · `PAY_TO_ADDRESS` | only if it equals a signer address |

`abra keygen foundry <project> --pay-to` sets `PAY_TO_ADDRESS` to the generated signer, so it is
sweepable. If `PAY_TO_ADDRESS` was later pointed at an external wallet, nothing in the vault can
sign for it and USDC sent there is stranded. **Check before assuming a receiver is sweepable:**

```sh
abra ls <project>        # names + public addresses; secrets stay masked
```

If the receiver is not a vault-held address, repoint `PAY_TO_ADDRESS` at the treasury address
(`abra treasury address`) or at the project signer, and redeploy whatever reads it.

## Prerequisites

- Foundry `cast` on PATH (`cast --version`)
- `abra` CLI with the vault unlocked; Touch ID available
- Public RPC `https://mainnet.base.org` is fine (or set `ABRA_TREASURY_RPC`)

## Step 0 — check balances (no Touch ID)

```sh
PROJECT=myproj
RPC=https://mainnet.base.org
USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
SRC=$(abra ls $PROJECT | awk '$1=="EVM_ADDRESS"{print $2}')
DST=$(abra treasury address)

abra treasury status                                          # treasury USDC + ETH
cast call $USDC 'balanceOf(address)(uint256)' $SRC --rpc-url $RPC   # source USDC, base units
cast balance $SRC --rpc-url $RPC -e                           # source ETH (often 0)
```

`balanceOf` returns base units: `246000` = 0.246 USDC.

## Step 1 — gas top-up (only if source ETH is 0)

x402 payer wallets usually hold no ETH because EIP-3009 payments are relayed. A plain ERC-20
transfer needs gas, so send a sliver from the treasury. A USDC transfer on Base costs well under
0.000001 ETH; 0.00002 ETH (`20000000000000` wei) is a comfortable margin.

```sh
cast send $SRC --value 20000000000000 --rpc-url $RPC \
  --private-key "$(abra get __abra_treasury__ TREASURY_PRIVATE_KEY)"
```

Touch ID prompts once. Wait for `status 1 (success)` in the receipt.

## Step 2 — transfer the USDC

Use the exact `balanceOf` value from step 0 to sweep everything.

```sh
AMOUNT=246000
cast send $USDC 'transfer(address,uint256)' $DST $AMOUNT --rpc-url $RPC \
  --private-key "$(abra get $PROJECT EVM_PRIVATE_KEY)"
```

Touch ID prompts once. The receipt should show `status 1 (success)` and a single `Transfer`
log from `$SRC` to `$DST`.

## Step 3 — verify

```sh
abra treasury status                                          # USDC increased
cast call $USDC 'balanceOf(address)(uint256)' $SRC --rpc-url $RPC   # 0
```

A little ETH dust remains in the signer wallet. Leave it; it covers the next sweep.

## Notes and gotchas

- **Secret hygiene.** `$(abra get …)` hands the key to `cast` as an argument on your own
  machine; it never appears in the receipt. Do not `echo` it, log it, or paste receipts that
  contain it (they don't). Command substitution strips the trailing newline, so no `-n` flag
  is needed.
- **Agent sessions.** Agents running under a permission classifier are typically blocked from
  `cast send` with a vault private key. Let the agent do steps 0 and 3; run steps 1 and 2
  yourself (in Claude Code, the `!` prefix runs a command in-session so receipts land in the
  conversation).
- **Multiple wallets.** `abra keygen foundry <project> -n 3` stores `EVM_ADDRESS_1…3` /
  `EVM_PRIVATE_KEY_1…3`. Repeat steps 0–3 per suffix.
- **Gasless alternative.** Base USDC implements EIP-3009 `transferWithAuthorization`: the source
  signs an authorization offline and the treasury (which has ETH) relays it, skipping step 1.
  Not worth the signing complexity at small amounts.
- **Other chains.** Swap the USDC address and RPC. The treasury tooling (`abra treasury status`
  / `pay`) is Base-only.
