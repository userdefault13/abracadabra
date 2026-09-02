# abracadabra × Aarcade cartridge

`gameId`: **`abracadabra`**

Cloud checkpoints carry **vault metadata only** (project names, var counts, license wallet) — never secret values. USB backup remains the path for full vault portability.

## Why

- Bind your Abra License wallet to an Aarcade memory card
- Sync project index across machines without exposing secrets
- Same cartridge platform as GotchiBot / Gotchiverse (SIM today, on-chain later)

## CLI

```bash
# Rules manifest (public)
abra cartridge rules

# Mint/fetch cartridge (requires Abra License NFT when ABRA_LICENSE_NFT is set on server)
abra cartridge ensure 0xYourWallet

# Push signed checkpoint
abra cartridge checkpoint --dry-run    # preview sign message
abra cartridge checkpoint --label "after-onboard"

# Inspect
abra cartridge status
```

Local state: `~/.abracadabra/cartridge.json`

## Env

| Variable | Purpose |
|----------|---------|
| `ABRA_CARTRIDGE_API` | Override sim API (default `https://www.aarcadeghst.com/api/cartridge-sim`) |
| `ABRA_CHECKPOINT_PRIVATE_KEY` | Optional — `cast wallet sign` for headless checkpoint (dev only) |

## AarcadeGh-t registration

Fixtures live in AarcadeGh-t:

- `fixtures/abracadabra-rules-v1.json`
- `fixtures/abracadabra-checkpoint-schema-v1.json`
- `fixtures/abracadabra-cartridge-v1.json`

Registered in `lib/cartridgeSim.cjs` + `CARTRIDGE_ENABLED_GAME_IDS`.

Server auth: when `ABRA_LICENSE_NFT` / `VITE_ABRA_LICENSE_NFT` is set, `POST /cartridges/ensure` for `gameId: abracadabra` requires `balanceOf(wallet) >= 1` on that contract.

## Related

- [ABRACADABRA-DIST.md](https://github.com/userdefault13/AarcadeGh-t/blob/main/docs/ABRACADABRA-DIST.md) — NFT + CDN
- GotchiBot cartridge: `gameId: gotchibot` (separate SKU)
