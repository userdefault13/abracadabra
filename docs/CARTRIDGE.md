# abracadabra × Aarcade cartridge

`gameId`: **`abracadabra`**

Cloud checkpoints carry **vault metadata** by default (project names, var counts, license wallet). With `abra cartridge checkpoint --full`, a **passphrase-sealed** `BackupBundle` (vault + master key) is included — same crypto as USB backup. Plaintext secrets are never uploaded.

## Why

- Bind your Abra License wallet to an Aarcade memory card
- Sync project index across machines without exposing secrets (default)
- Optionally port the full vault through a sealed checkpoint (`--full` / `restore`)
- Same cartridge platform as GotchiBot / Gotchiverse (SIM today, on-chain later)

## CLI

```bash
# Rules manifest (public)
abra cartridge rules

# Mint/fetch cartridge (requires Abra License NFT when ABRA_LICENSE_NFT is set on server)
abra cartridge ensure 0xYourWallet

# Metadata-only checkpoint
abra cartridge checkpoint --dry-run
abra cartridge checkpoint --label "after-onboard"

# Full vault (prompts for passphrase; schemaVersion 2 + sealedVault)
abra cartridge checkpoint --full

# Restore from latest full checkpoint (overwrites local vault + master key)
abra cartridge restore

# Inspect (includes hasSealedVault)
abra cartridge status
```

Local state: `~/.abracadabra/cartridge.json`

## Checkpoint schemas

| Version | Contents |
|---------|----------|
| `1` | Metadata only (backward compatible) |
| `2` | Metadata + optional `sealedVault` (`abracadabra-backup` bundle) |

Aarcade sim/fixtures may need a v2 schema update to accept `sealedVault`; until then, servers that reject unknown fields will error on `--full`.

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
