/** Aarcade cartridge sim game id for abracadabra. */
export const ABRA_CARTRIDGE_GAME_ID = "abracadabra";

export function cartridgeApiBase(): string {
  const raw =
    process.env.ABRA_CARTRIDGE_API?.trim() ||
    process.env.AARCADE_CARTRIDGE_API?.trim() ||
    "https://www.aarcadeghst.com/api/cartridge-sim";
  return raw.replace(/\/$/, "");
}
