import crypto from "node:crypto";

/** Failed PIN attempts before a LAN host / pairing listener locks. */
export const PIN_MAX_FAILURES = 8;

/** Uniform 6-digit session PIN. */
export function generatePin(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

export function timingSafePin(expected: Buffer, provided: string): boolean {
  const got = Buffer.from(provided.normalize("NFKC"), "utf8");
  if (got.length !== expected.length) {
    crypto.timingSafeEqual(expected, expected);
    return false;
  }
  return crypto.timingSafeEqual(expected, got);
}
