#!/usr/bin/env node
/**
 * One-shot scrypt timing for passphrase-file H1 (not part of the vitest suite).
 * Usage: node scripts/bench-scrypt-kdf.mjs
 */
import crypto from "node:crypto";

function derive(N, label) {
  const salt = crypto.randomBytes(16);
  const t0 = performance.now();
  crypto.scryptSync("bench-passphrase!!", salt, 32, {
    N,
    r: 8,
    p: 1,
    maxmem: Math.max(256 * 1024 * 1024, 128 * N * 8),
  });
  const ms = performance.now() - t0;
  console.log(`${label}: ${ms.toFixed(1)} ms`);
  return ms;
}

derive(16384, "v1 N=2^14 (16384)");
derive(131072, "v2 N=2^17 (131072)");
