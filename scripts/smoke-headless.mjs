#!/usr/bin/env node
/**
 * F3 — headless CLI smoke: set → run → env (passphrase-file, isolated ABRA_DIR)
 * G2 — USB bundle restore on a fresh ABRA_DIR (Linux passphrase-file path)
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const ABBR = join(ROOT, "dist", "index.js");
const PROJECT = "smoke-headless";
const VAR = "SMOKE_HELLO";
const VALUE = "abra-smoke-ok";
const VAULT_PASS = "smoke-vault-passphrase-12";
const BUNDLE_PASS = "smoke-bundle-passphrase-12";

function log(step, msg) {
  console.log(`[smoke] ${step}: ${msg}`);
}

function die(msg, code = 1) {
  console.error(`[smoke] FAIL: ${msg}`);
  process.exit(code);
}

function isolatedEnv(home, abraDir) {
  return {
    HOME: home,
    USERPROFILE: home,
    ABRA_DIR: abraDir,
    ABRA_SKIP_BIOMETRICS: "1",
    ABRA_AUTH: "none",
    ABRA_KEYSTORE: "passphrase-file",
    ABRA_HEADLESS_PASSPHRASE: VAULT_PASS,
  };
}

function runAbra(args, env, { input } = {}) {
  return spawnSync(process.execPath, [ABBR, ...args], {
    env: { ...process.env, ...env },
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function assertOk(r, label) {
  if (r.status !== 0) {
    console.error(r.stdout);
    console.error(r.stderr);
    die(`${label} exited ${r.status ?? "?"}`);
  }
}

function f3Smoke(env) {
  log("F3", "set var via stdin");
  assertOk(
    runAbra(["set", PROJECT, VAR, "--stdin", "--no-secret"], env, { input: VALUE }),
    "abra set",
  );

  log("F3", "abra run injects var");
  assertOk(
    runAbra(
      ["run", PROJECT, "--", process.execPath, "-e", `process.exit(process.env.${VAR}==='${VALUE}'?0:1)`],
      env,
    ),
    "abra run",
  );

  log("F3", "abra env prints export");
  const envR = runAbra(["env", PROJECT, "-k", VAR], env);
  assertOk(envR, "abra env");
  if (!envR.stdout.includes(`export ${VAR}='${VALUE}'`)) {
    die("abra env output missing expected export line");
  }
}

async function g2Smoke(originEnv, bundlePath) {
  log("G2", "fresh ABRA_DIR usb restore");
  const homeB = mkdtempSync(join(tmpdir(), "abra-smoke-b-"));
  const abraDirB = join(homeB, ".abracadabra-restore");
  const envB = {
    ...originEnv,
    HOME: homeB,
    USERPROFILE: homeB,
    ABRA_DIR: abraDirB,
    ABRA_HEADLESS_PASSPHRASE: BUNDLE_PASS,
  };

  try {
    const restoreR = runAbra(["usb", "restore", bundlePath], envB, { input: "yes\n" });
    assertOk(restoreR, "abra usb restore");

    log("G2", "post-restore run uses restored var");
    assertOk(
      runAbra(
        ["run", PROJECT, "--", process.execPath, "-e", `process.exit(process.env.${VAR}==='${VALUE}'?0:1)`],
        envB,
      ),
      "post-restore abra run",
    );
  } finally {
    rmSync(homeB, { recursive: true, force: true });
  }
}

async function main() {
  const homeA = mkdtempSync(join(tmpdir(), "abra-smoke-a-"));
  const abraDirA = join(homeA, ".abracadabra");
  const envA = isolatedEnv(homeA, abraDirA);
  const bundlePath = join(homeA, "migrate.abrabak");

  try {
    f3Smoke(envA);

    log("G2", "seal USB bundle from origin vault");
    assertOk(
      runAbra(["set", PROJECT, "G2_MARKER", "--stdin", "--no-secret"], envA, { input: "present" }),
      "origin marker set",
    );

    process.env.HOME = homeA;
    process.env.ABRA_DIR = abraDirA;
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_HEADLESS_PASSPHRASE = VAULT_PASS;

    const { loadVault, encryptVault } = await import(join(ROOT, "dist/core/vault.js"));
    const { getMasterKey, resetPlatformForTests } = await import(join(ROOT, "dist/platform/index.js"));
    const { sealBundle } = await import(join(ROOT, "dist/core/backup.js"));
    resetPlatformForTests();

    const vault = await loadVault();
    const masterKey = await getMasterKey();
    const bundle = sealBundle(encryptVault(vault, masterKey), masterKey, BUNDLE_PASS);
    writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), { mode: 0o600 });

    await g2Smoke(envA, bundlePath);
  } catch (err) {
    die(err instanceof Error ? `${err.message}\n${err.stack}` : String(err));
  } finally {
    rmSync(homeA, { recursive: true, force: true });
  }

  console.log("[smoke] OK — F3 + G2 passed");
}

main().catch((e) => die(e?.message || String(e)));
