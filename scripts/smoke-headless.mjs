#!/usr/bin/env node
/**
 * F3 — headless CLI smoke: set → run → env (passphrase-file, isolated ABRA_DIR)
 * G2 — USB bundle restore on a fresh ABRA_DIR (Linux passphrase-file path)
 * S1 — abra sync whoami/peers; restore drops the origin sync identity
 * S2 — abra sync inbox/accept; restore drops inbox settings + accept policy
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const ABBR = join(ROOT, "dist", "index.js");
// ESM import() needs file:// URLs — raw absolute paths break on Windows (C:\…).
const distUrl = (...parts) => pathToFileURL(join(ROOT, "dist", ...parts)).href;
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

async function g2Smoke(originEnv, bundlePath, originIdentityId) {
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

    log("S1", "restore drops the origin's sync identity + peers");
    const peersR = runAbra(["sync", "peers", "--json"], envB);
    assertOk(peersR, "abra sync peers (restored)");
    if (JSON.parse(peersR.stdout).length !== 0) die("restored vault kept sync peers");
    const whoR = runAbra(["sync", "whoami", "--json"], envB);
    assertOk(whoR, "abra sync whoami (restored)");
    const who = JSON.parse(whoR.stdout);
    if (!who.created || who.id === originIdentityId) die("restored vault reused the origin sync identity");

    log("S2", "restore drops the origin's sync inbox settings + accept policy");
    const statusR = runAbra(["sync", "inbox", "--status", "--json"], envB);
    assertOk(statusR, "abra sync inbox --status (restored)");
    if (JSON.parse(statusR.stdout).enabled !== false) die("restored vault kept the sync inbox setting");
    const rulesR = runAbra(["sync", "accept", "--list", "--json"], envB);
    assertOk(rulesR, "abra sync accept --list (restored)");
    if (JSON.parse(rulesR.stdout).length !== 0) die("restored vault kept sync accept rules");
  } finally {
    rmSync(homeB, { recursive: true, force: true });
  }
}

function syncIdentitySmoke(env) {
  log("S1", "abra sync whoami creates an identity once");
  const first = runAbra(["sync", "whoami", "--json"], env);
  assertOk(first, "abra sync whoami");
  const a = JSON.parse(first.stdout);
  const second = runAbra(["sync", "whoami", "--json"], env);
  assertOk(second, "abra sync whoami (again)");
  const b = JSON.parse(second.stdout);
  if (!a.created || b.created || a.id !== b.id) die("sync whoami did not persist a stable identity");
  if (/privateKey/.test(first.stdout + second.stdout)) die("sync whoami printed private key material");

  log("S2", "abra sync inbox / accept (headless, no peers)");
  const emptyR = runAbra(["sync", "inbox", "--json"], env);
  assertOk(emptyR, "abra sync inbox --json");
  if (JSON.parse(emptyR.stdout).length !== 0) die("fresh inbox is not empty");
  assertOk(runAbra(["sync", "inbox", "--enable", "--bind", "127.0.0.1", "--port", "7444"], env), "abra sync inbox --enable");
  assertOk(runAbra(["sync", "accept", "-p", PROJECT, "--auto"], env), "abra sync accept --auto");
  const statusR = runAbra(["sync", "inbox", "--status", "--json"], env);
  assertOk(statusR, "abra sync inbox --status");
  const status = JSON.parse(statusR.stdout);
  if (status.enabled !== true || status.bind !== "127.0.0.1" || status.port !== 7444 || status.listening !== false) {
    die(`unexpected inbox status ${statusR.stdout}`);
  }
  return a.id;
}

async function main() {
  const homeA = mkdtempSync(join(tmpdir(), "abra-smoke-a-"));
  const abraDirA = join(homeA, ".abracadabra");
  const envA = isolatedEnv(homeA, abraDirA);
  const bundlePath = join(homeA, "migrate.abrabak");

  try {
    f3Smoke(envA);
    const originIdentityId = syncIdentitySmoke(envA);

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

    const { loadVault, encryptVault } = await import(distUrl("core", "vault.js"));
    const { getMasterKey, resetPlatformForTests } = await import(distUrl("platform", "index.js"));
    const { sealBundle } = await import(distUrl("core", "backup.js"));
    resetPlatformForTests();

    const vault = await loadVault();
    const masterKey = await getMasterKey();
    // Raw encryptVault (not ForExport): mimics an older bundle that still carries the sync identity.
    const bundle = sealBundle(encryptVault(vault, masterKey), masterKey, BUNDLE_PASS);
    writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), { mode: 0o600 });

    await g2Smoke(envA, bundlePath, originIdentityId);
  } catch (err) {
    die(err instanceof Error ? `${err.message}\n${err.stack}` : String(err));
  } finally {
    rmSync(homeA, { recursive: true, force: true });
  }

  console.log("[smoke] OK — F3 + G2 + S1 + S2 passed");
}

main().catch((e) => die(e?.message || String(e)));
