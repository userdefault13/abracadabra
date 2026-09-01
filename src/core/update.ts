import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { ABRA_DIR } from "./paths.js";
import { isNewerSemver } from "./semver.js";
import { prompt } from "./prompt.js";

const DEFAULT_CDN_LATEST =
  process.env.ABRA_CDN_LATEST ?? "https://cdn.aarcadeghst.com/releases/abracadabra/latest.json";
const DEFAULT_WWW_LATEST =
  process.env.ABRA_WWW_LATEST ?? "https://www.aarcadeghst.com/releases/abracadabra/latest.json";
const DEFAULT_GITHUB_LATEST =
  process.env.ABRA_GITHUB_LATEST ??
  "https://raw.githubusercontent.com/userdefault13/abracadabra/main/releases/latest.json";
const NPM_PACKAGE = "@userdefault/abracadabra";
const CACHE_FILE = path.join(ABRA_DIR, "update-cache.json");
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

export type ReleaseManifest = {
  version: string;
  url?: string;
  notes?: string;
  publishedAt?: string;
};

type UpdateCache = {
  checkedAt: number;
  latestVersion?: string;
  source?: "cdn" | "npm";
};

function readCache(): UpdateCache | null {
  try {
    return JSON.parse(fs.readFileSync(CACHE_FILE, "utf8")) as UpdateCache;
  } catch {
    return null;
  }
}

function writeCache(data: UpdateCache): void {
  fs.mkdirSync(ABRA_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CACHE_FILE, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
}

async function fetchJson(url: string, timeoutMs = 5000): Promise<unknown | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function parseManifest(raw: unknown): ReleaseManifest | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.version !== "string" || !o.version.trim()) return null;
  return {
    version: o.version.trim(),
    url: typeof o.url === "string" ? o.url : undefined,
    notes: typeof o.notes === "string" ? o.notes : undefined,
    publishedAt: typeof o.publishedAt === "string" ? o.publishedAt : undefined,
  };
}

async function fetchCdnLatest(): Promise<ReleaseManifest | null> {
  for (const url of [DEFAULT_CDN_LATEST, DEFAULT_WWW_LATEST, DEFAULT_GITHUB_LATEST]) {
    const raw = await fetchJson(url);
    const parsed = parseManifest(raw);
    if (parsed) return parsed;
  }
  return null;
}

async function fetchNpmLatest(): Promise<ReleaseManifest | null> {
  const raw = await fetchJson(`https://registry.npmjs.org/${NPM_PACKAGE}/latest`);
  const parsed = parseManifest(raw);
  if (parsed) return parsed;
  if (raw && typeof raw === "object" && typeof (raw as { version?: string }).version === "string") {
    return { version: (raw as { version: string }).version };
  }
  return null;
}

export async function resolveLatestRelease(): Promise<{ manifest: ReleaseManifest; source: "cdn" | "npm" } | null> {
  const cdn = await fetchCdnLatest();
  if (cdn) return { manifest: cdn, source: "cdn" };
  const npm = await fetchNpmLatest();
  if (npm) return { manifest: npm, source: "npm" };
  return null;
}

export type UpdateCheckResult = {
  currentVersion: string;
  latestVersion: string;
  source: "cdn" | "npm";
  manifest: ReleaseManifest;
  updateAvailable: boolean;
};

export async function checkForUpdate(
  currentVersion: string,
  opts: { force?: boolean } = {},
): Promise<UpdateCheckResult | null> {
  const cache = readCache();
  const force = opts.force || process.env.ABRA_UPDATE_CHECK === "always";
  if (!force && cache?.latestVersion && Date.now() - cache.checkedAt < CHECK_INTERVAL_MS) {
    if (isNewerSemver(cache.latestVersion, currentVersion)) {
      return {
        currentVersion,
        latestVersion: cache.latestVersion,
        source: cache.source ?? "npm",
        manifest: { version: cache.latestVersion },
        updateAvailable: true,
      };
    }
    return null;
  }

  const latest = await resolveLatestRelease();
  if (!latest) return null;

  writeCache({
    checkedAt: Date.now(),
    latestVersion: latest.manifest.version,
    source: latest.source,
  });

  if (!isNewerSemver(latest.manifest.version, currentVersion)) return null;

  return {
    currentVersion,
    latestVersion: latest.manifest.version,
    source: latest.source,
    manifest: latest.manifest,
    updateAvailable: true,
  };
}

function npmGlobalAvailable(): boolean {
  return spawnSync("npm", ["--version"], { encoding: "utf8", stdio: "ignore" }).status === 0;
}

export async function applyUpdate(manifest: ReleaseManifest, source: "cdn" | "npm"): Promise<boolean> {
  if (source === "npm" || !manifest.url?.endsWith(".pkg")) {
    if (!npmGlobalAvailable()) {
      console.error("✗ npm not found — install Node/npm or download from CDN");
      if (manifest.url) console.error(`  ${manifest.url}`);
      return false;
    }
    console.log(`→ npm install -g ${NPM_PACKAGE}@${manifest.version}`);
    const r = spawnSync("npm", ["install", "-g", `${NPM_PACKAGE}@${manifest.version}`], {
      stdio: "inherit",
      encoding: "utf8",
    });
    if (r.status === 0) {
      console.log("✓ updated — restart abra to use the new version");
      return true;
    }
    return false;
  }

  if (process.platform !== "darwin") {
    console.error("✗ .pkg installs are macOS only");
    console.error(`  download: ${manifest.url}`);
    return false;
  }

  const answer = (await prompt("Download installer in browser? [Y/n]: ")).trim().toLowerCase();
  if (answer && answer !== "y" && answer !== "yes") return false;

  spawnSync("open", [manifest.url], { stdio: "inherit" });
  console.log("✓ opened installer — complete setup, then restart abra");
  return true;
}

export async function maybePromptForUpdate(currentVersion: string): Promise<void> {
  if (process.env.ABRA_SKIP_UPDATE_CHECK === "1") return;
  if (!process.stdin.isTTY || !process.stdout.isTTY) return;

  const pending = await checkForUpdate(currentVersion);
  if (!pending) return;

  console.log(`\n✦ Update available: ${pending.currentVersion} → ${pending.latestVersion}`);
  if (pending.manifest.notes) console.log(`  ${pending.manifest.notes}`);
  const answer = (await prompt("Install update before continuing? [y/N]: ")).trim().toLowerCase();
  if (answer !== "y" && answer !== "yes") {
    console.log("  continuing with current version\n");
    return;
  }

  const ok = await applyUpdate(pending.manifest, pending.source);
  if (ok && pending.source === "npm") process.exit(0);
}
