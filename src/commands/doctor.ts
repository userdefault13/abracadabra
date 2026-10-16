import {
  existsSync,
  readlinkSync,
  realpathSync,
  accessSync,
  readFileSync as fsReadFileSync,
  constants,
} from "node:fs";
import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { vaultFile, masterKeyFile } from "../core/paths.js";
import { platformHealth, platformInfo } from "../platform/index.js";
import { getLicenseStatus, licenseContractAddress } from "../license/index.js";
import {
  checkUnitNetlink,
  parseUnitEnvironment,
  parseUnitExecStart,
  readInstalledAgentUnit,
} from "../agent/unit-check.js";
import { agentStatus, shouldTryAgent, resolveAgentSocketPath } from "../agent/index.js";
import { isGeneratedLauncher } from "./setup.js";

const execFileAsync = promisify(execFile);

const ok = (msg: string) => console.log(`ok    ${msg}`);
const warn = (msg: string) => console.log(`warn  ${msg}`);
const fail = (msg: string) => console.log(`fail  ${msg}`);
const info = (msg: string) => console.log(`info  ${msg}`);

export type DoctorRunner = (
  cmd: string,
  args: string[],
  opts: { timeout: number },
) => Promise<{ stdout: string; stderr: string; status: number | null }>;

export type DoctorDeps = {
  platform?: NodeJS.Platform;
  pathEnv?: string;
  existsSync?: (p: string) => boolean;
  readlinkSync?: (p: string) => string;
  realpathSync?: (p: string) => string;
  readFileSync?: (p: string, enc: "utf8") => string;
  accessSync?: (p: string, mode?: number) => void;
  whichOnPath?: (name: string, pathEnv: string) => string | null;
  run?: DoctorRunner;
  tryAgent?: () => boolean;
  resolveSocket?: () => string;
  agentStatus?: () => Promise<{ nodePath?: string; entryPath?: string; locked: boolean }>;
  masterKeyExists?: () => boolean;
  configHome?: string;
};

const defaultRun: DoctorRunner = async (cmd, args, opts) => {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      timeout: opts.timeout,
      encoding: "utf8",
      maxBuffer: 256 * 1024,
    });
    return {
      stdout: typeof stdout === "string" ? stdout : String(stdout),
      stderr: typeof stderr === "string" ? stderr : String(stderr),
      status: 0,
    };
  } catch (e) {
    const err = e as {
      status?: number | null;
      code?: string | number;
      stdout?: string;
      stderr?: string;
      killed?: boolean;
    };
    return {
      stdout: typeof err.stdout === "string" ? err.stdout : "",
      stderr: typeof err.stderr === "string" ? err.stderr : "",
      status: typeof err.status === "number" ? err.status : err.killed ? null : 1,
    };
  }
};

function defaultWhich(name: string, pathEnv: string): string | null {
  for (const dir of pathEnv.split(path.delimiter).filter(Boolean)) {
    const c = path.join(dir, name);
    try {
      accessSync(c, constants.X_OK);
      return c;
    } catch {
      /* next */
    }
  }
  return null;
}

/** Cheap mise-shim detection: abra symlink → mise binary and `mise which abra` fails. */
export async function detectMiseAbraShim(
  abraPath: string,
  deps: DoctorDeps,
): Promise<{ isMiseShim: boolean; miseRejects: boolean; detail: string }> {
  const readlink = deps.readlinkSync ?? readlinkSync;
  const realpath = deps.realpathSync ?? realpathSync;
  const run = deps.run ?? defaultRun;
  const which = deps.whichOnPath ?? defaultWhich;
  const pathEnv = deps.pathEnv ?? process.env.PATH ?? "";

  let linkTarget: string | null = null;
  try {
    linkTarget = readlink(abraPath);
  } catch {
    return { isMiseShim: false, miseRejects: false, detail: "not a symlink" };
  }

  let miseBin: string | null = which("mise", pathEnv);
  if (!miseBin) {
    // Symlink may point at mise by basename or absolute path
    const base = path.basename(linkTarget);
    if (base !== "mise" && !linkTarget.includes("/mise")) {
      return { isMiseShim: false, miseRejects: false, detail: "symlink not to mise" };
    }
  }

  let pointsAtMise = false;
  try {
    const linkReal = path.isAbsolute(linkTarget)
      ? realpath(linkTarget)
      : realpath(path.resolve(path.dirname(abraPath), linkTarget));
    if (miseBin) {
      try {
        pointsAtMise = linkReal === realpath(miseBin);
      } catch {
        pointsAtMise = path.basename(linkReal) === "mise";
      }
    } else {
      pointsAtMise = path.basename(linkReal) === "mise";
    }
  } catch {
    pointsAtMise =
      path.basename(linkTarget) === "mise" || /(?:^|\/)mise$/.test(linkTarget);
  }

  if (!pointsAtMise) {
    return { isMiseShim: false, miseRejects: false, detail: "symlink not to mise" };
  }

  if (!miseBin) {
    return {
      isMiseShim: true,
      miseRejects: true,
      detail: "abra is a mise shim but mise is not on PATH",
    };
  }

  const r = await run(miseBin, ["which", "abra"], { timeout: 2000 });
  const out = `${r.stdout}\n${r.stderr}`;
  const rejects =
    r.status !== 0 ||
    /not a valid shim|No such file|not found/i.test(out) ||
    !r.stdout.trim();

  return {
    isMiseShim: true,
    miseRejects: rejects,
    detail: rejects
      ? `mise rejects abra shim (${miseBin} which abra failed)`
      : "mise which abra ok",
  };
}

function looksLikeLauncher(content: string): boolean {
  return isGeneratedLauncher(content);
}

function looksLikeNpmBin(abraPath: string, deps: DoctorDeps): boolean {
  const realpath = deps.realpathSync ?? realpathSync;
  try {
    const real = realpath(abraPath);
    return real.endsWith(`${path.sep}dist${path.sep}index.js`) || real.endsWith("/dist/index.js");
  } catch {
    return false;
  }
}

async function doctorLinuxPathChecks(deps: DoctorDeps): Promise<void> {
  const pathEnv = deps.pathEnv ?? process.env.PATH ?? "";
  const which = deps.whichOnPath ?? defaultWhich;
  const existsSyncFn = deps.existsSync ?? existsSync;
  const readFile =
    deps.readFileSync ?? ((p: string, enc: "utf8") => fsReadFileSync(p, enc));

  const abraPath = which("abra", pathEnv);
  if (!abraPath) {
    warn("abra not found on PATH — install: abra setup launcher");
    return;
  }

  const mise = await detectMiseAbraShim(abraPath, deps);
  if (mise.isMiseShim && mise.miseRejects) {
    warn(
      `abra on PATH is a mise shim that mise rejects (${abraPath}) — ${mise.detail}`,
    );
    warn("fix: abra setup launcher  (then put ~/.local/bin before mise shims on PATH; hash -r)");
  }

  let content: string | null = null;
  try {
    content = readFile(abraPath, "utf8");
  } catch {
    content = null;
  }
  const isLauncher = content !== null && looksLikeLauncher(content);
  const isNpm = looksLikeNpmBin(abraPath, deps);
  if (mise.isMiseShim && mise.miseRejects) {
    // already warned
  } else if (isLauncher) {
    ok(`abra on PATH is the setup launcher (${abraPath})`);
  } else if (isNpm) {
    info(
      `abra on PATH is the npm bin (${abraPath}) — prefer abra setup launcher to pin the agent node`,
    );
  } else {
    warn(
      `abra on PATH (${abraPath}) is neither the setup launcher nor the npm bin — peer checks / mise may fail`,
    );
    warn("fix: abra setup launcher  (put ~/.local/bin first on PATH; hash -r)");
  }

  // Shebang node (first node on PATH) vs agent node
  const nodeOnPath = which("node", pathEnv);
  let pathNodeReal: string | null = null;
  if (nodeOnPath) {
    try {
      pathNodeReal = (deps.realpathSync ?? realpathSync)(nodeOnPath);
    } catch {
      pathNodeReal = nodeOnPath;
    }
  }

  let agentNode: string | null = null;
  if ((deps.tryAgent ?? shouldTryAgent)()) {
    try {
      const sock = (deps.resolveSocket ?? resolveAgentSocketPath)();
      if (existsSyncFn(sock)) {
        const st = await (deps.agentStatus ?? (() => agentStatus({ socketPath: sock })))();
        if (typeof st.nodePath === "string" && st.nodePath) agentNode = st.nodePath;
      }
    } catch {
      /* agent down */
    }
  }
  if (!agentNode) {
    const unit = readInstalledAgentUnit(deps.configHome);
    if (unit) {
      const exec = parseUnitExecStart(unit.texts);
      if (exec) {
        try {
          agentNode = (deps.realpathSync ?? realpathSync)(exec.node);
        } catch {
          agentNode = exec.node;
        }
      }
    }
  }

  if (pathNodeReal && agentNode) {
    let agentReal = agentNode;
    try {
      agentReal = (deps.realpathSync ?? realpathSync)(agentNode);
    } catch {
      /* keep */
    }
    if (pathNodeReal !== agentReal) {
      warn(
        `first node on PATH (${pathNodeReal}) ≠ abra-agent node (${agentReal}) — #!/usr/bin/env node shebang will fail peer checks`,
      );
      warn("fix: abra setup launcher  (pins agent node; put ~/.local/bin first on PATH)");
    } else {
      ok("PATH node matches abra-agent node");
    }
  }
}

export async function cmdDoctor(deps: DoctorDeps = {}): Promise<void> {
  let fails = 0;
  const infoP = platformInfo();
  const platform = deps.platform ?? infoP.platform;

  ok(`platform ${infoP.platform}`);
  ok(`keystore backend ${infoP.keystore}`);
  ok(`auth backend ${infoP.auth} (${infoP.authSelectionReason})`);

  // ABRA_KEYSTORE unset: ok when unit sets it or master.key.enc auto-detects.
  if (!process.env.ABRA_KEYSTORE && (platform === "linux" || platform === "win32")) {
    const masterExists =
      deps.masterKeyExists ?? (() => existsSync(masterKeyFile()));
    const unit =
      platform === "linux" ? readInstalledAgentUnit(deps.configHome) : null;
    const unitEnv = unit ? parseUnitEnvironment(unit.texts) : new Map();
    const unitKs = unitEnv.get("ABRA_KEYSTORE");
    if (unitKs) {
      ok(
        `ABRA_KEYSTORE unset in this shell; abra-agent unit sets Environment=ABRA_KEYSTORE=${unitKs}`,
      );
    } else if (masterExists() && infoP.keystore === "passphrase-file") {
      ok(
        "ABRA_KEYSTORE unset; passphrase-file selected via master.key.enc auto-detect (fine)",
      );
    } else if (infoP.keystore === "passphrase-file") {
      info("ABRA_KEYSTORE unset; keystore is passphrase-file");
    }
  }

  if (infoP.platform === "linux") {
    ok(
      `session headless: ${infoP.headless.headless ? "yes" : "no"} (${infoP.headless.reasons.join("; ")})`,
    );
  } else {
    ok(`session headless: n/a (${infoP.platform})`);
  }

  if (infoP.biometricsSkipped) warn("ABRA_SKIP_BIOMETRICS / ABRA_AUTH=none — no approval prompts");

  if (infoP.headless.headless && infoP.keystore !== "passphrase-file") {
    warn(
      "headless session with non-passphrase-file keystore — secret reveals will be DENIED. Set ABRA_KEYSTORE=passphrase-file (run: abra keystore migrate --to passphrase-file)",
    );
    fails++;
  }

  if (infoP.auth === "passphrase") {
    ok(
      "reveals prompt for the vault passphrase on the terminal (ssh -t); MCP/API denied while headless",
    );
  }

  const vault = vaultFile();
  if (existsSync(vault)) {
    ok(`vault ${vault}`);
  } else {
    warn(`no vault yet (${vault}) — run: abra project new <name>`);
  }

  if (infoP.keystore === "passphrase-file") {
    if (infoP.vaultLocked) {
      warn("passphrase vault locked — run: abra unlock");
    } else {
      ok("passphrase vault session unlocked");
    }
  }

  if (infoP.platform === "linux") {
    const unit = readInstalledAgentUnit(deps.configHome);
    if (unit) {
      const net = checkUnitNetlink(unit.texts);
      if (net.status === "missing_netlink") {
        warn(
          `abra-agent unit lacks AF_NETLINK (RestrictAddressFamilies=${net.families.join(" ")}) — peer checks fail, abra unlock cannot share the key (${unit.path})`,
        );
        warn(
          "fix: RestrictAddressFamilies=AF_UNIX AF_NETLINK, then: systemctl --user daemon-reload && systemctl --user restart abra-agent",
        );
      } else {
        ok(`abra-agent unit allows AF_NETLINK for ss (${unit.path})`);
      }
    }

    await doctorLinuxPathChecks(deps);
  }

  const health = await platformHealth();

  if (infoP.keystore === "keytar") {
    if (health.keytar?.ok) {
      ok("keytar credential store reachable");
    } else {
      warn(`keytar unavailable: ${health.keytar?.detail ?? "unknown"}`);
      warn("fallback: export ABRA_KEYSTORE=passphrase-file");
      fails++;
    }
  }

  if (health.polkit) {
    if (health.polkit.ok) {
      ok(`polkit ready (${health.polkit.pkcheck}; ${health.polkit.policy})`);
    } else if (infoP.auth === "polkit") {
      warn(`polkit not ready: ${health.polkit.detail ?? "unknown"}`);
      warn("secret reveals will be DENIED until the policy is installed: abra setup polkit");
      fails++;
    } else if (process.platform === "linux" && infoP.auth !== "passphrase") {
      warn(`polkit unavailable: ${health.polkit.detail ?? "unknown"} (auth=${infoP.auth} via ABRA_AUTH)`);
      warn("install: abra setup polkit, then unset ABRA_AUTH to use the PolKit gate");
    }
  } else if (infoP.auth === "passphrase" && process.platform === "linux") {
    ok("polkit not required (passphrase auth)");
  }

  if (infoP.keystore === "macos-keychain" && process.platform !== "darwin") {
    fail("macos-keychain selected on non-macOS");
    fails++;
  }

  const licContract = licenseContractAddress();
  if (licContract) {
    ok(`license contract ${licContract}`);
    const lic = await getLicenseStatus();
    if (lic.skip) warn("ABRA_SKIP_LICENSE=1 — NFT gate disabled");
    else if (!lic.activated) warn("license not activated — run: abra activate <wallet>");
    else if (lic.onChainOk) ok(`license activated ${lic.wallet}`);
    else if (lic.onChainOk === false) {
      warn(`license invalid on-chain for ${lic.wallet}`);
      fails++;
    } else warn("license on-chain check failed (RPC)");
  } else {
    warn("ABRA_LICENSE_NFT unset — commercial license gate off");
  }

  if (fails > 0) process.exit(1);
}
