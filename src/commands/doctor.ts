import { existsSync } from "node:fs";
import { vaultFile } from "../core/paths.js";
import { platformHealth, platformInfo } from "../platform/index.js";
import { getLicenseStatus, licenseContractAddress } from "../license/index.js";
import {
  formatAgentSocketVia,
  isAgentEnabled,
  resolveAgentRuntimeBase,
  resolveAgentSocketPath,
  type AgentPathDeps,
  type AgentRuntimeBase,
} from "../agent/paths.js";
import {
  probeAgentStatusState,
  type AgentStatusCliDeps,
  type AgentStatusState,
} from "./agent-status.js";
import { agentStatus } from "../agent/index.js";

const ok = (msg: string) => console.log(`ok    ${msg}`);
const warn = (msg: string) => console.log(`warn  ${msg}`);
const fail = (msg: string) => console.log(`fail  ${msg}`);

/** Short connect timeout for doctor’s agent probe (ms). */
const DOCTOR_AGENT_PROBE_MS = 250;

const UNLOCK_SSH_HINT =
  "ssh -t <host> 'PATH=$HOME/.local/share/mise/shims:$PATH abra unlock'";

export type DoctorDeps = {
  pathDeps?: AgentPathDeps;
  resolveRuntimeBase?: () => AgentRuntimeBase;
  resolveSocketPath?: () => string;
  agentEnabled?: () => boolean;
  /** Injectable agent probe (tests). Errors → treat as not running. */
  probeAgentStatus?: () => Promise<AgentStatusState>;
  /** Override platformInfo() (tests). */
  platformInfo?: () => ReturnType<typeof platformInfo>;
};

function reportAgentSocket(deps: DoctorDeps = {}): void {
  const env = deps.pathDeps?.env ?? process.env;
  const platform = deps.pathDeps?.platform ?? process.platform;
  const flag = env.ABRA_AGENT?.trim();
  if (flag === "0") {
    ok("abra-agent disabled (ABRA_AGENT=0)");
    return;
  }
  if (platform === "win32") {
    ok("abra-agent unsupported on win32");
    return;
  }

  const enabled = deps.agentEnabled?.() ?? isAgentEnabled(deps.pathDeps);
  const base =
    deps.resolveRuntimeBase?.() ?? resolveAgentRuntimeBase(deps.pathDeps);
  const via = formatAgentSocketVia(base.source, base.reason);

  if (!enabled && flag !== "1") {
    ok(`abra-agent disabled by default (${via})`);
    return;
  }

  try {
    const sock =
      deps.resolveSocketPath?.() ?? resolveAgentSocketPath(deps.pathDeps);
    ok(`abra-agent socket ${sock} (${via})`);
  } catch {
    warn(`abra-agent socket unavailable (${via})`);
  }
}

function defaultProbeAgent(deps: DoctorDeps): () => Promise<AgentStatusState> {
  return async () => {
    const statusDeps: AgentStatusCliDeps = {
      pathDeps: deps.pathDeps,
      resolveSocketPath: deps.resolveSocketPath,
      resolveRuntimeBase: deps.resolveRuntimeBase,
      status: () =>
        agentStatus({
          socketPath: deps.resolveSocketPath?.(),
          connectTimeoutMs: DOCTOR_AGENT_PROBE_MS,
        }),
    };
    return probeAgentStatusState(statusDeps);
  };
}

/**
 * Warn when Linux auto-detected passphrase-file and the agent is locked / down:
 * systemd units that call `abra run` may fail with "vault locked" (no TTY) on restart.
 */
async function warnAutoDetectAgentRisk(
  info: ReturnType<typeof platformInfo>,
  deps: DoctorDeps,
): Promise<void> {
  if (info.platform !== "linux") return;
  if (!info.keystoreSelectionReason.startsWith("auto-detected")) return;

  const probe = deps.probeAgentStatus ?? defaultProbeAgent(deps);
  let state: AgentStatusState;
  try {
    state = await probe();
  } catch {
    state = "not_running";
  }
  if (state === "unlocked") return;

  const agentLabel = state === "locked" ? "locked" : "not running";
  warn(
    `⚠ keystore auto-detected as passphrase-file (master.key.enc present, ABRA_KEYSTORE unset). ` +
      `abra-agent is ${agentLabel}: systemd units that run abra and restart now will fail with ` +
      `'vault locked' (no TTY). Fix: unlock (${UNLOCK_SSH_HINT}), or pin ` +
      `Environment=ABRA_KEYSTORE=keytar in those units during the transition, or add ` +
      `ExecStartPre=abra agent status --wait --timeout 0 — see docs/LINUX-HEADLESS.md#upgrading-existing-units`,
  );
}

export async function cmdDoctor(deps: DoctorDeps = {}): Promise<void> {
  let fails = 0;
  const info = deps.platformInfo?.() ?? platformInfo();

  ok(`platform ${info.platform}`);
  ok(`keystore backend ${info.keystore} (${info.keystoreSelectionReason})`);
  ok(`auth backend ${info.auth} (${info.authSelectionReason})`);

  if (info.platform === "linux") {
    ok(
      `session headless: ${info.headless.headless ? "yes" : "no"} (${info.headless.reasons.join("; ")})`,
    );
  } else {
    ok(`session headless: n/a (${info.platform})`);
  }

  if (info.biometricsSkipped) warn("ABRA_SKIP_BIOMETRICS / ABRA_AUTH=none — no approval prompts");

  if (info.headless.headless && info.keystore !== "passphrase-file") {
    warn(
      "headless session with non-passphrase-file keystore — secret reveals will be DENIED. Set ABRA_KEYSTORE=passphrase-file (run: abra keystore migrate --to passphrase-file)",
    );
    fails++;
  }

  if (info.auth === "passphrase") {
    ok(
      "reveals prompt for the vault passphrase on the terminal (ssh -t); MCP/API denied while headless",
    );
  }

  reportAgentSocket(deps);
  await warnAutoDetectAgentRisk(info, deps);

  const vault = vaultFile();
  if (existsSync(vault)) {
    ok(`vault ${vault}`);
  } else {
    warn(`no vault yet (${vault}) — run: abra project new <name>`);
  }

  if (info.keystore === "passphrase-file") {
    if (info.vaultLocked) {
      warn("passphrase vault locked — run: abra unlock");
    } else {
      ok("passphrase vault session unlocked");
    }
  }

  const health = await platformHealth();

  if (info.keystore === "keytar") {
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
    } else if (info.auth === "polkit") {
      warn(`polkit not ready: ${health.polkit.detail ?? "unknown"}`);
      warn("secret reveals will be DENIED until the policy is installed: sudo scripts/install-polkit.sh");
      fails++;
    } else if (process.platform === "linux" && info.auth !== "passphrase") {
      warn(`polkit unavailable: ${health.polkit.detail ?? "unknown"} (auth=${info.auth} via ABRA_AUTH)`);
      warn("install: sudo scripts/install-polkit.sh, then unset ABRA_AUTH to use the PolKit gate");
    }
  } else if (info.auth === "passphrase" && process.platform === "linux") {
    ok("polkit not required (passphrase auth)");
  }

  if (info.keystore === "macos-keychain" && process.platform !== "darwin") {
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
