import fs from "node:fs";
import { decryptVault } from "../core/vault.js";
import { prepareReceiverEnroll } from "../remote/enroll.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import {
  UnlockSession,
  createRemoteRequestHandler,
  dispatchRemoteSession,
  isRemoteUnlockEnrolled,
  loadOrCreateRemoteUnlockTls,
  startUnlockListener,
  REMOTE_UNLOCK_PORT,
  type UnlockListener,
} from "../remote/listener.js";
import { detectTailscaleIPv4 } from "../sync/tailscale.js";
import type { AgentState } from "./state.js";

/**
 * abra-agent side of remote unlock. Listener runs when ABRA_REMOTE_UNLOCK=1 and
 * either enrolled (device key + hub pin + blob) or unlocked (so enroll can be served).
 * Bind mirrors the sync inbox: Tailscale IPv4 (or explicit bind for tests).
 */

export interface AgentRemoteUnlockStatus {
  enabled: boolean;
  enrolled: boolean;
  listening: boolean;
  bind: string | null;
  port: number | null;
  error: string | null;
}

export interface AgentRemoteUnlockController {
  start(): Promise<void>;
  /** Re-check flag + enrollment; start/stop listener. */
  reconcile(): Promise<void>;
  status(): AgentRemoteUnlockStatus;
  stop(): Promise<void>;
}

export interface AgentRemoteUnlockDeps {
  base: string;
  state: AgentState;
  vaultPath: () => string;
  log: (detail: string) => void;
  /** Override bind (tests / explicit IP). Default: detect Tailscale IPv4. */
  bind?: string | null;
  port?: number;
  detectTailscale?: () => Promise<string | null>;
  loadTls?: (base: string) => { key: string; cert: string };
  startListener?: typeof startUnlockListener;
  now?: () => number;
  /** Fired after a successful remote unlock (e.g. inbox onUnlock). */
  onUnlocked?: () => void;
  /**
   * How this receiver names the hub when serving enroll offers.
   * Default: look up the paired source peer name from the unlocked vault.
   */
  hubNameOrIdForEnroll?: (vault: ReturnType<typeof decryptVault>) => string;
}

function defaultHubNameForEnroll(vault: ReturnType<typeof decryptVault>): string {
  const peers = vault.syncPeers ?? {};
  const source = Object.entries(peers).find(([, p]) => p.role === "source");
  if (source) return source[1].name;
  throw new Error("no paired source (hub) peer — pair first");
}

export class AgentRemoteUnlock implements AgentRemoteUnlockController {
  private listener: UnlockListener | null = null;
  private session: UnlockSession | null = null;
  private tlsCert: string | null = null;
  private error: string | null = null;
  private chain: Promise<void> = Promise.resolve();
  private stopped = false;

  constructor(private readonly deps: AgentRemoteUnlockDeps) {}

  private serial(fn: () => Promise<void>): Promise<void> {
    const run = this.chain.then(fn, fn).catch((err: unknown) => {
      this.deps.log(`error: ${err instanceof Error ? err.message : String(err)}`);
    });
    this.chain = run;
    return run;
  }

  start(): Promise<void> {
    return this.serial(() => this.reconcileInner());
  }

  reconcile(): Promise<void> {
    return this.serial(() => this.reconcileInner());
  }

  status(): AgentRemoteUnlockStatus {
    return {
      enabled: isRemoteUnlockEnabled(),
      enrolled: isRemoteUnlockEnrolled(this.deps.base),
      listening: this.listener !== null,
      bind: this.listener?.bind ?? null,
      port: this.listener?.port ?? null,
      error: this.error,
    };
  }

  stop(): Promise<void> {
    this.stopped = true;
    return this.serial(() => this.closeListener());
  }

  private async closeListener(): Promise<void> {
    const l = this.listener;
    this.listener = null;
    this.session = null;
    this.tlsCert = null;
    if (l) {
      await l.close();
      this.deps.log(`stopped ${l.bind}:${l.port}`);
    }
  }

  /** Enrolled, or unlocked so we can serve first enroll. */
  private shouldListen(): boolean {
    if (this.stopped || !isRemoteUnlockEnabled()) return false;
    if (isRemoteUnlockEnrolled(this.deps.base)) return true;
    return !this.deps.state.isLocked();
  }

  private async reconcileInner(): Promise<void> {
    const wanted = this.shouldListen();
    if (!wanted) {
      this.error = null;
      await this.closeListener();
      return;
    }

    let bind = this.deps.bind;
    if (bind === undefined) {
      bind = await (this.deps.detectTailscale ?? (() => detectTailscaleIPv4()))();
    }
    if (!bind) {
      this.error =
        "Tailscale IPv4 not found — remote unlock needs a tailnet address (or inject bind in tests)";
      this.deps.log("not listening: Tailscale IPv4 not found");
      await this.closeListener();
      return;
    }

    const port = this.deps.port ?? REMOTE_UNLOCK_PORT;
    const l = this.listener;
    if (l && l.bind === bind && (port === 0 || l.port === port)) return;

    await this.closeListener();
    try {
      const state = this.deps.state;
      const vaultPath = this.deps.vaultPath;
      const tls = (this.deps.loadTls ?? loadOrCreateRemoteUnlockTls)(this.deps.base);
      this.tlsCert = tls.cert;
      this.session = new UnlockSession({
        base: this.deps.base,
        now: this.deps.now,
        log: this.deps.log,
        isLocked: () => state.isLocked(),
        lockVault: () => {
          state.lock();
        },
        listenerCert: () => this.tlsCert,
        onNotEnrolled: () => {
          if (!isRemoteUnlockEnrolled(this.deps.base)) {
            void this.reconcile();
          }
        },
        prepareEnrollOffer: (hubNameOrId) => {
          const key = state.requireKey();
          const file = vaultPath();
          const raw = JSON.parse(fs.readFileSync(file, "utf8"));
          const vault = decryptVault(raw, key);
          const hub =
            hubNameOrId ||
            (this.deps.hubNameOrIdForEnroll ?? defaultHubNameForEnroll)(vault);
          const prepared = prepareReceiverEnroll({
            vault,
            masterKey: key,
            base: this.deps.base,
            hubNameOrId: hub,
            now: this.deps.now?.(),
          });
          return prepared.offer;
        },
        verifyMasterKey: (masterKey) => {
          const file = vaultPath();
          if (!fs.existsSync(file)) return true;
          try {
            const raw = JSON.parse(fs.readFileSync(file, "utf8"));
            decryptVault(raw, masterKey);
            return true;
          } catch {
            return false;
          }
        },
        unlockWithKey: (masterKey) => {
          state.unlockWithKey(masterKey);
          this.deps.onUnlocked?.();
        },
      });
      const session = this.session;
      this.listener = await (this.deps.startListener ?? startUnlockListener)({
        bind,
        port,
        tls,
        handler: createRemoteRequestHandler((path, raw) => dispatchRemoteSession(session, path, raw), {
          log: this.deps.log,
          now: this.deps.now,
        }),
      });
      this.error = null;
      this.deps.log(`listening ${bind}:${this.listener.port}`);
    } catch (err) {
      this.error = `listener failed: ${err instanceof Error ? err.message : String(err)}`;
      this.deps.log(this.error);
      this.session = null;
      this.tlsCert = null;
    }
  }
}
