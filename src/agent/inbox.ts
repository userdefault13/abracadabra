import fs from "node:fs";
import type { Vault } from "../core/vault.js";
import {
  SyncInbox,
  createInboxRequestHandler,
  startInboxListener,
  type InboxListener,
} from "../sync/inbox.js";
import {
  anchorsFile,
  loadOrCreateInboxTls,
  readAnchors,
  syncAnchorsFromVault,
  type InboxAnchors,
} from "../core/sync-inbox-store.js";
import { detectTailscaleIPv4 } from "../sync/tailscale.js";
import type { AgentInboxStatusBody } from "./protocol.js";

/**
 * abra-agent side of the sync inbox. The listener runs only while the inbox
 * is enabled AND at least one SOURCE peer is paired — decided from the
 * non-secret anchors mirror at agent start (the agent starts locked) and
 * re-derived from the vault on every unlock / agent vault.save.
 * With no anchors file the agent behaves exactly as before.
 */

export interface AgentInboxController {
  start(): Promise<void>;
  onUnlock(): Promise<void>;
  onVaultSaved(vault: Vault): Promise<void>;
  status(): AgentInboxStatusBody;
  stop(): Promise<void>;
}

export interface AgentInboxDeps {
  /** abra dir (holds vault.enc and sync-inbox/). */
  base: string;
  loadUnlockedVault: () => Promise<Vault | null>;
  saveVault: (vault: Vault) => Promise<void>;
  log: (detail: string) => void;
  detectTailscale?: () => Promise<string | null>;
  loadTls?: (base: string) => { key: string; cert: string };
  startListener?: typeof startInboxListener;
  now?: () => number;
}

export class AgentInbox implements AgentInboxController {
  private listener: InboxListener | null = null;
  private anchors: InboxAnchors | null = null;
  private error: string | null = null;
  private chain: Promise<void> = Promise.resolve();
  private stopped = false;
  readonly inbox: SyncInbox;

  constructor(private readonly deps: AgentInboxDeps) {
    this.inbox = new SyncInbox({
      base: deps.base,
      loadUnlockedVault: deps.loadUnlockedVault,
      saveVault: deps.saveVault,
      now: deps.now,
      log: deps.log,
    });
  }

  private serial(fn: () => Promise<void>): Promise<void> {
    const run = this.chain.then(fn, fn).catch((err: unknown) => {
      this.deps.log(`error: ${err instanceof Error ? err.message : String(err)}`);
    });
    this.chain = run;
    return run;
  }

  private configured(): boolean {
    return fs.existsSync(anchorsFile(this.deps.base));
  }

  start(): Promise<void> {
    return this.serial(() => this.reconcile(readAnchors(this.deps.base)));
  }

  onUnlock(): Promise<void> {
    return this.serial(async () => {
      if (!this.configured()) return;
      const vault = await this.deps.loadUnlockedVault();
      if (!vault) return;
      await this.reconcile(syncAnchorsFromVault(this.deps.base, vault));
      await this.inbox.processQueue();
    });
  }

  onVaultSaved(vault: Vault): Promise<void> {
    return this.serial(async () => {
      if (!vault.syncInbox && !this.configured()) return;
      await this.reconcile(syncAnchorsFromVault(this.deps.base, vault));
    });
  }

  status(): AgentInboxStatusBody {
    const a = this.anchors;
    let queued = 0;
    try {
      queued = this.inbox.queue.ids().length;
    } catch {
      /* unreadable dir */
    }
    return {
      configured: a !== null,
      enabled: a?.enabled ?? false,
      listening: this.listener !== null,
      bind: this.listener?.bind ?? a?.bind ?? null,
      port: this.listener?.port ?? a?.port ?? null,
      sources: a ? Object.keys(a.sources).length : 0,
      queued,
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
    if (l) {
      await l.close();
      this.deps.log(`stopped ${l.bind}:${l.port}`);
    }
  }

  private async reconcile(anchors: InboxAnchors | null): Promise<void> {
    this.anchors = anchors;
    const wanted =
      !this.stopped && anchors?.enabled === true && anchors.me !== null && Object.keys(anchors.sources).length > 0;
    if (!wanted) {
      this.error = null;
      await this.closeListener();
      return;
    }
    let bind = anchors.bind;
    if (!bind) {
      bind = await (this.deps.detectTailscale ?? (() => detectTailscaleIPv4()))();
      if (!bind) {
        this.error = "Tailscale IPv4 not found — run `abra sync inbox --enable --bind <ip>` to choose an address";
        this.deps.log("not listening: Tailscale IPv4 not found and no --bind set");
        await this.closeListener();
        return;
      }
    }
    const l = this.listener;
    if (l && l.bind === bind && (anchors.port === 0 || l.port === anchors.port)) return;
    await this.closeListener();
    try {
      const tls = (this.deps.loadTls ?? loadOrCreateInboxTls)(this.deps.base);
      this.listener = await (this.deps.startListener ?? startInboxListener)({
        bind,
        port: anchors.port,
        tls,
        handler: createInboxRequestHandler((raw, meta) => this.inbox.receive(raw, meta), {
          log: this.deps.log,
        }),
      });
      this.error = null;
      this.deps.log(`listening ${bind}:${this.listener.port}`);
    } catch (err) {
      this.error = `listener failed: ${err instanceof Error ? err.message : String(err)}`;
      this.deps.log(this.error);
    }
  }
}
