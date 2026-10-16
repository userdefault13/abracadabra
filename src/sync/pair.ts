import net from "node:net";
import os from "node:os";
import tls from "node:tls";
import type { SyncIdentity, SyncPeer, SyncPeerRole, Vault, VaultMutator } from "../core/vault.js";
import type { EphemeralTls } from "../core/tls-ephemeral.js";
import { connectPinnedTls } from "../core/tls-ephemeral.js";
import { PIN_MAX_FAILURES, timingSafePin } from "../core/pin.js";
import {
  assertValidPublicKeys,
  decodeRawKey,
  getOrCreateSyncIdentity,
  identityFingerprint,
  isUuid,
} from "./identity.js";
import {
  defaultPeerName,
  describeRoles,
  planPeerUpsert,
  resolveRoles,
  validatePeerName,
  type PeerCandidate,
  type PeerPlan,
} from "./peers.js";
import {
  PAIR_PROTOCOL,
  safetyCode,
  signTranscript,
  transcriptHash,
  verifyTranscript,
  type PairHello,
  type SafetyCode,
} from "./sas.js";

/**
 * `abra sync pair` — wire format: newline-delimited JSON over a TLS socket whose
 * certificate the connector pins (fingerprint verified before any byte is sent).
 *
 *   connector → listener  {t:"hello", pin, hello}
 *   listener  → connector {t:"hello", hello, sig}      (or {t:"error"} + close)
 *   connector → listener  {t:"sig", sig}
 *   both                  {t:"confirm", ok}            after the local user compares the code
 *   both                  {t:"saved", ok}              after the local vault write
 *
 * Only identity public keys, ids, names, nonces and roles cross the wire.
 */

export const PAIR_DEFAULT_PORT = 7334;
export const PAIR_DEFAULT_TTL_MS = 5 * 60 * 1000;
export const PAIR_APPROVAL_REASON = "abracadabra: pair this vault with another machine";
export const CONFIRM_QUESTION = "Do both screens show the same 6 words? [y/N] ";

const MAX_LINE_BYTES = 16 * 1024;

export interface PairTimeouts {
  /** Each protocol step before the human comparison. */
  stepMs: number;
  /** Waiting for the peer's human to confirm. */
  confirmMs: number;
  /** Waiting for the peer's "saved" ack after our write. */
  savedAckMs: number;
  /** After our half-close, waiting for the peer to close its side before destroying the socket. */
  closeMs: number;
}

export const DEFAULT_PAIR_TIMEOUTS: PairTimeouts = {
  stepMs: 30_000,
  confirmMs: 5 * 60_000,
  savedAckMs: 15_000,
  closeMs: 5_000,
};

export interface PairDeps {
  authenticate: (reason: string) => Promise<void>;
  loadVault: () => Promise<Vault>;
  /** Locked read-modify-write (see core/vault updateVault). */
  updateVault: (mutator: VaultMutator) => Promise<Vault>;
  /** Local TTY yes/no; must throw when there is no terminal. */
  confirm: (question: string) => Promise<boolean>;
  /** Hidden PIN entry (connector only). */
  promptPin: (question: string) => Promise<string>;
  createTls: (commonName: string) => EphemeralTls;
  generatePin: () => string;
  hostname: () => string;
  now: () => number;
  randomBytes: (n: number) => Buffer;
  /** User-facing output (names, ids, fingerprints, addresses only). */
  log: (line: string) => void;
  timeouts?: Partial<PairTimeouts>;
}

export interface PairResult {
  peerId: string;
  peer: SyncPeer;
  action: PeerPlan["action"];
  replaced?: PeerPlan["replaced"];
  safetyCode: SafetyCode;
  myRole: SyncPeerRole;
  /** False when the peer's "saved" ack never arrived (it may not have written). */
  peerSaved: boolean;
  /** Why `peerSaved` is false. */
  peerSaveError?: string;
}

export class PairAbortedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PairAbortedError";
  }
}

type Msg = { t: string; [k: string]: unknown };

/**
 * Newline-delimited JSON over a socket; buffered so messages are never lost to timing.
 * Frames already received stay readable via next() after the socket ends or errors.
 */
export class LineChannel {
  private buf = "";
  private queue: Msg[] = [];
  private waiters: { resolve: (m: Msg) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }[] = [];
  private closedErr: Error | null = null;
  private closing = false;
  private readonly closed: Promise<void>;

  constructor(
    private socket: net.Socket,
    private closeMs: number = DEFAULT_PAIR_TIMEOUTS.closeMs,
  ) {
    this.closed = socket.destroyed
      ? Promise.resolve()
      : new Promise((resolve) => socket.once("close", () => resolve()));
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => this.onData(chunk));
    socket.on("end", () => this.fail(new Error("peer disconnected")));
    socket.on("close", () => this.fail(new Error("peer disconnected")));
    socket.on("error", (err) => this.fail(err instanceof Error ? err : new Error(String(err))));
  }

  private onData(chunk: string) {
    this.buf += chunk;
    let idx: number;
    while ((idx = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 1);
      if (!line.trim()) continue;
      let msg: Msg;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (!parsed || typeof parsed !== "object" || typeof (parsed as Msg).t !== "string") {
          throw new Error("bad message");
        }
        msg = parsed as Msg;
      } catch {
        this.fail(new Error("malformed message from peer"));
        this.socket.destroy();
        return;
      }
      const w = this.waiters.shift();
      if (w) {
        clearTimeout(w.timer);
        w.resolve(msg);
      } else {
        this.queue.push(msg);
      }
    }
    if (Buffer.byteLength(this.buf) > MAX_LINE_BYTES) {
      this.fail(new Error("message from peer too large"));
      this.socket.destroy();
    }
  }

  private fail(err: Error) {
    if (this.closedErr) return;
    this.closedErr = err;
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  send(msg: Msg): void {
    if (this.socket.destroyed || this.socket.writableEnded) return;
    try {
      this.socket.write(`${JSON.stringify(msg)}\n`);
    } catch {
      /* peer gone — surfaced by next() */
    }
  }

  next(timeoutMs: number, what: string): Promise<Msg> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closedErr) return Promise.reject(this.closedErr);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w.timer !== timer);
        reject(new Error(`timed out waiting for ${what}`));
      }, timeoutMs);
      this.waiters.push({ resolve, reject, timer });
    });
  }

  /**
   * Half-close (flush our frames, send FIN), then resolve once the peer has closed
   * its side, force-destroying after `closeMs`. Await this before the process may
   * exit: exiting or destroying with frames in flight can turn into a TCP RST, and
   * Windows drops received-but-unread data when an RST arrives.
   */
  close(): Promise<void> {
    if (!this.closing) {
      this.closing = true;
      try {
        this.socket.end();
      } catch {
        /* ignore */
      }
      const timer = setTimeout(() => this.socket.destroy(), this.closeMs);
      timer.unref();
      void this.closed.then(() => clearTimeout(timer));
    }
    return this.closed;
  }
}

function timeoutsOf(deps: PairDeps): PairTimeouts {
  return { ...DEFAULT_PAIR_TIMEOUTS, ...(deps.timeouts ?? {}) };
}

function newNonce(deps: PairDeps): string {
  const n = deps.randomBytes(32);
  if (n.length !== 32) throw new Error("nonce must be 32 bytes");
  return n.toString("base64");
}

function ownHello(identity: SyncIdentity, deps: PairDeps, role: SyncPeerRole | null): PairHello {
  return {
    protocol: PAIR_PROTOCOL,
    id: identity.id,
    name: defaultPeerName(deps.hostname()),
    ed25519: identity.ed25519.publicKey,
    x25519: identity.x25519.publicKey,
    nonce: newNonce(deps),
    role,
  };
}

/** Validate an untrusted hello from the wire. */
export function parseHello(raw: unknown, opts: { roleRequired: boolean }): PairHello {
  if (!raw || typeof raw !== "object") throw new Error("missing hello");
  const h = raw as Record<string, unknown>;
  if (h.protocol !== PAIR_PROTOCOL) {
    throw new Error(`unsupported pairing protocol ${JSON.stringify(h.protocol)} (expected ${PAIR_PROTOCOL})`);
  }
  if (!isUuid(h.id)) throw new Error("invalid peer identity id");
  if (typeof h.name !== "string" || h.name.length > 256) throw new Error("invalid peer name");
  if (typeof h.ed25519 !== "string" || typeof h.x25519 !== "string") throw new Error("invalid peer keys");
  assertValidPublicKeys(h.ed25519, h.x25519);
  if (typeof h.nonce !== "string") throw new Error("invalid nonce");
  decodeRawKey(h.nonce);
  const role = h.role ?? null;
  if (role !== null && role !== "source" && role !== "receiver") throw new Error("invalid role");
  if (opts.roleRequired && role === null) throw new Error("peer did not state its role");
  return {
    protocol: PAIR_PROTOCOL,
    id: h.id,
    name: h.name,
    ed25519: h.ed25519,
    x25519: h.x25519,
    nonce: h.nonce,
    role: role as SyncPeerRole | null,
  };
}

function abortWith(ch: LineChannel, message: string, sendToPeer = message): never {
  ch.send({ t: "error", error: sendToPeer });
  ch.close();
  throw new PairAbortedError(message);
}

function peerErrorText(m: Msg): string {
  return typeof m.error === "string" ? m.error.slice(0, 300) : "unknown error";
}

interface Session {
  ch: LineChannel;
  transcript: Buffer;
  identity: SyncIdentity;
  identityCreated: boolean;
  candidate: PeerCandidate;
  myRole: SyncPeerRole;
  replace: boolean;
  explicitName: boolean;
}

/**
 * Shared tail: show the safety code, get a local "y", exchange confirms, then
 * write. Neither side writes unless both confirmed; the "saved" ack only
 * reports whether the peer's write landed.
 */
async function confirmAndSave(s: Session, deps: PairDeps): Promise<PairResult> {
  const t = timeoutsOf(deps);
  const code = safetyCode(s.transcript);
  const peerFp = identityFingerprint(s.candidate.ed25519, s.candidate.x25519);
  deps.log("");
  deps.log(`Pairing with "${s.candidate.name}"${s.candidate.address ? ` (${s.candidate.address})` : ""}`);
  deps.log(`  peer identity:   ${peerFp}`);
  deps.log(`  this identity:   ${identityFingerprint(s.identity.ed25519.publicKey, s.identity.x25519.publicKey)}`);
  deps.log(`  roles:           ${describeRoles(s.myRole)}`);
  deps.log(`  safety code:     ${code.words.join(" ")}`);
  deps.log(`                   ${code.digits}`);

  let ok: boolean;
  try {
    ok = await deps.confirm(CONFIRM_QUESTION);
  } catch (err) {
    s.ch.send({ t: "confirm", ok: false });
    s.ch.close();
    const why = err instanceof Error ? err.message : String(err);
    throw new PairAbortedError(`could not confirm the safety code (${why}) — nothing saved`);
  }
  s.ch.send({ t: "confirm", ok });
  if (!ok) {
    s.ch.close();
    throw new PairAbortedError("safety code not confirmed on this machine — nothing saved");
  }

  deps.log("Waiting for the other machine to confirm…");
  let peerMsg: Msg;
  try {
    peerMsg = await s.ch.next(t.confirmMs, "the peer's confirmation");
  } catch (err) {
    s.ch.close();
    const why = err instanceof Error ? err.message : String(err);
    throw new PairAbortedError(`peer did not confirm (${why}) — nothing saved`);
  }
  if (peerMsg.t === "error") {
    s.ch.close();
    throw new PairAbortedError(`peer aborted: ${peerErrorText(peerMsg)} — nothing saved`);
  }
  if (peerMsg.t !== "confirm" || peerMsg.ok !== true) {
    s.ch.close();
    throw new PairAbortedError("peer declined the safety code — nothing saved");
  }

  let plan!: PeerPlan;
  try {
    // Plan against the vault re-read under the lock so a long pairing session never clobbers concurrent edits.
    await deps.updateVault((fresh) => {
      let base: Vault;
      if (s.identityCreated) {
        if (fresh.syncIdentity) throw new Error("this vault's sync identity changed during pairing");
        base = { ...fresh, syncIdentity: s.identity };
      } else {
        if (fresh.syncIdentity?.id !== s.identity.id) {
          throw new Error("this vault's sync identity changed during pairing");
        }
        base = fresh;
      }
      plan = planPeerUpsert(base, s.candidate, {
        replace: s.replace,
        explicitName: s.explicitName,
        now: deps.now(),
      });
      return plan.vault;
    });
  } catch (err) {
    s.ch.send({ t: "saved", ok: false });
    s.ch.close();
    const why = err instanceof Error ? err.message : String(err);
    throw new PairAbortedError(
      `could not save the pairing here (${why}). The peer may have saved it — check with abra sync peers on both machines`,
    );
  }
  s.ch.send({ t: "saved", ok: true });

  let peerSaved = false;
  let peerSaveError: string | undefined;
  try {
    const ack = await s.ch.next(t.savedAckMs, "the peer's save acknowledgement");
    if (ack.t === "saved" && ack.ok === true) peerSaved = true;
    else if (ack.t === "saved") peerSaveError = "the peer reported that its save failed";
    else if (ack.t === "error") peerSaveError = `peer error: ${peerErrorText(ack)}`;
    else peerSaveError = `unexpected ${JSON.stringify(ack.t.slice(0, 40))} message instead of the save acknowledgement`;
  } catch (err) {
    peerSaveError = err instanceof Error ? err.message : String(err);
  }
  await s.ch.close();

  return {
    peerId: s.candidate.id,
    peer: plan.peer,
    action: plan.action,
    replaced: plan.replaced,
    safetyCode: code,
    myRole: s.myRole,
    peerSaved,
    ...(peerSaveError !== undefined ? { peerSaveError } : {}),
  };
}

async function approveAndLoadIdentity(deps: PairDeps): Promise<{
  vault: Vault;
  identity: SyncIdentity;
  created: boolean;
}> {
  await deps.authenticate(PAIR_APPROVAL_REASON);
  return getOrCreateSyncIdentity(await deps.loadVault(), { now: deps.now() });
}

/** Fail before the code is shown when the local peers table would refuse this peer. */
function precheckPlan(ch: LineChannel, vault: Vault, cand: PeerCandidate, replace: boolean, explicitName: boolean, now: number) {
  try {
    planPeerUpsert(vault, cand, { replace, explicitName, now });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    abortWith(ch, msg, "the other machine refused this pairing (peer table conflict)");
  }
}

// ───────────────────────────── listener ─────────────────────────────

export interface PairListenOptions {
  port?: number;
  /** Bind address (default 0.0.0.0, like `abra usb host`). */
  bind?: string;
  ttlMs?: number;
  /** This machine's role (default "source"). */
  role?: SyncPeerRole;
  /** Local name for the connecting peer (default: its sanitized hostname). */
  name?: string;
  replace?: boolean;
  onListening?: (info: PairListenInfo) => void;
}

export interface PairListenInfo {
  pin: string;
  port: number;
  bind: string;
  addresses: string[];
  tlsFingerprint: string;
  identityFingerprint: string;
  identityCreated: boolean;
  role: SyncPeerRole;
  hostname: string;
  expiresAt: number;
}

export function listenAddresses(bind: string): string[] {
  if (bind !== "0.0.0.0" && bind !== "::") return [bind];
  const out: string[] = [];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const e of entries ?? []) {
      if (!e.internal && e.family === "IPv4") out.push(e.address);
    }
  }
  return out;
}

export async function pairListen(opts: PairListenOptions, deps: PairDeps): Promise<PairResult> {
  const role = opts.role ?? "source";
  const bind = opts.bind ?? "0.0.0.0";
  if (net.isIP(bind) === 0) throw new Error(`--bind must be an IP address (got "${bind}")`);
  if (opts.name !== undefined) validatePeerName(opts.name);
  const ttlMs = opts.ttlMs ?? PAIR_DEFAULT_TTL_MS;
  const t = timeoutsOf(deps);

  // Approval first — nothing listens until the local user has approved.
  const { vault, identity, created } = await approveAndLoadIdentity(deps);

  const cert = deps.createTls(deps.hostname());
  const pin = deps.generatePin();
  const pinBuf = Buffer.from(pin, "utf8");
  let failCount = 0;
  let busy = false;

  const server = tls.createServer({ key: cert.key, cert: cert.cert });
  server.on("tlsClientError", () => {
    /* scanners / wrong-protocol clients — ignore */
  });

  return new Promise<PairResult>((resolve, reject) => {
    let settled = false;
    let ttlTimer: NodeJS.Timeout | undefined;
    const finish = (err: Error | null, result?: PairResult) => {
      if (settled) return;
      settled = true;
      if (ttlTimer) clearTimeout(ttlTimer);
      server.close();
      if (err) reject(err);
      else resolve(result!);
    };

    server.on("error", (err) => finish(err));

    server.on("secureConnection", (socket: tls.TLSSocket) => {
      const ch = new LineChannel(socket, t.closeMs);
      if (busy || settled) {
        ch.send({ t: "error", error: "listener busy" });
        ch.close();
        return;
      }
      void (async () => {
        let first: Msg;
        try {
          first = await ch.next(t.stepMs, "hello");
        } catch {
          ch.close();
          return;
        }
        if (busy || settled) {
          ch.send({ t: "error", error: "listener busy" });
          ch.close();
          return;
        }
        if (first.t !== "hello" || typeof first.pin !== "string" || !timingSafePin(pinBuf, first.pin)) {
          failCount += 1;
          ch.send({ t: "error", error: "invalid PIN" });
          ch.close();
          if (failCount >= PIN_MAX_FAILURES) {
            finish(new PairAbortedError("too many failed PIN attempts — pairing listener closed"));
          }
          return;
        }

        // PIN accepted: single pairing — stop accepting and stop the TTL clock.
        busy = true;
        if (ttlTimer) clearTimeout(ttlTimer);
        server.close();
        const remote = socket.remoteAddress?.replace(/^::ffff:/, "") ?? undefined;
        try {
          const result = await listenerSession(ch, first, {
            vault,
            identity,
            created,
            role,
            tlsFingerprint: cert.fingerprint,
            remote,
            opts,
            deps,
          });
          await ch.close();
          finish(null, result);
        } catch (err) {
          await ch.close();
          finish(err instanceof Error ? err : new Error(String(err)));
        }
      })();
    });

    server.listen(opts.port ?? PAIR_DEFAULT_PORT, bind, () => {
      const addr = server.address();
      const port = addr && typeof addr === "object" ? addr.port : (opts.port ?? PAIR_DEFAULT_PORT);
      const expiresAt = deps.now() + ttlMs;
      ttlTimer = setTimeout(
        () => finish(new PairAbortedError("pairing session expired — nothing saved")),
        ttlMs,
      );
      opts.onListening?.({
        pin,
        port,
        bind,
        addresses: listenAddresses(bind),
        tlsFingerprint: cert.fingerprint,
        identityFingerprint: identityFingerprint(identity.ed25519.publicKey, identity.x25519.publicKey),
        identityCreated: created,
        role,
        hostname: deps.hostname(),
        expiresAt,
      });
    });
  });
}

async function listenerSession(
  ch: LineChannel,
  first: Msg,
  ctx: {
    vault: Vault;
    identity: SyncIdentity;
    created: boolean;
    role: SyncPeerRole;
    tlsFingerprint: string;
    remote?: string;
    opts: PairListenOptions;
    deps: PairDeps;
  },
): Promise<PairResult> {
  const { deps, opts } = ctx;
  const t = timeoutsOf(deps);
  let theirs: PairHello;
  try {
    theirs = parseHello(first.hello, { roleRequired: false });
  } catch (err) {
    abortWith(ch, `invalid hello from peer: ${err instanceof Error ? err.message : String(err)}`);
  }
  let roles: { listener: SyncPeerRole; connector: SyncPeerRole };
  try {
    roles = resolveRoles(ctx.role, theirs.role);
  } catch (err) {
    abortWith(ch, err instanceof Error ? err.message : String(err));
  }

  const mine = { ...ownHello(ctx.identity, deps, roles.listener), role: roles.listener };
  const transcript = transcriptHash({
    tlsFingerprint: ctx.tlsFingerprint,
    listener: mine,
    connector: { ...theirs, role: roles.connector },
  });

  const candidate: PeerCandidate = {
    id: theirs.id,
    name: opts.name ?? defaultPeerName(theirs.name),
    ed25519: theirs.ed25519,
    x25519: theirs.x25519,
    role: roles.connector,
    address: ctx.remote,
  };
  precheckPlan(ch, ctx.vault, candidate, opts.replace === true, opts.name !== undefined, deps.now());

  ch.send({ t: "hello", hello: mine, sig: signTranscript(ctx.identity, "listener", transcript) });

  let reply: Msg;
  try {
    reply = await ch.next(t.stepMs, "the peer's signature");
  } catch (err) {
    ch.close();
    throw new PairAbortedError(`pairing failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (reply.t === "error") {
    ch.close();
    throw new PairAbortedError(`peer aborted: ${peerErrorText(reply)} — nothing saved`);
  }
  if (reply.t !== "sig" || typeof reply.sig !== "string" || !verifyTranscript(theirs.ed25519, "connector", transcript, reply.sig)) {
    abortWith(ch, "peer signature verification failed — possible tampering; nothing saved", "signature verification failed");
  }

  return confirmAndSave(
    {
      ch,
      transcript,
      identity: ctx.identity,
      identityCreated: ctx.created,
      candidate,
      myRole: roles.listener,
      replace: opts.replace === true,
      explicitName: opts.name !== undefined,
    },
    deps,
  );
}

// ───────────────────────────── connector ─────────────────────────────

export interface PairConnectOptions {
  /** host:port of the listener (port defaults to 7334). */
  target: string;
  /** Full SHA-256 TLS fingerprint printed by the listener. */
  fingerprint: string;
  /** This machine's role; must be the opposite of the listener's. Default: whatever is opposite. */
  role?: SyncPeerRole;
  /** Local name for the listening peer (default: its sanitized hostname). */
  name?: string;
  replace?: boolean;
}

export function parsePairTarget(target: string): { host: string; port: number } {
  const trimmed = target.trim();
  if (!trimmed) throw new Error("missing <host:port>");
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(trimmed);
  if (bracketed) {
    return { host: bracketed[1], port: bracketed[2] ? checkPort(bracketed[2], target) : PAIR_DEFAULT_PORT };
  }
  const colons = trimmed.split(":").length - 1;
  if (colons === 0) return { host: trimmed, port: PAIR_DEFAULT_PORT };
  if (colons > 1) return { host: trimmed, port: PAIR_DEFAULT_PORT }; // bare IPv6
  const idx = trimmed.lastIndexOf(":");
  return { host: trimmed.slice(0, idx), port: checkPort(trimmed.slice(idx + 1), target) };
}

function checkPort(raw: string, target: string): number {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid host:port: ${target}`);
  return port;
}

export function assertFullTlsFingerprint(fp: string | undefined): string {
  const hex = (fp ?? "").replace(/[^0-9a-fA-F]/g, "");
  if (hex.length !== 64) {
    throw new Error(
      "pairing requires the listener's full TLS fingerprint — pass --fingerprint <fp> exactly as printed by `abra sync pair --listen`",
    );
  }
  return fp!.trim();
}

export async function pairConnect(opts: PairConnectOptions, deps: PairDeps): Promise<PairResult> {
  const fingerprint = assertFullTlsFingerprint(opts.fingerprint);
  const { host, port } = parsePairTarget(opts.target);
  if (opts.name !== undefined) validatePeerName(opts.name);
  const t = timeoutsOf(deps);

  const { vault, identity, created } = await approveAndLoadIdentity(deps);

  const pin = (await deps.promptPin("Pairing PIN shown on the other machine (hidden): ")).trim();
  if (!/^\d{6}$/.test(pin)) throw new Error("PIN must be 6 digits");

  // Fingerprint is verified on the raw TLS socket before the PIN is written.
  const { socket, peerFingerprint } = await connectPinnedTls(host, port, fingerprint);
  const ch = new LineChannel(socket, t.closeMs);
  try {
    return await connectorSession(ch, { vault, identity, created, pin, host, peerFingerprint, opts, deps });
  } finally {
    await ch.close();
  }
}

async function connectorSession(
  ch: LineChannel,
  ctx: {
    vault: Vault;
    identity: SyncIdentity;
    created: boolean;
    pin: string;
    host: string;
    peerFingerprint: string;
    opts: PairConnectOptions;
    deps: PairDeps;
  },
): Promise<PairResult> {
  const { vault, identity, created, pin, host, peerFingerprint, opts, deps } = ctx;
  const t = timeoutsOf(deps);
  const mine = ownHello(identity, deps, opts.role ?? null);
  ch.send({ t: "hello", pin, hello: mine });

  let reply: Msg;
  try {
    reply = await ch.next(t.stepMs, "the listener's hello");
  } catch (err) {
    ch.close();
    throw new PairAbortedError(`pairing failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (reply.t === "error") {
    ch.close();
    throw new PairAbortedError(`listener refused: ${peerErrorText(reply)}`);
  }
  if (reply.t !== "hello") abortWith(ch, "unexpected message from listener", "unexpected message");

  let theirs: PairHello;
  try {
    theirs = parseHello(reply.hello, { roleRequired: true });
  } catch (err) {
    abortWith(ch, `invalid hello from listener: ${err instanceof Error ? err.message : String(err)}`);
  }
  let roles: { listener: SyncPeerRole; connector: SyncPeerRole };
  try {
    roles = resolveRoles(theirs.role as SyncPeerRole, opts.role);
  } catch (err) {
    abortWith(ch, err instanceof Error ? err.message : String(err));
  }

  const transcript = transcriptHash({
    tlsFingerprint: peerFingerprint,
    listener: { ...theirs, role: roles.listener },
    connector: { ...mine, role: roles.connector },
  });
  if (typeof reply.sig !== "string" || !verifyTranscript(theirs.ed25519, "listener", transcript, reply.sig)) {
    abortWith(ch, "listener signature verification failed — possible tampering; nothing saved", "signature verification failed");
  }

  const candidate: PeerCandidate = {
    id: theirs.id,
    name: opts.name ?? defaultPeerName(theirs.name),
    ed25519: theirs.ed25519,
    x25519: theirs.x25519,
    role: roles.listener,
    address: host,
  };
  precheckPlan(ch, vault, candidate, opts.replace === true, opts.name !== undefined, deps.now());

  ch.send({ t: "sig", sig: signTranscript(identity, "connector", transcript) });

  return confirmAndSave(
    {
      ch,
      transcript,
      identity,
      identityCreated: created,
      candidate,
      myRole: roles.connector,
      replace: opts.replace === true,
      explicitName: opts.name !== undefined,
    },
    deps,
  );
}
