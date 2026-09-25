/**
 * Per-user abra agent — holds the unlocked master key in memory with idle lock.
 *
 * Does not call authenticate()/PolKit. Reveal approval stays in CLI/MCP clients.
 * Sensitive ops require an abra CLI peer (Linux ss+/proc check; fail closed).
 * No key-export op: sync/usb/lan/cartridge keep using getMasterKey() directly.
 */
export {
  startAgent,
  stopAgent,
  lockAgent,
  agentStatus,
  installSignalHandlers,
  type StartAgentOpts,
  type AuthorizePeerFn,
} from "./server.js";
export {
  isAgentEnabled,
  resolveAgentSocketPath,
  resolveIdleSeconds,
  ensureAgentRuntimeDir,
  mkAgentTestDir,
  DEFAULT_IDLE_SECONDS,
} from "./paths.js";
export {
  agentRequest,
  agentUnlock,
  agentLock,
  agentVaultLoad,
  agentVaultSave,
  loadVaultViaAgent,
  saveVaultViaAgent,
  shouldTryAgent,
  isAgentUnavailable,
  clientVaultBinding,
  AgentClientError,
} from "./client.js";
export { AgentState } from "./state.js";
export { PROTOCOL_VERSION, MAX_FRAME_BYTES } from "./protocol.js";
export {
  authorizePeer,
  parseSsUnixXpn,
  resolvePeerPidFromSs,
  isAllowedAbraCliPeer,
  type PeerAuthResult,
} from "./peer.js";
