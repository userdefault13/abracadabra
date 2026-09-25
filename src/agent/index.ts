/**
 * Per-user abra agent — holds the unlocked master key in memory with idle lock.
 *
 * Does not call authenticate()/PolKit. Reveal approval stays in CLI/MCP clients.
 * No key-export op: sync/usb/lan/cartridge keep using getMasterKey() directly.
 */
export {
  startAgent,
  stopAgent,
  lockAgent,
  agentStatus,
  type StartAgentOpts,
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
  AgentClientError,
} from "./client.js";
export { AgentState } from "./state.js";
export { PROTOCOL_VERSION, MAX_FRAME_BYTES } from "./protocol.js";
