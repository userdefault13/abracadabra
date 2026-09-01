<script lang="ts">
  import { activateLicense, getLicenseStatus, type LicenseStatus } from "./api";

  let { onactivated }: { onactivated: () => void } = $props();

  let wallet = $state("");
  let busy = $state(false);
  let error = $state("");
  let status = $state<LicenseStatus | null>(null);

  async function loadStatus() {
    try {
      status = await getLicenseStatus();
    } catch {
      status = null;
    }
  }
  loadStatus();

  async function connectWallet() {
    error = "";
    const eth = (window as Window & { ethereum?: { request: (a: unknown) => Promise<unknown> } })
      .ethereum;
    if (!eth) {
      error = "No wallet in browser — paste your 0x address below";
      return;
    }
    busy = true;
    try {
      const accounts = (await eth.request({ method: "eth_requestAccounts" })) as string[];
      wallet = accounts[0] ?? "";
    } catch (e) {
      error = (e as Error).message || "wallet connect cancelled";
    } finally {
      busy = false;
    }
  }

  async function activate() {
    const w = wallet.trim();
    if (!w || busy) return;
    busy = true;
    error = "";
    try {
      await activateLicense(w);
      onactivated();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="gate" role="dialog" aria-modal="true" aria-label="Abra License activation">
  <div class="card">
    <img src="/logo.svg" alt="" class="logo" width="64" height="64" />
    <h1>Activate abracadabra</h1>
    <p class="sub">
      Connect the wallet that holds your <b>Abra License NFT</b> on Base.
      Verification runs locally — your key never leaves this machine.
    </p>

    {#if status?.contract}
      <p class="meta dim">contract: {status.contract.slice(0, 10)}…{status.contract.slice(-6)}</p>
    {/if}

    <input
      type="text"
      class="wallet"
      placeholder="0x… wallet address"
      bind:value={wallet}
      disabled={busy}
      spellcheck="false"
      autocomplete="off"
    />

    <div class="actions">
      <button class="secondary" disabled={busy} onclick={connectWallet}>Connect wallet</button>
      <button class="primary" disabled={busy || !wallet.trim()} onclick={activate}>
        {busy ? "checking NFT…" : "Activate"}
      </button>
    </div>

    <p class="hint">
      Need a license?
      <a href="https://www.aarcadeghst.com/concierge/terminal" target="_blank" rel="noopener noreferrer"
        >Mint in Concierge</a
      >
      ·
      <a href="https://www.aarcadeghst.com/baazaar" target="_blank" rel="noopener noreferrer">Baazaar resale</a>
    </p>

    {#if error}
      <p class="error">{error}</p>
    {/if}
  </div>
</div>

<style>
  .gate {
    position: fixed;
    inset: 0;
    z-index: 1100;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(10, 8, 16, 0.55);
    backdrop-filter: blur(18px) saturate(1.1);
    -webkit-backdrop-filter: blur(18px) saturate(1.1);
  }
  .card {
    width: 420px;
    max-width: calc(100vw - 32px);
    padding: 36px 32px 24px;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: rgba(26, 23, 37, 0.92);
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.55);
    text-align: center;
  }
  .logo {
    display: block;
    margin: 0 auto 8px;
  }
  h1 {
    margin: 0 0 10px;
    font-size: 18px;
    letter-spacing: 0.04em;
  }
  .sub {
    margin: 0 0 16px;
    color: var(--dim);
    font-size: 12px;
    line-height: 1.6;
  }
  .sub b {
    color: var(--text);
  }
  .meta {
    font-size: 11px;
    margin: 0 0 12px;
  }
  .wallet {
    width: 100%;
    box-sizing: border-box;
    margin-bottom: 12px;
    font-family: ui-monospace, monospace;
    font-size: 12px;
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  .actions button {
    flex: 1;
  }
  .primary {
    padding: 10px 0;
  }
  .secondary {
    padding: 10px 0;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    cursor: pointer;
  }
  .secondary:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .hint {
    margin: 8px 0 0;
    color: var(--dim);
    font-size: 11px;
    line-height: 1.5;
  }
  .hint a {
    color: var(--accent);
  }
  .error {
    color: var(--red);
    font-size: 12px;
    margin: 10px 0 0;
  }
  .dim {
    color: var(--dim);
  }
</style>
