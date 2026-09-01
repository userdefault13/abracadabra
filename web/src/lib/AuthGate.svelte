<script lang="ts">
  import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
  import {
    passkeyRegisterOptions,
    passkeyRegisterVerify,
    passkeyAuthOptions,
    passkeyAuthVerify,
  } from "./api";

  let { onunlocked }: { onunlocked: () => void } = $props();

  let mode = $state<"login" | "register">("login");
  let busy = $state(false);
  let error = $state("");

  async function register() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      const options = await passkeyRegisterOptions();
      const attestation = await startRegistration({ optionsJSON: options });
      await passkeyRegisterVerify(attestation);
      onunlocked();
    } catch (e) {
      const msg = (e as Error).name === "NotAllowedError"
        ? "passkey setup cancelled"
        : (e as Error).message;
      error = msg;
    } finally {
      busy = false;
    }
  }

  async function unlock() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      const options = await passkeyAuthOptions();
      const assertion = await startAuthentication({ optionsJSON: options });
      await passkeyAuthVerify(assertion);
      onunlocked();
    } catch (e) {
      const msg = (e as Error).name === "NotAllowedError"
        ? "cancelled or no matching passkey"
        : (e as Error).message;
      error = msg;
    } finally {
      busy = false;
    }
  }
</script>

<div class="gate" role="dialog" aria-modal="true" aria-label="passkey login required">
  <div class="card">
    <img src="/logo.svg" alt="" class="logo" width="64" height="64" />
    <h1>abracadabra</h1>

    {#if mode === "register"}
      <p class="sub">
        Set up a <b>biometric passkey</b> to unlock the dash.<br />
        Approve the Touch ID prompt, then save the passkey —
        Chrome can sync it to your Google Password Manager.
      </p>
    {:else}
      <p class="sub">Unlock with your biometric passkey<br />(Touch ID / Google Password Manager).</p>
    {/if}

    {#if mode === "register"}
      <button class="primary big" disabled={busy} onclick={register}>
        {busy ? "waiting for Touch ID…" : "Set up passkey"}
      </button>
      <p class="hint">
        Already have a passkey? <button class="link" onclick={() => { mode = "login"; error = ""; }}>Sign in</button>
      </p>
    {:else}
      <button class="primary big" disabled={busy} onclick={unlock}>
        {busy ? "waiting for biometric…" : "🔒 Unlock"}
      </button>
      <p class="hint">
        First time here? <button class="link" onclick={() => { mode = "register"; error = ""; }}>Set up a passkey</button>
      </p>
    {/if}

    {#if error}
      <p class="error">{error}</p>
    {:else}
      <p class="hint">&nbsp;</p>
    {/if}
  </div>
</div>

<style>
  .gate {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(10, 8, 16, 0.45);
    backdrop-filter: blur(18px) saturate(1.1);
    -webkit-backdrop-filter: blur(18px) saturate(1.1);
  }
  .card {
    width: 380px;
    padding: 36px 32px 24px;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: rgba(26, 23, 37, 0.85);
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
    margin: 0 0 22px;
    color: var(--dim);
    font-size: 12px;
    line-height: 1.6;
  }
  .sub b {
    color: var(--text);
  }
  .big {
    width: 100%;
    padding: 11px 0;
    font-size: 14px;
  }
  .hint {
    margin: 14px 0 0;
    color: var(--dim);
    font-size: 12px;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: 12px;
    text-decoration: underline;
  }
  .error {
    color: var(--red);
    font-size: 12px;
    min-height: 18px;
    margin: 10px 0 0;
  }
</style>
