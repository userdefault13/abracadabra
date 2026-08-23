<script lang="ts">
  import {
    createVar,
    deleteProject,
    deleteVar,
    revealVar,
    updateVar,
    type VarInfo,
  } from "./api";

  let {
    name,
    vars,
    onChanged,
    onDeleted,
    onToast,
  }: {
    name: string;
    vars: Record<string, VarInfo>;
    onChanged: () => void;
    onDeleted: () => void;
    onToast: (text: string, kind?: "ok" | "error") => void;
  } = $props();

  let revealed = $state<Record<string, string>>({});
  const revealTimers: Record<string, ReturnType<typeof setTimeout>> = {};

  // dialog state
  let dialog = $state<null | { mode: "add" } | { mode: "edit"; key: string; original: string }>(null);
  let dialogKey = $state("");
  let dialogValue = $state("");
  let dialogSecret = $state(true);
  let saving = $state(false);
  let confirmingDelete = $state(false);

  function forgetReveal(key: string) {
    delete revealed[key];
    clearTimeout(revealTimers[key]);
  }

  async function reveal(key: string) {
    try {
      const { value } = await revealVar(name, key);
      revealed[key] = value;
      clearTimeout(revealTimers[key]);
      revealTimers[key] = setTimeout(() => forgetReveal(key), 15000);
    } catch (e) {
      onToast((e as Error).message, "error");
    }
  }

  async function copy(key: string) {
    try {
      const { value } = await revealVar(name, key);
      void value;
      await navigator.clipboard.writeText(value);
      onToast(`${key} copied to clipboard (value not shown)`);
    } catch (e) {
      onToast((e as Error).message, "error");
    }
  }

  function openAdd() {
    dialog = { mode: "add" };
    dialogKey = "";
    dialogValue = "";
    dialogSecret = true;
  }

  function openEdit(key: string, info: VarInfo) {
    dialog = { mode: "edit", key, original: info.masked };
    dialogKey = key;
    dialogValue = "";
    dialogSecret = false; // filled below
    // fetch current value for editing (Touch ID)
    revealVar(name, key)
      .then(({ value }) => (dialogValue = value))
      .catch((e) => {
        onToast((e as Error).message, "error");
        dialog = null;
      });
  }

  async function save() {
    if (!dialog || saving) return;
    saving = true;
    try {
      if (dialog.mode === "add") {
        await createVar(name, dialogKey.trim(), dialogValue, dialogSecret);
        onToast(`${dialogKey} added`);
        if (dialogSecret) onToast(`Touch ID approved — ${dialogKey} stored encrypted`);
      } else {
        await updateVar(name, dialogKey, dialogValue);
        onToast(`${dialogKey} updated`);
      }
      dialog = null;
      onChanged();
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      saving = false;
    }
  }

  async function remove(key: string) {
    try {
      await deleteVar(name, key);
      forgetReveal(key);
      onToast(`${key} deleted`);
      onChanged();
    } catch (e) {
      onToast((e as Error).message, "error");
    }
  }

  async function removeProject() {
    try {
      await deleteProject(name);
      onToast(`project "${name}" deleted`);
      onDeleted();
    } catch (e) {
      onToast((e as Error).message, "error");
    }
  }
</script>

<div class="header">
  <h2 class="panel-title">{name}</h2>
  <button class="danger" onclick={() => (confirmingDelete = true)}>delete project</button>
</div>

{#if confirmingDelete}
  <div class="confirm">
    <span>Delete project “{name}” and all its vars?</span>
    <button class="danger" onclick={removeProject}>yes, delete</button>
    <button onclick={() => (confirmingDelete = false)}>cancel</button>
  </div>
{/if}

<table>
  <thead>
    <tr><th>key</th><th>value</th><th></th><th></th></tr>
  </thead>
  <tbody>
    {#each Object.entries(vars).sort(([a], [b]) => a.localeCompare(b)) as [key, info] (key)}
      <tr>
        <td>
          {key}
          {#if info.secret}<span class="badge secret">secret</span>{/if}
        </td>
        <td class="value">
          {#if revealed[key]}<code class="revealed">{revealed[key]}</code>
          {:else}<code class="masked">{info.masked}</code>{/if}
        </td>
        <td class="actions">
          {#if revealed[key]}
            <button onclick={() => forgetReveal(key)}>hide</button>
          {:else}
            <button title="reveal via Touch ID" onclick={() => reveal(key)}>👁</button>
            <button title="copy via Touch ID" onclick={() => copy(key)}>📋</button>
          {/if}
          <button title="edit" onclick={() => openEdit(key, info)}>✏️</button>
          <button class="danger" title="delete" onclick={() => remove(key)}>🗑</button>
        </td>
        <td class="dim">
          {new Date(info.updatedAt).toLocaleDateString()}
        </td>
      </tr>
    {/each}
    {#if Object.keys(vars).length === 0}
      <tr><td colspan="4" class="dim">no vars yet — add one below</td></tr>
    {/if}
  </tbody>
</table>

<div class="footer-row">
  <button class="primary" onclick={openAdd}>+ add var</button>
  <span class="dim">reveal · copy · edit · add each require Touch ID approval</span>
</div>

{#if dialog}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (dialog = null)}>
    <div class="modal">
      <h3>{dialog.mode === "add" ? `Add var to ${name}` : `Edit ${dialog.key}`}</h3>
      {#if dialog.mode === "add"}
        <label>
          key
          <input type="text" bind:value={dialogKey} placeholder="MY_API_KEY" />
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={dialogSecret} />
          secret (stored encrypted, masked in listings)
        </label>
      {:else}
        <p class="dim">original: <code>{dialog.original}</code></p>
      {/if}
      <label>
        value
        <textarea rows="3" bind:value={dialogValue} placeholder="paste value…" disabled={saving && dialog.mode === 'edit' && !dialogValue}></textarea>
      </label>
      <div class="modal-actions">
        <button class="primary" disabled={saving || !dialogKey || !dialogValue} onclick={save}>
          {saving ? "approve Touch ID…" : "save"}
        </button>
        <button onclick={() => (dialog = null)} disabled={saving}>cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .header h2 {
    margin: 0;
  }
  .confirm {
    display: flex;
    gap: 10px;
    align-items: center;
    background: rgba(239, 83, 80, 0.08);
    border: 1px solid rgba(239, 83, 80, 0.4);
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 16px;
  }
  .value code {
    font-size: 13px;
  }
  .revealed {
    color: var(--green);
    word-break: break-all;
  }
  .masked {
    color: var(--dim);
    letter-spacing: 0.05em;
  }
  .actions {
    white-space: nowrap;
  }
  .actions button {
    padding: 3px 8px;
    margin-right: 4px;
  }
  .dim {
    color: var(--dim);
    font-size: 12px;
  }
  .footer-row {
    margin-top: 16px;
    display: flex;
    gap: 14px;
    align-items: center;
  }
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: grid;
    place-items: center;
    z-index: 50;
  }
  .modal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px;
    width: 440px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .modal h3 {
    margin: 0;
    color: var(--accent);
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    color: var(--dim);
    font-size: 12px;
  }
  label.check {
    flex-direction: row;
    align-items: center;
    gap: 8px;
    color: var(--text);
    font-size: 13px;
  }
  textarea {
    resize: vertical;
  }
  .modal-actions {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
  }
</style>
