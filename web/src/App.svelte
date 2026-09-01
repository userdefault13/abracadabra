<script lang="ts">
  import { getProjects, createProject, getSession, logout, type VarInfo } from "./lib/api";
  import ProjectView from "./lib/ProjectView.svelte";
  import ConnectionsPanel from "./lib/ConnectionsPanel.svelte";
  import GrantsPanel from "./lib/GrantsPanel.svelte";
  import AuthGate from "./lib/AuthGate.svelte";
  import UsbPanel from "./lib/UsbPanel.svelte";
  import KeysPanel from "./lib/KeysPanel.svelte";

  let projects = $state<Record<string, Record<string, VarInfo>>>({});
  let route = $state(location.hash || "#/");
  let toast = $state<{ text: string; kind: "ok" | "error" } | null>(null);
  let newProjectName = $state("");
  let creating = $state(false);
  // null = checking session, true = unlocked, false = locked (gate shown)
  let authed = $state<boolean | null>(null);
  let projectsLoaded = $state(false);
  let locking = $state(false);

  export function showToast(text: string, kind: "ok" | "error" = "ok") {
    toast = { text, kind };
    setTimeout(() => (toast = null), 5000);
  }

  async function refresh() {
    try {
      projects = (await getProjects()).projects;
      projectsLoaded = true;
    } catch (e) {
      showToast(String((e as Error).message), "error");
    }
  }

  async function checkSession() {
    try {
      authed = (await getSession()).authenticated;
    } catch {
      authed = false;
    }
    if (authed) void refresh();
  }
  checkSession();

  // any 401 from an API call re-locks the UI
  window.addEventListener("abra:unauthorized", () => (authed = false));

  // poll lightly so grants panel stays fresh
  const timer = setInterval(() => authed && refresh(), 15000);

  window.addEventListener("hashchange", () => (route = location.hash));

  async function lockSession() {
    if (locking) return;
    locking = true;
    try {
      await logout();
      authed = false;
      showToast("session locked");
    } catch (e) {
      showToast((e as Error).message, "error");
    } finally {
      locking = false;
    }
  }

  async function addProject() {
    const name = newProjectName.trim();
    if (!name || creating) return;
    creating = true;
    try {
      await createProject(name);
      await refresh();
      showToast(`project "${name}" created`);
      location.hash = `#/project/${name}`;
      newProjectName = "";
    } catch (e) {
      showToast((e as Error).message, "error");
    } finally {
      creating = false;
    }
  }
</script>

{#if authed === null}
  <div class="session-loading" aria-live="polite">checking session…</div>
{/if}

<aside class:dimmed={authed === null}>
  <div class="brand"><img src="/logo.svg" alt="" class="brand-logo" /> abracadabra</div>

  <div class="new-project">
    <input
      type="text"
      placeholder="new project…"
      bind:value={newProjectName}
      onkeydown={(e) => e.key === "Enter" && addProject()}
    />
    <button class="primary" disabled={creating} onclick={addProject}>+</button>
  </div>

  <nav>
    {#each Object.keys(projects).sort() as name}
      <a href={"#/project/" + name} class:selected={route === "#/project/" + name}>
        {name}
        <span class="count">{Object.keys(projects[name]).length}</span>
      </a>
    {/each}
  </nav>

  <div class="spacer"></div>

  <nav class="secondary">
    <a href="#/connections" class:selected={route === "#/connections"}>Connections</a>
    <a href="#/grants" class:selected={route === "#/grants"}>Grants</a>
    <a href="#/keys" class:selected={route === "#/keys"}>API Keys</a>
    <a href="#/usb" class:selected={route === "#/usb"}>USB</a>
  </nav>
  <div class="footer">
    {#if authed}
      <button class="lock-btn" disabled={locking} onclick={lockSession}>Lock</button>
    {/if}
    <span>local · loopback only</span>
  </div>
</aside>

<main class:dimmed={authed === null}>
  {#if route.startsWith("#/project/")}
    {@const name = decodeURIComponent(route.slice("#/project/".length))}
    {#if projects[name]}
      <ProjectView
        name={name}
        vars={projects[name]}
        onChanged={refresh}
        onDeleted={() => {
          location.hash = "#/";
          refresh();
        }}
        onToast={showToast}
      />
    {:else if projectsLoaded}
      <p class="dim">project not found: <strong>{name}</strong></p>
    {:else}
      <p class="dim">loading…</p>
    {/if}
  {:else if route === "#/connections"}
    <ConnectionsPanel onToast={showToast} />
  {:else if route === "#/grants"}
    <GrantsPanel />
  {:else if route === "#/usb"}
    <UsbPanel onToast={showToast} />
  {:else if route === "#/keys"}
    <KeysPanel onToast={showToast} />
  {:else}
    <div class="welcome">
      <h1><img src="/logo.svg" alt="" class="welcome-logo" /> abracadabra</h1>
      <p>Select a project from the sidebar, or create one above.</p>
      <p class="dim">
        Sensitive actions (reveal · edit · delete · create) pop a Touch ID prompt.
      </p>
    </div>
  {/if}
</main>

{#if toast}
  <div class="toast {toast.kind}">{toast.text}</div>
{/if}

{#if authed === false}
  <AuthGate onunlocked={() => { authed = true; void refresh(); }} />
{/if}

<style>
  aside {
    width: 240px;
    min-width: 240px;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 16px 12px;
  }
  .brand {
    font-weight: bold;
    color: var(--accent);
    margin-bottom: 16px;
    padding-left: 4px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .brand-logo {
    width: 22px;
    height: 22px;
    flex: none;
  }
  .welcome-logo {
    width: 28px;
    height: 28px;
    vertical-align: -6px;
    margin-right: 8px;
  }
  .new-project {
    display: flex;
    gap: 6px;
    margin-bottom: 12px;
  }
  .new-project input {
    flex: 1;
    min-width: 0;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow-y: auto;
  }
  a {
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text);
    text-decoration: none;
    padding: 7px 10px;
    border-radius: 6px;
  }
  a:hover {
    background: var(--bg3);
  }
  a.selected {
    background: rgba(210, 77, 240, 0.15);
    color: var(--accent);
  }
  .count {
    color: var(--dim);
    font-size: 12px;
  }
  .spacer {
    flex: 1;
  }
  .secondary a {
    color: var(--dim);
  }
  .session-loading {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(12, 8, 20, 0.85);
    color: var(--dim);
    backdrop-filter: blur(4px);
  }
  .dimmed {
    visibility: hidden;
  }
  .footer {
    margin-top: 10px;
    color: var(--dim);
    font-size: 11px;
    padding-left: 4px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .lock-btn {
    align-self: flex-start;
    font-size: 11px;
    padding: 4px 8px;
    color: var(--dim);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
  }
  .lock-btn:hover:not(:disabled) {
    color: var(--text);
    border-color: var(--accent);
  }
  main {
    flex: 1;
    padding: 28px 36px;
    max-width: 900px;
  }
  .welcome h1 {
    color: var(--accent);
  }
  .dim {
    color: var(--dim);
  }
</style>
