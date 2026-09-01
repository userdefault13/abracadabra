import type { Connection } from "../core/vault.js";

export interface ProviderField {
  /** Env var name the credential is stored under. */
  varName: string;
  prompt: string;
  secret: boolean;
  required?: boolean;
}

export interface Provider {
  id: string;
  label: string;
  /** Where to obtain the admin credential. */
  portalUrl?: string;
  fields: ProviderField[];
  /**
   * Map a stored connection to env vars for a target project.
   * When providers expose key-minting APIs, this becomes an API call.
   */
  issueVars: (conn: Connection) => Record<string, string>;
  /**
   * Optional: derive full credentials from a downloaded key file's raw JSON,
   * including API calls to fill in missing pieces (e.g. account IDs).
   */
  importFromFile?: (
    raw: Record<string, string>,
  ) => Promise<Record<string, { value: string; secret: boolean }>>;
}

export const providers: Record<string, Provider> = {
  cdp: {
    id: "cdp",
    label: "Coinbase Developer Platform (CDP)",
    portalUrl: "https://portal.cdp.coinbase.com/api-keys/secret",
    fields: [
      {
        varName: "CDP_API_KEY_ID",
        prompt:
          "API Key ID (e.g. organizations/{orgId}/apiKeys/{keyId}) — shown in the create-key modal",
        secret: false,
        required: true,
      },
      {
        varName: "CDP_API_KEY_SECRET",
        prompt:
          "API Key Secret (EC PEM or base64 Ed25519) — shown ONCE in the create-key modal",
        secret: true,
        required: true,
      },
      {
        varName: "CDP_WALLET_SECRET",
        prompt: "Wallet Secret (optional, for wallet write ops — enter to skip)",
        secret: true,
      },
    ],
    issueVars: (conn) => {
      const vars: Record<string, string> = {
        CDP_API_KEY_ID: conn.vars.CDP_API_KEY_ID?.value ?? "",
        CDP_API_KEY_SECRET: conn.vars.CDP_API_KEY_SECRET?.value ?? "",
      };
      const walletSecret = conn.vars.CDP_WALLET_SECRET?.value;
      if (walletSecret) vars.CDP_WALLET_SECRET = walletSecret;
      return vars;
    },
  },

  cloudflare: {
    id: "cloudflare",
    label: "Cloudflare",
    portalUrl: "https://dash.cloudflare.com/profile/api-tokens",
    fields: [
      {
        varName: "CLOUDFLARE_API_TOKEN",
        prompt:
          'API Token — create one with template "Edit Cloudflare Workers" or custom scoped token',
        secret: true,
        required: true,
      },
      {
        varName: "CLOUDFLARE_ACCOUNT_ID",
        prompt:
          "Account ID (dash.cloudflare.com → any domain overview → right sidebar)",
        secret: false,
        required: true,
      },
    ],
    issueVars: (conn) => ({
      CLOUDFLARE_API_TOKEN: conn.vars.CLOUDFLARE_API_TOKEN.value,
      CLOUDFLARE_ACCOUNT_ID: conn.vars.CLOUDFLARE_ACCOUNT_ID?.value ?? "",
    }),
    importFromFile: async (raw) => {
      const token =
        raw.ApiKey ?? raw.apiKey ?? raw.api_token ?? raw.token ?? raw.CLOUDFLARE_API_TOKEN;
      if (!token) throw new Error("No API token found in file (looked for ApiKey/apiKey/token)");
      const vars: Record<string, { value: string; secret: boolean }> = {
        CLOUDFLARE_API_TOKEN: { value: token, secret: true },
      };
      // discover Account ID via the API when not supplied in the file
      const accountId =
        raw.AccountId ?? raw.account_id ?? raw.accountId ?? raw.CLOUDFLARE_ACCOUNT_ID;
      if (accountId) {
        vars.CLOUDFLARE_ACCOUNT_ID = { value: accountId, secret: false };
      } else {
        const res = await fetch("https://api.cloudflare.com/client/v4/accounts", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await res.json()) as {
          success?: boolean;
          result?: { id: string; name: string }[];
          errors?: { message: string }[];
        };
        if (!res.ok || !data.success || !data.result?.length) {
          throw new Error(
            `Token rejected while discovering account ID: ${data.errors?.[0]?.message ?? res.status}`,
          );
        }
        if (data.result.length > 1) {
          console.error(`Multiple accounts found:`);
          for (const a of data.result) console.error(`  ${a.id}  ${a.name}`);
          throw new Error("Set CLOUDFLARE_ACCOUNT_ID explicitly — multiple accounts");
        }
        vars.CLOUDFLARE_ACCOUNT_ID = { value: data.result[0].id, secret: false };
      }
      return vars;
    },
  },

  nvidia: {
    id: "nvidia",
    label: "NVIDIA NIM / Nemotron",
    portalUrl: "https://build.nvidia.com/settings/api-keys",
    fields: [
      {
        varName: "NVIDIA_API_KEY",
        prompt:
          'API Key ("Get API Key" at build.nvidia.com — starts with nvapi-)',
        secret: true,
        required: true,
      },
      {
        varName: "NVIDIA_BASE_URL",
        prompt:
          "Base URL (optional — enter to default to https://integrate.api.nvidia.com/v1; set for self-hosted NIM)",
        secret: false,
      },
    ],
    issueVars: (conn) => {
      const vars: Record<string, string> = {
        NVIDIA_API_KEY: conn.vars.NVIDIA_API_KEY.value,
      };
      if (conn.vars.NVIDIA_BASE_URL?.value) vars.NVIDIA_BASE_URL = conn.vars.NVIDIA_BASE_URL.value;
      return vars;
    },
    importFromFile: async (raw) => {
      const token =
        raw.NVIDIA_API_KEY ?? raw.apiKey ?? raw.api_key ?? raw.token ?? raw.nvapi;
      if (!token) throw new Error("No API key found in file (looked for NVIDIA_API_KEY/apiKey/token)");
      if (!token.startsWith("nvapi-")) console.error("  note: NVIDIA keys usually start with nvapi-");
      // validate against the models listing and confirm the account works
      const res = await fetch("https://integrate.api.nvidia.com/v1/models", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        throw new Error(`Token rejected by NVIDIA: HTTP ${res.status}`);
      }
      const data = (await res.json()) as { data?: { id: string }[] };
      const models = data.data?.length ?? 0;
      if (models > 0) console.error(`  verified — ${models} model(s) available (incl. nemotron family)`);
      const vars: Record<string, { value: string; secret: boolean }> = {
        NVIDIA_API_KEY: { value: token, secret: true },
      };
      return vars;
    },
  },

  openrouter: {
    id: "openrouter",
    label: "OpenRouter",
    portalUrl: "https://openrouter.ai/settings/keys",
    fields: [
      {
        varName: "OPENROUTER_API_KEY",
        prompt:
          'API Key (openrouter.ai/settings/keys — starts with sk-or-)',
        secret: true,
        required: true,
      },
      {
        varName: "OPENROUTER_BASE_URL",
        prompt:
          "Base URL (optional — enter to default to https://openrouter.ai/api/v1)",
        secret: false,
      },
    ],
    issueVars: (conn) => {
      const vars: Record<string, string> = {
        OPENROUTER_API_KEY: conn.vars.OPENROUTER_API_KEY.value,
      };
      if (conn.vars.OPENROUTER_BASE_URL?.value)
        vars.OPENROUTER_BASE_URL = conn.vars.OPENROUTER_BASE_URL.value;
      return vars;
    },
    importFromFile: async (raw) => {
      const token =
        raw.OPENROUTER_API_KEY ?? raw.apiKey ?? raw.api_key ?? raw.token ?? raw.key;
      if (!token)
        throw new Error("No API key found in file (looked for OPENROUTER_API_KEY/apiKey/token)");
      if (!token.startsWith("sk-or-")) console.error("  note: OpenRouter keys usually start with sk-or-");
      // validate against the auth/key endpoint and pick up the label
      const res = await fetch("https://openrouter.ai/api/v1/auth/key", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as {
        data?: { label?: string; usage?: number; limit?: number | null; is_free_tier?: boolean };
        error?: { message?: string };
      };
      if (!res.ok || !data.data) {
        throw new Error(`Token rejected by OpenRouter: ${data.error?.message ?? res.status}`);
      }
      const { label, usage, limit } = data.data;
      const usageInfo =
        limit == null ? "no spend limit" : `${usage ?? 0}/${limit} used`;
      console.error(`  verified${label ? ` as "${label}"` : ""} — ${usageInfo}`);
      return {
        OPENROUTER_API_KEY: { value: token, secret: true },
      };
    },
  },

  digitalocean: {
    id: "digitalocean",
    label: "DigitalOcean",
    portalUrl: "https://cloud.digitalocean.com/account/api/tokens",
    fields: [
      {
        varName: "DIGITALOCEAN_TOKEN",
        prompt:
          "Personal Access Token — create at cloud.digitalocean.com/account/api/tokens (full access recommended)",
        secret: true,
        required: true,
      },
      {
        varName: "DIGITALOCEAN_SPACES_ACCESS_KEY",
        prompt:
          "Spaces access key (optional, S3-compatible — API → Spaces Keys — enter to skip)",
        secret: false,
      },
      {
        varName: "DIGITALOCEAN_SPACES_SECRET_KEY",
        prompt: "Spaces secret key (optional — enter to skip)",
        secret: true,
      },
    ],
    issueVars: (conn) => {
      const vars: Record<string, string> = {
        DIGITALOCEAN_TOKEN: conn.vars.DIGITALOCEAN_TOKEN.value,
      };
      for (const opt of [
        "DIGITALOCEAN_SPACES_ACCESS_KEY",
        "DIGITALOCEAN_SPACES_SECRET_KEY",
      ] as const) {
        if (conn.vars[opt]?.value) vars[opt] = conn.vars[opt].value;
      }
      return vars;
    },
    importFromFile: async (raw) => {
      const token =
        raw.ApiKey ?? raw.apiKey ?? raw.token ?? raw.access_token ?? raw.DIGITALOCEAN_TOKEN;
      if (!token) throw new Error("No token found in file (looked for ApiKey/apiKey/token)");
      // validate against the DO API and pick up the account email for the label
      const res = await fetch("https://api.digitalocean.com/v2/account", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as {
        account?: { email?: string; status?: string };
        message?: string;
      };
      if (!res.ok || !data.account) {
        throw new Error(`Token rejected by DigitalOcean: ${data.message ?? res.status}`);
      }
      console.error(`  verified as ${data.account.email} (${data.account.status})`);
      const vars: Record<string, { value: string; secret: boolean }> = {
        DIGITALOCEAN_TOKEN: { value: token, secret: true },
      };
      const spacesKey =
        raw.SpacesAccessKey ?? raw.spaces_access_key ?? raw.spacesAccessKey;
      if (spacesKey) vars.DIGITALOCEAN_SPACES_ACCESS_KEY = { value: spacesKey, secret: false };
      const spacesSecret =
        raw.SpacesSecretKey ?? raw.spaces_secret_key ?? raw.spacesSecretKey;
      if (spacesSecret) vars.DIGITALOCEAN_SPACES_SECRET_KEY = { value: spacesSecret, secret: true };
      return vars;
    },
  },

  vercel: {
    id: "vercel",
    label: "Vercel",
    portalUrl: "https://vercel.com/account/settings/tokens",
    fields: [
      {
        varName: "VERCEL_TOKEN",
        prompt:
          'Access Token — create at vercel.com/account/settings/tokens (scope to full account or a team)',
        secret: true,
        required: true,
      },
      {
        varName: "VERCEL_ORG_ID",
        prompt: "Org/Team ID (optional, vercel.com/team/<team>/settings — enter to skip)",
        secret: false,
      },
      {
        varName: "VERCEL_PROJECT_ID",
        prompt: "Project ID (optional, project settings → general — enter to skip)",
        secret: false,
      },
    ],
    issueVars: (conn) => {
      const vars: Record<string, string> = {
        VERCEL_TOKEN: conn.vars.VERCEL_TOKEN.value,
      };
      for (const opt of ["VERCEL_ORG_ID", "VERCEL_PROJECT_ID"] as const) {
        if (conn.vars[opt]?.value) vars[opt] = conn.vars[opt].value;
      }
      return vars;
    },
    importFromFile: async (raw) => {
      const token =
        raw.ApiKey ?? raw.apiKey ?? raw.token ?? raw.access_token ?? raw.VERCEL_TOKEN;
      if (!token) throw new Error("No token found in file (looked for ApiKey/apiKey/token)");
      // validate against the Vercel API and pick up username for the label
      const res = await fetch("https://api.vercel.com/v2/user", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as {
        user?: { username?: string; email?: string };
        error?: { message?: string };
      };
      if (!res.ok || !data.user) {
        throw new Error(`Token rejected by Vercel: ${data.error?.message ?? res.status}`);
      }
      console.error(`  verified as ${data.user.username ?? data.user.email}`);
      const vars: Record<string, { value: string; secret: boolean }> = {
        VERCEL_TOKEN: { value: token, secret: true },
      };
      const orgId = raw.orgId ?? raw.OrgId ?? raw.teamId ?? raw.VERCEL_ORG_ID;
      if (orgId) vars.VERCEL_ORG_ID = { value: orgId, secret: false };
      return vars;
    },
  },
};

export function getProvider(id: string): Provider {
  const provider = providers[id];
  if (!provider) {
    throw new Error(
      `Unknown provider "${id}". Available: ${Object.keys(providers).join(", ")}`,
    );
  }
  return provider;
}
