import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:7331",
      "/grants": "http://127.0.0.1:7331",
      "/secret": "http://127.0.0.1:7331",
    },
  },
});
