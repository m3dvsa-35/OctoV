import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The built UI ships inside the Python package and is loaded from disk by the
// desktop shell, so every asset must be local (no CDNs) and paths relative.
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../src/octov/webui/dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 2000,
  },
  worker: { format: "es" },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // `octov serve --dev` (loopback, token protected) answers RPC calls.
      "/rpc": process.env.OCTOV_API ?? "http://127.0.0.1:8765",
    },
  },
  test: { environment: "node" },
});
