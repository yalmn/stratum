import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Im Entwicklungsmodus gehen API-Aufrufe an den laufenden stratum-Server.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
  build: { outDir: "dist", sourcemap: false },
});
