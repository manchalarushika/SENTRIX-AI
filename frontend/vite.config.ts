import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api and /ws to the FastAPI backend so the browser
// talks to a single origin (no CORS configuration needed for local use).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.SENTRIX_BACKEND_URL || "http://127.0.0.1:8000";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": { target, changeOrigin: true },
        "/ws": { target: target.replace(/^http/, "ws"), ws: true },
      },
    },
    preview: {
      port: 4173,
      proxy: {
        "/api": { target, changeOrigin: true },
        "/ws": { target: target.replace(/^http/, "ws"), ws: true },
      },
    },
    build: {
      chunkSizeWarningLimit: 1500,
    },
  };
});
