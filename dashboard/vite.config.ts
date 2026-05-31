import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard is a thin client: it only calls the API. In dev we proxy /api and
// /healthz to the FastAPI server so there are no CORS concerns.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/healthz": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
