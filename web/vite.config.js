import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Project site lives at https://<user>.github.io/llmvulntesting/, so assets must
// be referenced under that base path.
export default defineConfig({
  base: "/llmvulntesting/",
  plugins: [react()],
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
  },
});
