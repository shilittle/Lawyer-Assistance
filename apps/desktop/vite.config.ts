import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // The Tauri executable embeds every file in this directory. Keeping old
    // content-hashed bundles here silently ships obsolete UI code and bloats
    // every installer, so each production build must start from an empty dir.
    emptyOutDir: true,
    outDir: "frontend-dist",
  },
  plugins: [react()],
});
