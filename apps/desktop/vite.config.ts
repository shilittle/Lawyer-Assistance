import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // The Tauri executable embeds every file in this directory. Keeping old
    // content-hashed bundles here silently ships obsolete UI code and bloats
    // every installer, so each production build must start from an empty dir.
    emptyOutDir: true,
    outDir: "frontend-dist",
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("cytoscape")) return "graph-vendor";
          if (
            id.includes("react-markdown") ||
            id.includes("remark-") ||
            id.includes("rehype-") ||
            id.includes("micromark") ||
            id.includes("mdast-") ||
            id.includes("hast-") ||
            id.includes("unified")
          ) {
            return "markdown-vendor";
          }
          if (
            id.includes("react/") ||
            id.includes("react-dom") ||
            id.includes("scheduler")
          ) {
            return "react-vendor";
          }
          if (id.includes("@tauri-apps")) return "tauri-vendor";
          return "vendor";
        },
      },
    },
  },
  plugins: [react()],
});
