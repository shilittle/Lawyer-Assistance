import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

import {
  defineConfig,
  normalizePath,
  type Plugin,
} from "vite";

function normalizedModuleId(id: string): string {
  return normalizePath(id.split("?", 1)[0]);
}

function automationBundleBoundary(): Plugin {
  const entryModule = normalizedModuleId(
    fileURLToPath(new URL("./src/main.tsx", import.meta.url)),
  );
  const deferredModules = [
    "./src/features/settings/automation/McpAndAutomationWorkspace.tsx",
    "./src/features/settings/automation/AutomationOutboundApprovalPanel.tsx",
    "./src/features/settings/automation/ApprovedMcpPanel.tsx",
  ].map((relativePath) =>
    normalizedModuleId(
      fileURLToPath(new URL(relativePath, import.meta.url)),
    ),
  );

  return {
    name: "verify-automation-bundle-boundary",
    apply: "build",
    enforce: "post",
    generateBundle(_options, bundle) {
      const chunks = Object.values(bundle).filter(
        (output) => output.type === "chunk",
      );
      const chunksByFileName = new Map(
        chunks.map((chunk) => [chunk.fileName, chunk]),
      );
      const entryChunk = chunks.find(
        (chunk) =>
          (chunk.facadeModuleId !== null &&
            normalizedModuleId(chunk.facadeModuleId) === entryModule) ||
          (chunk.isEntry &&
            Object.keys(chunk.modules).some(
              (id) => normalizedModuleId(id) === entryModule,
            )),
      );
      if (!entryChunk) {
        this.error(
          "automation bundle boundary: src/main.tsx entry chunk was not generated",
        );
      }

      const reachableChunks = (includeDynamic: boolean): Set<string> => {
        const reachable = new Set<string>();
        const pending = [entryChunk.fileName];
        while (pending.length > 0) {
          const fileName = pending.pop();
          if (fileName === undefined || reachable.has(fileName)) continue;
          reachable.add(fileName);
          const chunk = chunksByFileName.get(fileName);
          if (!chunk) continue;
          pending.push(...chunk.imports);
          if (includeDynamic) {
            pending.push(...chunk.dynamicImports);
          }
        }
        return reachable;
      };

      const staticClosure = reachableChunks(false);
      const fullClosure = reachableChunks(true);
      for (const moduleId of deferredModules) {
        const containingChunks = chunks
          .filter((chunk) =>
            Object.keys(chunk.modules).some(
              (id) => normalizedModuleId(id) === moduleId,
            ),
          )
          .map((chunk) => chunk.fileName);
        if (containingChunks.length === 0) {
          this.error(
            `automation bundle boundary: required module is absent: ${moduleId}`,
          );
        }
        if (
          !containingChunks.some((fileName) =>
            fullClosure.has(fileName),
          )
        ) {
          this.error(
            `automation bundle boundary: required module is unreachable from src/main.tsx: ${moduleId}`,
          );
        }
        if (
          containingChunks.some((fileName) =>
            staticClosure.has(fileName),
          )
        ) {
          this.error(
            `automation bundle boundary: deferred module entered the static entry closure: ${moduleId}`,
          );
        }
      }
    },
  };
}

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
  plugins: [react(), automationBundleBoundary()],
});
