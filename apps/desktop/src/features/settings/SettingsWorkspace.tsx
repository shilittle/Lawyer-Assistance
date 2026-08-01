import type { ReactNode } from "react";

export interface SettingsWorkspaceProps {
  busy?: boolean;
  mode: "providers" | "mcp" | "local-processing" | "maintenance";
  children: ReactNode;
}

export function SettingsWorkspace({
  busy = false,
  mode,
  children,
}: SettingsWorkspaceProps) {
  return (
    <section
      className={
        mode === "providers"
          ? "provider-layout"
          : "settings-maintenance-workspace"
      }
      aria-busy={busy}
      aria-label={
        mode === "providers"
          ? "Provider 与凭据设置"
          : mode === "mcp"
            ? "MCP 与自动化设置"
            : mode === "local-processing"
              ? "本地处理环境与 OCR 组件设置"
              : "版本、备份与诊断"
      }
    >
      {children}
    </section>
  );
}
