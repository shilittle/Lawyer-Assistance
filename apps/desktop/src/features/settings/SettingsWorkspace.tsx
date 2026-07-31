import type { ReactNode } from "react";

export interface SettingsWorkspaceProps {
  busy?: boolean;
  mode: "providers" | "mcp" | "privacy" | "maintenance";
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
            : mode === "privacy"
              ? "隐私与本地处理设置"
              : "版本、备份与诊断"
      }
    >
      {children}
    </section>
  );
}
