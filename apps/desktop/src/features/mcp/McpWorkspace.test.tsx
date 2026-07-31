import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  McpServerConfig,
  McpServerConfigResponse,
  McpServerStatus,
} from "../../ipc/mcp/types";
import {
  McpWorkspaceView,
  mcpConfigDraftIsDirty,
  mcpConfigsEqual,
  mcpConfigToDraft,
  mcpDraftToConfig,
  mcpStatusResponseIsCurrent,
  mcpWorkspaceHasUnsavedChanges,
  mcpWorkspaceMutationAllowed,
  validateMcpBearerToken,
} from "./McpWorkspace";

const config: McpServerConfig = {
  schemaVersion: 1,
  autoStart: true,
  port: 8787,
  allowedRoots: ["C:/Cases/A", "D:/Evidence"],
  outputRoot: "C:/Exports",
  allowedOrigins: ["http://127.0.0.1:3000"],
  maxBodyBytes: 2 * 1024 * 1024,
  requestTimeoutMs: 30_000,
  maxConcurrency: 8,
};

const configResponse: McpServerConfigResponse = {
  config,
  legalDatabasePath: "C:/App/resources/legal_core.sqlite",
  userDatabasePath: "C:/Users/test/AppData/user.sqlite",
  bearerTokenConfigured: true,
  bearerTokenMasked: "****cdef",
};

const status: McpServerStatus = {
  phase: "running",
  endpoint: "http://127.0.0.1:8787/mcp",
  startedAt: "2026-07-17T12:00:00Z",
  lastError: null,
};

describe("McpWorkspace configuration", () => {
  it("round-trips the persisted non-secret config and normalizes duplicate lines", () => {
    const draft = mcpConfigToDraft(config);
    draft.allowedRoots += "\nC:/Cases/A\n";

    const normalized = mcpDraftToConfig(draft);
    expect(normalized).toEqual(config);
    expect(mcpConfigsEqual(config, normalized)).toBe(true);
    expect(mcpConfigDraftIsDirty(config, draft)).toBe(false);
    expect(
      mcpConfigDraftIsDirty(config, { ...draft, port: "not-a-port" }),
    ).toBe(true);
    expect(JSON.stringify(normalized)).not.toContain("bearer");
  });

  it("enforces the same bounded HTTP limits before IPC", () => {
    const draft = mcpConfigToDraft(config);
    expect(() => mcpDraftToConfig({ ...draft, port: "0" })).toThrow("端口");
    expect(() => mcpDraftToConfig({ ...draft, maxBodyBytes: "100" })).toThrow(
      "请求体上限",
    );
    expect(() =>
      mcpDraftToConfig({ ...draft, allowedOrigins: "https://example.com/path" }),
    ).toThrow("Origin");
  });

  it("accepts only 32–512 visible ASCII bearer bytes", () => {
    expect(validateMcpBearerToken("a".repeat(32))).toBeNull();
    expect(validateMcpBearerToken("a".repeat(31))).toContain("32");
    expect(validateMcpBearerToken(`${"a".repeat(31)} `)).toContain("可见 ASCII");
    expect(validateMcpBearerToken("密".repeat(32))).toContain("可见 ASCII");
  });

  it("treats a pending bearer as an unsaved draft and rejects stale poll responses", () => {
    expect(mcpWorkspaceHasUnsavedChanges(false, "")).toBe(false);
    expect(mcpWorkspaceHasUnsavedChanges(true, "")).toBe(true);
    expect(mcpWorkspaceHasUnsavedChanges(false, "pending-secret")).toBe(true);
    expect(mcpStatusResponseIsCurrent(4, 4, false)).toBe(true);
    expect(mcpStatusResponseIsCurrent(3, 4, false)).toBe(false);
    expect(mcpStatusResponseIsCurrent(4, 4, true)).toBe(false);
    expect(mcpWorkspaceMutationAllowed(false, false)).toBe(true);
    expect(mcpWorkspaceMutationAllowed(true, false)).toBe(false);
    expect(mcpWorkspaceMutationAllowed(false, true)).toBe(false);
  });
});

describe("McpWorkspaceView", () => {
  it("renders a local-only status while hiding addresses, locations, and credential fragments", () => {
    const markup = renderToStaticMarkup(
      <McpWorkspaceView
        configResponse={configResponse}
        draft={mcpConfigToDraft(config)}
        status={status}
        bearerToken=""
        operation="idle"
        dirty={false}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onBearerTokenChange={vi.fn()}
        onSave={vi.fn()}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onWriteBearerToken={vi.fn()}
        onDeleteBearerToken={vi.fn()}
      />,
    );

    expect(markup).toContain("本地 MCP 服务");
    expect(markup).toContain("仅本机应用可访问");
    expect(markup).not.toContain("loopback");
    expect(markup).not.toContain("http://127.0.0.1:8787/mcp");
    expect(markup).not.toContain("****cdef");
    expect(markup).toContain("Windows 凭据管理器");
    expect(markup).not.toContain("legal_core.sqlite");
    expect(markup).toContain('type="password"');
    expect(markup).toContain("停止 MCP");
    expect(markup).toContain("aria-live=\"polite\"");
  });

  it("keeps start disabled until dirty configuration is saved", () => {
    const markup = renderToStaticMarkup(
      <McpWorkspaceView
        configResponse={{ ...configResponse, bearerTokenConfigured: false, bearerTokenMasked: null }}
        draft={{ ...mcpConfigToDraft(config), port: "8788" }}
        status={{ ...status, phase: "stopped", endpoint: null, startedAt: null }}
        bearerToken="temporary-secret-that-is-long-enough"
        operation="idle"
        dirty={true}
        notice=""
        error="配置尚未保存"
        onDraftChange={vi.fn()}
        onBearerTokenChange={vi.fn()}
        onSave={vi.fn()}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onWriteBearerToken={vi.fn()}
        onDeleteBearerToken={vi.fn()}
      />,
    );

    expect(markup).toContain("配置尚未保存；保存后才能启动服务");
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>启动 MCP<\/button>/u);
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('type="password"');
    expect(JSON.stringify(configResponse)).not.toContain(
      "temporary-secret-that-is-long-enough",
    );
  });

  it("keeps a pending bearer out of lifecycle use and labels its safe-write boundary", () => {
    const markup = renderToStaticMarkup(
      <McpWorkspaceView
        configResponse={configResponse}
        draft={mcpConfigToDraft(config)}
        status={{ ...status, phase: "stopped", endpoint: null, startedAt: null }}
        bearerToken="pending-secret-that-has-not-been-written"
        operation="idle"
        dirty={false}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onBearerTokenChange={vi.fn()}
        onSave={vi.fn()}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onWriteBearerToken={vi.fn()}
        onDeleteBearerToken={vi.fn()}
      />,
    );

    expect(markup).toContain("Bearer Token 尚未安全写入");
    expect(markup).toContain('aria-describedby="mcp-bearer-token-help"');
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>启动 MCP<\/button>/u);
  });

  it("locks configuration and credential controls during an external lifecycle transition", () => {
    const markup = renderToStaticMarkup(
      <McpWorkspaceView
        configResponse={configResponse}
        draft={mcpConfigToDraft(config)}
        status={{ ...status, phase: "starting", endpoint: null, startedAt: null }}
        bearerToken=""
        operation="idle"
        dirty={false}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onBearerTokenChange={vi.fn()}
        onSave={vi.fn()}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onWriteBearerToken={vi.fn()}
        onDeleteBearerToken={vi.fn()}
      />,
    );

    expect(markup).toContain('aria-busy="true"');
    expect(markup).toMatch(
      /<input(?=[^>]*value="8787")(?=[^>]*disabled="")[^>]*>/u,
    );
    expect(markup).toMatch(/<input[^>]*type="password"[^>]*disabled=""/u);
  });

  it("keeps status visible but locks every mutation control while another automation is active", () => {
    const markup = renderToStaticMarkup(
      <McpWorkspaceView
        configResponse={configResponse}
        draft={mcpConfigToDraft(config)}
        status={{
          ...status,
          phase: "stopped",
          endpoint: null,
          startedAt: null,
        }}
        bearerToken=""
        operation="idle"
        dirty={false}
        notice=""
        error=""
        externalDisabled={true}
        onDraftChange={vi.fn()}
        onBearerTokenChange={vi.fn()}
        onSave={vi.fn()}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onWriteBearerToken={vi.fn()}
        onDeleteBearerToken={vi.fn()}
      />,
    );

    expect(markup).toContain('aria-disabled="true"');
    expect(markup).toContain('aria-live="polite"');
    for (const control of markup.match(/<(?:button|input)\b[^>]*>/gu) ?? []) {
      expect(control).toContain('disabled=""');
    }
  });
});
