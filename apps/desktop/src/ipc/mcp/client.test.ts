import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  deleteMcpBearerToken,
  getMcpServerConfig,
  getMcpServerStatus,
  saveMcpServerConfig,
  startMcpServer,
  stopMcpServer,
  writeMcpBearerToken,
} from "./client";
import type { McpServerConfig } from "./types";

const config: McpServerConfig = {
  schemaVersion: 1,
  autoStart: false,
  port: 8787,
  allowedRoots: ["C:/cases"],
  outputRoot: "C:/exports",
  allowedOrigins: [],
  maxBodyBytes: 2 * 1024 * 1024,
  requestTimeoutMs: 30_000,
  maxConcurrency: 8,
};

describe("MCP IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses the exact read and lifecycle command names", async () => {
    await getMcpServerConfig();
    await getMcpServerStatus();
    await startMcpServer();
    await stopMcpServer();

    expect(invoke).toHaveBeenNthCalledWith(1, "get_mcp_server_config");
    expect(invoke).toHaveBeenNthCalledWith(2, "get_mcp_server_status");
    expect(invoke).toHaveBeenNthCalledWith(3, "start_mcp_server");
    expect(invoke).toHaveBeenNthCalledWith(4, "stop_mcp_server");
  });

  it("saves only the typed non-secret configuration envelope", async () => {
    await saveMcpServerConfig({ config });

    expect(invoke).toHaveBeenCalledWith("save_mcp_server_config", {
      request: { config },
    });
    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).not.toContain("bearerToken");
    expect(payload).not.toContain("secret");
  });

  it("keeps bearer credential writes and confirmed deletion separate from config", async () => {
    await writeMcpBearerToken({ token: "0123456789abcdef0123456789abcdef" });
    await deleteMcpBearerToken({ userConfirmed: true });

    expect(invoke).toHaveBeenNthCalledWith(1, "write_mcp_bearer_token", {
      request: { token: "0123456789abcdef0123456789abcdef" },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "delete_mcp_bearer_token", {
      request: { userConfirmed: true },
    });
  });
});
