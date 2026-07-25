import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  approveReviewForApprovedWorkspace,
  createStandaloneApprovedMcpSession,
  getApprovedMcpQualificationStatus,
  listApprovedGenerations,
  listApprovedPrivacyReviewSelections,
  listStandaloneApprovedMcpSessions,
  publishApprovedGeneration,
  revokeApprovedGeneration,
  revokeApprovedMcpQualification,
  revokeStandaloneApprovedMcpSession,
  runApprovedMcpQualification,
} from "./approved-mcp-client";

describe("approved MCP IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("publishes and revokes only by opaque IDs and immutable hashes", async () => {
    await publishApprovedGeneration({
      redactionId: "red_00000000000000000000000000000001",
      caseId: "case_00000000000000000000000000000001",
      expectedApprovedPayloadSha256: "a".repeat(64),
    });
    await listApprovedGenerations("case_00000000000000000000000000000001");
    await revokeApprovedGeneration({
      caseId: "case_00000000000000000000000000000001",
      materialId: "mat_00000000000000000000000000000001",
      documentVersion: 1,
      publicationId: "pub_00000000000000000000000000000001",
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "publish_approved_generation", {
      request: {
        redactionId: "red_00000000000000000000000000000001",
        caseId: "case_00000000000000000000000000000001",
        expectedApprovedPayloadSha256: "a".repeat(64),
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "list_approved_generations", {
      request: { caseId: "case_00000000000000000000000000000001" },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "revoke_approved_generation", {
      request: {
        caseId: "case_00000000000000000000000000000001",
        materialId: "mat_00000000000000000000000000000001",
        documentVersion: 1,
        publicationId: "pub_00000000000000000000000000000001",
      },
    });
    const wire = JSON.stringify(invoke.mock.calls);
    for (const forbidden of [
      "path",
      "filename",
      "originalText",
      "redactedText",
      "approvedPayloadJson",
      "receiptToken",
      "accessTicket",
    ]) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it("runs, reads and revokes persisted qualification through exact commands", async () => {
    await runApprovedMcpQualification(3600);
    await getApprovedMcpQualificationStatus();
    await revokeApprovedMcpQualification();

    expect(invoke).toHaveBeenNthCalledWith(1, "run_approved_mcp_qualification", {
      request: { ttlSeconds: 3600 },
    });
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "get_approved_mcp_qualification_status",
    );
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      "revoke_approved_mcp_qualification",
    );
  });

  it("uses a dedicated fixed approval command with no caller-selected destination or token", async () => {
    await approveReviewForApprovedWorkspace({
      redactionId: "red_00000000000000000000000000000001",
      expectedApprovedPayloadSha256: "a".repeat(64),
      reviewer: "reviewer-01",
      ttlSeconds: 3600,
      confirmed: true,
    });
    await listApprovedPrivacyReviewSelections();

    expect(invoke).toHaveBeenNthCalledWith(1, "approve_review_for_approved_workspace", {
      request: {
        redactionId: "red_00000000000000000000000000000001",
        expectedApprovedPayloadSha256: "a".repeat(64),
        reviewer: "reviewer-01",
        ttlSeconds: 3600,
        confirmed: true,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "list_approved_privacy_review_selections",
    );
    const wire = JSON.stringify(invoke.mock.calls);
    for (const forbidden of [
      "receiptToken", "destination", "purpose", "pages", "content", "path",
    ]) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it("creates Streamable HTTP only from loopback port and canonical Origin inputs", async () => {
    const response = {
      session: {
        serverInstanceId: "srv_00000000000000000000000000000002",
        transport: "streamable_http",
        endpoint: "http://127.0.0.1:8787/mcp",
      },
      oneTimeHttpBearer: `mcp-http-${"b".repeat(64)}`,
    };
    invoke.mockResolvedValueOnce(response);
    expect(await createStandaloneApprovedMcpSession({
      connectorId: "codex",
      transport: "streamable_http",
      grantGroups: ["read"],
      ttlSeconds: 3600,
      httpPort: 8787,
      allowedOrigins: ["https://example.com", "http://127.0.0.1:3000"],
    })).toBe(response);

    expect(invoke).toHaveBeenCalledWith("create_standalone_approved_mcp_session", {
      request: {
        connectorId: "codex",
        transport: "streamable_http",
        grantGroups: ["read"],
        ttlSeconds: 3600,
        httpPort: 8787,
        allowedOrigins: ["https://example.com", "http://127.0.0.1:3000"],
      },
    });
    const requestWire = JSON.stringify(invoke.mock.calls);
    expect(requestWire).not.toContain(response.oneTimeHttpBearer);
    expect(requestWire).not.toContain("oneTimeHttpBearer");
  });

  it("creates a fixed stdio host session and never returns frontend ticket authority", async () => {
    await createStandaloneApprovedMcpSession({
      connectorId: "workbuddy",
      transport: "stdio",
      grantGroups: ["read", "write", "diagram_read", "diagram_write"],
      ttlSeconds: 600,
      httpPort: null,
      allowedOrigins: [],
    });
    await listStandaloneApprovedMcpSessions();
    await revokeStandaloneApprovedMcpSession(
      "srv_00000000000000000000000000000001",
    );

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "create_standalone_approved_mcp_session",
      {
        request: {
          connectorId: "workbuddy",
          transport: "stdio",
          grantGroups: ["read", "write", "diagram_read", "diagram_write"],
          ttlSeconds: 600,
          httpPort: null,
          allowedOrigins: [],
        },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "list_standalone_approved_mcp_sessions",
    );
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      "revoke_standalone_approved_mcp_session",
      { request: { serverInstanceId: "srv_00000000000000000000000000000001" } },
    );
    const wire = JSON.stringify(invoke.mock.calls);
    for (const forbidden of [
      "httpBearer",
      "token",
      "secret",
      "descriptorPath",
      "legalDatabasePath",
      "userDatabasePath",
      "allowedRoots",
      "outputRoot",
      "content",
    ]) {
      expect(wire).not.toContain(forbidden);
    }
  });
});
