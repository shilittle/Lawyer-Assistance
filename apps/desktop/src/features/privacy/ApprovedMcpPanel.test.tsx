import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  ApprovedGenerationHistory,
  ApprovedMcpQualificationStatus,
  ApprovedPrivacyReviewSelection,
  StandaloneApprovedMcpSessionMetadata,
} from "../../ipc/privacy/approved-mcp-client";
import {
  ApprovedMcpPanel,
  ApprovedMcpPanelView,
  buildApprovedGenerationPublication,
  buildApprovedWorkspaceApproval,
  buildStandaloneHostConfiguration,
  buildStandaloneHttpServerCommand,
  buildStandaloneSession,
  buildStandaloneStdioSession,
  normalizeAllowedOrigins,
} from "./ApprovedMcpPanel";

const APPROVED_PROFILE_TOOLS = [
  "system_status",
  "legal_search",
  "legal_get_article",
  "legal_get_versions",
  "legal_get_relations",
  "case_list",
  "case_get_public_metadata",
  "case_list_approved_materials",
  "case_read_approved_material",
  "case_search_approved_materials",
  "case_list_work_products",
  "case_read_work_product",
  "case_write_work_product",
  "case_update_work_product",
  "case_export_work_product_manifest",
  "diagram.list_templates",
  "diagram.get_schema",
  "diagram.validate",
  "diagram.render",
  "diagram.update",
  "diagram.export",
] as const;

const qualification: ApprovedMcpQualificationStatus = {
  qualified: true,
  reasonCode: "QUALIFIED",
  evidenceId: "mcpqe_opaque_evidence",
  evidenceSha256: "a".repeat(64),
  stdioCanaryPassed: true,
  streamableHttpCanaryPassed: true,
  exactAppPolicyBinding: true,
  exactServerKeyBinding: true,
  appVersion: "0.4.0-beta.2",
  policyId: "approved-mcp-local-egress-v1",
  policyVersion: 2,
  serverKeyId: "mcpkey_opaque",
  serverKeyVersion: 1,
  revocationEpoch: 3,
  issuedAtUnix: 1_700_000_000,
  expiresAtUnix: 1_700_003_600,
  revoked: false,
};

const reviewSelection: ApprovedPrivacyReviewSelection = {
  redactionId: "red_00000000000000000000000000000001",
  materialId: "mat_00000000000000000000000000000001",
  caseId: "case_00000000000000000000000000000001",
  approvedPayloadSha256: "d".repeat(64),
  mcpPublishApproved: true,
  mcpPublishApprovalExpiresAtUnix: 1_700_003_600,
};

const generation: ApprovedGenerationHistory = {
  caseId: "case_00000000000000000000000000000001",
  materialId: "mat_00000000000000000000000000000001",
  documentVersion: 2,
  publicationId: "pub_00000000000000000000000000000001",
  manifestSha256: "b".repeat(64),
  contentSha256: "c".repeat(64),
  createdAtUnix: 1_700_000_000,
  committedAtUnix: 1_700_000_001,
  revokedAtUnix: null,
  revocationEpoch: 0,
};

const session: StandaloneApprovedMcpSessionMetadata = {
  descriptorId: "mcpd_00000000000000000000000000000001",
  connectorId: "workbuddy",
  workspaceInstanceId: "ws_00000000000000000000000000000001",
  serverInstanceId: "srv_00000000000000000000000000000001",
  sessionId: "session_stdio_00000000000000000000000000000001",
  transport: "stdio",
  grantGroups: ["read", "write"],
  grants: [
    { toolName: "case_list", purpose: "mcp.case_list.v1" },
    { toolName: "case_write_work_product", purpose: "mcp.case_write_work_product.v1" },
  ],
  endpoint: null,
  qualificationEvidenceId: "mcpqe_opaque_evidence",
  qualificationEvidenceSha256: "a".repeat(64),
  issuedAtUnix: 1_700_000_000,
  expiresAtUnix: 1_700_003_600,
  active: true,
  reasonCode: "ACTIVE",
};

const httpSession: StandaloneApprovedMcpSessionMetadata = {
  ...session,
  descriptorId: "mcpd_00000000000000000000000000000002",
  serverInstanceId: "srv_00000000000000000000000000000002",
  sessionId: "session_http_00000000000000000000000000000002",
  transport: "streamable_http",
  endpoint: "http://127.0.0.1:8787/mcp",
};

describe("approved MCP request builders", () => {
  it("builds only an opaque publication request", () => {
    expect(buildApprovedGenerationPublication({
      redactionId: "red_00000000000000000000000000000001",
      caseId: generation.caseId,
      approvedPayloadSha256: "d".repeat(64),
    })).toEqual({
      redactionId: "red_00000000000000000000000000000001",
      caseId: generation.caseId,
      expectedApprovedPayloadSha256: "d".repeat(64),
    });

    expect(() => buildApprovedGenerationPublication({
      redactionId: "C:/cases/raw.pdf",
      caseId: generation.caseId,
      approvedPayloadSha256: "d".repeat(64),
    })).toThrow("opaque ID");
    expect(() => buildApprovedGenerationPublication({
      redactionId: "red_00000000000000000000000000000001",
      caseId: "../case",
      approvedPayloadSha256: "d".repeat(64),
    })).toThrow("opaque ID");
  });

  it("creates only fixed stdio sessions with no host-supplied path or origin", () => {
    expect(buildStandaloneStdioSession({
      connectorId: "codex",
      minutes: "30",
      readEnabled: true,
      writeEnabled: true,
      diagramReadEnabled: false,
      diagramWriteEnabled: false,
    })).toEqual({
      connectorId: "codex",
      transport: "stdio",
      grantGroups: ["read", "write"],
      ttlSeconds: 1800,
      httpPort: null,
      allowedOrigins: [],
    });
    expect(() => buildStandaloneStdioSession({
      connectorId: "codex",
      minutes: "10081",
      readEnabled: true,
      writeEnabled: true,
      diagramReadEnabled: false,
      diagramWriteEnabled: false,
    })).toThrow("1–10080");
  });

  it("adds the diagram grant groups only when they are explicitly selected", () => {
    expect(buildStandaloneStdioSession({
      connectorId: "codex",
      minutes: "30",
      readEnabled: true,
      writeEnabled: true,
      diagramReadEnabled: true,
      diagramWriteEnabled: true,
    }).grantGroups).toEqual(["read", "write", "diagram_read", "diagram_write"]);

    expect(buildStandaloneStdioSession({
      connectorId: "codex",
      minutes: "30",
      readEnabled: false,
      writeEnabled: false,
      diagramReadEnabled: true,
      diagramWriteEnabled: true,
    }).grantGroups).toEqual(["diagram_read", "diagram_write"]);
  });

  it("canonicalizes HTTP origins and rejects path, credentials, bad ports and overlong TTLs", () => {
    expect(normalizeAllowedOrigins(
      "HTTPS://EXAMPLE.COM:443\nhttp://127.0.0.1:3000,https://example.com",
    )).toEqual(["https://example.com", "http://127.0.0.1:3000"]);
    expect(() => normalizeAllowedOrigins("https://example.com/path")).toThrow("无路径");
    expect(() => normalizeAllowedOrigins("https://user:pass@example.com")).toThrow("无凭据");
    expect(() => buildStandaloneSession({
      connectorId: "workbuddy",
      transport: "streamable_http",
      minutes: "1441",
      readEnabled: true,
      writeEnabled: false,
      diagramReadEnabled: false,
      diagramWriteEnabled: false,
      httpPort: "8787",
      allowedOriginsInput: "",
    })).toThrow("1–1440");
    expect(() => buildStandaloneSession({
      connectorId: "workbuddy",
      transport: "streamable_http",
      minutes: "60",
      readEnabled: true,
      writeEnabled: false,
      diagramReadEnabled: false,
      diagramWriteEnabled: false,
      httpPort: "80",
      allowedOriginsInput: "",
    })).toThrow("1024–65535");
  });

  it("builds a distinct, explicit approved-workspace publication approval", () => {
    expect(buildApprovedWorkspaceApproval({
      redactionId: reviewSelection.redactionId,
      approvedPayloadSha256: reviewSelection.approvedPayloadSha256,
      reviewer: "reviewer-01",
      minutes: "60",
      confirmed: true,
    })).toEqual({
      redactionId: reviewSelection.redactionId,
      expectedApprovedPayloadSha256: reviewSelection.approvedPayloadSha256,
      reviewer: "reviewer-01",
      ttlSeconds: 3600,
      confirmed: true,
    });
    expect(() => buildApprovedWorkspaceApproval({
      redactionId: reviewSelection.redactionId,
      approvedPayloadSha256: reviewSelection.approvedPayloadSha256,
      reviewer: "reviewer-01",
      minutes: "60",
      confirmed: false,
    })).toThrow("显式确认");
  });
});

describe("ApprovedMcpPanelView", () => {
  it("builds an exact no-path stdio host configuration", () => {
    expect(JSON.parse(buildStandaloneHostConfiguration(session))).toEqual({
      mcpServers: { lawyer_assistance: {
        type: "stdio",
        command: "lawyer-assistance-mcp",
        args: [
        "--privacy-profile",
        "approved_case_workspace",
        "--approved-session-id",
        session.serverInstanceId,
        "stdio",
      ],
      } },
    });
    expect(buildStandaloneHttpServerCommand(httpSession)).toContain(
      `--approved-session-id ${httpSession.serverInstanceId} serve`,
    );
    const bearer = `mcp-http-${"e".repeat(64)}`;
    for (const connectorId of ["workbuddy", "codex", "opencode"] as const) {
      const config = buildStandaloneHostConfiguration({ ...httpSession, connectorId }, bearer);
      expect(config.match(new RegExp(bearer, "gu"))).toHaveLength(1);
      expect(config).toContain(httpSession.endpoint ?? "");
      expect(config).toContain("Authorization");
      if (connectorId === "workbuddy") {
        expect(JSON.parse(config).mcpServers.lawyer_assistance.type).toBe("http");
      } else if (connectorId === "codex") {
        expect(config).toContain("[mcp_servers.lawyer_assistance]");
        expect(config).toContain("http_headers = { Authorization =");
        const enabledTools = Array.from(
          config.matchAll(/^ {2}"([^"]+)",$/gmu),
          (match) => match[1],
        );
        expect(enabledTools).toEqual(APPROVED_PROFILE_TOOLS);
      } else {
        const parsed = JSON.parse(config);
        expect(parsed.share).toBe("disabled");
        expect(parsed.mcp.lawyer_assistance.type).toBe("remote");
        expect(parsed.mcp.lawyer_assistance.oauth).toBe(false);
        expect(parsed.permission["lawyer_assistance_*"]).toBe("deny");
      }
    }
    expect(() => buildStandaloneHostConfiguration(httpSession)).toThrow("one-time");
    expect(() => buildStandaloneStdioSession({
      connectorId: "workbuddy",
      minutes: "60",
      readEnabled: false,
      writeEnabled: false,
      diagramReadEnabled: false,
      diagramWriteEnabled: false,
    })).toThrow("fixed grant group");
  });

  it("keeps both diagram grant groups disabled by default", () => {
    const markup = renderToStaticMarkup(<ApprovedMcpPanel />);
    for (const label of ["图示只读授权组", "图示写入授权组"]) {
      const input = markup.match(new RegExp(`<input[^>]*aria-label="${label}"[^>]*>`, "u"));
      expect(input?.[0]).toBeDefined();
      expect(input?.[0]).not.toContain("checked");
    }
  });

  it("renders qualification, generations and opaque host command without secrets or case text", () => {
    const markup = renderToStaticMarkup(
      <ApprovedMcpPanelView
        disabled={false}
        operation="idle"
        qualification={qualification}
        reviewSelections={[reviewSelection]}
        generations={[generation]}
        sessions={[session, httpSession]}
        selectedRedactionId={reviewSelection.redactionId}
        selectedGenerationKey={`${generation.publicationId}:${generation.documentVersion}`}
        historyCaseId={generation.caseId}
        qualificationDays="1"
        connectorId="workbuddy"
        transport="streamable_http"
        httpPort="8787"
        allowedOriginsInput="http://127.0.0.1:3000"
        sessionMinutes="60"
        mcpApprovalReviewer="reviewer-01"
        mcpApprovalMinutes="60"
        mcpApprovalConfirmed={true}
        oneTimeHttpProvisioning={{ session: httpSession, oneTimeHttpBearer: `mcp-http-${"e".repeat(64)}` }}
        readGrantEnabled={true}
        writeGrantEnabled={true}
        diagramReadGrantEnabled={false}
        diagramWriteGrantEnabled={false}
        notice="已完成"
        error=""
        onSelectedRedactionIdChange={vi.fn()}
        onSelectedGenerationKeyChange={vi.fn()}
        onHistoryCaseIdChange={vi.fn()}
        onQualificationDaysChange={vi.fn()}
        onConnectorIdChange={vi.fn()}
        onTransportChange={vi.fn()}
        onHttpPortChange={vi.fn()}
        onAllowedOriginsInputChange={vi.fn()}
        onSessionMinutesChange={vi.fn()}
        onMcpApprovalReviewerChange={vi.fn()}
        onMcpApprovalMinutesChange={vi.fn()}
        onMcpApprovalConfirmedChange={vi.fn()}
        onReadGrantEnabledChange={vi.fn()}
        onWriteGrantEnabledChange={vi.fn()}
        onDiagramReadGrantEnabledChange={vi.fn()}
        onDiagramWriteGrantEnabledChange={vi.fn()}
        onRefresh={vi.fn()}
        onQualify={vi.fn()}
        onRevokeQualification={vi.fn()}
        onApprovePublication={vi.fn()}
        onPublish={vi.fn()}
        onRevokeGeneration={vi.fn()}
        onCreateSession={vi.fn()}
        onCopyServerId={vi.fn()}
        onCopyHostConfig={vi.fn()}
        onCopyHttpHostConfig={vi.fn()}
        onRevokeSession={vi.fn()}
      />,
    );

    expect(markup).toContain("发布批准 generation、运行资格认证并管理宿主会话");
    expect(markup).toContain("stdio canary");
    expect(markup).toContain(reviewSelection.redactionId);
    expect(markup).toContain(reviewSelection.materialId);
    expect(markup).toContain(reviewSelection.caseId);
    expect(markup).toContain(reviewSelection.approvedPayloadSha256);
    expect(markup).toContain(generation.publicationId);
    expect(markup).toContain("<select");
    expect(markup).toContain(session.serverInstanceId);
    expect(markup).toContain(session.serverInstanceId);
    expect(markup).toContain("\u590d\u5236 server ID");
    expect(markup).toContain("\u590d\u5236\u65e0\u8def\u5f84\u5bbf\u4e3b\u914d\u7f6e");
    expect(markup).toContain("严格匹配 21 项 profile");
    expect(markup).toContain("图示只读（4 项模板、schema、校验与导出工具）");
    expect(markup).toContain("图示写入（2 项渲染与更新工具）");
    expect(markup).toContain("禁止附加或粘贴案件原文");
    expect(markup).toContain("memory、subagent、远程 OCR");
    expect(markup).toContain("独立的 approved MCP 发布批准");
    expect(markup).toContain("一次性 HTTP 宿主配置已就绪");
    expect(markup).toContain(httpSession.endpoint ?? "");
    expect(markup).toContain(buildStandaloneHttpServerCommand(httpSession));
    expect(markup).not.toContain(`mcp-http-${"e".repeat(64)}`);
    for (const forbidden of [
      "SYNTHETIC_RAW_PARTY",
      "C:/cases/raw.pdf",
      "accessTicket",
      "receiptToken",
      "approvedPayloadJson",
      "httpBearer",
      "descriptorPath",
      "legalDatabasePath",
      "userDatabasePath",
      "allowedRoots",
      "outputRoot",
    ]) {
      expect(markup).not.toContain(forbidden);
    }
  });
});
