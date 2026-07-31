import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  CaseAssistantGeneration,
  CaseAssistantPendingOutput,
} from "../../../ipc/case-assistant/types";
import { CaseAssistantGenerationPicker } from "./CaseAssistantGenerationPicker";
import {
  CASE_ASSISTANT_PROVIDER_WARNING,
  CaseAssistantProviderNotice,
} from "./CaseAssistantProviderNotice";
import { CaseAssistantPendingOutputs } from "./CaseAssistantPendingOutputs";

const generation: CaseAssistantGeneration = {
  redactionGenerationId: "generation-1",
  materialId: "material-1",
  generationNumber: 3,
  mediaType: "application/pdf",
  pageCount: 8,
  approvedAt: "2026-07-31T08:00:00Z",
  selected: true,
  displayName: "合同脱敏版本",
};

const pending: CaseAssistantPendingOutput = {
  pendingOutputId: "pending-1",
  projectId: "case-project-1",
  conversationId: "case-conversation-1",
  runId: "case-run-1",
  outputKind: "case_document",
  preview: "待审阅的案件文书预览",
  outputSha256: "a".repeat(64),
  version: 1,
  workspaceDigest: "b".repeat(64),
  status: "pending",
  createdAt: "2026-07-31T09:00:00Z",
  confirmedAt: null,
  artifactId: null,
  proposalId: null,
};

describe("Case Assistant presentational boundaries", () => {
  it("keeps the Provider disclosure visible and names only selected metadata", () => {
    const markup = renderToStaticMarkup(
      <CaseAssistantProviderNotice
        outputKind="case_analysis"
        provider={{ displayName: "律师模型服务" }}
        selectedGenerations={[generation]}
      />,
    );

    expect(markup).toContain('aria-label="案件助理模型外发提示"');
    expect(markup).toContain(CASE_ASSISTANT_PROVIDER_WARNING);
    expect(markup).toContain("律师模型服务");
    expect(markup).toContain("合同脱敏版本");
    expect(markup).toContain("不发送案件原件");
    expect(markup).toContain("扫描通过后才一次性显示");
    expect(markup).not.toContain("privacyCaseId");
    expect(markup).not.toContain("baseUrl");
    expect(markup).not.toContain("modelId");
  });

  it("renders only approved/current generation metadata without payload or hashes", () => {
    const markup = renderToStaticMarkup(
      <CaseAssistantGenerationPicker
        disabled={false}
        generations={[generation]}
        loading={false}
        selectedIds={["generation-1"]}
        onReload={vi.fn()}
        onToggle={vi.fn()}
      />,
    );

    expect(markup).toContain("合同脱敏版本");
    expect(markup).toContain("第 3 代");
    expect(markup).toContain("8 页");
    expect(markup).toContain("每次发送都必须重新明确勾选");
    expect(markup).not.toContain("approvedPayloadSha256");
    expect(markup).not.toContain("riskRevision");
    expect(markup).not.toContain("Vault");
  });

  it("keeps generated work pending until a separate confirmation", () => {
    const markup = renderToStaticMarkup(
      <CaseAssistantPendingOutputs
        busyOutputId={null}
        outputs={[pending]}
        onConfirm={vi.fn()}
      />,
    );

    expect(markup).toContain("待审阅的案件文书预览");
    expect(markup).toContain("待确认，尚未写入");
    expect(markup).toContain("审阅后确认应用");
    expect(markup).not.toContain(pending.outputSha256);
    expect(markup).not.toContain(pending.workspaceDigest);
    expect(markup).not.toContain(pending.pendingOutputId);
  });
});
