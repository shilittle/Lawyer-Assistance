import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ProviderProfile } from "../../../ipc/provider/types";
import type { PrivacyRiskReviewState } from "../../../ipc/privacy/risk-types";
import type {
  ApprovedProviderOutputSummary,
  PrivacyReview,
  ProviderQualificationStatus,
} from "../../../ipc/privacy/types";
import {
  APPROVED_PROVIDER_TASK_OPTIONS,
  AutomationOutboundApprovalPanelView,
  approvedProviderPurpose,
  buildProviderApprovalRequest,
  buildProviderDispatchRequest,
  effectiveProviderModel,
  providerApprovalUiBindingKey,
  providerTaskRequiresPriorOutput,
} from "./AutomationOutboundApprovalPanel";
import automationOutboundApprovalPanelSource from "./AutomationOutboundApprovalPanel.tsx?raw";

const profile: ProviderProfile = {
  id: "provider-main",
  displayName: "主 Provider",
  kind: "custom",
  modelId: "model-main",
  baseUrl: "https://provider.example/v1",
  credentialAccountId: "default",
  capabilities: {
    chat: true,
    streaming: true,
    customModelId: true,
    customBaseUrl: true,
    reasoning: false,
  },
  options: {},
};

const riskReview: PrivacyRiskReviewState = {
  schemaVersion: "privacy-risk-review-state-v1",
  redactionId: "red_approved_1",
  caseId: "case_1",
  materialId: "mat_1",
  documentVersion: 1,
  detectorRunCompleted: true,
  revision: 7,
  documentRisk: {
    route: "full_review_required",
    readinessScore: 100,
    pageRisks: [],
    totalP0: 0,
    totalP1: 0,
    totalP2: 0,
    policyId: "privacy-vnext",
    policyVersion: 1,
    calibrationEvidenceVersion: null,
    qualificationReportId: "qual-synthetic",
    autoApprovalPolicyMode: "shadow",
    productionAutomaticEnabled: false,
    shadowWouldAutoApprove: false,
    automaticPublishAllowed: false,
    reasonCodes: [],
  },
  hardGates: [],
  findings: [],
  residualScan: {
    passed: true,
    evidenceHash: "9".repeat(64),
    blockingHitCount: 0,
    reviewHitCount: 0,
    reasonCodes: [],
  },
  visualRiskResolutions: [],
  canUndo: false,
  canRedo: false,
  rejected: false,
};

const review: PrivacyReview = {
  redactionId: "red_approved_1",
  materialId: "mat_1",
  caseId: "case_1",
  vaultObjectId: "obj_1",
  vaultObjectVersion: 1,
  vaultIsolation: null,
  sourceDisplayName: "不得进入 Provider 请求的案件原文件名.pdf",
  sourceSha256: "a".repeat(64),
  extractionSha256: "b".repeat(64),
  suggestedRedactedContentSha256: "c".repeat(64),
  processingVersion: "privacy-vnext",
  mediaType: "application/pdf",
  pageCount: 1,
  backendTrace: [],
  summary: {
    total: 1,
    counts: { person: 1 },
    changed: true,
    manualReviewRequired: true,
    redactionVersion: "privacy-vnext",
  },
  reviewState: "approved",
  pages: [
    {
      pageNumber: 1,
      locator: "page-1",
      assessment: {
        pageNumber: 1,
        nonWhitespaceChars: 20,
        printableRatio: 1,
        replacementCharRatio: 0,
        cjkRatio: 1,
        readingOrderScore: 1,
        decision: "native_accepted",
        reasonCodes: ["native_text_healthy"],
      },
      originalText: "SENSITIVE_RAW_PERSON_NAME",
      redactedText: "原告：[PERSON_001]",
    },
  ],
  riskReview,
};

const qualification: ProviderQualificationStatus = {
  qualified: true,
  reasonCode: "QUALIFIED",
  evidenceId: "pvq_123",
  evidenceSha256: "d".repeat(64),
  providerId: profile.id,
  providerContractSha256: "e".repeat(64),
  modelId: profile.modelId,
  endpointOriginSha256: "f".repeat(64),
  taskContractSha256: "1".repeat(64),
  exactWorkspaceAppPolicyBinding: true,
  exactProviderContractBinding: true,
  exactTaskContractBinding: true,
  prepareCanaryPassed: true,
  approvalRestoreCanaryPassed: true,
  realLoopbackTransportPassed: true,
  approvedOutputPersisted: true,
  rawCanaryAbsent: true,
  exactlyOneRequest: true,
  signingKeyId: "pvqkey_safe_identifier",
  signingKeyVersion: 1,
  revocationEpoch: 1,
  issuedAtUnix: 1_700_000_000,
  expiresAtUnix: 1_700_003_600,
  revoked: false,
};
const priorOutput: ApprovedProviderOutputSummary = {
  outputId: "out_1",
  redactionId: review.redactionId,
  approvalGenerationId: "gen_1",
  task: "summary",
  taskBindingSha256: "8".repeat(64),
  providerSha256: "5".repeat(64),
  modelSha256: "6".repeat(64),
  purposeSha256: "7".repeat(64),
  approvedPayloadSha256: "2".repeat(64),
  contentSha256: "4".repeat(64),
  contentBytes: 12,
  createdAtUnix: 1_700_000_001,
  expiresAtUnix: 1_700_003_600,
  revoked: false,
  eligibleAsPrior: true,
};

describe("Provider approved task contract", () => {
  it("covers every case workflow with a unique fixed purpose", () => {
    expect(APPROVED_PROVIDER_TASK_OPTIONS).toHaveLength(12);
    expect(new Set(APPROVED_PROVIDER_TASK_OPTIONS.map((entry) => entry.task)).size).toBe(12);
    expect(new Set(APPROVED_PROVIDER_TASK_OPTIONS.map((entry) => entry.purpose)).size).toBe(12);
    expect(approvedProviderPurpose("assistant")).toBe("assistant_case_response");
    expect(approvedProviderPurpose("case_organization")).toBe("case_organization");
    expect(approvedProviderPurpose("case_legal_qa")).toBe("case_legal_qa");
    expect(approvedProviderPurpose("relationship_graph")).toBe("case_relationship_graph");
    expect(approvedProviderPurpose("document_generation")).toBe("case_document_generation");
    expect(approvedProviderPurpose("regenerate")).toBe("case_regenerate");
    expect(approvedProviderPurpose("repair")).toBe("case_repair");
    expect(providerTaskRequiresPriorOutput("regenerate")).toBe(true);
    expect(providerTaskRequiresPriorOutput("summary")).toBe(false);
    expect(
      APPROVED_PROVIDER_TASK_OPTIONS.filter(
        ({ task }) => !providerTaskRequiresPriorOutput(task),
      ),
    ).toHaveLength(10);
    expect(
      APPROVED_PROVIDER_TASK_OPTIONS.filter(({ task }) =>
        providerTaskRequiresPriorOutput(task),
      ).map(({ task }) => task),
    ).toEqual(["regenerate", "repair"]);
  });

  it("builds exact approval and minimal dispatch without raw material or browser authority", () => {
    const approval = buildProviderApprovalRequest({
      review,
      providerId: profile.id,
      task: "case_legal_qa",
      instruction: "  仅回答问题。\r\n保留占位符。  ",
      priorOutput: null,
      maxTokens: "1024",
      reviewer: "reviewer-1",
      ttlSeconds: "3600",
      confirmed: true,
    });
    const dispatch = buildProviderDispatchRequest({
      review,
      providerId: profile.id,
      task: "case_legal_qa",
      instruction: "  仅回答问题。\r\n保留占位符。  ",
      priorOutput: null,
      maxTokens: "1024",
    });

    expect(approval.expectedRiskRevision).toBe(riskReview.revision);
    expect(approval.editedPages).toEqual([
      { pageNumber: 1, redactedText: "原告：[PERSON_001]" },
    ]);
    expect(approval.providerId).toBe(profile.id);
    expect(approval.task).toBe("case_legal_qa");
    expect(approval.instruction).toBe("仅回答问题。\n保留占位符。");
    expect(approval.priorOutput).toBeNull();
    expect(approval.maxTokens).toBe(1024);
    expect(approval.confirmed).toBe(true);
    expect(dispatch).toEqual({
      redactionId: review.redactionId,
      providerId: profile.id,
      task: "case_legal_qa",
      maxTokens: 1024,
      instruction: "仅回答问题。\n保留占位符。",
      priorOutput: null,
    });
    const dispatchWire = JSON.stringify(dispatch);
    expect(dispatchWire).not.toContain("purpose");
    expect(dispatchWire).not.toContain("receiptToken");
    expect(dispatchWire).not.toContain("approvedPayloadJson");
    expect(dispatchWire).not.toContain("SENSITIVE_RAW_PERSON_NAME");
    expect(dispatchWire).not.toContain(review.sourceDisplayName);
    expect(dispatchWire).not.toContain("path");
  });

  it("requires an already manually approved generation and explicit confirmation", () => {
    expect(() =>
      buildProviderApprovalRequest({
        review: { ...review, reviewState: "review_required" },
        providerId: profile.id,
        task: "summary",
        reviewer: "reviewer-1",
        ttlSeconds: "3600",
        instruction: "归纳争议焦点。",
        priorOutput: null,
        maxTokens: "1024",
        confirmed: true,
      }),
    ).toThrow("先在双栏复核区完成人工批准");
    expect(() =>
      buildProviderApprovalRequest({
        review,
        providerId: profile.id,
        task: "summary",
        reviewer: "reviewer-1",
        ttlSeconds: "3600",
        instruction: "归纳争议焦点。",
        priorOutput: null,
        maxTokens: "1024",
        confirmed: false,
      }),
    ).toThrow("逐页核对");
    expect(() =>
      buildProviderApprovalRequest({
        review: { ...review, riskReview: null },
        providerId: profile.id,
        task: "summary",
        reviewer: "reviewer-1",
        ttlSeconds: "3600",
        instruction: "归纳争议焦点。",
        priorOutput: null,
        maxTokens: "1024",
        confirmed: true,
      }),
    ).toThrow("缺少当前风险复核 revision");
  });

  it("requires a backend-listed eligible prior output only for regenerate and repair", () => {
    expect(() =>
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "regenerate",
        instruction: "重新组织已批准结果。",
        priorOutput: null,
        maxTokens: "1024",
      }),
    ).toThrow("必须从受保护输出历史中选择");
    expect(() =>
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "summary",
        instruction: "生成摘要。",
        priorOutput,
        maxTokens: "1024",
      }),
    ).toThrow("不允许携带历史输出");
    expect(
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "repair",
        instruction: "仅修复格式。",
        priorOutput,
        maxTokens: "1024",
      }).priorOutput,
    ).toEqual({ outputId: "out_1", task: "summary" });
    expect(() =>
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "repair",
        instruction: "仅修复格式。",
        priorOutput: { ...priorOutput, eligibleAsPrior: false },
        maxTokens: "1024",
      }),
    ).toThrow("已失效");
  });

  it("binds instruction and max token changes to different request shapes", () => {
    const base = buildProviderDispatchRequest({
      review,
      providerId: profile.id,
      task: "summary",
      instruction: "生成摘要。",
      priorOutput: null,
      maxTokens: "1024",
    });
    expect(
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "summary",
        instruction: "生成三点摘要。",
        priorOutput: null,
        maxTokens: "1024",
      }),
    ).not.toEqual(base);
    expect(
      buildProviderDispatchRequest({
        review,
        providerId: profile.id,
        task: "summary",
        instruction: "生成摘要。",
        priorOutput: null,
        maxTokens: "2048",
      }),
    ).not.toEqual(base);
  });

  it("changes the stale-approval identity for every UI-bound field", () => {
    const bindingInput: Parameters<typeof providerApprovalUiBindingKey>[0] = {
      review,
      providerId: profile.id,
      modelId: profile.modelId,
      task: "summary",
      instruction: "生成摘要。",
      priorOutput: null,
      maxTokens: "1024",
      reviewer: "reviewer-1",
      ttlSeconds: "3600",
    };
    const base = providerApprovalUiBindingKey(bindingInput);
    const changed = (
      override: Partial<Parameters<typeof providerApprovalUiBindingKey>[0]>,
    ) => providerApprovalUiBindingKey({ ...bindingInput, ...override });

    expect(changed({ providerId: "provider-second" })).not.toBe(base);
    expect(changed({ modelId: "model-second" })).not.toBe(base);
    expect(changed({ task: "legal_analysis" })).not.toBe(base);
    expect(changed({ instruction: "生成详细摘要。" })).not.toBe(base);
    expect(changed({ priorOutput })).not.toBe(base);
    expect(changed({ maxTokens: "2048" })).not.toBe(base);
    expect(changed({ reviewer: "reviewer-2" })).not.toBe(base);
    expect(changed({ ttlSeconds: "7200" })).not.toBe(base);
    expect(
      changed({
        review: {
          ...review,
          suggestedRedactedContentSha256: "0".repeat(64),
        },
      }),
    ).not.toBe(base);
    expect(
      changed({
        review: {
          ...review,
          pages: [
            {
              ...review.pages[0],
              redactedText: "变更后的脱敏正文",
            },
          ],
        },
      }),
    ).not.toBe(base);
  });


  it("uses the Volcengine endpoint ID as the exact transport model binding", () => {
    expect(effectiveProviderModel({
      ...profile,
      kind: "volcengine_ark",
      options: { endpointId: "ep-bound-model" },
    })).toBe("ep-bound-model");
  });

  it("has no compatibility task injection or route-state acknowledgement", () => {
    expect(automationOutboundApprovalPanelSource).not.toContain(
      "taskRequest",
    );
    expect(automationOutboundApprovalPanelSource).not.toContain(
      "onTaskRequestConsumed",
    );
    expect(automationOutboundApprovalPanelSource).not.toContain(
      "handledTaskRequestId",
    );
  });

  it("never loads an unscoped latest review and explains the case-scoped handoff", () => {
    expect(automationOutboundApprovalPanelSource).not.toContain(
      "loadLatestPrivacyReview",
    );
    expect(automationOutboundApprovalPanelSource).toContain(
      "设置页不再自动读取未限定案件的“最近一次”脱敏记录",
    );
    expect(automationOutboundApprovalPanelSource).toContain(
      "请从案件工作台的“材料与脱敏”",
    );
  });
});

describe("AutomationOutboundApprovalPanelView", () => {
  it("shows qualification, exact purpose, approved generation and protected outputs", () => {
    const markup = renderToStaticMarkup(
      <AutomationOutboundApprovalPanelView
        disabled={false}
        operation="idle"
        providers={[profile]}
        review={review}
        providerId={profile.id}
        task="summary"
        instruction="生成案件摘要并保留全部脱敏占位符。"
        priorOutputId=""
        reviewer="reviewer-1"
        ttlSeconds="3600"
        maxTokens="1024"
        confirmed={true}
        qualification={qualification}
        approval={{
          receiptId: "opaque-audit-id",
          approvedPayloadSha256: "2".repeat(64),
          redactedContentSha256: "3".repeat(64),
          issuedAtUnix: 1_700_000_000,
          taskBindingSha256: "8".repeat(64),
          providerId: profile.id,
          modelId: profile.modelId,
          task: "summary",
          expiresAtUnix: 1_700_003_600,
          purpose: "case_summary",
          transportEnforcement: "active_receipt_persisted_exact_destination",
        }}
        dispatchResult={{
          resultId: "out_1",
          providerId: profile.id,
          modelId: profile.modelId,
          purpose: "case_summary",
          task: "summary",
          content: "安全结果",
          contentSha256: "4".repeat(64),
          taskBindingSha256: "8".repeat(64),
          approvalGenerationId: "gen_1",
        }}
        outputs={[{
          outputId: "out_1",
          redactionId: review.redactionId,
          approvalGenerationId: "gen_1",
          providerSha256: "5".repeat(64),
          modelSha256: "6".repeat(64),
          task: "summary",
          taskBindingSha256: "8".repeat(64),
          purposeSha256: "7".repeat(64),
          approvedPayloadSha256: "2".repeat(64),
          contentSha256: "4".repeat(64),
          contentBytes: 12,
          createdAtUnix: 1_700_000_001,
          expiresAtUnix: 1_700_003_600,
          eligibleAsPrior: true,
          revoked: false,
        }]}
        loadedOutput={null}
        notice="已从旧入口切换并预选固定任务。"
        error=""
        onProviderChange={vi.fn()}
        onTaskChange={vi.fn()}
        onReviewerChange={vi.fn()}
        onTtlSecondsChange={vi.fn()}
        onMaxTokensChange={vi.fn()}
        onInstructionChange={vi.fn()}
        onPriorOutputChange={vi.fn()}
        onConfirmedChange={vi.fn()}
        onRefresh={vi.fn()}
        onRunQualification={vi.fn()}
        onRevokeQualification={vi.fn()}
        onApprove={vi.fn()}
        onDispatch={vi.fn()}
        onLoadOutput={vi.fn()}
        onRevokeOutput={vi.fn()}
      />,
    );

    expect(markup).toContain("自动化出站批准");
    expect(markup).toContain("case_summary");
    expect(markup).toContain('id="automation-outbound-approval"');
    expect(markup).toContain("已从旧入口切换并预选固定任务。");
    expect(markup).toContain(review.redactionId);
    expect(markup).toContain("真实 localhost wire：通过");
    expect(markup).toContain("原始 canary 不在 wire：通过");
    expect(markup).toContain("按同一任务绑定发送");
    expect(markup).toContain('data-provider-dispatch-ready="true"');
    expect(markup).toContain("out_1");
    expect(markup).toContain("安全结果");
    expect(markup).not.toContain("SENSITIVE_RAW_PERSON_NAME");
    expect(markup).not.toContain(review.sourceDisplayName);
    expect(markup).not.toContain("opaque-audit-id");
  });
});
