import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { PrivacyRiskReviewState } from "../../ipc/privacy/risk-types";
import { RiskReviewPanel } from "./RiskReviewPanel";

const gateIds = [
  "qualified_processing_chain", "complete_pages_and_order", "no_p0", "no_unresolved_p1",
  "ocr_thresholds", "visual_risks_resolved", "required_dictionary_entities_stable",
  "deterministic_high_risk_fields_resolved", "detector_conflicts_resolved",
  "cluster_alias_consistency", "independent_residual_scan", "provenance_receiptable",
  "calibrated_policy", "approval_mode_allows_automatic",
  "organization_policy_allows_automatic", "publication_target_fixed",
  "exact_worker_model_qualification",
];

const state: PrivacyRiskReviewState = {
  schemaVersion: "privacy-risk-review-state-v1",
  redactionId: `red_${"a".repeat(32)}`,
  caseId: `case_${"1".repeat(32)}`,
  materialId: `mat_${"2".repeat(32)}`,
  documentVersion: 1,
  detectorRunCompleted: true,
  revision: 4,
  documentRisk: {
    route: "full_review_required",
    readinessScore: 42,
    pageRisks: [{
      pageIndex: 0, p0Count: 1, p1Count: 0, p2Count: 0, p3Count: 1,
      ocrMinPpm: 760000, ocrMeanPpm: 900000, ocrP10Ppm: 800000,
      coveragePpm: 970000, unknownLongNumberCount: 1,
      visualRisks: ["seal_text_unresolved"], completenessPassed: true,
      detectorConflictCount: 1, clusterInconsistencyCount: 0,
      visualReviewRequired: true, readinessScore: 42,
      reasonCodes: ["ocr_threshold_failed"],
    }],
    totalP0: 1, totalP1: 0, totalP2: 0,
    policyId: "privacy-shadow-v1", policyVersion: 1,
    calibrationEvidenceVersion: null, qualificationReportId: "qual-synthetic",
    autoApprovalPolicyMode: "shadow", productionAutomaticEnabled: false,
    shadowWouldAutoApprove: false, automaticPublishAllowed: false,
    reasonCodes: ["p0_unresolved", "automatic_policy_not_calibrated"],
  },
  hardGates: gateIds.map((gateId, index) => ({
    gateId, passed: index !== 2 && index !== 12 && index !== 13,
    blocking: true,
    reasonCodes: index === 2 ? ["p0_unresolved"] : index === 12 ? ["automatic_policy_not_calibrated"] : index === 13 ? ["shadow_mode_requires_human"] : [],
  })),
  findings: [{
    findingId: `fnd_${"b".repeat(32)}`, pageIndex: 0, blockId: "page-1",
    startOffset: 2, endOffset: 20, entityType: "identity_number",
    detectorSources: ["cn_identity_checksum", "case_dictionary"],
    detectorVersions: { cn_identity_checksum: "v2", case_dictionary: "v1" },
    modelVersions: {}, calibratedConfidencePpm: 600000,
    ocrConfidencePpm: 760000, layoutConfidencePpm: 810000,
    caseDictionaryMatch: true, clusterId: `clu_${"c".repeat(32)}`,
    clusterOccurrenceCount: 3, detectorAgreement: false, severity: "p0_blocking",
    reviewPriority: 1000,
    reasonCodes: ["detector_or_location_conflict", "low_ocr_confidence"],
    proposedReplacement: "[IDENTITY_A]", resolutionState: "unresolved",
  }],
  residualScan: {
    passed: false, evidenceHash: "f".repeat(64), blockingHitCount: 1,
    reviewHitCount: 1, reasonCodes: ["residual_long_digit_sequence"],
  },
  visualRiskResolutions: [],
  canUndo: true, canRedo: false, rejected: false,
};

describe("RiskReviewPanel", () => {
  it("renders strict gates, evidence and visual confirmations without placeholder actions", () => {
    const markup = renderToStaticMarkup(
      <RiskReviewPanel
        state={state}
        busy={false}
        onAction={vi.fn()}
        onUndo={vi.fn()}
        onRedo={vi.fn()}
        onManualApprove={vi.fn()}
      />,
    );
    expect(state.hardGates).toHaveLength(17);
    for (const text of [
      "按严重度、页码与证据逐项处理", "P0 阻断", "17 项后端硬闸门",
      "风险优先", "仅 OCR 风险", "视觉风险显式确认", "确认已脱敏",
      "确认不敏感", "detector 冲突", "接受替换", "标记为不敏感",
      "拆分 cluster", "加入词典", "批量接受 P3", "进入人工批准",
      "保存当前编辑并重跑残留扫描",
    ]) {
      expect(markup).toContain(text);
    }
    expect(markup).toContain("aria-label=\"P0 阻断，第 1 页，身份证号\"");
    expect(markup).not.toContain("重新运行检测");
    expect(markup).not.toContain("重新运行本地 OCR");
    expect(markup).toContain("has-conflict");
    expect(markup).toContain("is-uncertain");
    expect(markup).not.toContain("privateValue");
    expect(markup).not.toContain("originalText");
    expect(markup).not.toContain(state.caseId);
  });

  it("disables only undo and redo for an outer workbench draft", () => {
    const markup = renderToStaticMarkup(
      <RiskReviewPanel
        state={{ ...state, canRedo: true }}
        busy={false}
        historyActionsDisabled
        onAction={vi.fn(async () => true)}
        onUndo={vi.fn()}
        onRedo={vi.fn()}
        onManualApprove={vi.fn()}
      />,
    );

    expect(markup).toContain(
      '<button type="button" disabled="">撤销</button>',
    );
    expect(markup).toContain(
      '<button type="button" disabled="">重做</button>',
    );
    expect(markup).toContain(
      '<button type="button">接受替换</button>',
    );
    expect(markup).toContain(
      '<button type="button">保存当前编辑并重跑残留扫描</button>',
    );
  });
});
