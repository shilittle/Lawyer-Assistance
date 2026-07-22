import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  ApprovePrivacyReviewResponse,
  PrivacyReview,
} from "../../ipc/privacy/types";
import {
  LOCAL_SAFE_EXPORT_SCOPES,
  PrivacyReviewWorkbenchView,
  approvalMatchesTarget,
  parseCustomRedactionTerms,
} from "./PrivacyReviewWorkbench";

const review: PrivacyReview = {
  redactionId: "red_1",
  materialId: "mat_1",
  caseId: "case_1",
  vaultObjectId: "obj_1",
  vaultObjectVersion: 1,
  vaultIsolation: {
    isolationLevel: "windows_current_user_encrypted_vault",
    privateAclEnforced: true,
    contentIndexingDisabled: true,
    encryptedAtRest: true,
    brokerBoundary: "in_process_vault_broker_interface_v1",
    strongServiceIdentityBoundary: false,
    sameUserProcessLimitation: "same_user_processes_are_not_technically_excluded_without_a_service_identity",
  },
  sourceDisplayName: "案件材料.pdf",
  sourceSha256: "a".repeat(64),
  extractionSha256: "b".repeat(64),
  suggestedRedactedContentSha256: "c".repeat(64),
  processingVersion: "lawyer-assistance-material-processing-v1",
  mediaType: "application/pdf",
  pageCount: 1,
  backendTrace: [
    {
      backend: "native_text",
      workerSha256: null,
      modelManifestSha256: null,
      configSha256: null,
      device: "cpu",
      pageNumbers: [1],
      isolationVerified: true,
      isolationMechanism: "in_process_no_network_code_path",
    },
  ],
  summary: {
    total: 1,
    counts: { person_name: 1 },
    changed: true,
    manualReviewRequired: true,
    redactionVersion: "lawyer-assistance-redactor-v2",
  },
  reviewState: "review_required",
  pages: [
    {
      pageNumber: 1,
      locator: "page:1",
      assessment: {
        pageNumber: 1,
        nonWhitespaceChars: 24,
        printableRatio: 1,
        replacementCharRatio: 0,
        cjkRatio: 0.8,
        readingOrderScore: 1,
        decision: "native_accepted",
        reasonCodes: ["native_text_healthy"],
      },
      originalText: "原告张三起诉被告。",
      redactedText: "原告[姓名1]起诉被告。",
    },
  ],
  riskReview: null,
};

const approval: ApprovePrivacyReviewResponse = {
  receiptId: "rct_1",
  approvedPayloadSha256: "d".repeat(64),
  redactedContentSha256: "e".repeat(64),
  issuedAtUnix: 1_700_000_000,
  expiresAtUnix: 1_700_003_600,
  destination: {
    kind: "verified_local_provider",
    identifier: "local-safe-pdf-export-v1",
  },
  purpose: "local_safe_pdf_export",
  transportEnforcement:
    "active_receipt_persisted_exact_destination",
};

describe("local safe export approval targets", () => {
  it("maps every format to a unique fixed destination and requires an exact match", () => {
    const scopes = Object.values(LOCAL_SAFE_EXPORT_SCOPES);
    expect(new Set(scopes.map((scope) => scope.destination.identifier)).size).toBe(4);
    expect(new Set(scopes.map((scope) => scope.purpose)).size).toBe(4);
    expect(
      approvalMatchesTarget(approval, {
        kind: "local_safe_export",
        format: "pdf",
      }),
    ).toBe(true);
    expect(
      approvalMatchesTarget(approval, {
        kind: "local_safe_export",
        format: "docx",
      }),
    ).toBe(false);
  });
});

describe("PrivacyReviewWorkbenchView", () => {
  it("renders the end-to-end local review boundary without a path or transport claim", () => {
    const markup = renderToStaticMarkup(
      <PrivacyReviewWorkbenchView
        disabled={false}
        operation="idle"
        customTerms="内部代号"
        review={review}
        editedPages={[{ pageNumber: 1, redactedText: "原告[姓名1]起诉被告。" }]}
        approvalDraft={{
          reviewer: "复核员",
          ttlSeconds: "3600",
          target: { kind: "local_safe_export", format: "pdf" },
        }}
        approval={approval}
        notice=""
        error=""
        onCustomTermsChange={vi.fn()}
        onChooseMaterial={vi.fn()}
        onLoadLatest={vi.fn()}
        onDelete={vi.fn()}
        onEditedPageChange={vi.fn()}
        onApprovalDraftChange={vi.fn()}
        onApprove={vi.fn()}
        onExport={vi.fn()}
      />,
    );

    expect(markup).toContain("选择材料并生成审阅");
    expect(markup).toContain("本机原文（只读、不得外发）");
    expect(markup).toContain("拟批准脱敏文本（必须逐项人工核对）");
    expect(markup).toContain("批准精确载荷并签发本机回执");
    expect(markup).toContain("本机安全导出格式（切换后必须重新批准）");
    for (const label of ["重建 PDF", "纯文本 TXT", "Markdown", "安全 DOCX"]) {
      expect(markup).toContain(label);
    }
    expect(markup).toContain("重新验证活动回执并保存 重建 PDF");
    expect(markup).toContain("这里只生成本地获批产物，不执行发送");
    expect(markup).toContain("本机导出回执不能授权这些通道");
    expect(markup).toContain("后端固定目标与用途");
    expect(markup).toContain("local-safe-pdf-export-v1");
    expect(markup).toContain("格式只映射到固定枚举");
    expect(markup).toContain("系统输入法、辅助功能、屏幕截图和操作系统剪贴板");
    expect(markup).toContain("只从获批脱敏文本全新构造");
    expect(markup).toContain("不复制原文包、元数据、批注、附件、图片");
    expect(markup).toContain("PDF 使用固定哈希字体");
    expect(markup).toContain("DOCX 仅含 allowlist");
    expect(markup).toContain("尚未取得法院提交、打印保真或多阅读器兼容资格");
    expect(markup).toContain("撤销回执并删除应用内复核数据");
    expect(markup).toContain("不删除所选原始文书或已另存的安全派生文书");
    expect(markup).toContain("哈希审计会保留");
    expect(markup).toContain("不承诺存储介质级取证擦除");
    expect(markup).toContain("保存命令不接收网页层回传的回执 token");
    expect(markup).not.toContain('name="path"');
    expect(markup).not.toContain('type="file"');
    expect(markup).not.toContain("SECRET_RECEIPT_TOKEN_MUST_NOT_RENDER");
    expect(markup).not.toContain("PRIVATE_APPROVED_JSON");
  });

  it("disables spelling and correction services on every sensitive control", () => {
    const markup = renderToStaticMarkup(
      <PrivacyReviewWorkbenchView
        disabled={false}
        operation="idle"
        customTerms="内部代号"
        review={review}
        editedPages={[{ pageNumber: 1, redactedText: "原告[姓名1]起诉被告。" }]}
        approvalDraft={{
          reviewer: "复核员",
          ttlSeconds: "3600",
          target: { kind: "local_safe_export", format: "pdf" },
        }}
        approval={null}
        notice=""
        error=""
        onCustomTermsChange={vi.fn()}
        onChooseMaterial={vi.fn()}
        onLoadLatest={vi.fn()}
        onDelete={vi.fn()}
        onEditedPageChange={vi.fn()}
        onApprovalDraftChange={vi.fn()}
        onApprove={vi.fn()}
        onExport={vi.fn()}
      />,
    );

    expect(markup.match(/spellcheck="false"/giu)?.length).toBe(5);
    expect(markup.match(/autocorrect="off"/giu)?.length).toBe(5);
    expect(markup.match(/autocomplete="off"/giu)?.length).toBe(5);
    expect(markup.toLowerCase()).not.toContain("spellcheck=\"true\"");
  });
});

describe("parseCustomRedactionTerms", () => {
  it("deduplicates local custom terms and rejects bracket injection or oversized input", () => {
    expect(parseCustomRedactionTerms("甲公司\n乙项目，甲公司")).toEqual([
      "甲公司",
      "乙项目",
    ]);
    expect(() => parseCustomRedactionTerms("[姓名1]")).toThrow("方括号");
    expect(() => parseCustomRedactionTerms("甲".repeat(129))).toThrow(
      "256 字节",
    );
    expect(() =>
      parseCustomRedactionTerms(
        Array.from({ length: 129 }, (_, index) => `词${index}`).join("\n"),
      ),
    ).toThrow("最多 128 个");
  });
});
