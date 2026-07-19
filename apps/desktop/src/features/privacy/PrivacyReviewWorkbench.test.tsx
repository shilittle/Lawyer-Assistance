import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  ApprovePrivacyReviewResponse,
  PrivacyReview,
} from "../../ipc/privacy/types";
import {
  PrivacyReviewWorkbenchView,
  parseCustomRedactionTerms,
} from "./PrivacyReviewWorkbench";

const review: PrivacyReview = {
  redactionId: "red_1",
  materialId: "mat_1",
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
};

const approval: ApprovePrivacyReviewResponse = {
  receiptId: "rct_1",
  receiptToken: "SECRET_RECEIPT_TOKEN_MUST_NOT_RENDER",
  approvedPayloadJson:
    '{"schemaVersion":1,"pages":[{"pageNumber":1,"text":"PRIVATE_APPROVED_JSON"}]}',
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
    "local_receipt_issued_provider_transport_not_fully_gated",
};

describe("PrivacyReviewWorkbenchView", () => {
  it("renders the end-to-end local review boundary without a path or transport claim", () => {
    const markup = renderToStaticMarkup(
      <PrivacyReviewWorkbenchView
        disabled={false}
        operation="idle"
        customTerms="内部代号"
        review={review}
        editedPages={[{ pageNumber: 1, redactedText: "原告[姓名1]起诉被告。" }]}
        approvalDraft={{ reviewer: "复核员", ttlSeconds: "3600" }}
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
    expect(markup).toContain("验证精确回执并保存重建 PDF");
    expect(markup).toContain("这里只生成本地获批产物，不执行发送");
    expect(markup).toContain("transport 尚未完成同一回执闸门");
    expect(markup).toContain("本机安全 PDF 重建器");
    expect(markup).toContain("固定枚举不接受案件名称");
    expect(markup).toContain("系统输入法、辅助功能、屏幕截图和操作系统剪贴板");
    expect(markup).toContain("文本重排版脱敏副本");
    expect(markup).toContain("不保留原版式、签章或图片");
    expect(markup).toContain("固定哈希嵌入的常用中文字体");
    expect(markup).toContain("字体不支持的字符");
    expect(markup).toContain("未完成多阅读器渲染、打印或法院提交资格验证");
    expect(markup).toContain("撤销回执并删除应用内复核数据");
    expect(markup).toContain("不删除所选原始文书或已另存的 PDF");
    expect(markup).toContain("哈希审计会保留");
    expect(markup).toContain("不承诺存储介质级取证擦除");
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
        approvalDraft={{ reviewer: "复核员", ttlSeconds: "3600" }}
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
