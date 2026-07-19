import { FormEvent, useCallback, useMemo, useState } from "react";

import {
  approvePrivacyReview,
  deletePrivacyReview,
  exportApprovedReviewPdf,
  loadLatestPrivacyReview,
  preparePrivacyMaterial,
} from "../../ipc/privacy/client";
import type {
  ApprovePrivacyReviewResponse,
  EditedRedactedPage,
  PrivacyReview,
} from "../../ipc/privacy/types";
import { deletePrivacyReviewAfterConfirmation } from "./privacyReviewDeletion";

type ReviewOperation =
  | "idle"
  | "preparing"
  | "loading"
  | "approving"
  | "exporting"
  | "deleting";

export interface ApprovalDraft {
  reviewer: string;
  ttlSeconds: string;
}

export interface PrivacyReviewWorkbenchProps {
  disabled?: boolean;
  onActivityChange?: (active: boolean) => void;
}

export interface PrivacyReviewWorkbenchViewProps {
  disabled: boolean;
  operation: ReviewOperation;
  customTerms: string;
  review: PrivacyReview | null;
  editedPages: EditedRedactedPage[];
  approvalDraft: ApprovalDraft;
  approval: ApprovePrivacyReviewResponse | null;
  notice: string;
  error: string;
  onCustomTermsChange: (value: string) => void;
  onChooseMaterial: () => void;
  onLoadLatest: () => void;
  onDelete: () => void;
  onEditedPageChange: (pageNumber: number, value: string) => void;
  onApprovalDraftChange: (value: ApprovalDraft) => void;
  onApprove: () => void;
  onExport: () => void;
}

const LOCAL_SAFE_PDF_DESTINATION = {
  kind: "verified_local_provider" as const,
  identifier: "local-safe-pdf-export-v1",
};
const LOCAL_SAFE_PDF_PURPOSE = "local_safe_pdf_export";

const DEFAULT_APPROVAL_DRAFT: ApprovalDraft = {
  reviewer: "",
  ttlSeconds: "3600",
};

function displayError(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "本机脱敏工作流操作失败。";
}

// eslint-disable-next-line react-refresh/only-export-components
export function parseCustomRedactionTerms(value: string): string[] {
  const terms = value
    .split(/[\r\n,，;；]+/u)
    .map((term) => term.trim())
    .filter(Boolean);
  const unique = [...new Set(terms)];
  const encoder = new TextEncoder();
  if (
    unique.length > 128 ||
    unique.some(
      (term) =>
        term.includes("[") ||
        term.includes("]") ||
        encoder.encode(term).length > 256,
    )
  ) {
    throw new Error(
      "自定义敏感词最多 128 个、每项不超过 256 字节，且不能包含方括号。",
    );
  }
  return unique;
}

function reviewStateLabel(state: PrivacyReview["reviewState"]): string {
  switch (state) {
    case "review_required":
      return "待人工复核";
    case "approved":
      return "曾获批准；本次仍需重新核对回执";
    case "revoked":
      return "已撤销";
  }
}

function backendLabel(backend: PrivacyReview["backendTrace"][number]["backend"]): string {
  return backend === "native_text" ? "本机原生文本提取" : "本机 MinerU";
}

function validateApprovalDraft(draft: ApprovalDraft): number {
  const ttlSeconds = Number(draft.ttlSeconds);
  if (!draft.reviewer.trim() || draft.reviewer.trim().length > 128) {
    throw new Error("批准人必填且不超过 128 个字符。");
  }
  if (
    !Number.isSafeInteger(ttlSeconds) ||
    ttlSeconds < 300 ||
    ttlSeconds > 604_800
  ) {
    throw new Error("回执有效期必须是 300–604800 秒之间的整数。");
  }
  return ttlSeconds;
}

export function PrivacyReviewWorkbenchView({
  disabled,
  operation,
  customTerms,
  review,
  editedPages,
  approvalDraft,
  approval,
  notice,
  error,
  onCustomTermsChange,
  onChooseMaterial,
  onLoadLatest,
  onDelete,
  onEditedPageChange,
  onApprovalDraftChange,
  onApprove,
  onExport,
}: PrivacyReviewWorkbenchViewProps) {
  const busy = disabled || operation !== "idle";
  const editedByNumber = useMemo(
    () => new Map(editedPages.map((page) => [page.pageNumber, page.redactedText])),
    [editedPages],
  );
  const approve = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onApprove();
  };

  return (
    <section className="privacy-review-workbench" aria-busy={busy}>
      <header className="privacy-heading">
        <div>
          <p className="eyebrow">本机材料闭环</p>
          <h2>法律文书脱敏审阅</h2>
        </div>
        <span className="privacy-config-state is-valid">原件禁止外发</span>
      </header>

      <div className="privacy-boundary-warning" role="note">
        <strong>这里只生成本地获批产物，不执行发送</strong>
        <p>
          选择的 PDF、DOCX、TXT 或 Markdown 仅在本机读取。批准回执只授权精确获批
          JSON、指定目标、用途和有效期；legacy assistant、Provider 附件与 MCP
          transport 尚未完成同一回执闸门，绝不能把本页结果理解为原件或消息已获准发送。
        </p>
        <p>
          系统输入法、辅助功能、屏幕截图和操作系统剪贴板仍属于 OS 信任边界；处理真实案件时应关闭云输入、云剪贴板与第三方辅助工具。
        </p>
      </div>

      <section className="privacy-review-picker" aria-labelledby="privacy-material-picker-title">
        <div className="panel-heading">
          <div>
            <h3 id="privacy-material-picker-title">1. 选择本机材料</h3>
            <p>文件路径由原生选择器返回给 Rust；网页层不接收也不保存任意路径。</p>
          </div>
          <div className="privacy-actions">
            <button disabled={busy} type="button" onClick={onChooseMaterial}>
              {operation === "preparing" ? "正在本机处理…" : "选择材料并生成审阅"}
            </button>
            <button disabled={busy} type="button" onClick={onLoadLatest}>
              {operation === "loading" ? "正在恢复…" : "恢复最近审阅"}
            </button>
          </div>
        </div>
        <label className="privacy-custom-terms">
          <span>本案自定义敏感词（每行或逗号分隔）</span>
          <textarea
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            disabled={busy}
            rows={3}
            value={customTerms}
            placeholder="内部项目代号&#10;特定单位简称"
            onChange={(event) => onCustomTermsChange(event.target.value)}
          />
        </label>
        <p className="privacy-help">
          自定义词与自动识别出的敏感值只进入本机受保护审阅数据；canary
          不进入界面、日志或外发审计。
        </p>
      </section>

      {review ? (
        <>
          <section className="privacy-review-summary" aria-labelledby="privacy-review-summary-title">
            <div className="panel-heading">
              <div>
                <h3 id="privacy-review-summary-title">2. 核对提取与脱敏结果</h3>
                <p>
                  {review.sourceDisplayName} · {review.mediaType} · {review.pageCount} 页/段 ·{" "}
                  {reviewStateLabel(review.reviewState)}
                </p>
              </div>
              <span>{review.summary.total} 处自动替换</span>
            </div>
            <dl>
              <div>
                <dt>源文件 SHA-256</dt>
                <dd><code>{review.sourceSha256}</code></dd>
              </div>
              <div>
                <dt>提取结果 SHA-256</dt>
                <dd><code>{review.extractionSha256}</code></dd>
              </div>
              <div>
                <dt>初始脱敏草稿 SHA-256</dt>
                <dd><code>{review.suggestedRedactedContentSha256}</code></dd>
              </div>
              <div>
                <dt>处理版本</dt>
                <dd><code>{review.processingVersion}</code></dd>
              </div>
            </dl>
            <ul className="privacy-backend-trace" aria-label="本机处理后端证据">
              {review.backendTrace.map((trace, index) => (
                <li key={`${trace.backend}-${index}`}>
                  <strong>{backendLabel(trace.backend)}</strong>
                  <span>
                    页/段 {trace.pageNumbers.join("、")} · 设备 {trace.device} ·{" "}
                    {trace.isolationVerified ? "隔离证据已验证" : "隔离证据未验证"}
                  </span>
                  {trace.workerSha256 ? <code>worker {trace.workerSha256}</code> : null}
                  {trace.modelManifestSha256 ? (
                    <code>model {trace.modelManifestSha256}</code>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>

          <div className="privacy-review-pages">
            {review.pages.map((page) => (
              <article className="privacy-review-page" key={page.pageNumber}>
                <header>
                  <h3>页/段 {page.pageNumber}</h3>
                  <span>{page.locator}</span>
                  <span>
                    {page.assessment.decision === "native_accepted"
                      ? "本机文本层已接受"
                      : "需要本地 OCR"}
                  </span>
                </header>
                <div className="privacy-review-columns">
                  <label>
                    <span>本机原文（只读、不得外发）</span>
                    <textarea
                      aria-label={`页/段 ${page.pageNumber} 本机原文`}
                      autoCapitalize="off"
                      autoComplete="off"
                      autoCorrect="off"
                      spellCheck={false}
                      readOnly
                      rows={12}
                      value={page.originalText}
                    />
                  </label>
                  <label>
                    <span>拟批准脱敏文本（必须逐项人工核对）</span>
                    <textarea
                      aria-label={`页/段 ${page.pageNumber} 脱敏文本`}
                      autoCapitalize="off"
                      autoComplete="off"
                      autoCorrect="off"
                      spellCheck={false}
                      disabled={busy}
                      rows={12}
                      value={editedByNumber.get(page.pageNumber) ?? ""}
                      onChange={(event) =>
                        onEditedPageChange(page.pageNumber, event.target.value)
                      }
                    />
                  </label>
                </div>
              </article>
            ))}
          </div>

          <form className="privacy-approval-form" onSubmit={approve}>
            <fieldset disabled={busy}>
              <legend>3. 人工批准与本机回执</legend>
              <div className="privacy-grid">
                <label>
                  <span>批准人</span>
                  <input
                    autoCapitalize="off"
                    autoComplete="off"
                    autoCorrect="off"
                    spellCheck={false}
                    value={approvalDraft.reviewer}
                    onChange={(event) =>
                      onApprovalDraftChange({
                        ...approvalDraft,
                        reviewer: event.target.value,
                      })
                    }
                  />
                </label>
                <div className="privacy-fixed-scope">
                  <span>固定本机目标与用途</span>
                  <strong>本机安全 PDF 重建器</strong>
                  <code>
                    {LOCAL_SAFE_PDF_DESTINATION.identifier} · {LOCAL_SAFE_PDF_PURPOSE}
                  </code>
                  <small>固定枚举不接受案件名称、当事人信息或其他自由文本。</small>
                </div>
                <label>
                  <span>回执有效期（秒）</span>
                  <input
                    autoCapitalize="off"
                    autoComplete="off"
                    autoCorrect="off"
                    spellCheck={false}
                    inputMode="numeric"
                    value={approvalDraft.ttlSeconds}
                    onChange={(event) =>
                      onApprovalDraftChange({
                        ...approvalDraft,
                        ttlSeconds: event.target.value,
                      })
                    }
                  />
                </label>
              </div>
              <div className="privacy-fixed-invariants">
                <span>✓ 批准对象是精确 JSON 字节，不是“看起来已脱敏”的泛化许可</span>
                <span>✓ 回执同时绑定源哈希、提取哈希、目标、用途、detector 与 TTL</span>
                <span>✓ 人工改回姓名、证件号等源 canary（含零宽/空格/标点混淆）会被拒绝</span>
              </div>
              <div className="privacy-actions">
                <button type="submit">
                  {operation === "approving" ? "正在复检并签发…" : "批准精确载荷并签发本机回执"}
                </button>
              </div>
            </fieldset>
          </form>

          {approval ? (
            <section className="privacy-approved-result" aria-labelledby="privacy-approved-result-title">
              <h3 id="privacy-approved-result-title">4. 安全重建脱敏 PDF</h3>
              <p>
                本机回执已签发，但没有执行 Provider/MCP/assistant 发送。回执 token
                和精确获批 JSON 仅驻留当前界面内存；修改文本或批准参数会立即作废本次导出状态。
              </p>
              <dl>
                <div>
                  <dt>回执 ID</dt>
                  <dd><code>{approval.receiptId}</code></dd>
                </div>
                <div>
                  <dt>获批载荷 SHA-256</dt>
                  <dd><code>{approval.approvedPayloadSha256}</code></dd>
                </div>
                <div>
                  <dt>有效至</dt>
                  <dd>{new Date(approval.expiresAtUnix * 1000).toLocaleString("zh-CN")}</dd>
                </div>
              </dl>
              <p className="privacy-export-sync-warning">
                本轮只允许保存到非网络本地磁盘；UNC、映射网络盘及 OneDrive 等云端占位/召回位置会被后端拒绝。任何后续外发必须另行取得目标绑定回执。
              </p>
              <p className="privacy-export-fidelity-warning" role="note">
                输出使用固定哈希嵌入的常用中文字体；若获批文本含字体不支持的字符，签发或导出会失败关闭。它仍是文本重排版脱敏副本，不保留原版式、签章或图片，也未完成多阅读器渲染、打印或法院提交资格验证。
              </p>
              <button disabled={busy} type="button" onClick={onExport}>
                {operation === "exporting"
                  ? "正在验证回执并重建…"
                  : "验证精确回执并保存重建 PDF"}
              </button>
            </section>
          ) : null}

          <section className="privacy-review-delete" aria-labelledby="privacy-review-delete-title">
            <h3 id="privacy-review-delete-title">本机数据生命周期</h3>
            <p>
              删除应用内受保护的复核草稿并撤销其全部回执；不删除所选原始文书或已另存的 PDF。
              不含正文的哈希审计会保留。SQLite secure_delete 仅是尽力清理，不承诺存储介质级取证擦除。
            </p>
            <button className="danger" disabled={busy} type="button" onClick={onDelete}>
              {operation === "deleting"
                ? "正在撤销并删除本机复核数据…"
                : "撤销回执并删除应用内复核数据"}
            </button>
          </section>
        </>
      ) : null}

      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="privacy-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}

export function PrivacyReviewWorkbench({
  disabled = false,
  onActivityChange,
}: PrivacyReviewWorkbenchProps) {
  const [operation, setOperation] = useState<ReviewOperation>("idle");
  const [customTerms, setCustomTerms] = useState("");
  const [review, setReview] = useState<PrivacyReview | null>(null);
  const [editedPages, setEditedPages] = useState<EditedRedactedPage[]>([]);
  const [approvalDraft, setApprovalDraft] = useState(DEFAULT_APPROVAL_DRAFT);
  const [approval, setApproval] = useState<ApprovePrivacyReviewResponse | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const begin = useCallback(
    (next: ReviewOperation) => {
      setOperation(next);
      onActivityChange?.(true);
      setError("");
      setNotice("");
    },
    [onActivityChange],
  );
  const finish = useCallback(() => {
    setOperation("idle");
    onActivityChange?.(false);
  }, [onActivityChange]);

  const installReview = useCallback((nextReview: PrivacyReview) => {
    setReview(nextReview);
    setEditedPages(
      nextReview.pages.map((page) => ({
        pageNumber: page.pageNumber,
        redactedText: page.redactedText,
      })),
    );
    setApproval(null);
  }, []);

  const chooseMaterial = useCallback(async () => {
    if (disabled || operation !== "idle") return;
    let terms: string[];
    try {
      terms = parseCustomRedactionTerms(customTerms);
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("preparing");
    try {
      const response = await preparePrivacyMaterial({ customTerms: terms });
      if (response.cancelled || !response.review) {
        setNotice("未选择材料；本机未生成新的审阅记录。");
        return;
      }
      installReview(response.review);
      setNotice("材料已在本机提取和初步脱敏，请逐页/逐段人工复核。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [begin, customTerms, disabled, finish, installReview, operation]);

  const loadLatest = useCallback(async () => {
    if (disabled || operation !== "idle") return;
    begin("loading");
    try {
      const loaded = await loadLatestPrivacyReview();
      if (!loaded) {
        setNotice("本机尚无可恢复的脱敏审阅。");
        return;
      }
      installReview(loaded);
      setNotice(
        loaded.reviewState === "approved"
          ? "已恢复曾获批准的审阅；为避免复用失效内存凭证，请重新核对并签发本次回执。"
          : "已恢复最近的本机脱敏审阅。",
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [begin, disabled, finish, installReview, operation]);

  const editPage = useCallback((pageNumber: number, value: string) => {
    setEditedPages((current) =>
      current.map((page) =>
        page.pageNumber === pageNumber ? { ...page, redactedText: value } : page,
      ),
    );
    setApproval(null);
    setNotice("");
  }, []);

  const updateApprovalDraft = useCallback((next: ApprovalDraft) => {
    setApprovalDraft(next);
    setApproval(null);
    setNotice("");
  }, []);

  const approve = useCallback(async () => {
    if (disabled || operation !== "idle" || !review) return;
    let ttlSeconds: number;
    try {
      ttlSeconds = validateApprovalDraft(approvalDraft);
      if (
        editedPages.length !== review.pages.length ||
        editedPages.some((page) => !Number.isSafeInteger(page.pageNumber))
      ) {
        throw new Error("必须提交全部页/段的脱敏文本。");
      }
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("approving");
    try {
      const response = await approvePrivacyReview({
        redactionId: review.redactionId,
        expectedSuggestedRedactedSha256:
          review.suggestedRedactedContentSha256,
        editedPages,
        reviewer: approvalDraft.reviewer.trim(),
        destination: LOCAL_SAFE_PDF_DESTINATION,
        purpose: LOCAL_SAFE_PDF_PURPOSE,
        ttlSeconds,
      });
      setApproval(response);
      setNotice(
        "精确脱敏载荷已在本机复检并签发回执；尚未执行任何 Provider、assistant 或 MCP 发送。",
      );
    } catch (reason: unknown) {
      setApproval(null);
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    approvalDraft,
    begin,
    disabled,
    editedPages,
    finish,
    operation,
    review,
  ]);

  const exportPdf = useCallback(async () => {
    if (disabled || operation !== "idle" || !review || !approval) return;
    begin("exporting");
    try {
      const response = await exportApprovedReviewPdf({
        redactionId: review.redactionId,
        receiptToken: approval.receiptToken,
        approvedPayloadJson: approval.approvedPayloadJson,
        destination: approval.destination,
        purpose: approval.purpose,
      });
      if (response.cancelled) {
        setNotice("已取消保存；没有写入脱敏 PDF。");
        return;
      }
      setNotice(
        `已安全保存 ${response.fileName ?? "脱敏 PDF"}（${response.outputPageCount} 页，SHA-256 ${response.pdfSha256 ?? "未返回"}）。`,
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [approval, begin, disabled, finish, operation, review]);

  const deleteCurrentReview = useCallback(async () => {
    if (disabled || operation !== "idle" || !review) return;
    let started = false;
    try {
      const outcome = await deletePrivacyReviewAfterConfirmation(
        {
          redactionId: review.redactionId,
          expectedSourceSha256: review.sourceSha256,
          expectedExtractionSha256: review.extractionSha256,
        },
        {
          confirm: (message) => window.confirm(message),
          deleteReview: deletePrivacyReview,
          onConfirmed: () => {
            started = true;
            begin("deleting");
          },
        },
      );
      if (outcome.cancelled) {
        setNotice("已取消删除；本机复核数据与回执保持不变。");
        return;
      }
      setReview(null);
      setEditedPages([]);
      setApproval(null);
      setCustomTerms("");
      setApprovalDraft({ ...DEFAULT_APPROVAL_DRAFT });
      setNotice(
        outcome.deleted
          ? "已撤销关联回执并删除应用内加密复核数据；原始文书、已另存文件及哈希审计未删除。"
          : "该复核记录已不存在；已清空当前界面，未删除任何原始文书或已另存文件。",
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      if (started) finish();
    }
  }, [begin, disabled, finish, operation, review]);

  return (
    <PrivacyReviewWorkbenchView
      disabled={disabled}
      operation={operation}
      customTerms={customTerms}
      review={review}
      editedPages={editedPages}
      approvalDraft={approvalDraft}
      approval={approval}
      notice={notice}
      error={error}
      onCustomTermsChange={setCustomTerms}
      onChooseMaterial={() => void chooseMaterial()}
      onLoadLatest={() => void loadLatest()}
      onDelete={() => void deleteCurrentReview()}
      onEditedPageChange={editPage}
      onApprovalDraftChange={updateApprovalDraft}
      onApprove={() => void approve()}
      onExport={() => void exportPdf()}
    />
  );
}
