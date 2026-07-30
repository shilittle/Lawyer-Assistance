import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  applyCaseRedactionRiskReviewAction,
  approveCaseRedactionReview,
  deleteCaseRedactionReview,
  exportApprovedCaseRedaction,
  loadCaseRedactionReview,
  prepareCaseMaterial,
  redoCaseRedactionRiskReview,
  undoCaseRedactionRiskReview,
} from "../../../ipc/privacy/case-material-client";
import type {
  ApproveCaseRedactionReviewResponse,
  CaseRedactionReview,
} from "../../../ipc/privacy/case-material-types";
import type { PrivacyRiskReviewAction } from "../../../ipc/privacy/risk-types";
import type {
  EditedRedactedPage,
} from "../../../ipc/privacy/types";
import {
  PrivacyReviewWorkbenchView,
  approvalMatchesTarget,
  localSafeExportScope,
  parseCustomRedactionTerms,
  type ApprovalDraft,
  type ReviewOperation,
} from "../../privacy/PrivacyReviewWorkbench";
import { PRIVACY_REVIEW_DELETION_CONFIRMATION } from "../../privacy/privacyReviewDeletion";
import {
  caseRedactionDraftIsDirty,
  caseRedactionNonCustomDraftIsDirty,
  cloneCaseRedactionDraftSnapshot,
  executeCaseRedactionHistoryIfClean,
  type CaseRedactionDraftSnapshot,
} from "./redactionWorkbenchState";

function defaultApprovalDraft(): ApprovalDraft {
  return {
    reviewer: "",
    ttlSeconds: "3600",
    target: { kind: "local_safe_export", format: "pdf" },
  };
}

type ReviewInstallMode =
  | "context_load"
  | "prepare"
  | "risk_action"
  | "risk_history"
  | "approval";

interface ReviewInstallSubmission {
  customTerms?: string;
  approvalDraft?: ApprovalDraft;
}

export interface RedactionWorkbenchProps {
  projectId: string;
  selectedRedactionId: string | null;
  latestRedactionId: string | null;
  disabled?: boolean;
  onDraftDirtyChange: (dirty: boolean) => void;
  onMutationActivityChange: (active: boolean) => void;
  onReviewChanged: (
    materialId: string,
    redactionId: string | null,
  ) => Promise<void> | void;
}

function displayError(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "当前案件的脱敏操作失败。";
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

export function RedactionWorkbench({
  projectId,
  selectedRedactionId,
  latestRedactionId,
  disabled = false,
  onDraftDirtyChange,
  onMutationActivityChange,
  onReviewChanged,
}: RedactionWorkbenchProps) {
  const [operation, setOperation] = useState<ReviewOperation>("idle");
  const [customTerms, setCustomTerms] = useState("");
  const [review, setReview] = useState<CaseRedactionReview | null>(null);
  const [editedPages, setEditedPages] = useState<EditedRedactedPage[]>([]);
  const [approvalDraft, setApprovalDraft] = useState<ApprovalDraft>(
    defaultApprovalDraft,
  );
  const [riskDraftDirty, setRiskDraftDirty] = useState(false);
  const [riskDraftContextKey, setRiskDraftContextKey] = useState(0);
  const [draftBaseline, setDraftBaseline] =
    useState<CaseRedactionDraftSnapshot>(() => ({
      customTerms: "",
      editedPages: [],
      approvalDraft: defaultApprovalDraft(),
    }));
  const [approval, setApproval] =
    useState<ApproveCaseRedactionReviewResponse | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const requestSequence = useRef(0);
  const loadedRedactionId = useRef<string | null>(null);

  const currentDraft = useMemo<CaseRedactionDraftSnapshot>(
    () => ({
      customTerms,
      editedPages,
      approvalDraft,
    }),
    [approvalDraft, customTerms, editedPages],
  );
  const dirty = useMemo(
    () =>
      caseRedactionDraftIsDirty(
        draftBaseline,
        currentDraft,
        riskDraftDirty,
      ),
    [currentDraft, draftBaseline, riskDraftDirty],
  );
  const nonCustomDraftDirty = useMemo(
    () =>
      caseRedactionNonCustomDraftIsDirty(
        draftBaseline,
        currentDraft,
        riskDraftDirty,
      ),
    [currentDraft, draftBaseline, riskDraftDirty],
  );

  useEffect(() => {
    onDraftDirtyChange(dirty);
  }, [dirty, onDraftDirtyChange]);

  useEffect(
    () => () => {
      onDraftDirtyChange(false);
    },
    [onDraftDirtyChange],
  );

  useEffect(
    () => () => {
      requestSequence.current += 1;
      onMutationActivityChange(false);
    },
    [onMutationActivityChange],
  );

  const begin = useCallback(
    (next: ReviewOperation) => {
      setOperation(next);
      onMutationActivityChange(true);
      setError("");
      setNotice("");
    },
    [onMutationActivityChange],
  );

  const finish = useCallback(() => {
    setOperation("idle");
    onMutationActivityChange(false);
  }, [onMutationActivityChange]);

  const installReview = useCallback(
    (
      nextReview: CaseRedactionReview,
      mode: ReviewInstallMode,
      submission: ReviewInstallSubmission = {},
    ) => {
      if (nextReview.projectId !== projectId) {
        throw new Error("后端返回的审阅不属于当前案件；已阻断显示。");
      }
      const nextEditedPages = nextReview.pages.map((page) => ({
        pageNumber: page.pageNumber,
        redactedText: page.redactedText,
      }));
      loadedRedactionId.current = nextReview.redactionId;
      setReview(nextReview);
      setEditedPages(nextEditedPages);
      setApproval(null);

      if (mode === "context_load" || mode === "prepare") {
        const nextCustomTerms =
          mode === "prepare" ? (submission.customTerms ?? "") : "";
        const nextApprovalDraft = defaultApprovalDraft();
        setCustomTerms(nextCustomTerms);
        setApprovalDraft(nextApprovalDraft);
        setRiskDraftDirty(false);
        setRiskDraftContextKey((current) => current + 1);
        setDraftBaseline(
          cloneCaseRedactionDraftSnapshot({
            customTerms: nextCustomTerms,
            editedPages: nextEditedPages,
            approvalDraft: nextApprovalDraft,
          }),
        );
        return;
      }

      if (
        mode === "risk_action" &&
        submission.approvalDraft
      ) {
        const reviewer = submission.approvalDraft.reviewer.trim();
        setApprovalDraft((current) => ({
          ...current,
          reviewer,
        }));
      }

      setDraftBaseline((current) => {
        const next = cloneCaseRedactionDraftSnapshot(current);
        next.editedPages = nextEditedPages.map((page) => ({
          ...page,
        }));
        if (
          mode === "risk_action" &&
          submission.approvalDraft
        ) {
          next.approvalDraft.reviewer =
            submission.approvalDraft.reviewer.trim();
        } else if (
          mode === "approval" &&
          submission.approvalDraft
        ) {
          next.approvalDraft = {
            ...submission.approvalDraft,
            target: { ...submission.approvalDraft.target },
          };
        }
        return next;
      });

      if (mode === "risk_history") {
        setRiskDraftDirty(false);
        setRiskDraftContextKey((current) => current + 1);
      }
    },
    [projectId],
  );

  const loadReview = useCallback(
    async (redactionId: string, message: string) => {
      const sequence = requestSequence.current + 1;
      requestSequence.current = sequence;
      begin("loading");
      try {
        const loaded = await loadCaseRedactionReview({
          projectId,
          redactionId,
        });
        if (sequence !== requestSequence.current) return;
        installReview(loaded, "context_load");
        setNotice(message);
      } catch (reason: unknown) {
        if (sequence === requestSequence.current) {
          setError(displayError(reason));
        }
      } finally {
        if (sequence === requestSequence.current) {
          finish();
        }
      }
    },
    [begin, finish, installReview, projectId],
  );

  useEffect(() => {
    if (!selectedRedactionId) {
      requestSequence.current += 1;
      loadedRedactionId.current = null;
      const nextApprovalDraft = defaultApprovalDraft();
      setReview(null);
      setCustomTerms("");
      setEditedPages([]);
      setApprovalDraft(nextApprovalDraft);
      setApproval(null);
      setRiskDraftDirty(false);
      setRiskDraftContextKey((current) => current + 1);
      setDraftBaseline({
        customTerms: "",
        editedPages: [],
        approvalDraft: nextApprovalDraft,
      });
      return;
    }
    if (loadedRedactionId.current === selectedRedactionId) return;
    void loadReview(
      selectedRedactionId,
      "已恢复当前案件所选脱敏代次。",
    );
  }, [loadReview, selectedRedactionId]);

  const chooseMaterial = useCallback(async () => {
    if (disabled || operation !== "idle") return;
    if (
      nonCustomDraftDirty &&
      !window.confirm(
        "选择新材料将丢弃当前尚未提交的脱敏页、批准参数或风险审阅草稿。确定继续吗？",
      )
    ) {
      setNotice("已取消选择新材料；当前未保存草稿保持不变。");
      return;
    }
    let terms: string[];
    try {
      terms = parseCustomRedactionTerms(customTerms);
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("preparing");
    try {
      const response = await prepareCaseMaterial({
        projectId,
        customTerms: terms,
      });
      if (response.cancelled || !response.review) {
        setNotice("未选择材料；当前案件未生成新的审阅记录。");
        return;
      }
      installReview(response.review, "prepare", {
        customTerms,
      });
      await onReviewChanged(
        response.review.materialId,
        response.review.redactionId,
      );
      setNotice(
        "材料已归入当前案件，并在本机完成提取和初步脱敏；请逐页/逐段人工复核。",
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    begin,
    customTerms,
    disabled,
    finish,
    installReview,
    nonCustomDraftDirty,
    onReviewChanged,
    operation,
    projectId,
  ]);

  const loadLatest = useCallback(() => {
    if (disabled || operation !== "idle") return;
    if (
      dirty &&
      !window.confirm(
        "恢复最近审阅将丢弃当前所有尚未保存的材料与风险审阅草稿。确定继续吗？",
      )
    ) {
      setNotice("已取消切换代次；当前未保存草稿保持不变。");
      return;
    }
    const redactionId = latestRedactionId ?? selectedRedactionId;
    if (!redactionId) {
      setNotice("当前材料尚无可恢复的脱敏代次。");
      return;
    }
    void loadReview(
      redactionId,
      "已恢复当前材料的最近脱敏代次。",
    );
  }, [
    dirty,
    disabled,
    latestRedactionId,
    loadReview,
    operation,
    selectedRedactionId,
  ]);

  const editPage = useCallback(
    (pageNumber: number, value: string) => {
      setEditedPages((current) =>
        current.map((page) =>
          page.pageNumber === pageNumber
            ? { ...page, redactedText: value }
            : page,
        ),
      );
      setApproval(null);
      setNotice("");
    },
    [],
  );

  const applyRiskAction = useCallback(
    async (action: PrivacyRiskReviewAction) => {
      if (
        disabled ||
        operation !== "idle" ||
        !review?.riskReview
      ) {
        return false;
      }
      const actor = approvalDraft.reviewer.trim();
      if (!actor || actor.length > 128) {
        setError(
          "执行风险审阅动作前必须填写不超过 128 个字符的批准人。",
        );
        return false;
      }
      begin("risk_review");
      let persisted = false;
      try {
        const nextReview =
          await applyCaseRedactionRiskReviewAction({
            projectId,
            redactionId: review.redactionId,
            expectedRevision: review.riskReview.revision,
            actor,
            editedPages,
            action,
          });
        installReview(nextReview, "risk_action", {
          approvalDraft,
        });
        persisted = true;
        await onReviewChanged(
          nextReview.materialId,
          nextReview.redactionId,
        );
        setNotice(
          "风险动作、脱敏页与 append-only revision 已在当前案件原子保存。",
        );
        return true;
      } catch (reason: unknown) {
        setError(displayError(reason));
        return persisted;
      } finally {
        finish();
      }
    },
    [
      approvalDraft,
      begin,
      disabled,
      editedPages,
      finish,
      installReview,
      onReviewChanged,
      operation,
      projectId,
      review,
    ],
  );

  const undoRisk = useCallback(async () => {
    if (
      disabled ||
      operation !== "idle" ||
      !review?.riskReview
    ) {
      return;
    }
    const riskReview = review.riskReview;
    let started = false;
    try {
      const guarded =
        await executeCaseRedactionHistoryIfClean(
          dirty,
          async () => {
            started = true;
            begin("risk_review");
            return undoCaseRedactionRiskReview({
              projectId,
              redactionId: review.redactionId,
              expectedRevision: riskReview.revision,
            });
          },
        );
      if (!guarded.executed) {
        setError(
          "当前案件材料或风险审阅仍有未保存草稿；撤销已阻断。",
        );
        return;
      }
      const nextReview = guarded.value;
      installReview(nextReview, "risk_history");
      await onReviewChanged(
        nextReview.materialId,
        nextReview.redactionId,
      );
      setNotice("已撤销上一项风险审阅动作。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      if (started) finish();
    }
  }, [
    begin,
    disabled,
    dirty,
    finish,
    installReview,
    onReviewChanged,
    operation,
    projectId,
    review,
  ]);

  const redoRisk = useCallback(async () => {
    if (
      disabled ||
      operation !== "idle" ||
      !review?.riskReview
    ) {
      return;
    }
    const riskReview = review.riskReview;
    let started = false;
    try {
      const guarded =
        await executeCaseRedactionHistoryIfClean(
          dirty,
          async () => {
            started = true;
            begin("risk_review");
            return redoCaseRedactionRiskReview({
              projectId,
              redactionId: review.redactionId,
              expectedRevision: riskReview.revision,
            });
          },
        );
      if (!guarded.executed) {
        setError(
          "当前案件材料或风险审阅仍有未保存草稿；重做已阻断。",
        );
        return;
      }
      const nextReview = guarded.value;
      installReview(nextReview, "risk_history");
      await onReviewChanged(
        nextReview.materialId,
        nextReview.redactionId,
      );
      setNotice("已重做风险审阅动作。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      if (started) finish();
    }
  }, [
    begin,
    disabled,
    dirty,
    finish,
    installReview,
    onReviewChanged,
    operation,
    projectId,
    review,
  ]);

  const approve = useCallback(async () => {
    if (disabled || operation !== "idle" || !review) return;
    if (riskDraftDirty) {
      setError(
        "风险审阅面板仍有尚未提交的草稿；请先提交或撤销这些编辑，再批准当前代次。",
      );
      return;
    }
    if (!review.riskReview?.detectorRunCompleted) {
      setError("风险 revision 或真实检测完成证据缺失；批准已阻断。");
      return;
    }
    const blockingGate = review.riskReview.hardGates.find(
      (gate) =>
        gate.blocking &&
        !gate.passed &&
        ![
          "calibrated_policy",
          "approval_mode_allows_automatic",
          "organization_policy_allows_automatic",
          "publication_target_fixed",
        ].includes(gate.gateId),
    );
    if (blockingGate) {
      setError(
        `风险硬闸门 ${blockingGate.gateId} 未通过；批准已阻断。`,
      );
      return;
    }
    let ttlSeconds: number;
    try {
      ttlSeconds = validateApprovalDraft(approvalDraft);
      if (
        editedPages.length !== review.pages.length ||
        editedPages.some(
          (page) => !Number.isSafeInteger(page.pageNumber),
        )
      ) {
        throw new Error("必须提交全部页/段的脱敏文本。");
      }
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("approving");
    try {
      const response = await approveCaseRedactionReview({
        projectId,
        redactionId: review.redactionId,
        expectedRiskRevision: review.riskReview.revision,
        expectedSuggestedRedactedSha256:
          review.suggestedRedactedContentSha256,
        editedPages,
        reviewer: approvalDraft.reviewer.trim(),
        destination: localSafeExportScope(
          approvalDraft.target,
        ).destination,
        purpose: localSafeExportScope(approvalDraft.target).purpose,
        ttlSeconds,
      });
      if (!approvalMatchesTarget(response, approvalDraft.target)) {
        throw new Error("后端签发的回执目标与所选本机格式不一致。");
      }
      setDraftBaseline((current) => {
        const next = cloneCaseRedactionDraftSnapshot(current);
        next.editedPages = editedPages.map((page) => ({
          ...page,
        }));
        next.approvalDraft = {
          ...approvalDraft,
          target: { ...approvalDraft.target },
        };
        return next;
      });
      const refreshed = await loadCaseRedactionReview({
        projectId,
        redactionId: review.redactionId,
      });
      installReview(refreshed, "approval", {
        approvalDraft,
      });
      setApproval(response);
      await onReviewChanged(
        refreshed.materialId,
        refreshed.redactionId,
      );
      setNotice(
        `已为 ${localSafeExportScope(approvalDraft.target).label} 复检并签发精确目标回执；尚未执行任何外发。`,
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
    installReview,
    onReviewChanged,
    operation,
    projectId,
    review,
    riskDraftDirty,
  ]);

  const exportArtifact = useCallback(async () => {
    if (
      disabled ||
      operation !== "idle" ||
      !review ||
      !approval ||
      !approvalMatchesTarget(approval, approvalDraft.target)
    ) {
      return;
    }
    const scope = localSafeExportScope(approvalDraft.target);
    begin("exporting");
    try {
      const response = await exportApprovedCaseRedaction({
        projectId,
        redactionId: review.redactionId,
        format: approvalDraft.target.format,
      });
      setNotice(
        response.cancelled
          ? `已取消保存；没有写入 ${scope.label}。`
          : `已安全保存 ${response.fileName ?? scope.label}（产物 SHA-256 ${response.artifactSha256 ?? "未返回"}）。`,
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    approval,
    approvalDraft,
    begin,
    disabled,
    finish,
    operation,
    projectId,
    review,
  ]);

  const deleteCurrentReview = useCallback(async () => {
    if (disabled || operation !== "idle" || !review) return;
    if (!window.confirm(PRIVACY_REVIEW_DELETION_CONFIRMATION)) {
      setNotice("已取消删除；本机复核数据与回执保持不变。");
      return;
    }
    begin("deleting");
    try {
      const response = await deleteCaseRedactionReview({
        projectId,
        redactionId: review.redactionId,
        expectedSourceSha256: review.sourceSha256,
        expectedExtractionSha256: review.extractionSha256,
      });
      const materialId = review.materialId;
      const nextApprovalDraft = defaultApprovalDraft();
      setReview(null);
      loadedRedactionId.current = null;
      setCustomTerms("");
      setEditedPages([]);
      setApprovalDraft(nextApprovalDraft);
      setApproval(null);
      setRiskDraftDirty(false);
      setRiskDraftContextKey((current) => current + 1);
      setDraftBaseline({
        customTerms: "",
        editedPages: [],
        approvalDraft: nextApprovalDraft,
      });
      await onReviewChanged(materialId, null);
      setNotice(
        response.deleted
          ? "已将材料标记为已删除，并撤销全部脱敏代次、回执、发布与派生工作能力；版本和审计历史已保留。"
          : "该复核记录已不存在；当前界面已清空。",
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    begin,
    disabled,
    finish,
    onReviewChanged,
    operation,
    projectId,
    review,
  ]);

  const updateApprovalDraft = useCallback((next: ApprovalDraft) => {
    setApprovalDraft(next);
    setApproval(null);
    setNotice("");
  }, []);

  const updateCustomTerms = useCallback((value: string) => {
    setCustomTerms(value);
    setNotice("");
  }, []);

  return (
    <div className="case-redaction-workbench">
      <div className="case-redaction-context" role="note">
        <strong>案件归属</strong>
        <code>{projectId}</code>
        {review ? (
          <span>
            材料 {review.materialId} · 第 {review.generationNumber} 代
          </span>
        ) : null}
      </div>
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
        riskDraftContextKey={riskDraftContextKey}
        riskDraftDirty={riskDraftDirty}
        riskHistoryActionsDisabled={dirty}
        onCustomTermsChange={updateCustomTerms}
        onChooseMaterial={() => void chooseMaterial()}
        onLoadLatest={loadLatest}
        onDelete={() => void deleteCurrentReview()}
        onEditedPageChange={editPage}
        onRiskAction={applyRiskAction}
        onRiskDraftDirtyChange={setRiskDraftDirty}
        onRiskUndo={() => void undoRisk()}
        onRiskRedo={() => void redoRisk()}
        onApprovalDraftChange={updateApprovalDraft}
        onApprove={() => void approve()}
        onExport={() => void exportArtifact()}
      />
    </div>
  );
}
