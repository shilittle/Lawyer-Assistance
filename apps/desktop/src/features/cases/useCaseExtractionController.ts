import {
  type Dispatch,
  type MutableRefObject,
  type SetStateAction,
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from "react";

import {
  confirmStructuredCaseExtraction,
  discardStructuredCaseExtraction,
  getPendingStructuredCaseExtraction,
  updatePendingStructuredCaseExtraction,
} from "../../ipc/case/client";
import {
  buildConfirmationRequest,
  createExtractionContext,
  drainPendingExtractionSaves,
  extractionLocksSources,
  extractionMutationBlocksClose,
  extractionReducer,
  extractionReviewNeedsCloseFlush,
  pendingExtractionUpdateAtRevision,
  structuredCaseExtractionIsPublic,
} from "../../ipc/case/extractionReview";
import type { PendingExtractionDraftSaveRequest } from "../../ipc/case/extractionReview";
import type {
  CaseWorkspace,
  StructuredCaseExtraction,
} from "../../ipc/case/types";
import { publicErrorMessage } from "../../publicOutput";
import type { CaseDraftKind } from "../../app/navigationGuards";
import {
  createId,
  extractionReviewDiscardConfirmation,
  isCurrentCaseWorkspaceEpoch,
  pendingReviewFilesStillExist,
  unrestorableExtractionDiscardConfirmation,
  type ExtractionDraftSaveState,
  type MutableEpoch,
  type PendingReviewRecoveryBlock,
  type QueuedExtractionDraftSave,
} from "./model";
import {
  createCaseCloseGuard,
  type CaseCloseGuardPort,
} from "./caseCloseGuard";
import type { CaseLoadState } from "./useCaseWorkspaceController";

export interface CaseExtractionWorkspacePort {
  selectedProjectIdRef: MutableRefObject<string | null>;
  workspaceEpoch: MutableEpoch;
  setCaseState: Dispatch<SetStateAction<CaseLoadState>>;
  setWorkspaceWriteBlocked: Dispatch<SetStateAction<boolean>>;
  beginCaseMutation: (allowDuringExtraction?: boolean) => number | null;
  finishCaseMutation: () => void;
  caseMutationIsLocked: () => boolean;
  readDirtyCaseDrafts: () => readonly CaseDraftKind[];
  blockWorkspaceReloadForDirtyDrafts: (
    allowed: readonly CaseDraftKind[],
    action: string,
  ) => boolean;
  loadCaseWorkspace: (
    projectId: string,
    requestEpoch: number,
    recoverAfterPersistedMutation?: boolean,
  ) => Promise<boolean>;
}

export interface UseCaseExtractionControllerOptions {
  workspace: CaseExtractionWorkspacePort;
  confirmAction: (message: string) => boolean;
}

function errorMessage(error: unknown): string {
  return publicErrorMessage(error);
}

async function runConfirmedAction<T>(
  message: string,
  confirmAction: (message: string) => boolean,
  action: () => Promise<T>,
): Promise<{ executed: false } | { executed: true; value: T }> {
  if (!confirmAction(message)) {
    return { executed: false };
  }
  return { executed: true, value: await action() };
}

export function useCaseExtractionController({
  workspace,
  confirmAction,
}: UseCaseExtractionControllerOptions) {
  const [providerId, setProviderId] = useState("");
  const [fileIds, setFileIds] = useState<string[]>([]);
  const [state, dispatch] = useReducer(extractionReducer, {
    kind: "idle",
  });
  const stateRef = useRef(state);
  stateRef.current = state;
  const [confirmPreparing, setConfirmPreparing] = useState(false);
  const confirmInFlight = useRef(false);
  const [discarding, setDiscarding] = useState(false);
  const discardInFlight = useRef(false);
  const [discardError, setDiscardError] = useState<string | null>(null);
  const [draftSaveState, setDraftSaveState] =
    useState<ExtractionDraftSaveState>({ kind: "idle" });
  const pendingDraftSave = useRef<QueuedExtractionDraftSave | null>(null);
  const draftSaveTimer = useRef<number | null>(null);
  const draftSavePromise = useRef<Promise<boolean>>(Promise.resolve(true));
  const draftSaveSession = useRef(0);
  const draftSaveSequence = useRef(0);
  const draftSavedSequence = useRef(0);
  const serverRevision = useRef<number | null>(null);
  const reviewReloadRequired = useRef(false);
  const lifecycleLock = useRef(false);
  const closeInProgress = useRef(false);
  const [closePreparing, setClosePreparing] = useState(false);
  const [pendingReviewRecoveryBlock, setPendingReviewRecoveryBlock] =
    useState<PendingReviewRecoveryBlock | null>(null);
  const reviewRef = useRef<HTMLDivElement | null>(null);
  const reviewReturnFocusRef = useRef<HTMLElement | null>(null);
  const sourcesLocked = extractionLocksSources(state);

  function clearDraftSaveTimer() {
    if (draftSaveTimer.current !== null) {
      window.clearTimeout(draftSaveTimer.current);
      draftSaveTimer.current = null;
    }
  }

  function beginDraftSaveSession(
    initial: ExtractionDraftSaveState = { kind: "idle" },
    initialServerRevision: number | null = null,
  ) {
    draftSaveSession.current += 1;
    draftSaveSequence.current = 0;
    draftSavedSequence.current = 0;
    serverRevision.current = initialServerRevision;
    reviewReloadRequired.current = false;
    clearDraftSaveTimer();
    pendingDraftSave.current = null;
    draftSavePromise.current = Promise.resolve(true);
    setDraftSaveState(initial);
  }

  function lockReviewForServerReload(message: string) {
    reviewReloadRequired.current = true;
    clearDraftSaveTimer();
    pendingDraftSave.current = null;
    setDraftSaveState({
      kind: "conflict",
      message: `${message} 已锁定本窗口的编辑、确认和取消操作；请重新加载最新草稿后核对。`,
    });
  }

  async function persistDraft(
    queued: QueuedExtractionDraftSave,
    session: number,
  ): Promise<boolean> {
    if (draftSaveSession.current !== session || reviewReloadRequired.current) {
      return false;
    }
    const expectedRevision = serverRevision.current;
    if (expectedRevision === null) {
      if (draftSaveSession.current === session) {
        lockReviewForServerReload("待审阅草稿缺少可核对的版本信息。");
      }
      return false;
    }
    try {
      const response = await updatePendingStructuredCaseExtraction(
        pendingExtractionUpdateAtRevision(queued.request, expectedRevision),
      );
      if (
        !response.updated ||
        !Number.isSafeInteger(response.revision) ||
        response.revision !== expectedRevision + 1
      ) {
        throw new Error("审阅草稿的保存结果不连续");
      }
      if (draftSaveSession.current === session) {
        draftSavedSequence.current = Math.max(
          draftSavedSequence.current,
          queued.sequence,
        );
        serverRevision.current = response.revision;
        dispatch({
          type: "saved",
          reviewId: queued.request.reviewId,
          revision: response.revision,
          expiresAt: response.expiresAt,
        });
        if (pendingDraftSave.current) {
          setDraftSaveState({ kind: "pending" });
        } else if (queued.sequence === draftSaveSequence.current) {
          setDraftSaveState({
            kind: "saved",
            expiresAt: response.expiresAt,
          });
        }
      }
      return true;
    } catch (error: unknown) {
      if (draftSaveSession.current === session) {
        lockReviewForServerReload(
          `审阅修改的保存结果无法安全确认：${errorMessage(error)}`,
        );
      }
      return false;
    }
  }

  function enqueueDraftSave(
    queued: QueuedExtractionDraftSave,
  ): Promise<boolean> {
    const session = draftSaveSession.current;
    const operation = draftSavePromise.current.then(() =>
      persistDraft(queued, session),
    );
    draftSavePromise.current = operation;
    return operation;
  }

  async function flushPendingDraftSave(): Promise<boolean> {
    if (reviewReloadRequired.current) {
      return false;
    }
    clearDraftSaveTimer();
    return drainPendingExtractionSaves({
      targetSequence: () => draftSaveSequence.current,
      isBlocked: () => reviewReloadRequired.current,
      savedSequence: () => draftSavedSequence.current,
      hasPending: () => pendingDraftSave.current !== null,
      takePending: () => {
        clearDraftSaveTimer();
        const queued = pendingDraftSave.current;
        pendingDraftSave.current = null;
        return queued;
      },
      waitForCurrent: () => draftSavePromise.current,
      enqueue: (queued) => {
        setDraftSaveState({ kind: "saving" });
        return enqueueDraftSave(queued);
      },
    });
  }

  function scheduleDraftSave(request: PendingExtractionDraftSaveRequest) {
    if (
      reviewReloadRequired.current ||
      closeInProgress.current ||
      confirmInFlight.current ||
      discardInFlight.current
    ) {
      return;
    }
    draftSaveSequence.current += 1;
    pendingDraftSave.current = {
      request,
      sequence: draftSaveSequence.current,
    };
    clearDraftSaveTimer();
    setDraftSaveState({ kind: "pending" });
    draftSaveTimer.current = window.setTimeout(() => {
      draftSaveTimer.current = null;
      void flushPendingDraftSave();
    }, 400);
  }

  useEffect(() => {
    if (state.kind !== "reviewing") {
      return;
    }
    const frame = requestAnimationFrame(() => reviewRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [state.kind]);

  useEffect(
    () => () => {
      clearDraftSaveTimer();
    },
    [],
  );

  function syncWorkspaceFiles(caseWorkspace: CaseWorkspace) {
    const availableFileIds = new Set(
      caseWorkspace.files.map((file) => file.fileId),
    );
    setFileIds((current) =>
      current.filter((fileId) => availableFileIds.has(fileId)),
    );
  }

  async function restorePendingReview(
    caseWorkspace: CaseWorkspace,
    requestEpoch: number,
  ): Promise<string | null> {
    setPendingReviewRecoveryBlock(null);
    const active = stateRef.current;
    if (
      (active.kind === "generating" ||
        active.kind === "reviewing" ||
        active.kind === "committing") &&
      active.context.projectId === caseWorkspace.project.projectId
    ) {
      return null;
    }

    lifecycleLock.current = false;
    setDiscardError(null);
    dispatch({ type: "reset" });
    beginDraftSaveSession();
    try {
      const response = await getPendingStructuredCaseExtraction({
        projectId: caseWorkspace.project.projectId,
      });
      if (
        !isCurrentCaseWorkspaceEpoch(
          workspace.workspaceEpoch,
          requestEpoch,
        )
      ) {
        return null;
      }
      const pending = response.pending ?? null;
      if (!pending) {
        return null;
      }
      if (pending.projectId !== caseWorkspace.project.projectId) {
        return "待恢复抽取审阅的案件归属不匹配，已拒绝载入。";
      }
      if (!Number.isSafeInteger(pending.revision) || pending.revision < 0) {
        return "待恢复草稿缺少有效的版本信息，已拒绝载入。";
      }
      if (!pending.providerSnapshot) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message:
            "待恢复抽取审阅缺少可信的生成配置快照，只能永久放弃，不能确认写入。",
        });
        return "待恢复抽取审阅缺少可信的生成配置快照，已拒绝载入。";
      }
      if (!structuredCaseExtractionIsPublic(pending.extraction)) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message: "待恢复内容未通过安全检查，只能放弃后重新整理。",
        });
        return "待恢复内容未通过安全检查，已拒绝载入。";
      }

      const workspaceFileIds = caseWorkspace.files.map((file) => file.fileId);
      if (!pendingReviewFilesStillExist(workspaceFileIds, pending.fileIds)) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message: "待恢复抽取审阅引用的案件材料已变化，不能安全确认。",
        });
        return "待恢复抽取审阅引用的案件材料已变化，已拒绝自动载入。";
      }
      const restorableFileIds = [...pending.fileIds];
      const context = createExtractionContext(
        createId("extraction-restore"),
        pending.projectId,
        pending.providerId,
        restorableFileIds,
        pending.providerSnapshot,
      );
      setProviderId(pending.providerId);
      setFileIds(restorableFileIds);
      lifecycleLock.current = true;
      beginDraftSaveSession(
        {
          kind: "saved",
          expiresAt: pending.expiresAt,
        },
        pending.revision,
      );
      dispatch({
        type: "restore",
        context,
        reviewId: pending.reviewId,
        draft: pending.extraction,
        revision: pending.revision,
        createdAt: pending.createdAt,
        expiresAt: pending.expiresAt,
      });
      return null;
    } catch (error: unknown) {
      return `未能恢复待审阅的材料整理结果：${errorMessage(error)}`;
    }
  }

  function resetForNewProject() {
    lifecycleLock.current = false;
    setFileIds([]);
    setDiscardError(null);
    beginDraftSaveSession();
    dispatch({ type: "reset" });
  }

  function updateDraft(
    update: (draft: StructuredCaseExtraction) => StructuredCaseExtraction,
  ) {
    if (
      state.kind === "reviewing" &&
      !reviewReloadRequired.current &&
      !closeInProgress.current &&
      !confirmInFlight.current &&
      !discardInFlight.current
    ) {
      const draft = update(state.draft);
      if (!structuredCaseExtractionIsPublic(draft)) {
        workspace.setCaseState({
          kind: "error",
          message: "该内容不适合写入案件业务字段，请删除其中的系统信息后重试。",
        });
        return;
      }
      dispatch({
        type: "edit",
        draft,
      });
      scheduleDraftSave({
        reviewId: state.reviewId,
        projectId: state.context.projectId,
        providerId: state.context.providerId,
        fileIds: [...state.context.sourceFileIds],
        extraction: draft,
      });
    }
  }

  async function cancelReview() {
    if (
      state.kind !== "reviewing" ||
      confirmPreparing ||
      confirmInFlight.current ||
      discardInFlight.current ||
      closeInProgress.current ||
      workspace.caseMutationIsLocked() ||
      reviewReloadRequired.current
    ) {
      return;
    }

    const reviewId = state.reviewId;
    const permission = await runConfirmedAction(
      extractionReviewDiscardConfirmation(),
      confirmAction,
      async () => {
        if (
          discardInFlight.current ||
          confirmInFlight.current ||
          closeInProgress.current
        ) {
          return false;
        }
        discardInFlight.current = true;
        setDiscarding(true);
        setDiscardError(null);
        return true;
      },
    );
    if (!permission.executed || !permission.value) {
      return;
    }
    try {
      clearDraftSaveTimer();
      pendingDraftSave.current = null;
      await draftSavePromise.current;
      if (reviewReloadRequired.current) {
        return;
      }
      const expectedRevision = serverRevision.current;
      if (expectedRevision === null) {
        lockReviewForServerReload("取消前无法确认待审草稿的最新状态。");
        return;
      }
      const response = await discardStructuredCaseExtraction({
        reviewId,
        projectId: state.context.projectId,
        expectedRevision,
      });
      if (!response.discarded) {
        lockReviewForServerReload(
          "草稿已被其他窗口更新或处理，取消结果未生效。",
        );
        return;
      }
      lifecycleLock.current = false;
      beginDraftSaveSession();
      dispatch({ type: "cancel" });
      requestAnimationFrame(() => reviewReturnFocusRef.current?.focus());
    } catch (error: unknown) {
      const message = errorMessage(error);
      lockReviewForServerReload(`取消请求的结果无法安全确认：${message}`);
      setDiscardError(`取消结果不明确，不能继续操作该草稿：${message}`);
      workspace.setCaseState({ kind: "error", message });
    } finally {
      discardInFlight.current = false;
      setDiscarding(false);
    }
  }

  async function discardUnrestorablePendingReview() {
    const blocked = pendingReviewRecoveryBlock;
    if (!blocked || discardInFlight.current) {
      return;
    }
    const permission = await runConfirmedAction(
      unrestorableExtractionDiscardConfirmation(),
      confirmAction,
      async () => {
        if (
          discardInFlight.current ||
          confirmInFlight.current ||
          closeInProgress.current
        ) {
          return false;
        }
        discardInFlight.current = true;
        setDiscarding(true);
        return true;
      },
    );
    if (!permission.executed || !permission.value) {
      return;
    }
    try {
      const response = await discardStructuredCaseExtraction({
        reviewId: blocked.reviewId,
        projectId: blocked.projectId,
        expectedRevision: blocked.revision,
      });
      if (!response.discarded) {
        setPendingReviewRecoveryBlock({
          ...blocked,
          reloadRequired: true,
          message:
            "草稿已被其他窗口更新或处理，本窗口不能按旧内容放弃。",
        });
        return;
      }
      if (workspace.selectedProjectIdRef.current === blocked.projectId) {
        setPendingReviewRecoveryBlock(null);
        workspace.setWorkspaceWriteBlocked(false);
        workspace.setCaseState({ kind: "idle" });
      }
    } catch (error: unknown) {
      setPendingReviewRecoveryBlock({
        ...blocked,
        reloadRequired: true,
        message: `放弃请求的结果无法安全确认：${errorMessage(error)}`,
      });
      workspace.setCaseState({
        kind: "error",
        message: `无法放弃不兼容的抽取审阅：${errorMessage(error)}`,
      });
    } finally {
      discardInFlight.current = false;
      setDiscarding(false);
    }
  }

  async function reloadServerDraft(projectId: string) {
    if (
      workspace.selectedProjectIdRef.current !== projectId ||
      discardInFlight.current ||
      confirmInFlight.current ||
      confirmPreparing
    ) {
      return;
    }
    const requestEpoch = workspace.beginCaseMutation(true);
    if (requestEpoch === null) {
      return;
    }

    lifecycleLock.current = false;
    setDiscardError(null);
    setPendingReviewRecoveryBlock(null);
    beginDraftSaveSession();
    dispatch({ type: "reset" });
    try {
      await workspace.loadCaseWorkspace(projectId, requestEpoch);
    } finally {
      workspace.finishCaseMutation();
    }
  }

  function resetResult() {
    if (state.kind === "failed" || state.kind === "committed") {
      lifecycleLock.current = false;
      setDiscardError(null);
      beginDraftSaveSession();
      dispatch({ type: "reset" });
    }
  }

  async function confirmReview() {
    if (
      confirmPreparing ||
      confirmInFlight.current ||
      buildConfirmationRequest(state) === null ||
      discardInFlight.current ||
      closeInProgress.current ||
      reviewReloadRequired.current
    ) {
      return;
    }
    if (
      workspace.blockWorkspaceReloadForDirtyDrafts(
        [],
        "确认材料整理结果",
      )
    ) {
      return;
    }
    confirmInFlight.current = true;
    setConfirmPreparing(true);
    let mutationStarted = false;
    try {
      if (!(await flushPendingDraftSave())) {
        workspace.setCaseState({
          kind: "error",
          message:
            "审阅修改尚未安全保存，已阻止确认写入。请重试自动保存后再确认。",
        });
        return;
      }
      const confirmation = buildConfirmationRequest(stateRef.current);
      if (!confirmation) {
        return;
      }
      const expectedRevision = serverRevision.current;
      if (expectedRevision === null) {
        lockReviewForServerReload("确认前无法确认待审草稿的最新状态。");
        return;
      }
      confirmation.expectedRevision = expectedRevision;
      const requestEpoch = workspace.beginCaseMutation(true);
      if (requestEpoch === null) {
        return;
      }
      mutationStarted = true;
      setDiscardError(null);
      dispatch({ type: "begin_commit" });
      let response: Awaited<
        ReturnType<typeof confirmStructuredCaseExtraction>
      >;
      try {
        response = await confirmStructuredCaseExtraction(confirmation);
      } catch (error: unknown) {
        const message = errorMessage(error);
        dispatch({ type: "commit_failed", message });
        lockReviewForServerReload(`确认请求的结果无法安全确认：${message}`);
        workspace.setCaseState({ kind: "error", message });
        return;
      }
      if (!response.applied) {
        const message = "当前无法确认写入结果。";
        dispatch({ type: "commit_failed", message });
        lockReviewForServerReload(message);
        return;
      }

      lifecycleLock.current = false;
      beginDraftSaveSession();
      const workspaceReloaded = await workspace.loadCaseWorkspace(
        confirmation.projectId,
        requestEpoch,
        true,
      );
      dispatch({
        type: "committed",
        message: workspaceReloaded
          ? `已保存 ${response.counts.facts} 项事实、${response.counts.evidence} 项证据和 ${response.counts.uncertainties} 项待核实事项。`
          : "审阅结果已保存，但案件内容暂未刷新。为避免重复保存，确认按钮已停用，请重新加载当前案件。",
      });
      requestAnimationFrame(() => reviewReturnFocusRef.current?.focus());
    } finally {
      if (mutationStarted) {
        workspace.finishCaseMutation();
      }
      confirmInFlight.current = false;
      setConfirmPreparing(false);
    }
  }

  const closeGuardRef = useRef<CaseCloseGuardPort | null>(null);
  if (!closeGuardRef.current) {
    closeGuardRef.current = createCaseCloseGuard({
      readSnapshot: () => ({
        dirtyDrafts: workspace.readDirtyCaseDrafts(),
        caseMutationInFlight: workspace.caseMutationIsLocked(),
        extractionMutationInFlight: extractionMutationBlocksClose(
          confirmInFlight.current,
          discardInFlight.current,
        ),
        extractionNeedsFlush: extractionReviewNeedsCloseFlush(
          stateRef.current,
          draftSavedSequence.current,
          draftSaveSequence.current,
          pendingDraftSave.current !== null,
        ),
        extractionCloseInProgress: closeInProgress.current,
      }),
      flushPendingDraft: flushPendingDraftSave,
      beginControlledClose: (needsFlush) => {
        closeInProgress.current = true;
        setClosePreparing(needsFlush);
      },
      finishBlockedClose: () => {
        closeInProgress.current = false;
        setClosePreparing(false);
      },
    });
  }

  function interactionIsLocked(): boolean {
    return lifecycleLock.current || discardInFlight.current;
  }

  function blocksCaseMutation(allowDuringExtraction: boolean): boolean {
    return (
      (!allowDuringExtraction && lifecycleLock.current) ||
      discardInFlight.current
    );
  }

  const selectInitialProvider = useCallback((selectedProviderId: string) => {
    setProviderId(selectedProviderId);
  }, []);

  const handleProviderSaved = useCallback((savedProviderId: string) => {
    setProviderId((current) => current || savedProviderId);
  }, []);

  const handleProviderDeleted = useCallback(
    (deletedProviderId: string, fallbackProviderId: string | null) => {
      if (fallbackProviderId) {
        setProviderId((current) =>
          current === deletedProviderId ? fallbackProviderId : current,
        );
      } else {
        setProviderId("");
      }
    },
    [],
  );

  const deletionBlockedProviderId =
    sourcesLocked && "context" in state ? state.context.providerId : null;

  return {
    providerId,
    setProviderId,
    fileIds,
    setFileIds,
    state,
    confirmPreparing,
    discarding,
    discardError,
    draftSaveState,
    reviewReloadRequired,
    closePreparing,
    pendingReviewRecoveryBlock,
    reviewRef,
    reviewReturnFocusRef,
    sourcesLocked,
    deletionBlockedProviderId,
    closeGuard: closeGuardRef.current,
    syncWorkspaceFiles,
    restorePendingReview,
    resetForNewProject,
    updateDraft,
    cancelReview,
    discardUnrestorablePendingReview,
    reloadServerDraft,
    resetResult,
    confirmReview,
    interactionIsLocked,
    blocksCaseMutation,
    selectInitialProvider,
    handleProviderSaved,
    handleProviderDeleted,
  };
}

export type CaseExtractionController = ReturnType<
  typeof useCaseExtractionController
>;
