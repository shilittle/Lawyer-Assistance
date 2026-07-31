import {
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  CASE_DRAFT_LABELS,
  canBypassDirtyDraftsForWorkspaceRecovery,
  type CaseDraftKind,
} from "../../app/navigationGuards";
import {
  addCaseLegalBasis,
  deleteCaseEntity,
  deleteCaseProject,
  getCaseWorkspace,
  listCaseProjects,
  upsertCaseFact,
  upsertCaseFile,
  upsertCaseParty,
  upsertCaseProject,
  upsertEvidenceItem,
  upsertEvidenceLink,
  upsertFactIssueLink,
  upsertLegalIssue,
} from "../../ipc/case/client";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  EvidenceItem,
  LegalIssue,
} from "../../ipc/case/types";
import { publicErrorMessage, publicTitle } from "../../publicOutput";
import {
  advanceCaseWorkspaceEpoch,
  blockingDirtyCaseDrafts,
  caseEntityDeletionConfirmation,
  caseEntityDeletionDisplayName,
  caseEntityEditorMatches,
  caseProjectDeletionConfirmation,
  caseProjectPageForId,
  caseProjectToLoadAfterRefresh,
  caseWorkspaceWritesAreSafe,
  copyCaseEntityForEditing,
  createCaseFile,
  createCaseProject,
  createEvidence,
  createFact,
  createId,
  createIssue,
  createParty,
  detectDirtyCaseDrafts,
  isCurrentCaseWorkspaceEpoch,
  paginateCaseProjects,
  publicCaseBusinessText,
  publicEvidenceNumber,
  releaseCaseMutation,
  tryAcquireCaseMutation,
  validateFactIssueLinkSelection,
  type ActiveCaseEntityEditor,
  type CaseDraftDirtyState,
  type CaseEntityEditTarget,
  type DeletableCaseEntityType,
  type EditableCaseEntityType,
} from "./model";
import { useCaseExtractionController } from "./useCaseExtractionController";

export type CaseLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string };

export interface UseCaseWorkspaceControllerOptions {
  confirmAction?: (message: string) => boolean;
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

export function useCaseWorkspaceController({
  confirmAction = (message) => window.confirm(message),
}: UseCaseWorkspaceControllerOptions = {}) {
  const [caseState, setCaseState] = useState<CaseLoadState>({ kind: "idle" });
  const [caseProjects, setCaseProjects] = useState<CaseProject[]>([]);
  const [caseProjectPage, setCaseProjectPage] = useState(1);
  const [selectedCaseProjectId, setSelectedCaseProjectId] = useState<
    string | null
  >(null);
  const selectedCaseProjectIdRef = useRef<string | null>(null);
  selectedCaseProjectIdRef.current = selectedCaseProjectId;
  const [caseWorkspace, setCaseWorkspace] = useState<CaseWorkspace | null>(
    null,
  );
  const [caseWorkspaceWriteBlocked, setCaseWorkspaceWriteBlocked] =
    useState(false);
  const persistedMutationRecoveryProjectId = useRef<string | null>(null);
  const dirtyCaseDraftsForClose = useRef<CaseDraftKind[]>([]);
  const [caseValidationTargetId, setCaseValidationTargetId] = useState<
    string | null
  >(null);
  const caseWorkspaceEpoch = useRef(0);
  const caseMutationLock = useRef(false);
  const [caseMutationInFlight, setCaseMutationInFlight] = useState(false);
  const [activeCaseEntityEditor, setActiveCaseEntityEditor] =
    useState<ActiveCaseEntityEditor | null>(null);
  const [caseProjectDraft, setCaseProjectDraft] = useState<CaseProject>(() =>
    createCaseProject(),
  );
  const caseProjectDraftBaseline = useRef(caseProjectDraft);
  const [fileDraft, setFileDraft] = useState<CaseFile>(() =>
    createCaseFile(caseProjectDraft.projectId),
  );
  const [partyDraft, setPartyDraft] = useState<CaseParty>(() =>
    createParty(caseProjectDraft.projectId),
  );
  const [factDraft, setFactDraft] = useState<CaseFact>(() =>
    createFact(caseProjectDraft.projectId),
  );
  const [evidenceDraft, setEvidenceDraft] = useState<EvidenceItem>(() =>
    createEvidence(caseProjectDraft.projectId, 1),
  );
  const [issueDraft, setIssueDraft] = useState<LegalIssue>(() =>
    createIssue(caseProjectDraft.projectId),
  );
  const [basisSourceId, setBasisSourceId] = useState("");
  const [basisIssueId, setBasisIssueId] = useState("");
  const [basisCaseDate, setBasisCaseDate] = useState("");
  const [basisIncludeExpired, setBasisIncludeExpired] = useState(false);
  const [basisNote, setBasisNote] = useState("");
  const [linkFactId, setLinkFactId] = useState("");
  const [linkEvidenceId, setLinkEvidenceId] = useState("");
  const [factIssueFactId, setFactIssueFactId] = useState("");
  const [factIssueIssueId, setFactIssueIssueId] = useState("");

  function beginCaseMutation(allowDuringExtraction = false): number | null {
    if (extraction.blocksCaseMutation(allowDuringExtraction)) {
      return null;
    }
    const requestEpoch = tryAcquireCaseMutation(
      caseMutationLock,
      caseWorkspaceEpoch,
    );
    if (requestEpoch !== null) {
      setCaseMutationInFlight(true);
    }
    return requestEpoch;
  }

  function finishCaseMutation() {
    releaseCaseMutation(caseMutationLock);
    setCaseMutationInFlight(false);
  }

  function caseInteractionIsLocked(): boolean {
    return caseMutationLock.current || extraction.interactionIsLocked();
  }

  function focusElement(elementId: string) {
    requestAnimationFrame(() => {
      document.getElementById(elementId)?.focus();
    });
  }

  function showCaseValidationError(message: string, elementId: string) {
    setCaseValidationTargetId(elementId);
    setCaseState({ kind: "error", message });
    focusElement(elementId);
  }

  function clearCaseValidationError() {
    setCaseValidationTargetId(null);
  }

  function currentCaseDraftDirtyState(): CaseDraftDirtyState {
    const projectId = caseProjectDraft.projectId;
    const editingFileBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "file",
    )
      ? caseWorkspace?.files.find(
          (item) => item.fileId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingPartyBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "party",
    )
      ? caseWorkspace?.parties.find(
          (item) => item.partyId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingFactBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "fact",
    )
      ? caseWorkspace?.facts.find(
          (item) => item.factId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingEvidenceBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "evidence",
    )
      ? caseWorkspace?.evidence.find(
          (item) => item.evidenceId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingIssueBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "legal_issue",
    )
      ? caseWorkspace?.legalIssues.find(
          (item) => item.issueId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const baselineFactId = caseWorkspace?.facts[0]?.factId ?? "";
    const baselineEvidenceId =
      caseWorkspace?.evidence[0]?.evidenceId ?? "";
    const baselineIssueId = caseWorkspace?.legalIssues[0]?.issueId ?? "";

    return detectDirtyCaseDrafts({
      project: {
        draft: caseProjectDraft,
        baseline: caseWorkspace?.project ?? caseProjectDraftBaseline.current,
      },
      file: {
        draft: fileDraft,
        baseline: editingFileBaseline ?? createCaseFile(projectId),
      },
      party: {
        draft: partyDraft,
        baseline: editingPartyBaseline ?? createParty(projectId),
      },
      fact: {
        draft: factDraft,
        baseline: editingFactBaseline ?? createFact(projectId),
      },
      evidence: {
        draft: evidenceDraft,
        baseline:
          editingEvidenceBaseline ??
          createEvidence(projectId, (caseWorkspace?.evidence.length ?? 0) + 1),
      },
      legalIssue: {
        draft: issueDraft,
        baseline: editingIssueBaseline ?? createIssue(projectId),
      },
      evidenceLink: {
        factId: linkFactId,
        evidenceId: linkEvidenceId,
        baselineFactId,
        baselineEvidenceId,
      },
      factIssueLink: {
        factId: factIssueFactId,
        issueId: factIssueIssueId,
        baselineFactId,
        baselineIssueId,
      },
      legalBasis: {
        sourceId: basisSourceId,
        issueId: basisIssueId,
        caseDate: basisCaseDate,
        includeExpired: basisIncludeExpired,
        note: basisNote,
        baselineIssueId,
        baselineCaseDate: "",
      },
    });
  }

  dirtyCaseDraftsForClose.current = blockingDirtyCaseDrafts(
    currentCaseDraftDirtyState(),
    [],
  );

  function blockWorkspaceReloadForDirtyDrafts(
    allowed: readonly CaseDraftKind[],
    action: string,
  ): boolean {
    const blocking = blockingDirtyCaseDrafts(
      currentCaseDraftDirtyState(),
      allowed,
    );
    if (blocking.length === 0) {
      return false;
    }
    setCaseState({
      kind: "error",
      message: `${action}会刷新案件工作区。请先保存或清空这些未保存内容：${blocking
        .map((kind) => CASE_DRAFT_LABELS[kind])
        .join("、")}。`,
    });
    return true;
  }

  function applyCaseWorkspace(workspace: CaseWorkspace) {
    setActiveCaseEntityEditor(null);
    setCaseWorkspace(workspace);
    setCaseWorkspaceWriteBlocked(false);
    persistedMutationRecoveryProjectId.current = null;
    clearCaseValidationError();
    setSelectedCaseProjectId(workspace.project.projectId);
    setCaseProjectDraft(workspace.project);
    caseProjectDraftBaseline.current = workspace.project;
    setFileDraft(createCaseFile(workspace.project.projectId));
    setPartyDraft(createParty(workspace.project.projectId));
    setFactDraft(createFact(workspace.project.projectId));
    setEvidenceDraft(
      createEvidence(workspace.project.projectId, workspace.evidence.length + 1),
    );
    setIssueDraft(createIssue(workspace.project.projectId));
    setBasisSourceId("");
    setBasisIssueId(workspace.legalIssues[0]?.issueId ?? "");
    setBasisCaseDate("");
    setBasisIncludeExpired(false);
    setBasisNote("");
    setLinkFactId(workspace.facts[0]?.factId ?? "");
    setLinkEvidenceId(workspace.evidence[0]?.evidenceId ?? "");
    setFactIssueFactId(workspace.facts[0]?.factId ?? "");
    setFactIssueIssueId(workspace.legalIssues[0]?.issueId ?? "");
    extraction.syncWorkspaceFiles(workspace);
  }

  async function loadCaseWorkspace(
    projectId: string,
    requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch),
    recoverAfterPersistedMutation = false,
  ): Promise<boolean> {
    if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
      return false;
    }
    setCaseState({ kind: "loading" });
    try {
      const response = await getCaseWorkspace({ projectId });
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return false;
      }
      const workspace = response.workspace ?? null;
      if (!workspace || workspace.project.projectId !== projectId) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
        setCaseState({
          kind: "error",
          message:
            "目标案件未返回有效工作区；已保留原案件与草稿并锁定写操作。请重试加载案件后再继续编辑。",
        });
        return false;
      }
      applyCaseWorkspace(workspace);
      const extractionRestoreError =
        await extraction.restorePendingReview(workspace, requestEpoch);
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return false;
      }
      if (extractionRestoreError) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
      }
      setCaseState(
        extractionRestoreError
          ? {
              kind: "error",
              message: `${extractionRestoreError} 写操作已锁定；请点击当前案件重试完整加载。`,
            }
          : { kind: "idle" },
      );
      return extractionRestoreError === null;
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
        setCaseState({
          kind: "error",
          message: `案件加载失败；已保留原案件与草稿并锁定写操作。请重试：${errorMessage(error)}`,
        });
      }
      return false;
    }
  }

  const extraction = useCaseExtractionController({
    workspace: {
      selectedProjectIdRef: selectedCaseProjectIdRef,
      workspaceEpoch: caseWorkspaceEpoch,
      setCaseState,
      setWorkspaceWriteBlocked: setCaseWorkspaceWriteBlocked,
      beginCaseMutation,
      finishCaseMutation,
      caseMutationIsLocked: () => caseMutationLock.current,
      readDirtyCaseDrafts: () => dirtyCaseDraftsForClose.current,
      blockWorkspaceReloadForDirtyDrafts: (allowed, action) =>
        blockWorkspaceReloadForDirtyDrafts(allowed, action),
      loadCaseWorkspace,
    },
    confirmAction,
  });

  async function refreshCaseProjects(
    preferredProjectId: string | undefined,
    requestEpoch: number,
    recoverAfterPersistedMutation = false,
  ) {
    try {
      const response = await listCaseProjects();
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return response.projects;
      }
      setCaseProjects(response.projects);
      const nextProject = caseProjectToLoadAfterRefresh(
        response.projects,
        preferredProjectId,
        recoverAfterPersistedMutation,
      );

      if (nextProject) {
        setCaseProjectPage(
          caseProjectPageForId(response.projects, nextProject.projectId),
        );
        const workspaceLoaded = await loadCaseWorkspace(
          nextProject.projectId,
          requestEpoch,
          recoverAfterPersistedMutation,
        );
        if (!workspaceLoaded) {
          return undefined;
        }
      } else if (recoverAfterPersistedMutation && preferredProjectId) {
        const workspaceLoaded = await loadCaseWorkspace(
          preferredProjectId,
          requestEpoch,
          true,
        );
        if (!workspaceLoaded) {
          return undefined;
        }
        if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
          setCaseState({
            kind: "error",
            message:
              "案件已保存并安全加载，但案件列表未返回该案件；当前编辑可继续，重启应用后列表会重新读取。",
          });
        }
      } else {
        setActiveCaseEntityEditor(null);
        setSelectedCaseProjectId(null);
        setCaseWorkspace(null);
        setCaseWorkspaceWriteBlocked(false);
        persistedMutationRecoveryProjectId.current = null;
        setCaseProjectPage(1);
        setCaseState({ kind: "idle" });
      }
      return response.projects;
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        if (recoverAfterPersistedMutation && preferredProjectId) {
          const workspaceLoaded = await loadCaseWorkspace(
            preferredProjectId,
            requestEpoch,
            true,
          );
          if (workspaceLoaded) {
            if (
              isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
            ) {
              setCaseState({
                kind: "error",
                message: `案件已保存并安全加载，但案件列表刷新失败；当前编辑可继续：${errorMessage(error)}`,
              });
            }
            return caseProjects;
          }
        } else {
          setCaseState({ kind: "error", message: errorMessage(error) });
        }
      }
      return undefined;
    }
  }

  useEffect(() => {
    let isMounted = true;
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);

    listCaseProjects()
      .then(async (response) => {
        if (
          !isMounted ||
          !isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          return;
        }
        setCaseProjects(response.projects);
        const firstProject = response.projects[0];
        if (firstProject) {
          setCaseProjectPage(1);
          await loadCaseWorkspace(firstProject.projectId, requestEpoch);
        } else {
          setCaseState({ kind: "idle" });
        }
      })
      .catch((error: unknown) => {
        if (
          isMounted &&
          isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          setCaseState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
      }
    };
    // This mount request deliberately owns one fixed epoch; later navigation
    // invalidates it instead of recreating the loader closure.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function resetAllCaseEntityDrafts(
    projectId = caseProjectDraft.projectId,
    nextEvidenceNumber = (caseWorkspace?.evidence.length ?? 0) + 1,
  ) {
    setFileDraft(createCaseFile(projectId));
    setPartyDraft(createParty(projectId));
    setFactDraft(createFact(projectId));
    setEvidenceDraft(createEvidence(projectId, nextEvidenceNumber));
    setIssueDraft(createIssue(projectId));
  }

  function startCaseEntityEdit(target: CaseEntityEditTarget) {
    if (
      !caseChildrenReady ||
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "开始编辑")) {
      return;
    }
    resetAllCaseEntityDrafts(target.entity.projectId);
    switch (target.entityType) {
      case "file": {
        const draft = copyCaseEntityForEditing(target.entity);
        setFileDraft({
          ...draft,
          summary: publicCaseBusinessText(draft.summary),
        });
        setActiveCaseEntityEditor({
          entityType: "file",
          entityId: target.entity.fileId,
        });
        break;
      }
      case "party": {
        const draft = copyCaseEntityForEditing(target.entity);
        setPartyDraft({
          ...draft,
          name: publicTitle(draft.name, ""),
          normalizedName: publicCaseBusinessText(draft.normalizedName),
          contact: publicCaseBusinessText(draft.contact),
          notes: publicCaseBusinessText(draft.notes),
        });
        setActiveCaseEntityEditor({
          entityType: "party",
          entityId: target.entity.partyId,
        });
        break;
      }
      case "fact": {
        const draft = copyCaseEntityForEditing(target.entity);
        setFactDraft({
          ...draft,
          description: publicCaseBusinessText(draft.description),
          source: publicCaseBusinessText(draft.source),
        });
        setActiveCaseEntityEditor({
          entityType: "fact",
          entityId: target.entity.factId,
        });
        break;
      }
      case "evidence": {
        const draft = copyCaseEntityForEditing(target.entity);
        setEvidenceDraft({
          ...draft,
          evidenceNumber: publicEvidenceNumber(draft.evidenceNumber, ""),
          source: publicCaseBusinessText(draft.source),
          summary: publicCaseBusinessText(draft.summary),
        });
        setActiveCaseEntityEditor({
          entityType: "evidence",
          entityId: target.entity.evidenceId,
        });
        break;
      }
      case "legal_issue": {
        const draft = copyCaseEntityForEditing(target.entity);
        setIssueDraft({
          ...draft,
          title: publicTitle(draft.title, ""),
          description: publicCaseBusinessText(draft.description),
          claim: publicCaseBusinessText(draft.claim),
        });
        setActiveCaseEntityEditor({
          entityType: "legal_issue",
          entityId: target.entity.issueId,
        });
        break;
      }
    }
    setCaseState({ kind: "idle" });
  }

  function cancelCaseEntityEdit() {
    if (caseMutationLock.current) {
      return;
    }
    const editor = activeCaseEntityEditor;
    if (!editor) {
      return;
    }
    switch (editor.entityType) {
      case "file":
        setFileDraft(createCaseFile(caseProjectDraft.projectId));
        break;
      case "party":
        setPartyDraft(createParty(caseProjectDraft.projectId));
        break;
      case "fact":
        setFactDraft(createFact(caseProjectDraft.projectId));
        break;
      case "evidence":
        setEvidenceDraft(
          createEvidence(
            caseProjectDraft.projectId,
            (caseWorkspace?.evidence.length ?? 0) + 1,
          ),
        );
        break;
      case "legal_issue":
        setIssueDraft(createIssue(caseProjectDraft.projectId));
        break;
    }
    setActiveCaseEntityEditor(null);
  }

  function startNewCaseProject() {
    if (caseInteractionIsLocked()) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "新建案件")) {
      return;
    }
    advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    setActiveCaseEntityEditor(null);
    const project = createCaseProject();
    setSelectedCaseProjectId(null);
    setCaseWorkspace(null);
    setCaseWorkspaceWriteBlocked(false);
    clearCaseValidationError();
    setCaseProjectDraft(project);
    caseProjectDraftBaseline.current = project;
    setFileDraft(createCaseFile(project.projectId));
    setPartyDraft(createParty(project.projectId));
    setFactDraft(createFact(project.projectId));
    setEvidenceDraft(createEvidence(project.projectId, 1));
    setIssueDraft(createIssue(project.projectId));
    setBasisSourceId("");
    setBasisIssueId("");
    setBasisCaseDate("");
    setBasisIncludeExpired(false);
    setBasisNote("");
    setLinkFactId("");
    setLinkEvidenceId("");
    setFactIssueFactId("");
    setFactIssueIssueId("");
    extraction.resetForNewProject();
    setCaseState({ kind: "idle" });
  }

  function selectCaseProject(project: CaseProject) {
    if (caseInteractionIsLocked()) {
      return;
    }
    if (
      project.projectId === selectedCaseProjectId &&
      !caseWorkspaceWriteBlocked
    ) {
      return;
    }
    const retriesPersistedMutationReload =
      canBypassDirtyDraftsForWorkspaceRecovery(
        project.projectId,
        selectedCaseProjectId,
        caseWorkspaceWriteBlocked,
        persistedMutationRecoveryProjectId.current,
      );
    if (
      !retriesPersistedMutationReload &&
      blockWorkspaceReloadForDirtyDrafts([], "切换案件")
    ) {
      return;
    }
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    void loadCaseWorkspace(project.projectId, requestEpoch).then((loaded) => {
      if (
        !loaded ||
        !isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
      ) {
        return;
      }
      setCaseProjectPage(caseProjectPageForId(caseProjects, project.projectId));
    });
  }

  async function saveCaseProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      setCaseState({
        kind: "error",
        message: "请先完成或取消当前子项编辑，再保存案件。",
      });
      return;
    }
    const project = {
      ...caseProjectDraft,
      title: caseProjectDraft.title.trim() || "未命名案件",
      caseType: caseProjectDraft.caseType.trim(),
      summary: caseProjectDraft.summary.trim(),
      openedOn: caseProjectDraft.openedOn || null,
    };
    if (blockWorkspaceReloadForDirtyDrafts(["project"], "保存案件")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }
    setCaseState({ kind: "loading" });
    try {
      const response = await upsertCaseProject({ project });
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseProjectDraft(response.project);
        caseProjectDraftBaseline.current = response.project;
        setBasisCaseDate("");
      }
      await refreshCaseProjects(response.project.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function removeCaseProject() {
    if (
      !selectedCaseProjectId ||
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      return;
    }
    const projectId = selectedCaseProjectId;
    if (blockWorkspaceReloadForDirtyDrafts([], "删除案件")) {
      return;
    }
    const projectTitle =
      caseProjects.find((project) => project.projectId === projectId)?.title ||
      caseProjectDraft.title ||
      "当前案件";
    await runConfirmedAction(
      caseProjectDeletionConfirmation(projectTitle),
      confirmAction,
      async () => {
        const requestEpoch = beginCaseMutation();
        if (requestEpoch === null) {
          return;
        }
        let startBlankProject = false;
        setCaseState({ kind: "loading" });
        try {
          await deleteCaseProject({ projectId });
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setSelectedCaseProjectId(null);
            setCaseWorkspace(null);
          }
          const projects = await refreshCaseProjects(undefined, requestEpoch);
          if (
            isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch) &&
            projects?.length === 0
          ) {
            startBlankProject = true;
          }
        } catch (error: unknown) {
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setCaseState({ kind: "error", message: errorMessage(error) });
          }
        } finally {
          finishCaseMutation();
        }
        if (
          startBlankProject &&
          isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          startNewCaseProject();
        }
      },
    );
  }

  function requirePersistedCaseWorkspace(
    entityType?: EditableCaseEntityType,
    entityId?: string,
  ): boolean {
    if (caseMutationLock.current) {
      setCaseState({
        kind: "error",
        message: "案件数据正在写入，请等待当前操作完成。",
      });
      return false;
    }
    if (caseWorkspaceWriteBlocked) {
      setCaseState({
        kind: "error",
        message:
          "案件加载失败后写操作仍处于锁定状态。请点击案件列表中的案件重新加载，成功后再继续。",
      });
      return false;
    }
    if (!caseChildrenReady) {
      setCaseState({
        kind: "error",
        message: "请先保存案件，再操作案件子项。",
      });
      return false;
    }
    if (caseNavigationLocked || extraction.interactionIsLocked()) {
      setCaseState({
        kind: "error",
        message: "材料信息整理进行中，请先完成或放弃当前任务。",
      });
      return false;
    }
    if (
      activeCaseEntityEditor !== null &&
      (entityType === undefined ||
        !caseEntityEditorMatches(
          activeCaseEntityEditor,
          entityType,
          entityId,
        ))
    ) {
      setCaseState({
        kind: "error",
        message: "请先完成或取消当前子项编辑。",
      });
      return false;
    }
    return true;
  }

  async function saveParty(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("party")) return;
    const party = {
      ...partyDraft,
      projectId: caseProjectDraft.projectId,
      name: partyDraft.name.trim(),
      normalizedName: partyDraft.normalizedName.trim(),
    };
    if (!party.name) {
      showCaseValidationError("请输入当事人名称。", "case-party-name");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["party"], "保存当事人")) return;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertCaseParty({ party });
      await loadCaseWorkspace(party.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("file")) return;
    const file = {
      ...fileDraft,
      projectId: caseProjectDraft.projectId,
      title: fileDraft.title.trim(),
      fileType: fileDraft.fileType.trim(),
      storageReference: fileDraft.storageReference.trim(),
      summary: fileDraft.summary.trim(),
    };
    if (!file.title) {
      showCaseValidationError("请输入案件材料标题。", "case-file-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["file"], "保存案件材料")) return;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertCaseFile({ file });
      await loadCaseWorkspace(file.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveFact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("fact")) return;
    const fact = {
      ...factDraft,
      projectId: caseProjectDraft.projectId,
      title: factDraft.title.trim(),
      occurredOn: factDraft.occurredOn || null,
    };
    if (!fact.title) {
      showCaseValidationError("请输入事实标题。", "case-fact-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["fact"], "保存事实")) return;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertCaseFact({ fact });
      await loadCaseWorkspace(fact.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveEvidence(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("evidence")) return;
    const evidence = {
      ...evidenceDraft,
      projectId: caseProjectDraft.projectId,
      evidenceNumber: evidenceDraft.evidenceNumber.trim(),
      title: evidenceDraft.title.trim(),
      formedOn: evidenceDraft.formedOn || null,
    };
    if (!evidence.evidenceNumber || !evidence.title) {
      showCaseValidationError(
        evidence.evidenceNumber
          ? "请输入证据标题。"
          : "请输入证据编号。",
        evidence.evidenceNumber
          ? "case-evidence-title"
          : "case-evidence-number",
      );
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["evidence"], "保存证据")) return;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertEvidenceItem({ evidence });
      await loadCaseWorkspace(evidence.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveIssue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("legal_issue")) return;
    const issue = {
      ...issueDraft,
      projectId: caseProjectDraft.projectId,
      title: issueDraft.title.trim(),
    };
    if (!issue.title) {
      showCaseValidationError("请输入争点标题。", "case-issue-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["legal_issue"], "保存争点")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertLegalIssue({ issue });
      await loadCaseWorkspace(issue.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveLegalBasis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace()) return;
    if (!basisSourceId.trim()) {
      showCaseValidationError("请选择本地法律来源。", "case-basis-source-id");
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(["legal_basis"], "添加法律依据")
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await addCaseLegalBasis({
        projectId,
        issueId: basisIssueId || null,
        sourceId: basisSourceId.trim(),
        caseDate: basisCaseDate || null,
        includeExpired: basisIncludeExpired,
        note: basisNote.trim(),
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setBasisSourceId("");
        setBasisNote("");
      }
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function linkEvidenceToFact() {
    if (!requirePersistedCaseWorkspace()) return;
    if (!linkFactId || !linkEvidenceId) {
      showCaseValidationError(
        linkFactId ? "请选择要关联的证据。" : "请选择要关联的事实。",
        linkFactId ? "case-link-evidence" : "case-link-fact",
      );
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(
        ["evidence_link"],
        "保存事实—证据关联",
      )
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertEvidenceLink({
        link: {
          linkId: createId("link"),
          projectId,
          factId: linkFactId,
          evidenceId: linkEvidenceId,
        },
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function linkFactToIssue() {
    if (!requirePersistedCaseWorkspace()) return;
    const validation = validateFactIssueLinkSelection(
      factIssueFactId,
      factIssueIssueId,
      caseWorkspace?.factIssueLinks ?? [],
    );
    if (!validation.valid) {
      showCaseValidationError(validation.message, validation.targetId);
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(
        ["fact_issue_link"],
        "保存事实—争点关联",
      )
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) return;
    try {
      await upsertFactIssueLink({
        link: {
          linkId: createId("fact-issue-link"),
          projectId,
          factId: factIssueFactId,
          issueId: factIssueIssueId,
        },
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function removeCaseEntity(
    entityType: DeletableCaseEntityType,
    id: string,
  ) {
    const editableEntityType =
      entityType === "file" ||
      entityType === "party" ||
      entityType === "fact" ||
      entityType === "evidence" ||
      entityType === "legal_issue"
        ? entityType
        : undefined;
    if (!requirePersistedCaseWorkspace(editableEntityType, id)) return;
    if (blockWorkspaceReloadForDirtyDrafts([], "删除案件子项")) return;
    if (!caseWorkspace) return;
    await runConfirmedAction(
      caseEntityDeletionConfirmation(
        entityType,
        caseEntityDeletionDisplayName(caseWorkspace, entityType, id),
      ),
      confirmAction,
      async () => {
        const projectId = caseProjectDraft.projectId;
        const requestEpoch = beginCaseMutation();
        if (requestEpoch === null) return;
        try {
          await deleteCaseEntity({ projectId, entityType, id });
          await loadCaseWorkspace(projectId, requestEpoch, true);
        } catch (error: unknown) {
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setCaseState({ kind: "error", message: errorMessage(error) });
          }
        } finally {
          finishCaseMutation();
        }
      },
    );
  }

  const caseNavigationLocked =
    extraction.sourcesLocked ||
    extraction.discarding ||
    caseMutationInFlight ||
    caseState.kind === "loading";
  const caseProjectMutationLocked =
    caseNavigationLocked ||
    caseWorkspaceWriteBlocked ||
    activeCaseEntityEditor !== null;
  const caseChildrenReady =
    caseState.kind !== "loading" &&
    caseWorkspaceWritesAreSafe(
      caseWorkspace,
      selectedCaseProjectId,
      caseProjectDraft.projectId,
      caseWorkspaceWriteBlocked,
    );
  const editingFile = caseEntityEditorMatches(activeCaseEntityEditor, "file");
  const editingParty = caseEntityEditorMatches(activeCaseEntityEditor, "party");
  const editingFact = caseEntityEditorMatches(activeCaseEntityEditor, "fact");
  const editingEvidence = caseEntityEditorMatches(
    activeCaseEntityEditor,
    "evidence",
  );
  const editingIssue = caseEntityEditorMatches(
    activeCaseEntityEditor,
    "legal_issue",
  );
  const paginatedCaseProjects = paginateCaseProjects(
    caseProjects,
    caseProjectPage,
  );
  const assistantActiveProject = selectedCaseProjectId
    ? caseProjects.find(
        (project) => project.projectId === selectedCaseProjectId,
      ) ?? null
    : null;
  const assistantProposalApplyBlockedReason =
    dirtyCaseDraftsForClose.current.length > 0
      ? "案件工作台仍有未保存草稿。请先保存或清空草稿，再确认写入助理建议。"
      : caseNavigationLocked || caseWorkspaceWriteBlocked
        ? "案件工作台正在处理其他操作或处于只读保护状态，请恢复后再确认写入。"
        : caseWorkspace?.project.projectId !== selectedCaseProjectId
          ? "当前案件工作区尚未完整加载，不能确认写入助理建议。"
          : null;

  function refreshCaseAfterAssistantProposal(projectId: string) {
    if (selectedCaseProjectIdRef.current !== projectId) return;
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    void loadCaseWorkspace(projectId, requestEpoch, true);
  }

  function reportCaseError(message: string) {
    setCaseState({ kind: "error", message });
  }

  function setUnsupportedGraphNodeStatus() {
    reportCaseError("暂不支持打开该项内容。");
  }

  return {
    caseState,
    caseProjects,
    caseProjectPage,
    setCaseProjectPage,
    selectedCaseProjectId,
    caseWorkspace,
    caseWorkspaceWriteBlocked,
    caseValidationTargetId,
    caseMutationInFlight,
    activeCaseEntityEditor,
    caseProjectDraft,
    setCaseProjectDraft,
    fileDraft,
    setFileDraft,
    partyDraft,
    setPartyDraft,
    factDraft,
    setFactDraft,
    evidenceDraft,
    setEvidenceDraft,
    issueDraft,
    setIssueDraft,
    basisSourceId,
    setBasisSourceId,
    basisIssueId,
    setBasisIssueId,
    basisCaseDate,
    setBasisCaseDate,
    basisIncludeExpired,
    setBasisIncludeExpired,
    basisNote,
    setBasisNote,
    linkFactId,
    setLinkFactId,
    linkEvidenceId,
    setLinkEvidenceId,
    factIssueFactId,
    setFactIssueFactId,
    factIssueIssueId,
    setFactIssueIssueId,
    caseNavigationLocked,
    caseProjectMutationLocked,
    caseChildrenReady,
    editingFile,
    editingParty,
    editingFact,
    editingEvidence,
    editingIssue,
    paginatedCaseProjects,
    assistantActiveProject,
    assistantProposalApplyBlockedReason,
    extraction,
    startCaseEntityEdit,
    cancelCaseEntityEdit,
    startNewCaseProject,
    selectCaseProject,
    saveCaseProject,
    removeCaseProject,
    saveParty,
    saveFile,
    saveFact,
    saveEvidence,
    saveIssue,
    saveLegalBasis,
    linkEvidenceToFact,
    linkFactToIssue,
    removeCaseEntity,
    refreshCaseAfterAssistantProposal,
    reportCaseError,
    setUnsupportedGraphNodeStatus,
  };
}

export type CaseWorkspaceController = ReturnType<
  typeof useCaseWorkspaceController
>;
