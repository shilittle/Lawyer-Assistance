import { describe, expect, it } from "vitest";

import {
  advanceCaseWorkspaceEpoch,
  advanceRequestEpoch,
  articleMatchesDocumentCitation,
  blockingDirtyCaseDrafts,
  caseGraphNodeDomId,
  caseEntityDeletionConfirmation,
  caseProjectDeletionConfirmation,
  caseProjectPageForId,
  caseProjectToLoadAfterRefresh,
  caseEntityEditorAllows,
  caseEntityEditorMatches,
  caseWorkspaceWritesAreSafe,
  citationHasTrustedSource,
  copyCaseEntityForEditing,
  currentLawSearchCriteria,
  detectDirtyCaseDrafts,
  extractionReviewDiscardConfirmation,
  exactLawDocumentMatchesRequest,
  formatCitationValidationSummary,
  graphNodeDestination,
  isCurrentCaseWorkspaceEpoch,
  isCurrentRequestEpoch,
  isPersistedCaseWorkspace,
  legalAnswerContextFromRecord,
  legalAnswerHistoryBelongsToProject,
  legalAnswerPreviewStillOwnsCurrentScope,
  legalAnswerRequestStillOwnsCurrentCase,
  mergeLegalAnswerHistory,
  paginateCaseProjects,
  pendingReviewFilesStillExist,
  providerNavigationHasUnsavedChanges,
  providerApiKeyDeletionConfirmation,
  providerApiKeyOverwriteConfirmation,
  providerDeletionConfirmation,
  publicCaseBusinessText,
  publicEvidenceNumber,
  qaFormDraftFromLegalAnswerRecord,
  releaseCaseMutation,
  resolveLegalAnswerQuestion,
  resolveSelectedQaSource,
  runConfirmedDestructiveAction,
  tryAcquireCaseMutation,
  unrestorableExtractionDiscardConfirmation,
  validateFactIssueLinkSelection,
  type CaseDraftComparisonState,
} from "./App";
import {
  assistantWritesBlockClose,
  canBypassDirtyDraftsForWorkspaceRecovery,
  decideMcpWorkspaceNavigation,
  decideWorkspaceClose,
  workspaceCloseWasApproved,
} from "./app/navigationGuards";
import type { GraphNode } from "./ipc/graph/types";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  EvidenceItem,
  LegalIssue,
} from "./ipc/case/types";
import type {
  LegalAnswerContext,
  LegalAnswerRecord,
  LegalSource,
} from "./ipc/legal/types";
import type { ProviderProfile } from "./ipc/provider/types";

function workspace(projectId: string): CaseWorkspace {
  return {
    project: {
      projectId,
      title: "测试案件",
      caseType: "民事",
      status: "active",
      openedOn: null,
      summary: "",
      createdAt: "",
      updatedAt: "",
    },
    files: [],
    parties: [],
    facts: [],
    evidence: [],
    evidenceLinks: [],
    factIssueLinks: [],
    legalIssues: [],
    legalBasis: [],
    uncertainties: [],
    gaps: [],
  };
}

function legalSource(sourceId: string): LegalSource {
  return {
    sourceId,
    articleId: `article-${sourceId}`,
    documentId: "document-1",
    versionId: "version-1",
    documentTitle: "中华人民共和国民法典",
    versionLabel: "现行版本",
    articleNumber: "第一条",
    articleTitle: null,
    canonicalLabel: "《中华人民共和国民法典》第一条",
    content: "示例原文",
    snippet: "示例原文",
    effectiveFrom: "2021-01-01",
    effectiveTo: null,
    versionStatus: "in_force",
  };
}

function legalContext(...sources: LegalSource[]): LegalAnswerContext {
  return {
    query: {
      lawNames: [],
      articleNumbers: [],
      keywords: [],
      legalIssue: "上下文中的原始问题",
      caseDate: null,
      effectivenessLevels: [],
      includeExpired: false,
    },
    sources,
    prompt: "",
    warnings: [],
  };
}

function draftComparison(): CaseDraftComparisonState {
  const project: CaseProject = {
    projectId: "case-1",
    title: "测试案件",
    caseType: "民事",
    status: "active",
    openedOn: "2026-07-13",
    summary: "",
    createdAt: "",
    updatedAt: "",
  };
  const file: CaseFile = {
    fileId: "file-1",
    projectId: project.projectId,
    title: "",
    fileType: "材料",
    storageReference: "",
    summary: "",
    createdAt: "",
  };
  const party: CaseParty = {
    partyId: "party-1",
    projectId: project.projectId,
    name: "",
    normalizedName: "",
    role: "plaintiff",
    contact: "",
    notes: "",
  };
  const fact: CaseFact = {
    factId: "fact-1",
    projectId: project.projectId,
    occurredOn: null,
    title: "",
    description: "",
    source: "",
    confirmationStatus: "confirmed",
  };
  const evidence: EvidenceItem = {
    evidenceId: "evidence-1",
    projectId: project.projectId,
    evidenceNumber: "E-1",
    title: "",
    source: "",
    formedOn: null,
    summary: "",
    storageReference: "",
    confirmationStatus: "confirmed",
  };
  const legalIssue: LegalIssue = {
    issueId: "issue-1",
    projectId: project.projectId,
    title: "",
    description: "",
    claim: "",
    status: "open",
    confirmationStatus: "confirmed",
  };

  return {
    project: { draft: { ...project }, baseline: { ...project } },
    file: { draft: { ...file }, baseline: { ...file } },
    party: { draft: { ...party }, baseline: { ...party } },
    fact: { draft: { ...fact }, baseline: { ...fact } },
    evidence: { draft: { ...evidence }, baseline: { ...evidence } },
    legalIssue: {
      draft: { ...legalIssue },
      baseline: { ...legalIssue },
    },
    evidenceLink: {
      factId: fact.factId,
      evidenceId: evidence.evidenceId,
      baselineFactId: fact.factId,
      baselineEvidenceId: evidence.evidenceId,
    },
    factIssueLink: {
      factId: fact.factId,
      issueId: legalIssue.issueId,
      baselineFactId: fact.factId,
      baselineIssueId: legalIssue.issueId,
    },
    legalBasis: {
      sourceId: "",
      issueId: legalIssue.issueId,
      caseDate: project.openedOn ?? "",
      includeExpired: false,
      note: "",
      baselineIssueId: legalIssue.issueId,
      baselineCaseDate: project.openedOn ?? "",
    },
  };
}

describe("App case workspace state helpers", () => {
  it("rejects an older workspace response after a newer navigation intent", () => {
    const epoch = { current: 0 };
    const firstRequest = advanceCaseWorkspaceEpoch(epoch);
    const secondRequest = advanceCaseWorkspaceEpoch(epoch);

    expect(isCurrentCaseWorkspaceEpoch(epoch, firstRequest)).toBe(false);
    expect(isCurrentCaseWorkspaceEpoch(epoch, secondRequest)).toBe(true);
  });

  it("enables child operations only for the selected persisted draft", () => {
    const saved = workspace("case-saved");

    expect(isPersistedCaseWorkspace(saved, "case-saved", "case-saved")).toBe(
      true,
    );
    expect(isPersistedCaseWorkspace(null, null, "case-new")).toBe(false);
    expect(isPersistedCaseWorkspace(saved, "case-other", "case-saved")).toBe(
      false,
    );
    expect(isPersistedCaseWorkspace(saved, "case-saved", "case-other")).toBe(
      false,
    );
  });

  it("locks writes after a failed target load even while the old snapshot remains", () => {
    const saved = workspace("case-a");

    expect(caseWorkspaceWritesAreSafe(saved, "case-a", "case-a", false)).toBe(
      true,
    );
    expect(caseWorkspaceWritesAreSafe(saved, "case-a", "case-a", true)).toBe(
      false,
    );
  });

  it("allows only the active child editor and exact persisted record", () => {
    const editor = { entityType: "file", entityId: "file-1" } as const;

    expect(caseEntityEditorAllows(null, "party")).toBe(true);
    expect(caseEntityEditorMatches(editor, "file")).toBe(true);
    expect(caseEntityEditorMatches(editor, "file", "file-1")).toBe(true);
    expect(caseEntityEditorAllows(editor, "file")).toBe(true);
    expect(caseEntityEditorAllows(editor, "file", "file-1")).toBe(true);
    expect(caseEntityEditorAllows(editor, "file", "file-2")).toBe(false);
    expect(caseEntityEditorAllows(editor, "party")).toBe(false);
  });

  it("copies a persisted child into a draft without changing its ids", () => {
    const file: CaseFile = {
      fileId: "file-1",
      projectId: "case-saved",
      title: "合同",
      fileType: "contract",
      storageReference: "vault://contract",
      summary: "原始摘要",
      createdAt: "2026-07-13T00:00:00Z",
    };

    const draft = copyCaseEntityForEditing(file);

    expect(draft).not.toBe(file);
    expect(draft).toEqual(file);
    expect(draft.fileId).toBe("file-1");
    expect(draft.projectId).toBe("case-saved");
  });

  it("keeps legacy service provenance out of editable case labels", () => {
    expect(publicEvidenceNumber("service-aabbccddeeff0011-3")).toBe("待编号");
    expect(
      publicCaseBusinessText(
        '{"proposalHash":"secret","sourceRefs":["attachment-secret"]}',
        "经确认的案件信息",
      ),
    ).toBe("经确认的案件信息");
    expect(
      publicCaseBusinessText(
        "材料存放在 C:\\Users\\someone\\private.pdf",
        "案件材料",
      ),
    ).not.toContain("C:\\Users");
  });

  it("serializes case mutations and advances the workspace epoch per owner", () => {
    const lock = { current: false };
    const epoch = { current: 4 };

    expect(tryAcquireCaseMutation(lock, epoch)).toBe(5);
    expect(tryAcquireCaseMutation(lock, epoch)).toBeNull();
    expect(epoch.current).toBe(5);

    releaseCaseMutation(lock);
    expect(tryAcquireCaseMutation(lock, epoch)).toBe(6);
  });

  it("keeps a second mutation out while an asynchronous owner is pending", async () => {
    const lock = { current: false };
    const epoch = { current: 0 };
    let finishOwner: (() => void) | undefined;
    const ownerFinished = new Promise<void>((resolve) => {
      finishOwner = resolve;
    });

    const ownerEpoch = tryAcquireCaseMutation(lock, epoch);
    const owner = ownerFinished.then(() => releaseCaseMutation(lock));
    await Promise.resolve();

    expect(ownerEpoch).toBe(1);
    expect(tryAcquireCaseMutation(lock, epoch)).toBeNull();

    finishOwner?.();
    await owner;
    expect(tryAcquireCaseMutation(lock, epoch)).toBe(2);
  });

  it("never falls back to another source for an explicit missing source id", () => {
    const first = legalSource("source-first");
    const second = legalSource("source-second");
    const context = legalContext(first, second);

    expect(resolveSelectedQaSource(context, null)).toBe(first);
    expect(resolveSelectedQaSource(context, "source-second")).toBe(second);
    expect(resolveSelectedQaSource(context, "source-not-in-context")).toBeNull();
  });

  it("exposes click navigation only for a validated citation source", () => {
    const source = legalSource("source-first");

    expect(
      citationHasTrustedSource({
        rawMarker: "[SRC:source-first]",
        sourceId: source.sourceId,
        status: "valid",
        source,
      }),
    ).toBe(true);
    expect(
      citationHasTrustedSource({
        rawMarker: "[SRC:source-first]",
        sourceId: source.sourceId,
        status: "invalid",
        reason: "not_in_context",
        source,
      }),
    ).toBe(false);
  });

  it("keeps the finalized context question authoritative over edited form text", () => {
    const context = legalContext();

    expect(resolveLegalAnswerQuestion(context, "后来编辑的问题")).toBe(
      "上下文中的原始问题",
    );
    expect(resolveLegalAnswerQuestion(null, " 提交时的问题 ")).toBe(
      "提交时的问题",
    );
  });

  it("detects unsaved content in every workspace-reload draft category", () => {
    const state = draftComparison();
    expect(Object.values(detectDirtyCaseDrafts(state))).toEqual([
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false,
    ]);

    state.project.draft.summary = "未保存的案件摘要";
    state.file.draft.title = "未保存材料";
    state.party.draft.name = "未保存当事人";
    state.fact.draft.description = "未保存事实";
    state.evidence.draft.summary = "未保存证据";
    state.legalIssue.draft.claim = "未保存主张";
    state.evidenceLink.factId = "fact-other";
    state.factIssueLink.issueId = "issue-other";
    state.legalBasis.note = "未保存依据备注";

    expect(detectDirtyCaseDrafts(state)).toEqual({
      project: true,
      file: true,
      party: true,
      fact: true,
      evidence: true,
      legal_issue: true,
      evidence_link: true,
      fact_issue_link: true,
      legal_basis: true,
    });
  });

  it("allows only the mutation target draft to be cleared by its own save", () => {
    const allDirty = {
      project: true,
      file: true,
      party: true,
      fact: true,
      evidence: true,
      legal_issue: true,
      evidence_link: true,
      fact_issue_link: true,
      legal_basis: true,
    } as const;

    expect(blockingDirtyCaseDrafts(allDirty, ["file"])).toEqual([
      "project",
      "party",
      "fact",
      "evidence",
      "legal_issue",
      "evidence_link",
      "fact_issue_link",
      "legal_basis",
    ]);
    expect(blockingDirtyCaseDrafts(allDirty, [])).toHaveLength(9);
  });

  it("requires an explicit, non-duplicate fact-to-issue selection", () => {
    const existing = [
      {
        linkId: "link-1",
        projectId: "case-1",
        factId: "fact-1",
        issueId: "issue-1",
      },
    ];

    expect(validateFactIssueLinkSelection("", "issue-1", existing)).toMatchObject({
      valid: false,
      targetId: "case-fact-issue-fact",
    });
    expect(validateFactIssueLinkSelection("fact-1", "", existing)).toMatchObject({
      valid: false,
      targetId: "case-fact-issue-issue",
    });
    expect(
      validateFactIssueLinkSelection("fact-1", "issue-1", existing),
    ).toMatchObject({ valid: false });
    expect(
      validateFactIssueLinkSelection("fact-1", "issue-2", existing),
    ).toEqual({ valid: true });
  });

  it("paginates cases with clamped boundaries and locates the selected case", () => {
    const projects = Array.from({ length: 19 }, (_, index) => ({
      ...workspace(`case-${index + 1}`).project,
      title: `案件 ${index + 1}`,
    }));

    expect(paginateCaseProjects(projects, 0, 8)).toMatchObject({
      page: 1,
      totalPages: 3,
    });
    expect(paginateCaseProjects(projects, 99, 8).projects).toHaveLength(3);
    expect(caseProjectPageForId(projects, "case-17", 8)).toBe(3);
    expect(caseProjectPageForId(projects, "missing", 8)).toBe(1);
  });

  it("never loads a different case when a persisted case is missing from a stale list", () => {
    const projects = [workspace("case-a").project, workspace("case-b").project];

    expect(
      caseProjectToLoadAfterRefresh(projects, "case-saved", true),
    ).toBeUndefined();
    expect(
      caseProjectToLoadAfterRefresh(projects, "case-saved", false)?.projectId,
    ).toBe("case-a");
    expect(
      caseProjectToLoadAfterRefresh(projects, "case-b", true)?.projectId,
    ).toBe("case-b");
  });

  it("blocks provider navigation for either profile edits or typed secrets", () => {
    const profile: ProviderProfile = {
      id: "provider-1",
      displayName: "DeepSeek",
      kind: "deep_seek",
      baseUrl: "https://api.deepseek.com",
      modelId: "deepseek-v4-flash",
      credentialAccountId: "default",
      capabilities: {
        chat: true,
        streaming: true,
        customModelId: true,
        customBaseUrl: true,
        reasoning: true,
      },
      options: {
        enableThinking: null,
        thinkingBudget: null,
        thinking: false,
        reasoningEffort: null,
        workspaceId: null,
        endpointId: null,
      },
    };

    expect(providerNavigationHasUnsavedChanges(profile, profile, "")).toBe(
      false,
    );
    expect(
      providerNavigationHasUnsavedChanges(
        profile,
        { ...profile, modelId: "changed" },
        "",
      ),
    ).toBe(true);
    expect(providerNavigationHasUnsavedChanges(profile, profile, "secret")).toBe(
      true,
    );
  });

  it("requires explicit close confirmation for case or provider drafts", () => {
    const decision = decideWorkspaceClose({
      dirtyCaseDrafts: ["project", "evidence"],
      providerDraftDirty: true,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
    });

    expect(decision.kind).toBe("confirm_discard");
    expect("message" in decision ? decision.message : "").toContain(
      "案件基本信息",
    );
    expect("message" in decision ? decision.message : "").toContain("证据");
    expect("message" in decision ? decision.message : "").toContain(
      "API Key",
    );
    let confirmations = 0;
    expect(
      workspaceCloseWasApproved(decision, () => {
        confirmations += 1;
        return false;
      }),
    ).toBe(false);
    expect(confirmations).toBe(1);
  });

  it("blocks close while any persisted write is unresolved", () => {
    for (const activeWrite of [
      "caseMutationInFlight",
      "providerMutationInFlight",
      "extractionMutationInFlight",
      "assistantMutationInFlight",
      "mcpMutationInFlight",
    ] as const) {
      const decision = decideWorkspaceClose({
        dirtyCaseDrafts: ["project"],
        providerDraftDirty: true,
        caseMutationInFlight: false,
        providerMutationInFlight: false,
        extractionMutationInFlight: false,
        [activeWrite]: true,
      });
      expect(decision.kind).toBe("block");
    }

    expect(
      decideWorkspaceClose({
        dirtyCaseDrafts: [],
        providerDraftDirty: false,
        caseMutationInFlight: false,
        providerMutationInFlight: false,
        extractionMutationInFlight: false,
      }),
    ).toEqual({ kind: "proceed" });
  });

  it("treats legal-library bridge writes as assistant mutations for close protection", () => {
    expect(assistantWritesBlockClose(false, false)).toBe(false);
    expect(assistantWritesBlockClose(true, false)).toBe(true);
    expect(assistantWritesBlockClose(false, true)).toBe(true);
    expect(assistantWritesBlockClose(true, true)).toBe(true);

    const bridgeWrite = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      assistantMutationInFlight: assistantWritesBlockClose(false, true),
    });
    expect(bridgeWrite.kind).toBe("block");
    expect("message" in bridgeWrite ? bridgeWrite.message : "").toContain(
      "法律库桥接",
    );
  });

  it("protects active assistant runs and unsent assistant drafts", () => {
    const activeRun = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      assistantRunActive: true,
    });
    expect(activeRun.kind).toBe("block");
    expect("message" in activeRun ? activeRun.message : "").toContain(
      "助理任务仍在运行",
    );

    const unsentDraft = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      assistantDraftDirty: true,
    });
    expect(unsentDraft.kind).toBe("confirm_discard");
    expect("message" in unsentDraft ? unsentDraft.message : "").toContain(
      "助理中未发送的任务草稿",
    );
  });

  it("protects MCP configuration writes and unsaved settings", () => {
    const activeMutation = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      mcpMutationInFlight: true,
    });
    expect(activeMutation.kind).toBe("block");
    expect("message" in activeMutation ? activeMutation.message : "").toContain(
      "MCP 服务配置",
    );

    const dirtyConfig = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      mcpDraftDirty: true,
    });
    expect(dirtyConfig.kind).toBe("confirm_discard");
    expect("message" in dirtyConfig ? dirtyConfig.message : "").toContain(
      "Bearer Token",
    );
  });

  it("guards every shell navigation while MCP state is unresolved", () => {
    expect(
      decideMcpWorkspaceNavigation("mcp", "mcp", true, true),
    ).toEqual({ kind: "proceed" });

    const activeMutation = decideMcpWorkspaceNavigation(
      "mcp",
      "providers",
      true,
      true,
    );
    expect(activeMutation.kind).toBe("block");
    expect(
      "message" in activeMutation ? activeMutation.message : "",
    ).toContain("阻止切换");

    const pendingBearer = decideMcpWorkspaceNavigation(
      "mcp",
      "release",
      false,
      true,
    );
    expect(pendingBearer.kind).toBe("confirm_discard");
    expect(
      "message" in pendingBearer ? pendingBearer.message : "",
    ).toContain("Bearer Token");

    expect(
      decideMcpWorkspaceNavigation("mcp", "assistant", false, false),
    ).toEqual({ kind: "proceed" });
  });

  it("bypasses dirty drafts only for the exact blocked case after a persisted mutation", () => {
    expect(
      canBypassDirtyDraftsForWorkspaceRecovery(
        "case-a",
        "case-a",
        true,
        "case-a",
      ),
    ).toBe(true);
    expect(
      canBypassDirtyDraftsForWorkspaceRecovery(
        "case-b",
        "case-a",
        true,
        "case-a",
      ),
    ).toBe(false);
    expect(
      canBypassDirtyDraftsForWorkspaceRecovery(
        "case-a",
        "case-a",
        true,
        "case-other",
      ),
    ).toBe(false);
    expect(
      canBypassDirtyDraftsForWorkspaceRecovery(
        "case-a",
        "case-a",
        false,
        "case-a",
      ),
    ).toBe(false);
  });

  it("reconstructs a traceable context from a saved answer record", () => {
    const source = legalSource("source-history");
    const unreferencedSource = legalSource("source-not-cited");
    const record: LegalAnswerRecord = {
      recordId: "record-1",
      projectId: "case-1",
      providerId: "provider-1",
      question: "历史问题",
      answer: "历史回答",
      caseDate: "2025-01-01",
      query: {
        lawNames: ["中华人民共和国劳动合同法"],
        articleNumbers: ["第四十七条"],
        keywords: ["经济补偿"],
        legalIssue: "历史问题",
        caseDate: "2025-01-01",
        effectivenessLevels: ["national_law"],
        includeExpired: true,
      },
      sourceIds: [source.sourceId, unreferencedSource.sourceId],
      sources: [source, unreferencedSource],
      missingSourceIds: [],
      citationReport: {
        citations: [
          {
            rawMarker: "[SRC:source-history]",
            sourceId: source.sourceId,
            status: "valid",
            source,
          },
        ],
        validCount: 1,
        invalidCount: 0,
        unsupportedLegalConclusion: false,
        semanticSupportVerified: false,
      },
      createdAt: "2026-07-14T00:00:00Z",
    };

    expect(legalAnswerContextFromRecord(record)).toMatchObject({
      query: {
        lawNames: ["中华人民共和国劳动合同法"],
        articleNumbers: ["第四十七条"],
        keywords: ["经济补偿"],
        legalIssue: "历史问题",
        caseDate: "2025-01-01",
        effectivenessLevels: ["national_law"],
        includeExpired: true,
      },
      sources: [
        { sourceId: "source-history" },
        { sourceId: "source-not-cited" },
      ],
    });
    expect(qaFormDraftFromLegalAnswerRecord(record)).toEqual({
      question: "历史问题",
      lawName: "中华人民共和国劳动合同法",
      articleNumber: "第四十七条",
      keywords: "经济补偿",
      caseDate: "2025-01-01",
      effectivenessLevels: ["national_law"],
      includeExpired: true,
    });
  });

  it("rejects an in-flight answer as soon as the selected case changes", () => {
    expect(legalAnswerRequestStillOwnsCurrentCase("case-a", "case-a")).toBe(
      true,
    );
    expect(legalAnswerRequestStillOwnsCurrentCase("case-a", "case-b")).toBe(
      false,
    );
    expect(legalAnswerRequestStillOwnsCurrentCase(null, "case-a")).toBe(false);
  });

  it("accepts a source preview only inside its original case scope", () => {
    expect(legalAnswerPreviewStillOwnsCurrentScope("case-a", "case-a")).toBe(
      true,
    );
    expect(legalAnswerPreviewStillOwnsCurrentScope("case-a", "case-b")).toBe(
      false,
    );
    expect(legalAnswerPreviewStillOwnsCurrentScope(null, null)).toBe(true);
    expect(legalAnswerPreviewStillOwnsCurrentScope(null, "case-a")).toBe(false);
  });

  it("requires every persisted extraction source to remain in the workspace", () => {
    expect(
      pendingReviewFilesStillExist(["file-a", "file-b"], ["file-b"]),
    ).toBe(true);
    expect(
      pendingReviewFilesStillExist(["file-a"], ["file-a", "file-b"]),
    ).toBe(false);
  });

  it("appends a same-createdAt page without duplicating its record-id boundary", () => {
    const first: LegalAnswerRecord = {
      recordId: "record-1",
      projectId: "case-1",
      providerId: "provider-1",
      question: "问题一",
      answer: "回答一",
      query: {
        lawNames: [],
        articleNumbers: [],
        keywords: [],
        legalIssue: "问题一",
        caseDate: null,
        effectivenessLevels: [],
        includeExpired: false,
      },
      sourceIds: [],
      sources: [],
      missingSourceIds: [],
      citationReport: {
        citations: [],
        validCount: 0,
        invalidCount: 0,
        unsupportedLegalConclusion: true,
        semanticSupportVerified: false,
      },
      createdAt: "2026-07-14T10:00:00Z",
    };
    const second = {
      ...first,
      recordId: "record-2",
      question: "问题二",
    };

    expect(mergeLegalAnswerHistory([first], [first, second])).toEqual([
      first,
      second,
    ]);
    expect(legalAnswerHistoryBelongsToProject([first, second], "case-1")).toBe(
      true,
    );
    expect(
      legalAnswerHistoryBelongsToProject(
        [{ ...second, projectId: "case-2" }],
        "case-1",
      ),
    ).toBe(false);
  });

  it("never labels an empty citation report as valid", () => {
    expect(
      formatCitationValidationSummary({
        citations: [],
        validCount: 0,
        invalidCount: 0,
        unsupportedLegalConclusion: true,
        semanticSupportVerified: false,
      }),
    ).toBe("未列出法条依据");
    expect(
      formatCitationValidationSummary({
        citations: [
          {
            rawMarker: "[SRC:missing]",
            sourceId: "missing",
            status: "invalid",
            reason: "not_found",
          },
        ],
        validCount: 0,
        invalidCount: 1,
        unsupportedLegalConclusion: true,
        semanticSupportVerified: false,
      }),
    ).toBe("1 条依据需要核对");
  });

  it("rejects stale search and detail responses by monotonically advancing epochs", () => {
    const epoch = { current: 0 };
    const first = advanceRequestEpoch(epoch);
    const second = advanceRequestEpoch(epoch);

    expect(isCurrentRequestEpoch(epoch, first)).toBe(false);
    expect(isCurrentRequestEpoch(epoch, second)).toBe(true);
  });

  it("reads the latest query after a delayed document-context request", async () => {
    const query = { current: "旧查询 A" };
    const caseDate = { current: "2024-01-01" };
    let releaseContext: (() => void) | undefined;
    const contextLoaded = new Promise<void>((resolve) => {
      releaseContext = resolve;
    });
    const delayedSearch = (async () => {
      await contextLoaded;
      return currentLawSearchCriteria(query, caseDate);
    })();

    query.current = "新查询 B";
    caseDate.current = "2025-02-03";
    releaseContext?.();

    await expect(delayedSearch).resolves.toEqual({
      query: "新查询 B",
      caseDate: "2025-02-03",
    });
  });

  it("names destructive targets and discloses cascading deletion impact", () => {
    expect(caseProjectDeletionConfirmation("劳动争议案")).toContain(
      "劳动争议案",
    );
    expect(caseProjectDeletionConfirmation("劳动争议案")).toContain(
      "法律问答历史",
    );
    expect(caseEntityDeletionConfirmation("evidence", "E-3 工资流水")).toBe(
      "确定永久删除证据“E-3 工资流水”吗？其关联数据（如有）也会一并删除，此操作不可撤销。",
    );
    expect(
      caseEntityDeletionConfirmation("fact_issue_link", "交付 ↔ 违约责任"),
    ).toContain("事实—争点关联");
    expect(providerDeletionConfirmation("DeepSeek", "default")).toContain(
      "已保存的访问凭据",
    );
    expect(
      providerApiKeyDeletionConfirmation("DeepSeek", "default"),
    ).toContain("重新录入");
    expect(
      providerApiKeyOverwriteConfirmation("DeepSeek", "default"),
    ).toContain("覆盖旧凭据");
    expect(extractionReviewDiscardConfirmation()).toContain("不可撤销");
    expect(unrestorableExtractionDiscardConfirmation()).toContain("不可撤销");
  });

  it("never executes a destructive action after confirmation is declined", async () => {
    const messages = [
      caseProjectDeletionConfirmation("案件 A"),
      caseEntityDeletionConfirmation("evidence", "E-1"),
      providerDeletionConfirmation("DeepSeek", "default"),
      providerApiKeyDeletionConfirmation("DeepSeek", "default"),
      providerApiKeyOverwriteConfirmation("DeepSeek", "default"),
      extractionReviewDiscardConfirmation(),
      unrestorableExtractionDiscardConfirmation(),
    ];
    let ipcCalls = 0;

    for (const message of messages) {
      const result = await runConfirmedDestructiveAction(
        message,
        () => false,
        async () => {
          ipcCalls += 1;
        },
      );
      expect(result).toEqual({ executed: false });
    }

    expect(ipcCalls).toBe(0);
  });
});

describe("graph navigation targets", () => {
  function node(sourceKind: string, sourceId = "source:1"): GraphNode {
    return {
      id: sourceId,
      label: "来源记录",
      category: "test",
      sourceKind,
      sourceId,
    };
  }

  it("routes persisted case entities back to the case workspace", () => {
    for (const sourceKind of [
      "case_fact",
      "evidence_item",
      "legal_issue",
      "verified_citation",
    ]) {
      expect(graphNodeDestination(node(sourceKind))).toBe("case");
    }
  });

  it("routes legal-core nodes back to the law search workspace", () => {
    expect(graphNodeDestination(node("legal_core", "law-1"))).toBe("law");
    expect(graphNodeDestination(node("fixture"))).toBe("unsupported");
  });

  it("builds stable DOM targets without leaking reserved identifier characters", () => {
    expect(caseGraphNodeDomId("verified_citation", "[SRC:law:article:1]")).toBe(
      "case-graph-source-verified_citation-%5BSRC%3Alaw%3Aarticle%3A1%5D",
    );
  });
});

describe("document citation navigation", () => {
  const citation = {
    articleId: "article-577",
    documentId: "civil-code",
    versionId: "civil-code-2020",
    sourceId: "law:civil-code:civil-code-2020:art:577",
  };

  it("opens only the exact article/version/source tuple returned by the local law database", () => {
    expect(
      articleMatchesDocumentCitation(
        {
          articleId: "article-577",
          documentId: "civil-code",
          versionId: "civil-code-2020",
          citationId: "law:civil-code:civil-code-2020:art:577",
        },
        citation,
      ),
    ).toBe(true);
    expect(
      articleMatchesDocumentCitation(
        {
          articleId: "article-577",
          documentId: "civil-code",
          versionId: "civil-code-2020",
          citationId: "law:invented:source:art:577",
        },
        citation,
      ),
    ).toBe(false);
    expect(articleMatchesDocumentCitation(null, citation)).toBe(false);
  });

  it("accepts document metadata only when the exact requested id is returned", () => {
    const document = {
      documentId: "civil-code",
      title: "中华人民共和国民法典",
      documentType: "code",
      authorityName: "全国人民代表大会",
      effectivenessLevel: "national_law",
      status: "in_force",
      currentVersionId: "civil-code-2020",
      currentEffectiveFrom: "2021-01-01",
      currentEffectiveTo: null,
      matchedAlias: null,
      summary: "",
      score: 1,
    };

    expect(exactLawDocumentMatchesRequest(document, "civil-code")).toBe(true);
    expect(exactLawDocumentMatchesRequest(document, "different-id")).toBe(false);
    expect(exactLawDocumentMatchesRequest(null, "civil-code")).toBe(false);
  });
});
