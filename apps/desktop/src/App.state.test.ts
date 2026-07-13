import { describe, expect, it } from "vitest";

import {
  advanceCaseWorkspaceEpoch,
  blockingDirtyCaseDrafts,
  caseEntityEditorAllows,
  caseEntityEditorMatches,
  citationHasTrustedSource,
  copyCaseEntityForEditing,
  detectDirtyCaseDrafts,
  isCurrentCaseWorkspaceEpoch,
  isPersistedCaseWorkspace,
  releaseCaseMutation,
  resolveLegalAnswerQuestion,
  resolveSelectedQaSource,
  tryAcquireCaseMutation,
  type CaseDraftComparisonState,
} from "./App";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  EvidenceItem,
  LegalIssue,
} from "./ipc/case/types";
import type { LegalAnswerContext, LegalSource } from "./ipc/legal/types";

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
    ]);

    state.project.draft.summary = "未保存的案件摘要";
    state.file.draft.title = "未保存材料";
    state.party.draft.name = "未保存当事人";
    state.fact.draft.description = "未保存事实";
    state.evidence.draft.summary = "未保存证据";
    state.legalIssue.draft.claim = "未保存主张";
    state.evidenceLink.factId = "fact-other";
    state.legalBasis.note = "未保存依据备注";

    expect(detectDirtyCaseDrafts(state)).toEqual({
      project: true,
      file: true,
      party: true,
      fact: true,
      evidence: true,
      legal_issue: true,
      evidence_link: true,
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
      legal_basis: true,
    } as const;

    expect(blockingDirtyCaseDrafts(allDirty, ["file"])).toEqual([
      "project",
      "party",
      "fact",
      "evidence",
      "legal_issue",
      "evidence_link",
      "legal_basis",
    ]);
    expect(blockingDirtyCaseDrafts(allDirty, [])).toHaveLength(8);
  });
});
