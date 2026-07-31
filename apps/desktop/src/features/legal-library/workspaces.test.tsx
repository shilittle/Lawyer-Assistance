import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { AssistantConversation } from "../../ipc/assistant/types";
import type { CaseProject, CaseWorkspace } from "../../ipc/case/types";
import { INITIAL_LEGAL_ANSWER_STREAM_STATE } from "../../ipc/legal/stream";
import type {
  LawArticleDetail,
  LawSearchResult,
  LegalAnswerContext,
  LegalSource,
} from "../../ipc/legal/types";
import { createProviderProfileDraft } from "../../ipc/provider/catalog";
import { LegacyQaWorkspace } from "./LegacyQaWorkspace";
import { LegalLibrarySearchWorkspace } from "./LegalLibrarySearchWorkspace";
import searchWorkspaceSource from "./LegalLibrarySearchWorkspace.tsx?raw";
import type { LegalLibraryController } from "./useLegalLibraryController";
import legalControllerSource from "./useLegalLibraryController.ts?raw";

function legalSource(): LegalSource {
  return {
    sourceId: "citation-civil-code-577",
    articleId: "article-civil-code-577",
    documentId: "civil-code",
    versionId: "civil-code-current",
    documentTitle: "中华人民共和国民法典",
    versionLabel: "现行版本",
    articleNumber: "第五百七十七条",
    articleTitle: null,
    canonicalLabel: "《中华人民共和国民法典》第五百七十七条",
    content: "当事人一方不履行合同义务的，应当承担违约责任。",
    snippet: "不履行合同义务，应当承担违约责任。",
    effectiveFrom: "2021-01-01",
    effectiveTo: null,
    versionStatus: "in_force",
  };
}

function lawDocument(): LawSearchResult {
  return {
    documentId: "civil-code",
    title: "中华人民共和国民法典",
    documentType: "法律",
    authorityName: "全国人民代表大会",
    effectivenessLevel: "law",
    status: "in_force",
    currentVersionId: "civil-code-current",
    currentEffectiveFrom: "2021-01-01",
    currentEffectiveTo: null,
    matchedAlias: "民法典",
    summary: "规范民事活动的基础性法律。",
    score: 1,
  };
}

function articleDetail(): LawArticleDetail {
  const source = legalSource();
  return {
    articleId: source.articleId,
    documentId: source.documentId,
    versionId: source.versionId,
    documentTitle: source.documentTitle,
    versionLabel: source.versionLabel,
    articleNumber: source.articleNumber,
    articleTitle: source.articleTitle,
    content: source.content,
    citationId: source.sourceId,
    canonicalLabel: source.canonicalLabel,
    effectiveFrom: source.effectiveFrom,
    effectiveTo: source.effectiveTo,
    versionStatus: source.versionStatus,
    topics: ["合同责任"],
  };
}

function caseProject(projectId = "case-1"): CaseProject {
  return {
    projectId,
    title: "合同纠纷案",
    caseType: "民事",
    status: "active",
    openedOn: "2026-07-30",
    summary: "",
    createdAt: "2026-07-30T08:00:00Z",
    updatedAt: "2026-07-30T08:00:00Z",
  };
}

function caseWorkspace(project = caseProject()): CaseWorkspace {
  return {
    project,
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

function legalContext(): LegalAnswerContext {
  const source = legalSource();
  return {
    query: {
      lawNames: ["民法典"],
      articleNumbers: ["第五百七十七条"],
      keywords: ["合同", "违约"],
      legalIssue: "合同违约责任如何承担？",
      caseDate: "2026-07-30",
      effectivenessLevels: ["law"],
      includeExpired: false,
    },
    sources: [source],
    prompt: "",
    warnings: ["本地候选来源仍需由律师逐条核对。"],
  };
}

type ControllerPatch = {
  search?: Partial<LegalLibraryController["search"]>;
  qa?: Partial<LegalLibraryController["qa"]>;
  context?: Partial<LegalLibraryController["context"]>;
};

function controllerFor(patch: ControllerPatch = {}): LegalLibraryController {
  const search: LegalLibraryController["search"] = {
    query: "合同",
    setQuery: vi.fn(),
    caseDate: "",
    setCaseDate: vi.fn(),
    state: { kind: "idle" },
    detailState: { kind: "idle" },
    documentState: { kind: "idle" },
    laws: [],
    articles: [],
    selectedDocument: null,
    versions: [],
    relations: [],
    selectedArticleId: null,
    selectedArticle: null,
    submit: vi.fn(),
    run: vi.fn(async () => undefined),
    loadArticleDetail: vi.fn(async () => undefined),
    loadDocumentContext: vi.fn(async () => undefined),
    clearDocumentFilter: vi.fn(async () => undefined),
    openLawGraph: vi.fn(),
    bridgeState: { kind: "idle" },
    addSelectedArticleToAssistant: vi.fn(async () => undefined),
    proposeSelectedArticleForCase: vi.fn(async () => undefined),
    openCaseAssistant: vi.fn(),
    openAssistant: vi.fn(),
    ...patch.search,
  };
  const qa: LegalLibraryController["qa"] = {
    state: { kind: "idle" },
    question: "",
    setQuestion: vi.fn(),
    lawName: "",
    setLawName: vi.fn(),
    articleNumber: "",
    setArticleNumber: vi.fn(),
    keywords: "",
    setKeywords: vi.fn(),
    caseDate: "",
    setCaseDate: vi.fn(),
    effectivenessLevels: [],
    setEffectivenessLevels: vi.fn(),
    includeExpired: false,
    setIncludeExpired: vi.fn(),
    providerId: "",
    setProviderId: vi.fn(),
    context: null,
    answer: null,
    historyState: { kind: "idle" },
    historyRecords: [],
    historyHasMore: false,
    stream: INITIAL_LEGAL_ANSWER_STREAM_STATE,
    selectedSourceId: null,
    setSelectedSourceId: vi.fn(),
    activeContext: null,
    selectedSource: null,
    answeredQuestion: null,
    answeredScope: "",
    requestLocked: false,
    preview: vi.fn(async () => undefined),
    cancel: vi.fn(async () => undefined),
    restoreRecord: vi.fn(),
    refreshHistory: vi.fn(async () => undefined),
    openLawGraph: vi.fn(),
    ...patch.qa,
  };
  const context: LegalLibraryController["context"] = {
    selectedCaseProjectId: null,
    assistantConversation: null,
    assistantActiveProject: null,
    ...patch.context,
  };

  return {
    search,
    qa,
    context,
    graphDocumentId: null,
    activeSources: qa.activeContext?.sources ?? [],
    bridgeMutationInFlightRef: { current: false },
    providerBridge: {
      selectInitialProvider: vi.fn(),
      handleProviderDeleted: vi.fn(),
    },
    openDocumentCitation: vi.fn(async () => undefined),
    consumeDocumentCitation: vi.fn(async () => undefined),
    openLawDocumentFromGraph: vi.fn(async () => undefined),
  };
}

describe("LegalLibrarySearchWorkspace", () => {
  it("copies a typed citation into the controller before acknowledging route state", () => {
    expect(searchWorkspaceSource).toMatch(
      /void consumeDocumentCitation\(citationRequest\);[\s\S]*onCitationRequestConsumed\?\.\(citationRequest\);/u,
    );
    expect(legalControllerSource).toMatch(
      /async function consumeDocumentCitation[\s\S]*resolveDocumentCitation\(citation, false\)/u,
    );
  });

  it("renders local legal detail and keeps the mismatched-case assistant warning", () => {
    const selectedDocument = lawDocument();
    const selectedArticle = articleDetail();
    const activeProject = caseProject("case-1");
    const assistantConversation: AssistantConversation = {
      conversationId: "conversation-1",
      projectId: "case-other",
      title: "其他案件会话",
      status: "open",
      createdAt: "2026-07-30T08:00:00Z",
      updatedAt: "2026-07-30T08:00:00Z",
    };
    const markup = renderToStaticMarkup(
      <LegalLibrarySearchWorkspace
        controller={controllerFor({
          search: {
            laws: [selectedDocument],
            selectedDocument,
            selectedArticleId: selectedArticle.articleId,
            selectedArticle,
          },
          context: {
            selectedCaseProjectId: activeProject.projectId,
            assistantConversation,
            assistantActiveProject: activeProject,
          },
        })}
      />,
    );

    expect(markup).toContain('aria-label="法律库工作区"');
    expect(markup).toContain("当前法律：中华人民共和国民法典");
    expect(markup).toContain(selectedArticle.canonicalLabel);
    expect(markup).toContain("加入当前案件（待确认）");
    expect(markup).toContain("未绑定所选案件");
    expect(markup).toContain("请先点“在案件助理中继续”");
  });
});

describe("LegacyQaWorkspace", () => {
  it("renders explicit case/provider ownership without the removed approval redirect", () => {
    const project = caseProject();
    const context = legalContext();
    const selectedSource = context.sources[0];
    const provider = createProviderProfileDraft("deep_seek", "provider-1");
    const markup = renderToStaticMarkup(
      <LegacyQaWorkspace
        caseWorkspace={caseWorkspace(project)}
        controller={controllerFor({
          qa: {
            question: context.query.legalIssue,
            providerId: provider.id,
            activeContext: context,
            selectedSourceId: selectedSource.sourceId,
            selectedSource,
          },
          context: { selectedCaseProjectId: project.projectId },
        })}
        providerProfiles={[provider]}
      />,
    );

    expect(markup).toContain("回答归属：");
    expect(markup).toContain(project.title);
    expect(markup).toContain(provider.displayName);
    expect(markup).not.toContain("转到脱敏批准后问答");
    expect(markup).toContain("请核对候选法律资料后再使用回答");
    expect(markup).toContain(selectedSource.canonicalLabel);
    expect(markup).toContain("当前案件暂无已保存回答");
  });

  it("states that an unassigned QA may search but cannot generate or save", () => {
    const markup = renderToStaticMarkup(
      <LegacyQaWorkspace
        caseWorkspace={null}
        controller={controllerFor()}
        providerProfiles={[]}
      />,
    );

    expect(markup).toContain(
      "未选择已保存案件；可检索来源，但不能生成或保存回答",
    );
    expect(markup).toContain("请先在案件工作台选择案件");
  });
});
