import { FormEvent, useCallback, useEffect, useReducer, useState } from "react";

import {
  addCaseLegalBasis,
  confirmStructuredCaseExtraction,
  deleteCaseEntity,
  deleteCaseProject,
  getCaseWorkspace,
  listCaseProjects,
  generateStructuredCaseExtraction,
  upsertCaseFile,
  upsertCaseFact,
  upsertCaseParty,
  upsertCaseProject,
  upsertEvidenceItem,
  upsertEvidenceLink,
  upsertLegalIssue,
} from "./ipc/case/client";
import {
  formatConfirmationStatus,
  formatGapKind,
  formatGapSeverity,
  formatLegalBasisInvalidReason,
  formatLegalBasisStatus,
  formatLegalIssueStatus,
  formatPartyRole,
} from "./ipc/case/format";
import {
  buildConfirmationRequest,
  createExtractionContext,
  extractionLocksSources,
  extractionReducer,
} from "./ipc/case/extractionReview";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  ConfirmationStatus,
  EvidenceItem,
  LegalBasis,
  LegalIssue,
  LegalIssueStatus,
  PartyRole,
  StructuredCaseExtraction,
} from "./ipc/case/types";
import { formatHealthCheck } from "./ipc/health/format";
import { healthCheck } from "./ipc/health/client";
import type { HealthCheckResponse } from "./ipc/health/types";
import {
  answerLegalQuestion,
  findLegalAnswerCandidates,
  getArticle,
  getLawRelations,
  getLawVersions,
  searchArticles,
  searchLaws,
} from "./ipc/legal/client";
import {
  formatArticleLabel,
  formatCitationInvalidReason,
  formatEffectiveWindow,
  formatLegalSourceLabel,
  formatStatus,
} from "./ipc/legal/format";
import type {
  ArticleSearchResult,
  LawArticleDetail,
  LawRelationInfo,
  LawSearchResult,
  LawVersionInfo,
  LegalAnswerContext,
  LegalAnswerResponse,
  LegalSource,
} from "./ipc/legal/types";
import {
  deleteProviderApiKey,
  deleteProviderProfile,
  getProviderApiKeyStatus,
  listProviderProfiles,
  testProviderConnection,
  upsertProviderProfile,
  writeProviderApiKey,
} from "./ipc/provider/client";
import {
  formatConnectionResult,
  formatHttpStatus,
  formatKeyStatus,
  formatLatency,
  formatProviderKind,
} from "./ipc/provider/format";
import type {
  ConnectionTest,
  ProviderApiKeyStatus,
  ProviderCapabilities,
  ProviderKind,
  ProviderOptions,
  ProviderProfile,
  ReasoningEffort,
} from "./ipc/provider/types";

type ViewMode = "search" | "qa" | "cases" | "providers";

type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; response: HealthCheckResponse }
  | { kind: "error"; message: string };

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string };

const INITIAL_QUERY = "合同";

const PROVIDER_KINDS: ProviderKind[] = [
  "deep_seek",
  "qwen",
  "silicon_flow",
  "volcengine_ark",
];

const DEFAULT_CAPABILITIES: ProviderCapabilities = {
  chat: true,
  streaming: true,
  customModelId: true,
  customBaseUrl: true,
  reasoning: true,
};

const PROVIDER_DEFAULTS: Record<
  ProviderKind,
  { displayName: string; modelId: string; baseUrl: string }
> = {
  deep_seek: {
    displayName: "DeepSeek",
    modelId: "deepseek-chat",
    baseUrl: "https://api.deepseek.com",
  },
  qwen: {
    displayName: "Qwen",
    modelId: "qwen-plus",
    baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  },
  silicon_flow: {
    displayName: "SiliconFlow",
    modelId: "deepseek-ai/DeepSeek-V3",
    baseUrl: "https://api.siliconflow.cn/v1",
  },
  volcengine_ark: {
    displayName: "Volcengine Ark",
    modelId: "doubao-seed-1-6-250615",
    baseUrl: "https://ark.cn-beijing.volces.com/api/v3",
  },
};

function createId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 7)}`;
}

function createProviderProfile(kind: ProviderKind): ProviderProfile {
  const defaults = PROVIDER_DEFAULTS[kind];

  return {
    id: createId(kind),
    displayName: defaults.displayName,
    kind,
    modelId: defaults.modelId,
    baseUrl: defaults.baseUrl,
    credentialAccountId: "default",
    capabilities: DEFAULT_CAPABILITIES,
    options: {},
  };
}

function createCaseProject(): CaseProject {
  return {
    projectId: createId("case"),
    title: "新案件",
    caseType: "民事",
    status: "active",
    openedOn: new Date().toISOString().slice(0, 10),
    summary: "",
    createdAt: "",
    updatedAt: "",
  };
}

function createParty(projectId: string): CaseParty {
  return {
    partyId: createId("party"),
    projectId,
    name: "",
    normalizedName: "",
    role: "plaintiff",
    contact: "",
    notes: "",
  };
}

function createCaseFile(projectId: string): CaseFile {
  return {
    fileId: createId("file"),
    projectId,
    title: "",
    fileType: "材料",
    storageReference: "",
    summary: "",
    createdAt: "",
  };
}

function createFact(projectId: string): CaseFact {
  return {
    factId: createId("fact"),
    projectId,
    occurredOn: null,
    title: "",
    description: "",
    source: "",
    confirmationStatus: "confirmed",
  };
}

function createEvidence(projectId: string, nextIndex: number): EvidenceItem {
  return {
    evidenceId: createId("evidence"),
    projectId,
    evidenceNumber: `E-${nextIndex}`,
    title: "",
    source: "",
    formedOn: null,
    summary: "",
    storageReference: "",
    confirmationStatus: "confirmed",
  };
}

function createIssue(projectId: string): LegalIssue {
  return {
    issueId: createId("issue"),
    projectId,
    title: "",
    description: "",
    claim: "",
    status: "open",
    confirmationStatus: "confirmed",
  };
}

function formatLegalBasisTitle(basis: LegalBasis): string {
  if (!basis.documentTitle || !basis.articleNumber) {
    return basis.sourceId;
  }

  const suffix = basis.articleTitle ? `：${basis.articleTitle}` : "";

  return `《${basis.documentTitle}》${basis.articleNumber}${suffix}`;
}

function formatLegalBasisWindow(basis: LegalBasis): string {
  if (!basis.effectiveFrom) {
    return "未校验效力";
  }

  return formatEffectiveWindow(basis.effectiveFrom, basis.effectiveTo);
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof (error as { message: unknown }).message === "string"
  ) {
    return (error as { message: string }).message;
  }

  return String(error);
}

function normalizeProfile(profile: ProviderProfile): ProviderProfile {
  return {
    ...profile,
    id: profile.id.trim(),
    displayName: profile.displayName.trim(),
    modelId: profile.modelId.trim(),
    baseUrl: profile.baseUrl.trim(),
    credentialAccountId: profile.credentialAccountId.trim() || "default",
    options: normalizeOptions(profile.options),
  };
}

function normalizeOptions(options: ProviderOptions): ProviderOptions {
  return {
    thinking: options.thinking ?? null,
    enableThinking: options.enableThinking ?? null,
    thinkingBudget: options.thinkingBudget ?? null,
    reasoningEffort: options.reasoningEffort ?? null,
    endpointId: options.endpointId?.trim() || null,
    workspaceId: options.workspaceId?.trim() || null,
  };
}

function splitKeywords(value: string): string[] {
  return value
    .split(/[\s,，、;；]+/u)
    .map((keyword) => keyword.trim())
    .filter(Boolean);
}

export function App() {
  const [viewMode, setViewMode] = useState<ViewMode>("search");
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [query, setQuery] = useState(INITIAL_QUERY);
  const [caseDate, setCaseDate] = useState("");
  const [searchState, setSearchState] = useState<LoadState>({ kind: "idle" });
  const [detailState, setDetailState] = useState<LoadState>({ kind: "idle" });
  const [documentState, setDocumentState] = useState<LoadState>({
    kind: "idle",
  });
  const [laws, setLaws] = useState<LawSearchResult[]>([]);
  const [articles, setArticles] = useState<ArticleSearchResult[]>([]);
  const [selectedDocument, setSelectedDocument] =
    useState<LawSearchResult | null>(null);
  const [versions, setVersions] = useState<LawVersionInfo[]>([]);
  const [relations, setRelations] = useState<LawRelationInfo[]>([]);
  const [selectedArticleId, setSelectedArticleId] = useState<string | null>(
    null,
  );
  const [selectedArticle, setSelectedArticle] =
    useState<LawArticleDetail | null>(null);

  const [qaState, setQaState] = useState<LoadState>({ kind: "idle" });
  const [qaQuestion, setQaQuestion] = useState("合同违约责任如何承担？");
  const [qaLawName, setQaLawName] = useState("");
  const [qaArticleNumber, setQaArticleNumber] = useState("");
  const [qaKeywords, setQaKeywords] = useState("违约责任");
  const [qaCaseDate, setQaCaseDate] = useState("");
  const [qaIncludeExpired, setQaIncludeExpired] = useState(false);
  const [qaProviderId, setQaProviderId] = useState("");
  const [qaContext, setQaContext] = useState<LegalAnswerContext | null>(null);
  const [qaAnswer, setQaAnswer] = useState<LegalAnswerResponse | null>(null);
  const [selectedQaSourceId, setSelectedQaSourceId] = useState<string | null>(
    null,
  );

  const [providerState, setProviderState] = useState<LoadState>({
    kind: "idle",
  });
  const [providerProfiles, setProviderProfiles] = useState<ProviderProfile[]>(
    [],
  );
  const [providerDraft, setProviderDraft] = useState<ProviderProfile>(() =>
    createProviderProfile("deep_seek"),
  );
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
    null,
  );
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [keyStatuses, setKeyStatuses] = useState<
    Record<string, ProviderApiKeyStatus>
  >({});
  const [connectionResults, setConnectionResults] = useState<
    Record<string, ConnectionTest>
  >({});

  const [caseState, setCaseState] = useState<LoadState>({ kind: "idle" });
  const [caseProjects, setCaseProjects] = useState<CaseProject[]>([]);
  const [selectedCaseProjectId, setSelectedCaseProjectId] = useState<
    string | null
  >(null);
  const [caseWorkspace, setCaseWorkspace] = useState<CaseWorkspace | null>(
    null,
  );
  const [caseProjectDraft, setCaseProjectDraft] = useState<CaseProject>(() =>
    createCaseProject(),
  );
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
  const [extractionProviderId, setExtractionProviderId] = useState("");
  const [extractionFileIds, setExtractionFileIds] = useState<string[]>([]);
  const [extractionState, dispatchExtraction] = useReducer(extractionReducer, {
    kind: "idle",
  });
  const extractionSourcesLocked = extractionLocksSources(extractionState);

  useEffect(() => {
    let isMounted = true;

    healthCheck()
      .then((response) => {
        if (isMounted) {
          setHealth({ kind: "ready", response });
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setHealth({ kind: "error", message: errorMessage(error) });
        }
      });

    async function loadInitialSearch() {
      setSearchState({ kind: "loading" });

      try {
        const [lawResponse, articleResponse] = await Promise.all([
          searchLaws({ query: INITIAL_QUERY, limit: 12 }),
          searchArticles({ query: INITIAL_QUERY, limit: 24 }),
        ]);

        if (!isMounted) {
          return;
        }

        setLaws(lawResponse.results);
        setArticles(articleResponse.results);
        setSearchState({ kind: "idle" });

        const initialArticle = articleResponse.results[0];
        if (initialArticle) {
          setSelectedArticleId(initialArticle.articleId);
          setDetailState({ kind: "loading" });
          const detailResponse = await getArticle({
            articleId: initialArticle.articleId,
          });

          if (isMounted) {
            setSelectedArticle(detailResponse.article ?? null);
            setDetailState({ kind: "idle" });
          }
        }
      } catch (error: unknown) {
        if (isMounted) {
          setSearchState({ kind: "error", message: errorMessage(error) });
          setDetailState({ kind: "error", message: errorMessage(error) });
        }
      }
    }

    void loadInitialSearch();

    return () => {
      isMounted = false;
    };
  }, []);

  const refreshKeyStatus = useCallback(async (profile: ProviderProfile) => {
    const response = await getProviderApiKeyStatus({
      providerId: profile.id,
      accountId: profile.credentialAccountId,
    });

    setKeyStatuses((current) => ({
      ...current,
      [profile.id]: response.status,
    }));
  }, []);

  useEffect(() => {
    let isMounted = true;

    listProviderProfiles()
      .then(async (response) => {
        if (!isMounted) {
          return;
        }

        setProviderProfiles(response.profiles);

        if (response.profiles.length > 0) {
          setSelectedProviderId(response.profiles[0].id);
          setQaProviderId(response.profiles[0].id);
          setExtractionProviderId(response.profiles[0].id);
          setProviderDraft(response.profiles[0]);
        }

        const statuses = await Promise.all(
          response.profiles.map(async (profile) => {
            const statusResponse = await getProviderApiKeyStatus({
              providerId: profile.id,
              accountId: profile.credentialAccountId,
            });

            return [profile.id, statusResponse.status] as const;
          }),
        );

        if (isMounted) {
          setKeyStatuses(Object.fromEntries(statuses));
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setProviderState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  async function loadCaseWorkspace(projectId: string) {
    setCaseState({ kind: "loading" });

    try {
      const response = await getCaseWorkspace({ projectId });
      const workspace = response.workspace ?? null;
      setCaseWorkspace(workspace);

      if (workspace) {
        setSelectedCaseProjectId(workspace.project.projectId);
        setCaseProjectDraft(workspace.project);
        setFileDraft(createCaseFile(workspace.project.projectId));
        setPartyDraft(createParty(workspace.project.projectId));
        setFactDraft(createFact(workspace.project.projectId));
        setEvidenceDraft(
          createEvidence(workspace.project.projectId, workspace.evidence.length + 1),
        );
        setIssueDraft(createIssue(workspace.project.projectId));
        setBasisSourceId("");
        setBasisIssueId(workspace.legalIssues[0]?.issueId ?? "");
        setBasisCaseDate(workspace.project.openedOn ?? "");
        setBasisIncludeExpired(false);
        setBasisNote("");
        setLinkFactId(workspace.facts[0]?.factId ?? "");
        setLinkEvidenceId(workspace.evidence[0]?.evidenceId ?? "");
        const availableFileIds = new Set(
          workspace.files.map((file) => file.fileId),
        );
        setExtractionFileIds((current) =>
          current.filter((fileId) => availableFileIds.has(fileId)),
        );
      }

      setCaseState({ kind: "idle" });
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function refreshCaseProjects(preferredProjectId?: string) {
    try {
      const response = await listCaseProjects();
      setCaseProjects(response.projects);
      const nextProject =
        response.projects.find(
          (project) => project.projectId === preferredProjectId,
        ) ?? response.projects[0];

      if (nextProject) {
        await loadCaseWorkspace(nextProject.projectId);
      }
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  useEffect(() => {
    let isMounted = true;

    listCaseProjects()
      .then(async (response) => {
        if (!isMounted) {
          return;
        }

        setCaseProjects(response.projects);
        const firstProject = response.projects[0];

        if (firstProject) {
          const workspaceResponse = await getCaseWorkspace({
            projectId: firstProject.projectId,
          });

          if (isMounted && workspaceResponse.workspace) {
            setSelectedCaseProjectId(firstProject.projectId);
            setCaseWorkspace(workspaceResponse.workspace);
            setCaseProjectDraft(workspaceResponse.workspace.project);
            setFileDraft(createCaseFile(firstProject.projectId));
            setPartyDraft(createParty(firstProject.projectId));
            setFactDraft(createFact(firstProject.projectId));
            setEvidenceDraft(
              createEvidence(
                firstProject.projectId,
                workspaceResponse.workspace.evidence.length + 1,
              ),
            );
            setIssueDraft(createIssue(firstProject.projectId));
            setBasisSourceId("");
            setBasisIssueId(
              workspaceResponse.workspace.legalIssues[0]?.issueId ?? "",
            );
            setBasisCaseDate(workspaceResponse.workspace.project.openedOn ?? "");
            setBasisIncludeExpired(false);
            setBasisNote("");
            setLinkFactId(workspaceResponse.workspace.facts[0]?.factId ?? "");
            setLinkEvidenceId(
              workspaceResponse.workspace.evidence[0]?.evidenceId ?? "",
            );
          }
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setCaseState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  async function runSearch(documentId: string | null) {
    const normalizedQuery = query.trim();

    setSearchState({ kind: "loading" });

    try {
      const [lawResponse, articleResponse] = await Promise.all([
        searchLaws({ query: normalizedQuery, limit: 12 }),
        searchArticles({
          query: normalizedQuery,
          documentId,
          caseDate: caseDate || null,
          limit: 24,
        }),
      ]);

      setLaws(lawResponse.results);
      setArticles(articleResponse.results);
      setSearchState({ kind: "idle" });

      if (articleResponse.results[0]) {
        await loadArticleDetail(articleResponse.results[0].articleId);
      } else {
        setSelectedArticleId(null);
        setSelectedArticle(null);
      }
    } catch (error: unknown) {
      setSearchState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function loadArticleDetail(articleId: string) {
    setSelectedArticleId(articleId);
    setDetailState({ kind: "loading" });

    try {
      const response = await getArticle({ articleId });
      setSelectedArticle(response.article ?? null);
      setDetailState({ kind: "idle" });
    } catch (error: unknown) {
      setDetailState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function loadDocumentContext(document: LawSearchResult) {
    setSelectedDocument(document);
    setDocumentState({ kind: "loading" });

    try {
      const [versionResponse, relationResponse] = await Promise.all([
        getLawVersions({ documentId: document.documentId }),
        getLawRelations({ documentId: document.documentId, direction: "both" }),
      ]);

      setVersions(versionResponse.versions);
      setRelations(relationResponse.relations);
      setDocumentState({ kind: "idle" });
      await runSearch(document.documentId);
    } catch (error: unknown) {
      setDocumentState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function clearDocumentFilter() {
    setSelectedDocument(null);
    setVersions([]);
    setRelations([]);
    setDocumentState({ kind: "idle" });
    await runSearch(null);
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runSearch(selectedDocument?.documentId ?? null);
  }

  function buildLegalAnswerCandidateRequest() {
    return {
      question: qaQuestion.trim(),
      lawName: qaLawName.trim() || null,
      articleNumber: qaArticleNumber.trim() || null,
      keywords: splitKeywords(qaKeywords),
      caseDate: qaCaseDate || null,
      effectivenessLevels: [],
      includeExpired: qaIncludeExpired,
      limit: 8,
    };
  }

  async function previewLegalAnswerContext(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const request = buildLegalAnswerCandidateRequest();
    if (!request.question) {
      setQaState({ kind: "error", message: "请输入法律问题" });
      return;
    }

    setQaState({ kind: "loading" });
    setQaAnswer(null);

    try {
      const response = await findLegalAnswerCandidates(request);
      setQaContext(response.context);
      setSelectedQaSourceId(response.context.sources[0]?.sourceId ?? null);
      setQaState({ kind: "idle" });
    } catch (error: unknown) {
      setQaState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function submitLegalAnswer(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const request = buildLegalAnswerCandidateRequest();
    if (!request.question) {
      setQaState({ kind: "error", message: "请输入法律问题" });
      return;
    }
    if (!qaProviderId) {
      setQaState({ kind: "error", message: "请先选择已保存的 Provider" });
      return;
    }

    setQaState({ kind: "loading" });

    try {
      const response = await answerLegalQuestion({
        ...request,
        providerId: qaProviderId,
        temperature: 0.1,
        maxTokens: 1024,
      });
      setQaAnswer(response);
      setQaContext(response.context);
      setSelectedQaSourceId(response.context.sources[0]?.sourceId ?? null);
      setQaState({ kind: "idle" });
    } catch (error: unknown) {
      setQaState({ kind: "error", message: errorMessage(error) });
    }
  }

  function selectQaSource(source: LegalSource) {
    setSelectedQaSourceId(source.sourceId);
  }

  function startNewCaseProject() {
    const project = createCaseProject();
    setSelectedCaseProjectId(null);
    setCaseWorkspace(null);
    setCaseProjectDraft(project);
    setFileDraft(createCaseFile(project.projectId));
    setPartyDraft(createParty(project.projectId));
    setFactDraft(createFact(project.projectId));
    setEvidenceDraft(createEvidence(project.projectId, 1));
    setIssueDraft(createIssue(project.projectId));
    setBasisSourceId("");
    setBasisIssueId("");
    setBasisCaseDate(project.openedOn ?? "");
    setBasisIncludeExpired(false);
    setBasisNote("");
    setLinkFactId("");
    setLinkEvidenceId("");
    setExtractionFileIds([]);
    dispatchExtraction({ type: "reset" });
    setCaseState({ kind: "idle" });
  }

  function selectCaseProject(project: CaseProject) {
    setExtractionFileIds([]);
    dispatchExtraction({ type: "reset" });
    void loadCaseWorkspace(project.projectId);
  }

  async function saveCaseProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const project = {
      ...caseProjectDraft,
      title: caseProjectDraft.title.trim() || "未命名案件",
      caseType: caseProjectDraft.caseType.trim(),
      summary: caseProjectDraft.summary.trim(),
      openedOn: caseProjectDraft.openedOn || null,
    };

    setCaseState({ kind: "loading" });

    try {
      const response = await upsertCaseProject({ project });
      setCaseProjectDraft(response.project);
      setBasisCaseDate(response.project.openedOn ?? "");
      await refreshCaseProjects(response.project.projectId);
      setCaseState({ kind: "idle" });
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function removeCaseProject() {
    if (!selectedCaseProjectId) {
      return;
    }

    setCaseState({ kind: "loading" });

    try {
      await deleteCaseProject({ projectId: selectedCaseProjectId });
      startNewCaseProject();
      await refreshCaseProjects();
      setCaseState({ kind: "idle" });
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveParty(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!caseWorkspace && !selectedCaseProjectId) {
      return;
    }

    const party = {
      ...partyDraft,
      projectId: caseProjectDraft.projectId,
      name: partyDraft.name.trim(),
      normalizedName: partyDraft.normalizedName.trim(),
    };

    if (!party.name) {
      return;
    }

    try {
      await upsertCaseParty({ party });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setPartyDraft(createParty(caseProjectDraft.projectId));
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = {
      ...fileDraft,
      projectId: caseProjectDraft.projectId,
      title: fileDraft.title.trim(),
      fileType: fileDraft.fileType.trim(),
      storageReference: fileDraft.storageReference.trim(),
      summary: fileDraft.summary.trim(),
    };

    if (!file.title) {
      return;
    }

    try {
      await upsertCaseFile({ file });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setFileDraft(createCaseFile(caseProjectDraft.projectId));
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveFact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fact = {
      ...factDraft,
      projectId: caseProjectDraft.projectId,
      title: factDraft.title.trim(),
      occurredOn: factDraft.occurredOn || null,
    };

    if (!fact.title) {
      return;
    }

    try {
      await upsertCaseFact({ fact });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setFactDraft(createFact(caseProjectDraft.projectId));
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveEvidence(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const evidence = {
      ...evidenceDraft,
      projectId: caseProjectDraft.projectId,
      evidenceNumber: evidenceDraft.evidenceNumber.trim(),
      title: evidenceDraft.title.trim(),
      formedOn: evidenceDraft.formedOn || null,
    };

    if (!evidence.evidenceNumber || !evidence.title) {
      return;
    }

    try {
      await upsertEvidenceItem({ evidence });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setEvidenceDraft(
        createEvidence(
          caseProjectDraft.projectId,
          (caseWorkspace?.evidence.length ?? 0) + 2,
        ),
      );
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveIssue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const issue = {
      ...issueDraft,
      projectId: caseProjectDraft.projectId,
      title: issueDraft.title.trim(),
    };

    if (!issue.title) {
      return;
    }

    try {
      await upsertLegalIssue({ issue });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setIssueDraft(createIssue(caseProjectDraft.projectId));
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveLegalBasis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!caseWorkspace || !basisSourceId.trim()) {
      return;
    }

    try {
      await addCaseLegalBasis({
        projectId: caseProjectDraft.projectId,
        issueId: basisIssueId || null,
        sourceId: basisSourceId.trim(),
        caseDate: basisCaseDate || null,
        includeExpired: basisIncludeExpired,
        note: basisNote.trim(),
      });
      await loadCaseWorkspace(caseProjectDraft.projectId);
      setBasisSourceId("");
      setBasisNote("");
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function linkEvidenceToFact() {
    if (!linkFactId || !linkEvidenceId) {
      return;
    }

    try {
      await upsertEvidenceLink({
        link: {
          linkId: createId("link"),
          projectId: caseProjectDraft.projectId,
          factId: linkFactId,
          evidenceId: linkEvidenceId,
        },
      });
      await loadCaseWorkspace(caseProjectDraft.projectId);
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function removeCaseEntity(
    entityType:
      | "file"
      | "party"
      | "fact"
      | "evidence"
      | "evidence_link"
      | "legal_issue"
      | "legal_basis"
      | "uncertainty",
    id: string,
  ) {
    try {
      await deleteCaseEntity({ entityType, id });
      await loadCaseWorkspace(caseProjectDraft.projectId);
    } catch (error: unknown) {
      setCaseState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function runStructuredExtraction() {
    if (
      !caseWorkspace ||
      !extractionProviderId ||
      extractionFileIds.length === 0
    ) {
      return;
    }

    const context = createExtractionContext(
      createId("extraction-request"),
      caseWorkspace.project.projectId,
      extractionProviderId,
      extractionFileIds,
    );
    dispatchExtraction({ type: "start", context });
    try {
      const response = await generateStructuredCaseExtraction({
        projectId: context.projectId,
        providerId: context.providerId,
        fileIds: context.sourceFileIds,
      });
      if (
        response.result.status === "review_required" &&
        response.result.extraction &&
        response.result.reviewId
      ) {
        dispatchExtraction({
          type: "generated",
          requestId: context.requestId,
          reviewId: response.result.reviewId,
          draft: response.result.extraction,
          repaired: response.result.repaired,
        });
      } else {
        dispatchExtraction({
          type: "failed",
          requestId: context.requestId,
          message: response.result.error?.message ?? "结构化抽取失败",
          repairAttempted: response.result.repairAttempted,
          rawOutput: response.result.rawOutput,
          repairOutput: response.result.repairOutput,
        });
      }
    } catch (error: unknown) {
      dispatchExtraction({
        type: "failed",
        requestId: context.requestId,
        message: errorMessage(error),
        repairAttempted: false,
      });
    }
  }

  function updateExtractionDraft(
    update: (draft: StructuredCaseExtraction) => StructuredCaseExtraction,
  ) {
    if (extractionState.kind === "reviewing") {
      dispatchExtraction({
        type: "edit",
        draft: update(extractionState.draft),
      });
    }
  }

  function cancelExtractionReview() {
    dispatchExtraction({ type: "cancel" });
  }

  async function confirmExtractionReview() {
    const confirmation = buildConfirmationRequest(extractionState);
    if (!confirmation) {
      return;
    }
    dispatchExtraction({ type: "begin_commit" });
    try {
      const response = await confirmStructuredCaseExtraction(confirmation);
      await loadCaseWorkspace(confirmation.projectId);
      dispatchExtraction({
        type: "committed",
        message: `已原子写入 ${response.counts.facts} 项事实、${response.counts.evidence} 项证据和 ${response.counts.uncertainties} 项待核实事项。`,
      });
    } catch (error: unknown) {
      const message = errorMessage(error);
      dispatchExtraction({ type: "commit_failed", message });
      setCaseState({ kind: "error", message });
    }
  }

  function startNewProvider(kind: ProviderKind) {
    const profile = createProviderProfile(kind);
    setSelectedProviderId(null);
    setProviderDraft(profile);
    setApiKeyInput("");
    setProviderState({ kind: "idle" });
  }

  function selectProvider(profile: ProviderProfile) {
    setSelectedProviderId(profile.id);
    setProviderDraft(profile);
    setApiKeyInput("");
    setProviderState({ kind: "idle" });
  }

  function updateProviderKind(kind: ProviderKind) {
    const defaults = PROVIDER_DEFAULTS[kind];
    setProviderDraft((current) => ({
      ...current,
      kind,
      displayName: defaults.displayName,
      modelId: defaults.modelId,
      baseUrl: defaults.baseUrl,
    }));
  }

  function updateOptions(patch: Partial<ProviderOptions>) {
    setProviderDraft((current) => ({
      ...current,
      options: {
        ...current.options,
        ...patch,
      },
    }));
  }

  async function saveProvider(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const profile = normalizeProfile(providerDraft);

    setProviderState({ kind: "loading" });

    try {
      const response = await upsertProviderProfile({ profile });
      setProviderProfiles((current) => {
        const others = current.filter((item) => item.id !== response.profile.id);
        return [response.profile, ...others];
      });
      setProviderDraft(response.profile);
      setSelectedProviderId(response.profile.id);
      setExtractionProviderId((current) => current || response.profile.id);
      await refreshKeyStatus(response.profile);
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function saveApiKey() {
    const profile = normalizeProfile(providerDraft);
    const apiKey = apiKeyInput.trim();

    if (!apiKey) {
      return;
    }

    setProviderState({ kind: "loading" });

    try {
      const response = await writeProviderApiKey({
        providerId: profile.id,
        accountId: profile.credentialAccountId,
        apiKey,
      });
      setKeyStatuses((current) => ({
        ...current,
        [profile.id]: response.status,
      }));
      setApiKeyInput("");
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function removeApiKey() {
    const profile = normalizeProfile(providerDraft);
    setProviderState({ kind: "loading" });

    try {
      const response = await deleteProviderApiKey({
        providerId: profile.id,
        accountId: profile.credentialAccountId,
      });
      setKeyStatuses((current) => ({
        ...current,
        [profile.id]: response.status,
      }));
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function removeProvider() {
    const profileId = providerDraft.id;
    if (
      extractionSourcesLocked &&
      "context" in extractionState &&
      extractionState.context.providerId === profileId
    ) {
      setProviderState({
        kind: "error",
        message: "请先取消当前案件抽取审阅，再删除本轮使用的 Provider。",
      });
      return;
    }
    setProviderState({ kind: "loading" });

    try {
      await deleteProviderProfile({ providerId: profileId });
      const remaining = providerProfiles.filter(
        (profile) => profile.id !== profileId,
      );
      setProviderProfiles(remaining);
      setKeyStatuses((current) => {
        const next = { ...current };
        delete next[profileId];
        return next;
      });
      setConnectionResults((current) => {
        const next = { ...current };
        delete next[profileId];
        return next;
      });

      if (remaining[0]) {
        setSelectedProviderId(remaining[0].id);
        setProviderDraft(remaining[0]);
        setExtractionProviderId((current) =>
          current === profileId ? remaining[0].id : current,
        );
      } else {
        setExtractionProviderId("");
        startNewProvider("deep_seek");
      }

      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function runProviderConnectionTest() {
    const profile = normalizeProfile(providerDraft);
    setProviderState({ kind: "loading" });

    try {
      const response = await testProviderConnection({ providerId: profile.id });
      setConnectionResults((current) => ({
        ...current,
        [profile.id]: response.result,
      }));
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  const healthText =
    health.kind === "ready"
      ? formatHealthCheck(health.response)
      : health.kind === "error"
        ? health.message
        : "正在调用 Rust command...";
  const currentKeyStatus = keyStatuses[providerDraft.id];
  const currentConnectionResult = connectionResults[providerDraft.id];
  const providerIsSaved = providerProfiles.some(
    (profile) => profile.id === providerDraft.id,
  );
  const providerHasKey = currentKeyStatus?.configured ?? false;
  const activeQaContext = qaAnswer?.context ?? qaContext;
  const selectedQaSource =
    activeQaContext?.sources.find(
      (source) => source.sourceId === selectedQaSourceId,
    ) ??
    activeQaContext?.sources[0] ??
    null;

  return (
    <main className="app-shell">
      <header className="top-bar">
        <div>
          <p className="eyebrow">
            {viewMode === "search"
              ? "离线法律库"
              : viewMode === "qa"
                ? "来源受限回答"
              : viewMode === "cases"
                ? "案件与证据"
                : "BYOK Provider"}
          </p>
          <h1>
            {viewMode === "search"
              ? "法律检索"
              : viewMode === "qa"
                ? "引用问答"
              : viewMode === "cases"
                ? "案件工作台"
                : "模型供应商设置"}
          </h1>
        </div>
        <div className="top-actions">
          <nav className="view-tabs" aria-label="主视图">
            <button
              className={viewMode === "search" ? "is-active" : ""}
              type="button"
              onClick={() => setViewMode("search")}
            >
              法律检索
            </button>
            <button
              className={viewMode === "qa" ? "is-active" : ""}
              type="button"
              onClick={() => setViewMode("qa")}
            >
              引用问答
            </button>
            <button
              className={viewMode === "cases" ? "is-active" : ""}
              type="button"
              onClick={() => setViewMode("cases")}
            >
              案件工作台
            </button>
            <button
              className={viewMode === "providers" ? "is-active" : ""}
              type="button"
              onClick={() => setViewMode("providers")}
            >
              Provider 设置
            </button>
          </nav>
          <div className="health-chip" role="status" aria-live="polite">
            <span className={`status-dot status-dot--${health.kind}`} />
            <span>{healthText}</span>
          </div>
        </div>
      </header>

      {viewMode === "search" ? (
        <>
          <section className="query-band" aria-label="检索条件">
            <form className="search-form" onSubmit={submitSearch}>
              <label>
                <span>关键词</span>
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="法律名称、条文关键词"
                />
              </label>
              <label>
                <span>案件日期</span>
                <input
                  type="date"
                  value={caseDate}
                  onChange={(event) => setCaseDate(event.target.value)}
                />
              </label>
              <button type="submit">检索</button>
            </form>

            <div className="filter-row">
              <span>
                {selectedDocument
                  ? `当前法律：${selectedDocument.title}`
                  : "全部法律"}
              </span>
              {selectedDocument ? (
                <button
                  type="button"
                  onClick={() => void clearDocumentFilter()}
                >
                  清除筛选
                </button>
              ) : null}
            </div>
          </section>

          <section className="workspace-grid">
            <aside
              className="panel law-panel"
              aria-labelledby="law-panel-title"
            >
              <div className="panel-heading">
                <h2 id="law-panel-title">法律</h2>
                <span>{laws.length}</span>
              </div>
              {searchState.kind === "error" ? (
                <p className="error-text">{searchState.message}</p>
              ) : null}
              <div className="result-list">
                {laws.map((law) => (
                  <button
                    className={`law-item ${
                      selectedDocument?.documentId === law.documentId
                        ? "is-selected"
                        : ""
                    }`}
                    key={law.documentId}
                    type="button"
                    onClick={() => void loadDocumentContext(law)}
                  >
                    <span className="item-title">{law.title}</span>
                    <span className="item-meta">
                      {formatStatus(law.status)} · {law.authorityName}
                    </span>
                    <span className="item-summary">{law.summary}</span>
                  </button>
                ))}
              </div>
            </aside>

            <section
              className="panel article-panel"
              aria-labelledby="article-title"
            >
              <div className="panel-heading">
                <h2 id="article-title">法条</h2>
                <span>
                  {searchState.kind === "loading" ? "检索中" : articles.length}
                </span>
              </div>
              <div className="article-list">
                {articles.map((article) => (
                  <button
                    className={`article-item ${
                      selectedArticleId === article.articleId
                        ? "is-selected"
                        : ""
                    }`}
                    key={article.articleId}
                    type="button"
                    onClick={() => void loadArticleDetail(article.articleId)}
                  >
                    <span className="item-title">
                      {formatArticleLabel(article)}
                    </span>
                    <span className="item-meta">
                      {formatStatus(article.versionStatus)} ·{" "}
                      {formatEffectiveWindow(
                        article.effectiveFrom,
                        article.effectiveTo,
                      )}
                    </span>
                    <span className="item-summary">{article.snippet}</span>
                  </button>
                ))}
              </div>
            </section>

            <aside
              className="panel detail-panel"
              aria-labelledby="detail-title"
            >
              <div className="panel-heading">
                <h2 id="detail-title">详情</h2>
                <span>{detailState.kind === "loading" ? "读取中" : "本地"}</span>
              </div>

              {detailState.kind === "error" ? (
                <p className="error-text">{detailState.message}</p>
              ) : null}

              {selectedArticle ? (
                <article className="article-detail">
                  <p className="detail-kicker">
                    {selectedArticle.canonicalLabel}
                  </p>
                  <h3>{formatArticleLabel(selectedArticle)}</h3>
                  <p className="article-content">{selectedArticle.content}</p>
                  <dl className="meta-grid">
                    <div>
                      <dt>引用 ID</dt>
                      <dd>{selectedArticle.citationId}</dd>
                    </div>
                    <div>
                      <dt>效力期间</dt>
                      <dd>
                        {formatEffectiveWindow(
                          selectedArticle.effectiveFrom,
                          selectedArticle.effectiveTo,
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>主题</dt>
                      <dd>
                        {selectedArticle.topics.length > 0
                          ? selectedArticle.topics.join("、")
                          : "未标注"}
                      </dd>
                    </div>
                  </dl>
                </article>
              ) : (
                <p className="empty-state">暂无法条详情</p>
              )}

              <section className="detail-section" aria-labelledby="version-title">
                <div className="section-heading">
                  <h3 id="version-title">版本</h3>
                  <span>
                    {documentState.kind === "loading"
                      ? "读取中"
                      : versions.length}
                  </span>
                </div>
                <div className="compact-list">
                  {versions.map((version) => (
                    <div className="compact-row" key={version.versionId}>
                      <strong>{version.versionLabel}</strong>
                      <span>
                        {formatStatus(version.status)} ·{" "}
                        {formatEffectiveWindow(
                          version.effectiveFrom,
                          version.effectiveTo,
                        )}
                      </span>
                      <span>{version.articleCount} 条</span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="detail-section" aria-labelledby="relation-title">
                <div className="section-heading">
                  <h3 id="relation-title">关系</h3>
                  <span>{relations.length}</span>
                </div>
                <div className="compact-list">
                  {relations.map((relation) => (
                    <div className="compact-row" key={relation.relationId}>
                      <strong>
                        {formatStatus(relation.relationType)} ·{" "}
                        {relation.toTitle}
                      </strong>
                      <span>{relation.description}</span>
                      <span>{relation.sourceReference}</span>
                    </div>
                  ))}
                </div>
              </section>
            </aside>
          </section>
        </>
      ) : viewMode === "qa" ? (
        <section className="qa-layout">
          <aside className="panel qa-control-panel" aria-labelledby="qa-control-title">
            <div className="panel-heading">
              <h2 id="qa-control-title">问题</h2>
              <span>{qaState.kind === "loading" ? "处理中" : "本地优先"}</span>
            </div>
            <form className="qa-form" onSubmit={submitLegalAnswer}>
              <label>
                <span>法律问题</span>
                <textarea
                  value={qaQuestion}
                  onChange={(event) => setQaQuestion(event.target.value)}
                  placeholder="输入需要检索和回答的法律问题"
                />
              </label>
              <div className="form-grid">
                <label>
                  <span>法律名称</span>
                  <input
                    value={qaLawName}
                    onChange={(event) => setQaLawName(event.target.value)}
                    placeholder="如：民法典"
                  />
                </label>
                <label>
                  <span>条号</span>
                  <input
                    value={qaArticleNumber}
                    onChange={(event) => setQaArticleNumber(event.target.value)}
                    placeholder="如：第五百七十七条"
                  />
                </label>
              </div>
              <label>
                <span>关键词</span>
                <input
                  value={qaKeywords}
                  onChange={(event) => setQaKeywords(event.target.value)}
                  placeholder="空格、逗号或顿号分隔"
                />
              </label>
              <div className="form-grid">
                <label>
                  <span>案件日期</span>
                  <input
                    type="date"
                    value={qaCaseDate}
                    onChange={(event) => setQaCaseDate(event.target.value)}
                  />
                </label>
                <label>
                  <span>Provider</span>
                  <select
                    value={qaProviderId}
                    onChange={(event) => setQaProviderId(event.target.value)}
                  >
                    <option value="">选择 Provider</option>
                    {providerProfiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.displayName}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={qaIncludeExpired}
                  onChange={(event) =>
                    setQaIncludeExpired(event.target.checked)
                  }
                />
                <span>包含失效版本</span>
              </label>
              <div className="command-row">
                <button
                  type="button"
                  onClick={() => void previewLegalAnswerContext()}
                >
                  本地检索来源
                </button>
                <button type="submit" disabled={!qaProviderId}>
                  生成带引用回答
                </button>
              </div>
            </form>
            {qaState.kind === "error" ? (
              <p className="error-text">{qaState.message}</p>
            ) : null}
            <section className="detail-section" aria-labelledby="qa-source-title">
              <div className="section-heading">
                <h3 id="qa-source-title">候选来源</h3>
                <span>{activeQaContext?.sources.length ?? 0}</span>
              </div>
              <div className="source-list">
                {activeQaContext?.sources.map((source) => (
                  <button
                    className={`source-item ${
                      selectedQaSource?.sourceId === source.sourceId
                        ? "is-selected"
                        : ""
                    }`}
                    key={source.sourceId}
                    type="button"
                    onClick={() => selectQaSource(source)}
                  >
                    <span className="item-title">
                      {formatLegalSourceLabel(source)}
                    </span>
                    <span className="item-meta">
                      {formatStatus(source.versionStatus)} ·{" "}
                      {formatEffectiveWindow(
                        source.effectiveFrom,
                        source.effectiveTo,
                      )}
                    </span>
                    <span className="item-summary">{source.snippet}</span>
                  </button>
                ))}
                {activeQaContext && activeQaContext.sources.length === 0 ? (
                  <p className="empty-state">未找到本地候选来源</p>
                ) : null}
              </div>
            </section>
          </aside>

          <section className="panel qa-answer-panel" aria-labelledby="qa-answer-title">
            <div className="panel-heading">
              <h2 id="qa-answer-title">回答</h2>
              <span>
                {qaAnswer
                  ? `${qaAnswer.citationReport.validCount} 个有效引用`
                  : "等待生成"}
              </span>
            </div>
            {qaState.kind === "loading" ? (
              <p className="empty-state">正在检索来源或等待 provider 返回。</p>
            ) : null}
            {qaAnswer ? (
              <>
                {qaAnswer.citationReport.unsupportedLegalConclusion ? (
                  <p className="risk-banner">存在未被有效来源支持的法律结论</p>
                ) : null}
                <article className="answer-box">
                  <p>{qaAnswer.answer}</p>
                </article>
                <div className="answer-meta-row">
                  <span>记录：{qaAnswer.recordId ?? "未保存"}</span>
                  <span>{qaAnswer.streamEvents.length} 个流式事件</span>
                </div>
                <section className="detail-section" aria-labelledby="qa-citation-title">
                  <div className="section-heading">
                    <h3 id="qa-citation-title">引用校验</h3>
                    <span>
                      {qaAnswer.citationReport.invalidCount > 0
                        ? `${qaAnswer.citationReport.invalidCount} 个无效`
                        : "全部通过"}
                    </span>
                  </div>
                  <div className="citation-list">
                    {qaAnswer.citationReport.citations.map((citation) => (
                      <button
                        className={`citation-item citation-item--${citation.status}`}
                        key={`${citation.rawMarker}-${citation.sourceId}`}
                        type="button"
                        onClick={() =>
                          citation.source
                            ? setSelectedQaSourceId(citation.source.sourceId)
                            : undefined
                        }
                      >
                        <strong>{citation.rawMarker}</strong>
                        <span>
                          {citation.status === "valid"
                            ? "已映射到本地原文"
                            : formatCitationInvalidReason(citation.reason)}
                        </span>
                      </button>
                    ))}
                    {qaAnswer.citationReport.citations.length === 0 ? (
                      <p className="empty-state">回答中没有可校验引用</p>
                    ) : null}
                  </div>
                </section>
              </>
            ) : (
              <p className="empty-state">
                先检索本地来源；配置 Provider 和 API Key 后再生成回答。
              </p>
            )}
          </section>

          <aside className="panel qa-source-detail" aria-labelledby="qa-detail-title">
            <div className="panel-heading">
              <h2 id="qa-detail-title">本地原文</h2>
              <span>{selectedQaSource ? "可追溯" : "未选择"}</span>
            </div>
            {selectedQaSource ? (
              <article className="article-detail">
                <p className="detail-kicker">{selectedQaSource.sourceId}</p>
                <h3>{formatLegalSourceLabel(selectedQaSource)}</h3>
                <p className="item-meta">{selectedQaSource.canonicalLabel}</p>
                <p className="article-content">{selectedQaSource.content}</p>
                <dl className="meta-grid">
                  <div>
                    <dt>版本</dt>
                    <dd>{selectedQaSource.versionLabel}</dd>
                  </div>
                  <div>
                    <dt>效力期间</dt>
                    <dd>
                      {formatEffectiveWindow(
                        selectedQaSource.effectiveFrom,
                        selectedQaSource.effectiveTo,
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>状态</dt>
                    <dd>{formatStatus(selectedQaSource.versionStatus)}</dd>
                  </div>
                </dl>
              </article>
            ) : (
              <p className="empty-state">选择候选来源或有效引用查看原文</p>
            )}
          </aside>
        </section>
      ) : viewMode === "cases" ? (
        <section className="case-layout">
          <aside className="panel case-list-panel" aria-labelledby="case-list-title">
            <div className="panel-heading">
              <h2 id="case-list-title">案件项目</h2>
              <span>{caseProjects.length}</span>
            </div>
            <div className="provider-create-row">
              <button type="button" onClick={startNewCaseProject}>
                新建案件
              </button>
            </div>
            {caseState.kind === "error" ? (
              <p className="error-text">{caseState.message}</p>
            ) : null}
            <div className="provider-list">
              {caseProjects.map((project) => (
                <button
                  className={`provider-item ${
                    selectedCaseProjectId === project.projectId
                      ? "is-selected"
                      : ""
                  }`}
                  key={project.projectId}
                  type="button"
                  onClick={() => selectCaseProject(project)}
                >
                  <span className="item-title">{project.title}</span>
                  <span className="item-meta">
                    {project.caseType || "未分类"} ·{" "}
                    {project.openedOn ?? "未登记日期"}
                  </span>
                  <span className="item-summary">{project.summary}</span>
                </button>
              ))}
              {caseProjects.length === 0 ? (
                <p className="empty-state">暂无案件项目</p>
              ) : null}
            </div>
          </aside>

          <section className="panel case-workbench-panel" aria-labelledby="case-workbench-title">
            <div className="panel-heading">
              <h2 id="case-workbench-title">案件工作台</h2>
              <span>{caseState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            <div className="case-scroll">
              <form className="case-form" onSubmit={saveCaseProject}>
                <div className="form-grid">
                  <label>
                    <span>案件名称</span>
                    <input
                      value={caseProjectDraft.title}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          title: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>案件类型</span>
                    <input
                      value={caseProjectDraft.caseType}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          caseType: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>立案/接案日期</span>
                    <input
                      type="date"
                      value={caseProjectDraft.openedOn ?? ""}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          openedOn: event.target.value || null,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>状态</span>
                    <select
                      value={caseProjectDraft.status}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          status: event.target.value as "active" | "archived",
                        }))
                      }
                    >
                      <option value="active">进行中</option>
                      <option value="archived">已归档</option>
                    </select>
                  </label>
                </div>
                <label>
                  <span>摘要</span>
                  <textarea
                    value={caseProjectDraft.summary}
                    onChange={(event) =>
                      setCaseProjectDraft((current) => ({
                        ...current,
                        summary: event.target.value,
                      }))
                    }
                  />
                </label>
                <div className="command-row">
                  <button type="submit">保存案件</button>
                  <button
                    disabled={!selectedCaseProjectId}
                    type="button"
                    onClick={() => void removeCaseProject()}
                  >
                    删除案件
                  </button>
                </div>
              </form>

              <section className="case-section">
                <div className="section-heading">
                  <h3>案件材料</h3>
                  <span>{caseWorkspace?.files.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFile}>
                  <div className="form-grid">
                    <label>
                      <span>标题</span>
                      <input
                        value={fileDraft.title}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>类型</span>
                      <input
                        value={fileDraft.fileType}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            fileType: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>存储引用</span>
                      <input
                        value={fileDraft.storageReference}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            storageReference: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>材料文本或摘要（仅由用户维护）</span>
                    <textarea
                      value={fileDraft.summary}
                      onChange={(event) =>
                        setFileDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <button type="submit">添加材料</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.files.map((file) => (
                    <div className="compact-row" key={file.fileId}>
                      <label className="material-select">
                        <input
                          checked={extractionFileIds.includes(file.fileId)}
                          disabled={extractionSourcesLocked}
                          type="checkbox"
                          onChange={(event) =>
                            setExtractionFileIds((current) =>
                              event.target.checked
                                ? [...current, file.fileId]
                                : current.filter(
                                    (fileId) => fileId !== file.fileId,
                                  ),
                            )
                          }
                        />
                        <strong>{file.title}</strong>
                      </label>
                      <span>
                        {file.fileType || "未分类"} ·{" "}
                        {file.storageReference || "未登记位置"}
                      </span>
                      <span>{file.summary || "未填写材料文本或摘要"}</span>
                      <button
                        disabled={extractionSourcesLocked}
                        type="button"
                        onClick={() => void removeCaseEntity("file", file.fileId)}
                      >
                        删除
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>当事人</h3>
                  <span>{caseWorkspace?.parties.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveParty}>
                  <div className="form-grid">
                    <label>
                      <span>名称</span>
                      <input
                        value={partyDraft.name}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            name: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标准化名称</span>
                      <input
                        value={partyDraft.normalizedName}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            normalizedName: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>角色</span>
                      <select
                        value={partyDraft.role}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            role: event.target.value as PartyRole,
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </label>
                    <label>
                      <span>联系方式</span>
                      <input
                        value={partyDraft.contact}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            contact: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <button type="submit">添加当事人</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.parties.map((party) => (
                    <div className="compact-row" key={party.partyId}>
                      <strong>{party.name}</strong>
                      <span>{formatPartyRole(party.role)}</span>
                      <button
                        type="button"
                        onClick={() =>
                          void removeCaseEntity("party", party.partyId)
                        }
                      >
                        删除
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实时间线</h3>
                  <span>{caseWorkspace?.facts.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFact}>
                  <div className="form-grid">
                    <label>
                      <span>日期</span>
                      <input
                        type="date"
                        value={factDraft.occurredOn ?? ""}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            occurredOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>事实标题</span>
                      <input
                        value={factDraft.title}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>状态</span>
                      <select
                        value={factDraft.confirmationStatus}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            confirmationStatus:
                              event.target.value as ConfirmationStatus,
                          }))
                        }
                      >
                        <option value="confirmed">已确认事实</option>
                        <option value="model_suggested">模型建议</option>
                      </select>
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={factDraft.source}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>事实描述</span>
                    <textarea
                      value={factDraft.description}
                      onChange={(event) =>
                        setFactDraft((current) => ({
                          ...current,
                          description: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <button type="submit">添加事实</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.facts.map((fact) => (
                    <div className="compact-row" key={fact.factId}>
                      <strong>{fact.title}</strong>
                      <span>
                        {fact.occurredOn ?? "未登记日期"} ·{" "}
                        {formatConfirmationStatus(fact.confirmationStatus)}
                      </span>
                      <span>{fact.description}</span>
                      <button
                        type="button"
                        onClick={() => void removeCaseEntity("fact", fact.factId)}
                      >
                        删除
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>证据目录</h3>
                  <span>{caseWorkspace?.evidence.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveEvidence}>
                  <div className="form-grid">
                    <label>
                      <span>编号</span>
                      <input
                        value={evidenceDraft.evidenceNumber}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            evidenceNumber: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标题</span>
                      <input
                        value={evidenceDraft.title}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={evidenceDraft.source}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>形成日期</span>
                      <input
                        type="date"
                        value={evidenceDraft.formedOn ?? ""}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            formedOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>摘要</span>
                    <textarea
                      value={evidenceDraft.summary}
                      onChange={(event) =>
                        setEvidenceDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <button type="submit">添加证据</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.evidence.map((item) => (
                    <div className="compact-row" key={item.evidenceId}>
                      <strong>
                        {item.evidenceNumber} · {item.title}
                      </strong>
                      <span>
                        {item.source || "缺少来源"} ·{" "}
                        {item.formedOn ?? "缺少形成时间"}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          void removeCaseEntity("evidence", item.evidenceId)
                        }
                      >
                        删除
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实-证据关联</h3>
                  <span>{caseWorkspace?.evidenceLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    value={linkFactId}
                    onChange={(event) => setLinkFactId(event.target.value)}
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {fact.title}
                      </option>
                    ))}
                  </select>
                  <select
                    value={linkEvidenceId}
                    onChange={(event) => setLinkEvidenceId(event.target.value)}
                  >
                    <option value="">选择证据</option>
                    {caseWorkspace?.evidence.map((item) => (
                      <option key={item.evidenceId} value={item.evidenceId}>
                        {item.evidenceNumber} · {item.title}
                      </option>
                    ))}
                  </select>
                  <button type="button" onClick={() => void linkEvidenceToFact()}>
                    关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.evidenceLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const evidence = caseWorkspace.evidence.find(
                      (item) => item.evidenceId === link.evidenceId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{fact?.title ?? link.factId}</strong>
                        <span>{evidence?.evidenceNumber ?? link.evidenceId}</span>
                        <button
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence_link", link.linkId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>争点与主张</h3>
                  <span>{caseWorkspace?.legalIssues.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveIssue}>
                  <div className="form-grid">
                    <label>
                      <span>争点</span>
                      <input
                        value={issueDraft.title}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>处理状态</span>
                      <select
                        value={issueDraft.status}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            status: event.target.value as LegalIssueStatus,
                          }))
                        }
                      >
                        <option value="open">待处理</option>
                        <option value="resolved">已解决</option>
                      </select>
                    </label>
                  </div>
                  <label>
                    <span>主张</span>
                    <textarea
                      value={issueDraft.claim}
                      onChange={(event) =>
                        setIssueDraft((current) => ({
                          ...current,
                          claim: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <button type="submit">添加争点</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalIssues.map((issue) => (
                    <div className="compact-row" key={issue.issueId}>
                      <strong>{issue.title}</strong>
                      <span>{formatLegalIssueStatus(issue.status)}</span>
                      <span>{issue.claim}</span>
                      <button
                        type="button"
                        onClick={() =>
                          void removeCaseEntity("legal_issue", issue.issueId)
                        }
                      >
                        删除
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>法律依据</h3>
                  <span>{caseWorkspace?.legalBasis.length ?? 0}</span>
                </div>
                <form
                  className="case-form compact-case-form"
                  onSubmit={saveLegalBasis}
                >
                  <div className="form-grid">
                    <label>
                      <span>引用 ID</span>
                      <input
                        value={basisSourceId}
                        onChange={(event) => setBasisSourceId(event.target.value)}
                        placeholder="[SRC:law:...]"
                      />
                    </label>
                    <label>
                      <span>关联争点</span>
                      <select
                        value={basisIssueId}
                        onChange={(event) => setBasisIssueId(event.target.value)}
                      >
                        <option value="">不关联争点</option>
                        {caseWorkspace?.legalIssues.map((issue) => (
                          <option key={issue.issueId} value={issue.issueId}>
                            {issue.title}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>案件日期</span>
                      <input
                        type="date"
                        value={basisCaseDate}
                        onChange={(event) => setBasisCaseDate(event.target.value)}
                      />
                    </label>
                  </div>
                  <label>
                    <span>备注</span>
                    <textarea
                      value={basisNote}
                      onChange={(event) => setBasisNote(event.target.value)}
                    />
                  </label>
                  <div className="toggle-row">
                    <label>
                      <input
                        checked={basisIncludeExpired}
                        type="checkbox"
                        onChange={(event) =>
                          setBasisIncludeExpired(event.target.checked)
                        }
                      />
                      <span>允许已失效版本</span>
                    </label>
                  </div>
                  <button type="submit">添加依据</button>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalBasis.map((basis) => {
                    const linkedIssue = caseWorkspace.legalIssues.find(
                      (issue) => issue.issueId === basis.issueId,
                    );

                    return (
                      <div
                        className={`compact-row legal-basis-row legal-basis-row--${basis.status}`}
                        key={basis.basisId}
                      >
                        <strong>{formatLegalBasisTitle(basis)}</strong>
                        <span>
                          {formatLegalBasisStatus(basis.status)}
                          {basis.status === "invalid"
                            ? ` · ${formatLegalBasisInvalidReason(
                                basis.invalidReason,
                              )}`
                            : ""}{" "}
                          ·{" "}
                          {basis.versionStatus
                            ? formatStatus(basis.versionStatus)
                            : "未校验版本"}{" "}
                          · {formatLegalBasisWindow(basis)}
                        </span>
                        <span>
                          {linkedIssue ? `争点：${linkedIssue.title}` : "未关联争点"}{" "}
                          · {basis.caseDate ?? "未指定案件日期"}
                        </span>
                        {basis.excerpt ? <span>{basis.excerpt}</span> : null}
                        {basis.note ? <span>{basis.note}</span> : null}
                        <button
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_basis", basis.basisId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.legalBasis.length === 0 ? (
                    <p className="empty-state">暂无法律依据</p>
                  ) : null}
                </div>
              </section>
            </div>
          </section>

          <aside className="panel case-gap-panel" aria-labelledby="case-gap-title">
            <div className="panel-heading">
              <h2 id="case-gap-title">缺口分析</h2>
              <span>{caseWorkspace?.gaps.length ?? 0}</span>
            </div>
            <div className="compact-list">
              {caseWorkspace?.gaps.map((gap) => (
                <div className="compact-row" key={gap.gapId}>
                  <strong>
                    {formatGapSeverity(gap.severity)} · {formatGapKind(gap.kind)}
                  </strong>
                  <span>{gap.message}</span>
                </div>
              ))}
              {caseWorkspace && caseWorkspace.gaps.length === 0 ? (
                <p className="empty-state">当前没有证据缺口</p>
              ) : null}
            </div>

            <section className="provider-subsection">
              <h3>待核实事项</h3>
              <div className="compact-list extraction-uncertainty-list">
                {caseWorkspace?.uncertainties.map((uncertainty) => (
                  <div className="compact-row" key={uncertainty.uncertaintyId}>
                    <strong>{uncertainty.description}</strong>
                    <span>
                      {uncertainty.status === "open" ? "待核实" : "已解决"} ·{" "}
                      {formatConfirmationStatus(uncertainty.confirmationStatus)}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        void removeCaseEntity(
                          "uncertainty",
                          uncertainty.uncertaintyId,
                        )
                      }
                    >
                      删除
                    </button>
                  </div>
                ))}
                {caseWorkspace && caseWorkspace.uncertainties.length === 0 ? (
                  <p className="empty-state">暂无独立待核实事项</p>
                ) : null}
              </div>
            </section>

            <section className="provider-subsection extraction-panel">
              <h3>模型结构化抽取</h3>
              <p className="privacy-note">
                仅发送已勾选材料的“材料文本或摘要”。模型建议先在本机审阅，确认事务不会修改案件材料记录。
              </p>
              <label>
                <span>Provider</span>
                <select
                  disabled={extractionSourcesLocked}
                  value={extractionProviderId}
                  onChange={(event) =>
                    setExtractionProviderId(event.target.value)
                  }
                >
                  <option value="">选择已保存 Provider</option>
                  {providerProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.displayName} · {profile.modelId}
                    </option>
                  ))}
                </select>
              </label>
              <button
                disabled={
                  !caseWorkspace ||
                  !extractionProviderId ||
                  extractionFileIds.length === 0 ||
                  extractionState.kind === "generating" ||
                  extractionState.kind === "committing"
                }
                type="button"
                onClick={() => void runStructuredExtraction()}
              >
                {extractionState.kind === "generating"
                  ? "正在请求并严格校验…"
                  : `生成模型建议（已选 ${extractionFileIds.length} 份材料）`}
              </button>

              {extractionState.kind === "reviewing" ||
              extractionState.kind === "committing" ? (
                <div className="extraction-review">
                  <div className="review-banner">
                    <strong>模型建议，尚未写入</strong>
                    <span>
                      {extractionState.repaired
                        ? "首次输出失败，Rust 已自动修复 1 次并重新严格校验。"
                        : "首次输出已通过 Rust 严格校验。"}
                    </span>
                  </div>

                  <fieldset
                    className="review-fields"
                    disabled={extractionState.kind === "committing"}
                  >
                  <h4>当事人</h4>
                  {extractionState.draft.parties.map((party, index) => (
                    <div className="review-card" key={`party-${index}`}>
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除此建议
                      </button>
                      <input
                        aria-label={`建议当事人 ${index + 1}`}
                        value={party.name}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, name: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <select
                        value={party.role}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    role: event.target.value as PartyRole,
                                  }
                                : item,
                            ),
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </div>
                  ))}

                  <h4>事实</h4>
                  {extractionState.draft.facts.map((fact, index) => (
                    <div className="review-card" key={`fact-${index}`}>
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除此建议
                      </button>
                      <input
                        type="date"
                        value={fact.occurredOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    occurredOn: event.target.value || null,
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        value={fact.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, title: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        value={fact.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, description: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label="关联证据编号，逗号分隔"
                        value={fact.evidenceNumbers.join(", ")}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    evidenceNumbers: event.target.value
                                      .split(/[,，]/u)
                                      .map((value) => value.trim())
                                      .filter(Boolean),
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4>证据</h4>
                  {extractionState.draft.evidence.map((item, index) => (
                    <div className="review-card" key={`evidence-${index}`}>
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除此建议
                      </button>
                      <input
                        value={item.evidenceNumber}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    evidenceNumber: event.target.value,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        value={item.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, title: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        value={item.source}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, source: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        type="date"
                        value={item.formedOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    formedOn: event.target.value || null,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <textarea
                        value={item.summary}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, summary: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4>争点与主张</h4>
                  {extractionState.draft.legalIssues.map((issue, index) => (
                    <div className="review-card" key={`issue-${index}`}>
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除此建议
                      </button>
                      <input
                        value={issue.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, title: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        value={issue.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? {
                                      ...item,
                                      description: event.target.value,
                                    }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        value={issue.claim}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, claim: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4>待核实事项</h4>
                  {extractionState.draft.uncertainties.map(
                    (uncertainty, index) => (
                      <div
                        className="review-card"
                        key={`uncertainty-${index}`}
                      >
                        <button
                          className="review-remove"
                          type="button"
                          onClick={() =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.filter(
                                (_, itemIndex) => itemIndex !== index,
                              ),
                            }))
                          }
                        >
                          移除此建议
                        </button>
                        <textarea
                          value={uncertainty.description}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        description: event.target.value,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                        <select
                          value={uncertainty.relatedEntityType}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedEntityType: event.target.value as typeof item.relatedEntityType,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        >
                          <option value="general">一般</option>
                          <option value="party">当事人</option>
                          <option value="fact">事实</option>
                          <option value="evidence">证据</option>
                          <option value="legal_issue">争点</option>
                        </select>
                        <input
                          placeholder="关联名称/标题/证据编号（可空）"
                          value={uncertainty.relatedReference ?? ""}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedReference:
                                          event.target.value || null,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                      </div>
                    ),
                  )}
                  </fieldset>

                  {extractionState.kind === "reviewing" &&
                  extractionState.commitError ? (
                    <p className="error-text">{extractionState.commitError}</p>
                  ) : null}

                  <div className="review-actions">
                    <button
                      className="secondary-action"
                      disabled={extractionState.kind === "committing"}
                      type="button"
                      onClick={cancelExtractionReview}
                    >
                      取消，不写入
                    </button>
                    <button
                      className="confirm-action"
                      disabled={extractionState.kind === "committing"}
                      type="button"
                      onClick={() => void confirmExtractionReview()}
                    >
                      {extractionState.kind === "committing"
                        ? "事务写入中…"
                        : "确认审阅结果并原子写入"}
                    </button>
                  </div>
                </div>
              ) : null}

              {extractionState.kind === "failed" ? (
                <div className="extraction-failure">
                  <strong>抽取失败：{extractionState.message}</strong>
                  <span>
                    {extractionState.repairAttempted
                      ? "Rust 已自动修复且仅修复 1 次，第二次严格校验仍失败。"
                      : "未进入结构修复流程（例如 provider、网络或响应信封错误）。"}
                  </span>
                  {extractionState.rawOutput ? (
                    <details>
                      <summary>
                        查看首次模型输出（API 凭据已脱敏，案件内容仍可能敏感）
                      </summary>
                      <pre>{extractionState.rawOutput}</pre>
                    </details>
                  ) : null}
                  {extractionState.repairOutput ? (
                    <details>
                      <summary>
                        查看一次修复输出（API 凭据已脱敏，案件内容仍可能敏感）
                      </summary>
                      <pre>{extractionState.repairOutput}</pre>
                    </details>
                  ) : null}
                  <button type="button" onClick={cancelExtractionReview}>
                    关闭
                  </button>
                </div>
              ) : null}

              {extractionState.kind === "committed" ? (
                <div className="connection-summary">
                  <span className="status-dot status-dot--succeeded" />
                  <strong>{extractionState.message}</strong>
                </div>
              ) : null}
            </section>
          </aside>
        </section>
      ) : (
        <section className="provider-layout">
          <aside className="panel provider-list-panel" aria-labelledby="provider-list-title">
            <div className="panel-heading">
              <h2 id="provider-list-title">Profiles</h2>
              <span>{providerProfiles.length}</span>
            </div>
            <div className="provider-create-row">
              {PROVIDER_KINDS.map((kind) => (
                <button
                  key={kind}
                  type="button"
                  onClick={() => startNewProvider(kind)}
                >
                  新建 {formatProviderKind(kind)}
                </button>
              ))}
            </div>
            <div className="provider-list">
              {providerProfiles.map((profile) => (
                <button
                  className={`provider-item ${
                    selectedProviderId === profile.id ? "is-selected" : ""
                  }`}
                  key={profile.id}
                  type="button"
                  onClick={() => selectProvider(profile)}
                >
                  <span className="item-title">{profile.displayName}</span>
                  <span className="item-meta">
                    {formatProviderKind(profile.kind)} · {profile.modelId}
                  </span>
                  <span className="item-summary">
                    {formatKeyStatus(keyStatuses[profile.id])}
                  </span>
                </button>
              ))}
              {providerProfiles.length === 0 ? (
                <p className="empty-state">暂无 Provider profile</p>
              ) : null}
            </div>
          </aside>

          <section className="panel provider-editor-panel" aria-labelledby="provider-editor-title">
            <div className="panel-heading">
              <h2 id="provider-editor-title">Profile</h2>
              <span>{providerState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            {providerState.kind === "error" ? (
              <p className="error-text">{providerState.message}</p>
            ) : null}

            <form className="provider-form" onSubmit={saveProvider}>
              <div className="form-grid">
                <label>
                  <span>名称</span>
                  <input
                    value={providerDraft.displayName}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        displayName: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>Provider</span>
                  <select
                    value={providerDraft.kind}
                    onChange={(event) =>
                      updateProviderKind(event.target.value as ProviderKind)
                    }
                  >
                    {PROVIDER_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {formatProviderKind(kind)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>模型 ID</span>
                  <input
                    value={providerDraft.modelId}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        modelId: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>Base URL</span>
                  <input
                    value={providerDraft.baseUrl}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        baseUrl: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>凭据账户</span>
                  <input
                    value={providerDraft.credentialAccountId}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        credentialAccountId: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>Endpoint ID</span>
                  <input
                    value={providerDraft.options.endpointId ?? ""}
                    onChange={(event) =>
                      updateOptions({ endpointId: event.target.value })
                    }
                  />
                </label>
                <label>
                  <span>Workspace ID</span>
                  <input
                    value={providerDraft.options.workspaceId ?? ""}
                    onChange={(event) =>
                      updateOptions({ workspaceId: event.target.value })
                    }
                  />
                </label>
                <label>
                  <span>Reasoning effort</span>
                  <select
                    value={providerDraft.options.reasoningEffort ?? ""}
                    onChange={(event) =>
                      updateOptions({
                        reasoningEffort:
                          event.target.value === ""
                            ? null
                            : (event.target.value as ReasoningEffort),
                      })
                    }
                  >
                    <option value="">未设置</option>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                  </select>
                </label>
                <label>
                  <span>Thinking budget</span>
                  <input
                    min="0"
                    type="number"
                    value={providerDraft.options.thinkingBudget ?? ""}
                    onChange={(event) =>
                      updateOptions({
                        thinkingBudget:
                          event.target.value === ""
                            ? null
                            : Number(event.target.value),
                      })
                    }
                  />
                </label>
              </div>

              <div className="toggle-row">
                <label>
                  <input
                    checked={providerDraft.options.enableThinking ?? false}
                    type="checkbox"
                    onChange={(event) =>
                      updateOptions({ enableThinking: event.target.checked })
                    }
                  />
                  <span>enable_thinking</span>
                </label>
                <label>
                  <input
                    checked={providerDraft.options.thinking ?? false}
                    type="checkbox"
                    onChange={(event) =>
                      updateOptions({ thinking: event.target.checked })
                    }
                  />
                  <span>thinking</span>
                </label>
              </div>

              <div className="command-row">
                <button type="submit">保存 Profile</button>
                <button
                  disabled={!providerIsSaved}
                  type="button"
                  onClick={() => void removeProvider()}
                >
                  删除 Profile
                </button>
              </div>
            </form>
          </section>

          <aside className="panel provider-status-panel" aria-labelledby="provider-status-title">
            <div className="panel-heading">
              <h2 id="provider-status-title">凭据与连接</h2>
              <span>{formatKeyStatus(currentKeyStatus)}</span>
            </div>
            <section className="provider-subsection">
              <h3>API Key</h3>
              <label>
                <span>Key</span>
                <input
                  autoComplete="off"
                  type="password"
                  value={apiKeyInput}
                  onChange={(event) => setApiKeyInput(event.target.value)}
                  placeholder="API Key"
                />
              </label>
              <div className="command-row">
                <button
                  disabled={!providerIsSaved || apiKeyInput.trim().length === 0}
                  type="button"
                  onClick={() => void saveApiKey()}
                >
                  保存 Key
                </button>
                <button
                  disabled={!providerHasKey}
                  type="button"
                  onClick={() => void removeApiKey()}
                >
                  删除 Key
                </button>
              </div>
            </section>

            <section className="provider-subsection">
              <h3>测试连接</h3>
              <div className="connection-summary">
                <span
                  className={`status-dot status-dot--${
                    currentConnectionResult?.status ?? "idle"
                  }`}
                />
                <strong>{formatConnectionResult(currentConnectionResult)}</strong>
              </div>
              <dl className="meta-grid">
                <div>
                  <dt>HTTP</dt>
                  <dd>{formatHttpStatus(currentConnectionResult?.httpStatus)}</dd>
                </div>
                <div>
                  <dt>模型</dt>
                  <dd>{currentConnectionResult?.model ?? "未返回"}</dd>
                </div>
                <div>
                  <dt>首字延迟</dt>
                  <dd>
                    {formatLatency(
                      currentConnectionResult?.firstTokenLatencyMs,
                    )}
                  </dd>
                </div>
                <div>
                  <dt>总耗时</dt>
                  <dd>{formatLatency(currentConnectionResult?.totalLatencyMs)}</dd>
                </div>
                <div>
                  <dt>错误类型</dt>
                  <dd>{currentConnectionResult?.errorType ?? "无"}</dd>
                </div>
              </dl>
              <button
                disabled={!providerIsSaved || !providerHasKey}
                type="button"
                onClick={() => void runProviderConnectionTest()}
              >
                测试连接
              </button>
            </section>
          </aside>
        </section>
      )}
    </main>
  );
}
