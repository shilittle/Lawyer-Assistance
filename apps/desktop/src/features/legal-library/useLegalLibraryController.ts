import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type MutableRefObject,
} from "react";

import type { AssistantConversation } from "../../ipc/assistant/types";
import type { CaseProject } from "../../ipc/case/types";
import type { DocumentCitation } from "../../ipc/document/types";
import type { GraphNode } from "../../ipc/graph/types";
import {
  cancelLegalAnswer,
  findLegalAnswerCandidates,
  getArticle,
  getLawDocument,
  getLawRelations,
  getLawVersions,
  listLegalAnswerRecords,
  searchArticles,
  searchLaws,
} from "../../ipc/legal/client";
import { buildLegalAnswerCandidateRequest } from "../../ipc/legal/query";
import {
  INITIAL_LEGAL_ANSWER_STREAM_STATE,
  isLegalAnswerStreamActive,
  markLegalAnswerCancelling,
  restoreLegalAnswerAfterRejectedCancellation,
  settleLegalAnswerCancellation,
  shouldCancelLegalAnswerOnPageLeave,
} from "../../ipc/legal/stream";
import type {
  ArticleSearchResult,
  LawArticleDetail,
  LawRelationInfo,
  LawSearchResult,
  LawVersionInfo,
  LegalAnswerContext,
  LegalAnswerRecord,
  LegalAnswerResponse,
} from "../../ipc/legal/types";
import { publicErrorMessage, publicTitle } from "../../publicOutput";
import {
  articleMatchesDocumentCitation,
  copyQaFormDraft,
  currentLawSearchCriteria,
  DEFAULT_QA_FORM_DRAFT,
  exactLawDocumentMatchesRequest,
  formatLegalAnswerScope,
  legalAnswerContextFromRecord,
  legalAnswerHistoryBelongsToProject,
  legalAnswerPreviewStillOwnsCurrentScope,
  legalAnswerRequestStillOwnsCurrentCase,
  LEGAL_ANSWER_HISTORY_PAGE_SIZE,
  mergeLegalAnswerHistory,
  qaFormDraftFromLegalAnswerRecord,
  resolveLegalAnswerQuestion,
  resolveSelectedQaSource,
  type QaFormDraft,
} from "./model";

export type LegalCitationTarget = Pick<
  DocumentCitation,
  "articleId" | "documentId" | "versionId" | "sourceId"
>;

export type LegalLibraryLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string };

export type LegalSourceBridgeState =
  | { kind: "idle" | "loading" }
  | { kind: "success" | "error"; message: string };

export interface UseLegalLibraryControllerOptions {
  qaActive: boolean;
  selectedCaseProjectId: string | null;
  assistantConversation: AssistantConversation | null;
  assistantActiveProject: CaseProject | null;
  onNavigateToSearch: () => void;
  onOpenLawGraph: (documentId: string) => void;
  onOpenCaseAssistant: () => void;
  onOpenAssistant: () => void;
  onAddAssistantLegalSource: (sourceId: string) => Promise<void>;
  onProposeAssistantLegalBasis: (sourceId: string) => Promise<void>;
}

const INITIAL_QUERY = "合同";

function errorMessage(error: unknown): string {
  return publicErrorMessage(error);
}

function advanceRequestEpoch(epoch: MutableRefObject<number>): number {
  epoch.current += 1;
  return epoch.current;
}

function isCurrentRequestEpoch(
  epoch: MutableRefObject<number>,
  requestEpoch: number,
): boolean {
  return epoch.current === requestEpoch;
}

export function useLegalLibraryController(
  options: UseLegalLibraryControllerOptions,
) {
  const {
    qaActive,
    selectedCaseProjectId,
    assistantConversation,
    assistantActiveProject,
  } = options;

  const [query, setQuery] = useState(INITIAL_QUERY);
  const [caseDate, setCaseDate] = useState("");
  const queryRef = useRef(query);
  queryRef.current = query;
  const caseDateRef = useRef(caseDate);
  caseDateRef.current = caseDate;
  const [searchState, setSearchState] = useState<LegalLibraryLoadState>({
    kind: "idle",
  });
  const [detailState, setDetailState] = useState<LegalLibraryLoadState>({
    kind: "idle",
  });
  const [documentState, setDocumentState] =
    useState<LegalLibraryLoadState>({ kind: "idle" });
  const [laws, setLaws] = useState<LawSearchResult[]>([]);
  const [articles, setArticles] = useState<ArticleSearchResult[]>([]);
  const searchRequestEpoch = useRef(0);
  const articleDetailRequestEpoch = useRef(0);
  const documentContextRequestEpoch = useRef(0);
  const [selectedDocument, setSelectedDocument] =
    useState<LawSearchResult | null>(null);
  const selectedDocumentIdRef = useRef<string | null>(null);
  selectedDocumentIdRef.current = selectedDocument?.documentId ?? null;
  const [versions, setVersions] = useState<LawVersionInfo[]>([]);
  const [relations, setRelations] = useState<LawRelationInfo[]>([]);
  const [selectedArticleId, setSelectedArticleId] = useState<string | null>(
    null,
  );
  const [selectedArticle, setSelectedArticle] =
    useState<LawArticleDetail | null>(null);
  const [graphDocumentId, setGraphDocumentId] = useState<string | null>(null);

  const [bridgeState, setBridgeState] = useState<LegalSourceBridgeState>({
    kind: "idle",
  });
  const bridgeMutationInFlightRef = useRef(false);

  const [qaState, setQaState] = useState<LegalLibraryLoadState>({
    kind: "idle",
  });
  const [qaQuestion, setQaQuestion] = useState(DEFAULT_QA_FORM_DRAFT.question);
  const [qaLawName, setQaLawName] = useState(DEFAULT_QA_FORM_DRAFT.lawName);
  const [qaArticleNumber, setQaArticleNumber] = useState(
    DEFAULT_QA_FORM_DRAFT.articleNumber,
  );
  const [qaKeywords, setQaKeywords] = useState(
    DEFAULT_QA_FORM_DRAFT.keywords,
  );
  const [qaCaseDate, setQaCaseDate] = useState(DEFAULT_QA_FORM_DRAFT.caseDate);
  const [qaEffectivenessLevels, setQaEffectivenessLevels] = useState<string[]>([
    ...DEFAULT_QA_FORM_DRAFT.effectivenessLevels,
  ]);
  const [qaIncludeExpired, setQaIncludeExpired] = useState(
    DEFAULT_QA_FORM_DRAFT.includeExpired,
  );
  const [qaContext, setQaContext] = useState<LegalAnswerContext | null>(null);
  const [qaAnswer, setQaAnswer] = useState<LegalAnswerResponse | null>(null);
  const [qaHistoryState, setQaHistoryState] =
    useState<LegalLibraryLoadState>({ kind: "idle" });
  const [qaHistoryRecords, setQaHistoryRecords] = useState<
    LegalAnswerRecord[]
  >([]);
  const [qaHistoryHasMore, setQaHistoryHasMore] = useState(false);
  const qaDraftsByProject = useRef(new Map<string, QaFormDraft>());
  const qaDraftProjectId = useRef<string | null>(null);
  const [qaSubmittedQuestion, setQaSubmittedQuestion] = useState<string | null>(
    null,
  );
  const [qaStream, setQaStream] = useState(
    INITIAL_LEGAL_ANSWER_STREAM_STATE,
  );
  const qaStreamRef = useRef(qaStream);
  qaStreamRef.current = qaStream;
  const activeQaRequestId = useRef<string | null>(null);
  const activeQaRequestProjectId = useRef<string | null>(null);
  const qaPreviewEpoch = useRef(0);
  const qaLeaveCancellationRequestId = useRef<string | null>(null);
  const [selectedQaSourceId, setSelectedQaSourceId] = useState<string | null>(
    null,
  );
  const qaHistoryLoadEpoch = useRef(0);
  const selectedCaseProjectIdRef = useRef<string | null>(
    selectedCaseProjectId,
  );
  selectedCaseProjectIdRef.current = selectedCaseProjectId;

  function currentQaFormDraft(): QaFormDraft {
    return {
      question: qaQuestion,
      lawName: qaLawName,
      articleNumber: qaArticleNumber,
      keywords: qaKeywords,
      caseDate: qaCaseDate,
      effectivenessLevels: [...qaEffectivenessLevels],
      includeExpired: qaIncludeExpired,
    };
  }

  function applyQaFormDraft(draft: Readonly<QaFormDraft>) {
    setQaQuestion(draft.question);
    setQaLawName(draft.lawName);
    setQaArticleNumber(draft.articleNumber);
    setQaKeywords(draft.keywords);
    setQaCaseDate(draft.caseDate);
    setQaEffectivenessLevels([...draft.effectivenessLevels]);
    setQaIncludeExpired(draft.includeExpired);
  }

  function qaDraftStorageKey(projectId: string | null): string {
    return projectId ?? "__unassigned__";
  }

  async function refreshLegalAnswerHistory(
    projectId: string,
    append = false,
  ) {
    const requestEpoch = ++qaHistoryLoadEpoch.current;
    const cursor = append ? qaHistoryRecords.at(-1) : undefined;
    if (!append) {
      setQaHistoryRecords([]);
      setQaHistoryHasMore(false);
    }
    setQaHistoryState({ kind: "loading" });
    try {
      const response = await listLegalAnswerRecords({
        projectId,
        limit: LEGAL_ANSWER_HISTORY_PAGE_SIZE,
        beforeCreatedAt: cursor?.createdAt ?? null,
        beforeRecordId: cursor?.recordId ?? null,
      });
      if (
        qaHistoryLoadEpoch.current !== requestEpoch ||
        selectedCaseProjectIdRef.current !== projectId
      ) {
        return;
      }
      if (!legalAnswerHistoryBelongsToProject(response.records, projectId)) {
        setQaHistoryRecords([]);
        setQaHistoryHasMore(false);
        setQaHistoryState({
          kind: "error",
          message: "历史回答归属校验失败，已拒绝显示。",
        });
        return;
      }
      setQaHistoryRecords((current) =>
        append
          ? mergeLegalAnswerHistory(current, response.records)
          : response.records,
      );
      setQaHistoryHasMore(response.hasMore);
      setQaHistoryState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        qaHistoryLoadEpoch.current === requestEpoch &&
        selectedCaseProjectIdRef.current === projectId
      ) {
        if (!append) {
          setQaHistoryRecords([]);
          setQaHistoryHasMore(false);
        }
        setQaHistoryState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  async function runSearch(
    documentId: string | null,
    requiredDocumentEpoch?: number,
  ) {
    const requestEpoch = advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    const criteria = currentLawSearchCriteria(queryRef, caseDateRef);

    setSearchState({ kind: "loading" });
    setSelectedArticleId(null);
    setSelectedArticle(null);
    setDetailState({ kind: "idle" });

    try {
      const [lawResponse, articleResponse] = await Promise.all([
        searchLaws({ query: criteria.query, limit: 12 }),
        searchArticles({
          query: criteria.query,
          documentId,
          caseDate: criteria.caseDate,
          limit: 24,
        }),
      ]);

      if (
        !isCurrentRequestEpoch(searchRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== documentId ||
        (requiredDocumentEpoch !== undefined &&
          !isCurrentRequestEpoch(
            documentContextRequestEpoch,
            requiredDocumentEpoch,
          ))
      ) {
        return;
      }

      setLaws(lawResponse.results);
      setArticles(articleResponse.results);
      setSearchState({ kind: "idle" });

      if (articleResponse.results[0]) {
        await loadArticleDetail(
          articleResponse.results[0].articleId,
          requestEpoch,
        );
      } else {
        setSelectedArticleId(null);
        setSelectedArticle(null);
      }
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(searchRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === documentId &&
        (requiredDocumentEpoch === undefined ||
          isCurrentRequestEpoch(
            documentContextRequestEpoch,
            requiredDocumentEpoch,
          ))
      ) {
        setSearchState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  async function loadArticleDetail(
    articleId: string,
    owningSearchEpoch?: number,
  ) {
    const requestEpoch = advanceRequestEpoch(articleDetailRequestEpoch);
    const documentId = selectedDocumentIdRef.current;
    setSelectedArticleId(articleId);
    setDetailState({ kind: "loading" });

    try {
      const response = await getArticle({ articleId });
      if (
        !isCurrentRequestEpoch(articleDetailRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== documentId ||
        (owningSearchEpoch !== undefined &&
          !isCurrentRequestEpoch(searchRequestEpoch, owningSearchEpoch))
      ) {
        return;
      }
      setSelectedArticle(response.article ?? null);
      setDetailState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(articleDetailRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === documentId &&
        (owningSearchEpoch === undefined ||
          isCurrentRequestEpoch(searchRequestEpoch, owningSearchEpoch))
      ) {
        setDetailState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  async function loadDocumentContext(document: LawSearchResult) {
    const requestEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    selectedDocumentIdRef.current = document.documentId;
    setSelectedDocument(document);
    setGraphDocumentId(document.documentId);
    setVersions([]);
    setRelations([]);
    setArticles([]);
    setSelectedArticleId(null);
    setSelectedArticle(null);
    setDocumentState({ kind: "loading" });

    try {
      const [versionResponse, relationResponse] = await Promise.all([
        getLawVersions({ documentId: document.documentId }),
        getLawRelations({ documentId: document.documentId, direction: "both" }),
      ]);

      if (
        !isCurrentRequestEpoch(documentContextRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== document.documentId
      ) {
        return;
      }

      setVersions(versionResponse.versions);
      setRelations(relationResponse.relations);
      setDocumentState({ kind: "idle" });
      await runSearch(document.documentId, requestEpoch);
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(documentContextRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === document.documentId
      ) {
        setDocumentState({ kind: "error", message: errorMessage(error) });
        setSearchState({ kind: "idle" });
      }
    }
  }

  async function clearDocumentFilter() {
    const requestEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    selectedDocumentIdRef.current = null;
    setSelectedDocument(null);
    setVersions([]);
    setRelations([]);
    setDocumentState({ kind: "idle" });
    await runSearch(null, requestEpoch);
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runSearch(selectedDocument?.documentId ?? null);
  }

  function openLawGraph(documentId: string) {
    setGraphDocumentId(documentId);
    options.onOpenLawGraph(documentId);
  }

  async function openLocalLawRecord(
    documentId: string,
    label: string,
    articleId?: string,
    navigate = true,
  ) {
    if (navigate) {
      options.onNavigateToSearch();
    }
    setQuery(label);
    queryRef.current = label;

    const loaded = laws.find((law) => law.documentId === documentId);
    if (loaded) {
      await loadDocumentContext(loaded);
      if (articleId && selectedDocumentIdRef.current === documentId) {
        await loadArticleDetail(articleId);
      }
      return;
    }

    const lookupEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    selectedDocumentIdRef.current = null;
    setSelectedDocument(null);
    setVersions([]);
    setRelations([]);
    setArticles([]);
    setSelectedArticle(null);
    setSelectedArticleId(null);
    setSearchState({ kind: "loading" });
    setDocumentState({ kind: "loading" });
    try {
      const response = await getLawDocument({ documentId });
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) {
        return;
      }
      const target = response.document;
      if (!target) {
        setSearchState({
          kind: "error",
          message: "当前本地法律库中没有找到对应法律文件。",
        });
        setDocumentState({ kind: "idle" });
        return;
      }
      if (!exactLawDocumentMatchesRequest(target, documentId)) {
        setSearchState({
          kind: "error",
          message: "法律文件校验未通过，已停止跳转，请重新检索。",
        });
        setDocumentState({ kind: "idle" });
        return;
      }
      setLaws((current) =>
        current.some((law) => law.documentId === documentId)
          ? current
          : [target, ...current],
      );
      await loadDocumentContext(target);
      if (articleId && selectedDocumentIdRef.current === documentId) {
        await loadArticleDetail(articleId);
      }
    } catch (error: unknown) {
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) {
        return;
      }
      setSearchState({ kind: "error", message: errorMessage(error) });
      setDocumentState({ kind: "idle" });
    }
  }

  async function openLawDocumentFromGraph(
    node: Pick<GraphNode, "sourceId" | "label">,
  ) {
    await openLocalLawRecord(node.sourceId, node.label);
  }

  async function resolveDocumentCitation(
    citation: LegalCitationTarget,
    navigate: boolean,
  ) {
    const lookupEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    if (navigate) {
      options.onNavigateToSearch();
    }
    setDocumentState({ kind: "loading" });
    setDetailState({ kind: "loading" });
    try {
      const response = await getArticle({ articleId: citation.articleId });
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) {
        return;
      }
      const article = response.article;
      if (!articleMatchesDocumentCitation(article, citation)) {
        setDocumentState({
          kind: "error",
          message: "该文书引用无法映射到当前正式本地法律库，已拒绝跳转。",
        });
        setDetailState({ kind: "idle" });
        return;
      }
      await openLocalLawRecord(
        article.documentId,
        article.documentTitle,
        article.articleId,
        navigate,
      );
    } catch (error: unknown) {
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) {
        return;
      }
      const message = errorMessage(error);
      setDocumentState({ kind: "error", message });
      setDetailState({ kind: "error", message });
    }
  }

  async function openDocumentCitation(citation: LegalCitationTarget) {
    await resolveDocumentCitation(citation, true);
  }

  async function consumeDocumentCitation(citation: LegalCitationTarget) {
    await resolveDocumentCitation(citation, false);
  }

  function createCandidateRequest() {
    return buildLegalAnswerCandidateRequest({
      question: qaQuestion,
      lawName: qaLawName,
      articleNumber: qaArticleNumber,
      keywords: qaKeywords,
      caseDate: qaCaseDate,
      effectivenessLevels: qaEffectivenessLevels,
      includeExpired: qaIncludeExpired,
      limit: 8,
    });
  }

  async function previewLegalAnswerContext(
    event?: FormEvent<HTMLFormElement>,
  ) {
    event?.preventDefault();
    const request = createCandidateRequest();
    if (!request.question) {
      setQaState({ kind: "error", message: "请输入法律问题" });
      return;
    }
    const previewEpoch = ++qaPreviewEpoch.current;
    const previewProjectId = selectedCaseProjectIdRef.current;

    setQaState({ kind: "loading" });
    setQaAnswer(null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);

    try {
      const response = await findLegalAnswerCandidates(request);
      if (
        qaPreviewEpoch.current !== previewEpoch ||
        !legalAnswerPreviewStillOwnsCurrentScope(
          previewProjectId,
          selectedCaseProjectIdRef.current,
        )
      ) {
        return;
      }
      setQaContext(response.context);
      setSelectedQaSourceId(response.context.sources[0]?.sourceId ?? null);
      setQaState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        qaPreviewEpoch.current !== previewEpoch ||
        !legalAnswerPreviewStillOwnsCurrentScope(
          previewProjectId,
          selectedCaseProjectIdRef.current,
        )
      ) {
        return;
      }
      setQaState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function cancelCurrentLegalAnswer() {
    const requestId = activeQaRequestId.current;
    const stream = qaStreamRef.current;
    if (
      !requestId ||
      !shouldCancelLegalAnswerOnPageLeave(stream, requestId)
    ) {
      return;
    }

    const previousStatus =
      stream.status === "streaming" ? "streaming" : "connecting";
    setQaStream((current) => markLegalAnswerCancelling(current));
    try {
      const response = await cancelLegalAnswer({ requestId });
      if (activeQaRequestId.current !== requestId) {
        return;
      }
      if (response.cancelled) {
        activeQaRequestId.current = null;
        activeQaRequestProjectId.current = null;
        setQaStream((current) =>
          settleLegalAnswerCancellation(current, requestId, true),
        );
        setQaState({ kind: "idle" });
      } else {
        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      }
    } catch (error: unknown) {
      setQaStream((current) => {
        const restored = restoreLegalAnswerAfterRejectedCancellation(
          current,
          requestId,
          previousStatus,
        );
        return restored === current
          ? current
          : {
              ...restored,
              message: `取消请求失败：${errorMessage(error)}；等待当前请求结束`,
            };
      });
    }
  }

  function restoreLegalAnswerRecord(record: LegalAnswerRecord) {
    if (record.projectId !== selectedCaseProjectId) {
      setQaHistoryState({
        kind: "error",
        message: "该历史回答不属于当前案件，已拒绝恢复。",
      });
      return;
    }
    const context = legalAnswerContextFromRecord(record);
    const formDraft = qaFormDraftFromLegalAnswerRecord(record);
    setQaAnswer({
      providerId: record.providerId,
      answer: record.answer,
      context,
      citationReport: record.citationReport,
      recordId: record.recordId,
    });
    setQaContext(context);
    setQaSubmittedQuestion(formDraft.question);
    applyQaFormDraft(formDraft);
    setSelectedQaSourceId(context.sources[0]?.sourceId ?? null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);
    setQaState({ kind: "idle" });
  }

  async function addSelectedArticleToAssistant() {
    if (
      !selectedArticle ||
      !assistantConversation ||
      bridgeMutationInFlightRef.current
    ) {
      return;
    }
    bridgeMutationInFlightRef.current = true;
    setBridgeState({ kind: "loading" });
    try {
      await options.onAddAssistantLegalSource(selectedArticle.citationId);
      setBridgeState({
        kind: "success",
        message: `已加入助理会话“${publicTitle(assistantConversation.title, "助理会话")}”。`,
      });
    } catch (error: unknown) {
      setBridgeState({
        kind: "error",
        message: `加入助理会话失败：${errorMessage(error)}`,
      });
    } finally {
      bridgeMutationInFlightRef.current = false;
    }
  }

  async function proposeSelectedArticleForCase() {
    if (
      !selectedArticle ||
      !assistantConversation ||
      !selectedCaseProjectId ||
      assistantConversation.projectId !== selectedCaseProjectId ||
      bridgeMutationInFlightRef.current
    ) {
      return;
    }
    bridgeMutationInFlightRef.current = true;
    setBridgeState({ kind: "loading" });
    try {
      await options.onProposeAssistantLegalBasis(selectedArticle.citationId);
      setBridgeState({
        kind: "success",
        message: `已为案件“${assistantActiveProject?.title ?? "当前案件"}”生成待确认法律依据；请到助理右侧审阅，尚未写入案件。`,
      });
    } catch (error: unknown) {
      setBridgeState({
        kind: "error",
        message: `生成待确认法律依据失败：${errorMessage(error)}`,
      });
    } finally {
      bridgeMutationInFlightRef.current = false;
    }
  }

  useEffect(() => {
    setBridgeState({ kind: "idle" });
  }, [selectedArticleId]);

  useEffect(() => {
    void runSearch(null);
    return () => {
      advanceRequestEpoch(searchRequestEpoch);
      advanceRequestEpoch(articleDetailRequestEpoch);
      advanceRequestEpoch(documentContextRequestEpoch);
    };
    // The initial search is deliberately issued once per mount. Subsequent
    // searches invalidate it through request epochs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const requestId = activeQaRequestId.current;
    const stream = qaStreamRef.current;
    if (
      qaActive ||
      !requestId ||
      !shouldCancelLegalAnswerOnPageLeave(stream, requestId) ||
      qaLeaveCancellationRequestId.current === requestId
    ) {
      return;
    }

    const previousStatus =
      stream.status === "streaming" ? "streaming" : "connecting";
    qaLeaveCancellationRequestId.current = requestId;
    setQaStream((current) => markLegalAnswerCancelling(current));
    void cancelLegalAnswer({ requestId })
      .then((response) => {
        if (qaLeaveCancellationRequestId.current === requestId) {
          qaLeaveCancellationRequestId.current = null;
        }
        if (activeQaRequestId.current !== requestId) {
          return;
        }
        if (response.cancelled) {
          activeQaRequestId.current = null;
          activeQaRequestProjectId.current = null;
          setQaStream((current) =>
            settleLegalAnswerCancellation(
              current,
              requestId,
              true,
              "离开问答页面，生成已取消",
            ),
          );
          setQaState({ kind: "idle" });
          return;
        }

        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      })
      .catch(() => {
        if (qaLeaveCancellationRequestId.current === requestId) {
          qaLeaveCancellationRequestId.current = null;
        }
        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      });
  }, [qaActive]);

  useEffect(
    () => () => {
      const requestId = activeQaRequestId.current;
      if (requestId) {
        activeQaRequestId.current = null;
        activeQaRequestProjectId.current = null;
        void cancelLegalAnswer({ requestId });
      }
    },
    [],
  );

  useEffect(() => {
    qaPreviewEpoch.current += 1;
    const previousProjectId = qaDraftProjectId.current;
    qaDraftsByProject.current.set(
      qaDraftStorageKey(previousProjectId),
      currentQaFormDraft(),
    );
    qaDraftProjectId.current = selectedCaseProjectId;
    applyQaFormDraft(
      copyQaFormDraft(
        qaDraftsByProject.current.get(
          qaDraftStorageKey(selectedCaseProjectId),
        ) ?? DEFAULT_QA_FORM_DRAFT,
      ),
    );

    const activeRequestId = activeQaRequestId.current;
    if (
      activeRequestId &&
      !legalAnswerRequestStillOwnsCurrentCase(
        activeQaRequestProjectId.current,
        selectedCaseProjectId,
      )
    ) {
      activeQaRequestId.current = null;
      activeQaRequestProjectId.current = null;
      qaLeaveCancellationRequestId.current = null;
      void cancelLegalAnswer({ requestId: activeRequestId });
    }

    qaHistoryLoadEpoch.current += 1;
    setQaHistoryRecords([]);
    setQaHistoryHasMore(false);
    setQaHistoryState({ kind: "idle" });
    setQaAnswer(null);
    setQaContext(null);
    setQaState({ kind: "idle" });
    setQaSubmittedQuestion(null);
    setSelectedQaSourceId(null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);

    if (selectedCaseProjectId) {
      void refreshLegalAnswerHistory(selectedCaseProjectId);
    }
    // Only a project transition may snapshot/restore these form fields. Their
    // live values intentionally are not dependencies of this transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCaseProjectId]);

  const activeQaContext = qaAnswer?.context ?? qaContext;
  const selectedQaSource = resolveSelectedQaSource(
    activeQaContext,
    selectedQaSourceId,
  );
  const answeredQaQuestion = resolveLegalAnswerQuestion(
    qaAnswer?.context ?? null,
    qaSubmittedQuestion,
  );
  const answeredQaScope = formatLegalAnswerScope(qaAnswer);
  const qaRequestLocked =
    qaState.kind === "loading" || isLegalAnswerStreamActive(qaStream);

  return {
    search: {
      query,
      setQuery,
      caseDate,
      setCaseDate,
      state: searchState,
      detailState,
      documentState,
      laws,
      articles,
      selectedDocument,
      versions,
      relations,
      selectedArticleId,
      selectedArticle,
      submit: submitSearch,
      run: runSearch,
      loadArticleDetail,
      loadDocumentContext,
      clearDocumentFilter,
      openLawGraph,
      bridgeState,
      addSelectedArticleToAssistant,
      proposeSelectedArticleForCase,
      openCaseAssistant: options.onOpenCaseAssistant,
      openAssistant: options.onOpenAssistant,
    },
    qa: {
      state: qaState,
      question: qaQuestion,
      setQuestion: setQaQuestion,
      lawName: qaLawName,
      setLawName: setQaLawName,
      articleNumber: qaArticleNumber,
      setArticleNumber: setQaArticleNumber,
      keywords: qaKeywords,
      setKeywords: setQaKeywords,
      caseDate: qaCaseDate,
      setCaseDate: setQaCaseDate,
      effectivenessLevels: qaEffectivenessLevels,
      setEffectivenessLevels: setQaEffectivenessLevels,
      includeExpired: qaIncludeExpired,
      setIncludeExpired: setQaIncludeExpired,
      context: qaContext,
      answer: qaAnswer,
      historyState: qaHistoryState,
      historyRecords: qaHistoryRecords,
      historyHasMore: qaHistoryHasMore,
      stream: qaStream,
      selectedSourceId: selectedQaSourceId,
      setSelectedSourceId: setSelectedQaSourceId,
      activeContext: activeQaContext,
      selectedSource: selectedQaSource,
      answeredQuestion: answeredQaQuestion,
      answeredScope: answeredQaScope,
      requestLocked: qaRequestLocked,
      preview: previewLegalAnswerContext,
      cancel: cancelCurrentLegalAnswer,
      restoreRecord: restoreLegalAnswerRecord,
      refreshHistory: refreshLegalAnswerHistory,
      openLawGraph,
    },
    context: {
      selectedCaseProjectId,
      assistantConversation,
      assistantActiveProject,
    },
    graphDocumentId,
    activeSources: activeQaContext?.sources ?? [],
    bridgeMutationInFlightRef,
    openDocumentCitation,
    consumeDocumentCitation,
    openLawDocumentFromGraph,
  };
}

export type LegalLibraryController = ReturnType<
  typeof useLegalLibraryController
>;
