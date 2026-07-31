import { useEffect, useRef } from "react";

import type { LegalCitationRequest } from "../../app/routes";
import {
  formatArticleLabel,
  formatEffectiveWindow,
  formatStatus,
} from "../../ipc/legal/format";
import {
  publicContentSummary,
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";
import { LegalLibraryWorkspace } from "./LegalLibraryWorkspace";
import type { LegalLibraryController } from "./useLegalLibraryController";

export interface LegalLibrarySearchWorkspaceProps {
  controller: LegalLibraryController;
  citationRequest?: LegalCitationRequest | null;
  onCitationRequestConsumed?: (request: LegalCitationRequest) => void;
}

export function LegalLibrarySearchWorkspace({
  controller,
  citationRequest = null,
  onCitationRequestConsumed,
}: LegalLibrarySearchWorkspaceProps) {
  const consumeDocumentCitation =
    controller.consumeDocumentCitation;
  const handledCitationKey = useRef<string | null>(null);
  useEffect(() => {
    if (!citationRequest) {
      handledCitationKey.current = null;
      return;
    }
    const requestKey = [
      citationRequest.sourceId,
      citationRequest.documentId,
      citationRequest.versionId,
      citationRequest.articleId,
    ].join("\u0000");
    if (handledCitationKey.current === requestKey) return;
    handledCitationKey.current = requestKey;
    void consumeDocumentCitation(citationRequest);
    onCitationRequestConsumed?.(citationRequest);
  }, [
    citationRequest,
    consumeDocumentCitation,
    onCitationRequestConsumed,
  ]);

  const {
    query,
    setQuery,
    caseDate,
    setCaseDate,
    state,
    detailState,
    documentState,
    laws,
    articles,
    selectedDocument,
    versions,
    relations,
    selectedArticleId,
    selectedArticle,
    submit,
    loadArticleDetail,
    loadDocumentContext,
    clearDocumentFilter,
    openLawGraph,
    bridgeState,
    addSelectedArticleToAssistant,
    proposeSelectedArticleForCase,
    openCaseAssistant,
    openAssistant,
  } = controller.search;
  const {
    assistantConversation,
    assistantActiveProject,
    selectedCaseProjectId,
  } = controller.context;

  return (
    <LegalLibraryWorkspace>
      <section className="query-band" aria-label="检索条件">
        <form className="search-form" onSubmit={submit}>
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
            <div className="command-row">
              <button
                type="button"
                onClick={() => openLawGraph(selectedDocument.documentId)}
              >
                查看法律关系图
              </button>
              <button
                type="button"
                onClick={() => void clearDocumentFilter()}
              >
                清除筛选
              </button>
            </div>
          ) : null}
        </div>
      </section>

      <section className="workspace-grid">
        <aside className="panel law-panel" aria-labelledby="law-panel-title">
          <div className="panel-heading">
            <h2 id="law-panel-title">法律</h2>
            <span>{laws.length}</span>
          </div>
          {state.kind === "error" ? (
            <p className="error-text">{state.message}</p>
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
                <span className="item-title">
                  {publicTitle(
                    law.title,
                    `${publicTitle(law.authorityName, "发布机关")}发布的${publicTitle(law.documentType, "法律文件")}`,
                  )}
                </span>
                <span className="item-meta">
                  {formatStatus(law.status)} · {law.authorityName}
                </span>
                <span className="item-summary">
                  内容摘要：{publicContentSummary(law.summary)}
                </span>
              </button>
            ))}
          </div>
        </aside>

        <section className="panel article-panel" aria-labelledby="article-title">
          <div className="panel-heading">
            <h2 id="article-title">法条</h2>
            <span>{state.kind === "loading" ? "检索中" : articles.length}</span>
          </div>
          <div className="article-list">
            {articles.map((article) => (
              <button
                className={`article-item ${
                  selectedArticleId === article.articleId ? "is-selected" : ""
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
                <span className="item-summary">
                  内容摘要：{publicContentSummary(article.snippet)}
                </span>
              </button>
            ))}
          </div>
        </section>

        <aside className="panel detail-panel" aria-labelledby="detail-title">
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
              <div className="command-row">
                <button
                  disabled={
                    !assistantConversation || bridgeState.kind === "loading"
                  }
                  type="button"
                  onClick={() => void addSelectedArticleToAssistant()}
                >
                  {bridgeState.kind === "loading"
                    ? "正在加入…"
                    : "加入当前助理会话"}
                </button>
                <button
                  disabled={
                    !assistantConversation ||
                    !selectedCaseProjectId ||
                    assistantConversation.projectId !== selectedCaseProjectId ||
                    bridgeState.kind === "loading"
                  }
                  type="button"
                  onClick={() => void proposeSelectedArticleForCase()}
                >
                  加入当前案件（待确认）
                </button>
                <button
                  type="button"
                  onClick={() =>
                    assistantActiveProject
                      ? openCaseAssistant()
                      : openAssistant()
                  }
                >
                  {assistantActiveProject ? "在案件助理中继续" : "打开助理"}
                </button>
              </div>
              <p
                className={
                  bridgeState.kind === "error" ? "error-text" : "privacy-note"
                }
                role={bridgeState.kind === "error" ? "alert" : "status"}
              >
                {bridgeState.kind === "success" ||
                bridgeState.kind === "error"
                  ? bridgeState.message
                  : assistantConversation
                    ? assistantActiveProject &&
                      assistantConversation.projectId !==
                        assistantActiveProject.projectId
                      ? `当前助理会话“${publicTitle(assistantConversation.title, "助理会话")}”未绑定所选案件；请先点“在案件助理中继续”，再返回生成待确认法律依据。`
                      : `目标会话：${publicTitle(assistantConversation.title, "助理会话")}`
                    : "请先在助理中创建或选择一个会话。"}
              </p>
              <dl className="meta-grid">
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
                {documentState.kind === "loading" ? "读取中" : versions.length}
              </span>
            </div>
            {documentState.kind === "error" ? (
              <p className="error-text" role="alert">
                法律版本或关系上下文加载失败：{documentState.message}
              </p>
            ) : null}
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
                    {formatStatus(relation.relationType)} · {relation.toTitle}
                  </strong>
                  <span>
                    {sanitizePublicGeneratedText(
                      relation.description,
                      "关系说明暂不可用。",
                    )}
                  </span>
                  {relation.sourceReference ? (
                    <span>官方来源记录已保留</span>
                  ) : null}
                </div>
              ))}
            </div>
          </section>
        </aside>
      </section>
    </LegalLibraryWorkspace>
  );
}
