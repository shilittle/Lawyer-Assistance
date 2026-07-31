import {
  formatCitationInvalidReason,
  formatEffectiveWindow,
  formatLegalContextWarning,
  formatLegalSourceLabel,
  formatStatus,
  segmentLegalAnswer,
} from "../../ipc/legal/format";
import { EFFECTIVENESS_LEVEL_OPTIONS } from "../../ipc/legal/query";
import {
  formatLegalAnswerStreamStatus,
  isLegalAnswerStreamCancellable,
} from "../../ipc/legal/stream";
import {
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";
import type { CaseWorkspace } from "../../ipc/case/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import {
  citationHasTrustedSource,
  formatCitationValidationSummary,
} from "./model";
import type { LegalLibraryController } from "./useLegalLibraryController";

export interface LegacyQaWorkspaceProps {
  controller: LegalLibraryController;
  providerProfiles: readonly ProviderProfile[];
  caseWorkspace: CaseWorkspace | null;
}

export function LegacyQaWorkspace({
  controller,
  providerProfiles,
  caseWorkspace,
}: LegacyQaWorkspaceProps) {
  const {
    state,
    question,
    setQuestion,
    lawName,
    setLawName,
    articleNumber,
    setArticleNumber,
    keywords,
    setKeywords,
    caseDate,
    setCaseDate,
    effectivenessLevels,
    setEffectivenessLevels,
    includeExpired,
    setIncludeExpired,
    providerId,
    setProviderId,
    answer,
    historyState,
    historyRecords,
    historyHasMore,
    stream,
    setSelectedSourceId,
    activeContext,
    selectedSource,
    answeredQuestion,
    answeredScope,
    requestLocked,
    preview,
    cancel,
    restoreRecord,
    refreshHistory,
    openLawGraph,
  } = controller.qa;
  const { selectedCaseProjectId } = controller.context;

  return (
    <section className="qa-layout">
      <aside
        className="panel qa-control-panel"
        aria-labelledby="qa-control-title"
      >
        <div className="panel-heading">
          <h2 id="qa-control-title">问题</h2>
          <span>{formatLegalAnswerStreamStatus(stream)}</span>
        </div>
        <form
          className="qa-form"
          onSubmit={(event) => event.preventDefault()}
        >
          <p className="privacy-note">
            回答归属：
            {caseWorkspace && selectedCaseProjectId
              ? publicTitle(caseWorkspace.project.title, "当前案件")
              : "未选择已保存案件；可检索来源，但不能生成或保存回答"}
          </p>
          <fieldset className="qa-request-fields" disabled={requestLocked}>
            <label>
              <span>法律问题</span>
              <textarea
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                placeholder="输入需要检索和回答的法律问题"
              />
            </label>
            <div className="form-grid">
              <label>
                <span>法律名称</span>
                <input
                  value={lawName}
                  onChange={(event) => setLawName(event.target.value)}
                  placeholder="如：民法典"
                />
              </label>
              <label>
                <span>条号</span>
                <input
                  value={articleNumber}
                  onChange={(event) => setArticleNumber(event.target.value)}
                  placeholder="如：第五百七十七条"
                />
              </label>
            </div>
            <label>
              <span>关键词</span>
              <input
                value={keywords}
                onChange={(event) => setKeywords(event.target.value)}
                placeholder="空格、逗号或顿号分隔"
              />
            </label>
            <div className="form-grid">
              <label>
                <span>案件日期</span>
                <input
                  type="date"
                  value={caseDate}
                  onChange={(event) => setCaseDate(event.target.value)}
                />
                <small>
                  留空按当前有效性检索；不会以立案/接案日期代替案件事实日期。
                </small>
              </label>
              <label>
                <span>Provider</span>
                <select
                  value={providerId}
                  onChange={(event) => setProviderId(event.target.value)}
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
            <fieldset className="qa-effectiveness-filter">
              <legend>效力层级（可多选）</legend>
              <div className="toggle-row">
                {EFFECTIVENESS_LEVEL_OPTIONS.map(([value, label]) => (
                  <label key={value}>
                    <input
                      type="checkbox"
                      checked={effectivenessLevels.includes(value)}
                      onChange={(event) =>
                        setEffectivenessLevels((current) =>
                          event.target.checked
                            ? [...current, value]
                            : current.filter((level) => level !== value),
                        )
                      }
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={includeExpired}
                onChange={(event) => setIncludeExpired(event.target.checked)}
              />
              <span>包含失效版本</span>
            </label>
          </fieldset>
          <div className="command-row">
            <button
              type="button"
              disabled={requestLocked}
              onClick={() => void preview()}
            >
              本地检索来源
            </button>
            {isLegalAnswerStreamCancellable(stream) ? (
              <button type="button" onClick={() => void cancel()}>
                取消生成
              </button>
            ) : null}
          </div>
        </form>
        {state.kind === "error" ? (
          <p className="error-text" role="alert">
            {state.message}
          </p>
        ) : null}
        {activeContext && activeContext.warnings.length > 0 ? (
          <div
            className="context-warning-list"
            role="status"
            aria-label="法律检索风险提示"
          >
            {activeContext.warnings.map((warning, index) => (
              <p key={`${index}-${warning}`}>
                {formatLegalContextWarning(warning)}
              </p>
            ))}
          </div>
        ) : null}
        <section className="detail-section" aria-labelledby="qa-history-title">
          <div className="section-heading">
            <h3 id="qa-history-title">当前案件问答历史</h3>
            <span>
              {historyState.kind === "loading"
                ? "读取中"
                : historyRecords.length}
            </span>
          </div>
          {historyState.kind === "error" ? (
            <p className="error-text" role="alert">
              历史回答读取失败：{historyState.message}
            </p>
          ) : null}
          <div className="qa-history-list">
            {historyRecords.map((record) => (
              <button
                className="qa-history-item"
                disabled={requestLocked}
                key={record.recordId}
                type="button"
                aria-label={`恢复历史回答：${record.question}`}
                onClick={() => restoreRecord(record)}
              >
                <strong>{record.question}</strong>
                <span>
                  保存于 {record.createdAt.replace("T", " ").replace("Z", "")}
                </span>
                <span>
                  {record.citationReport.validCount} 条法条依据
                  {record.citationReport.invalidCount > 0
                    ? ` · ${record.citationReport.invalidCount} 条需要核对`
                    : ""}
                </span>
              </button>
            ))}
            {selectedCaseProjectId &&
            historyState.kind !== "loading" &&
            historyRecords.length === 0 ? (
              <p className="empty-state">当前案件暂无已保存回答</p>
            ) : null}
            {selectedCaseProjectId && historyHasMore ? (
              <button
                className="secondary-action"
                disabled={requestLocked || historyState.kind === "loading"}
                type="button"
                onClick={() =>
                  void refreshHistory(selectedCaseProjectId, true)
                }
              >
                {historyState.kind === "loading"
                  ? "正在读取…"
                  : "加载更早回答"}
              </button>
            ) : null}
            {!selectedCaseProjectId ? (
              <p className="empty-state">请先在案件工作台选择案件</p>
            ) : null}
          </div>
        </section>
        <section className="detail-section" aria-labelledby="qa-source-title">
          <div className="section-heading">
            <h3 id="qa-source-title">候选来源</h3>
            <span>{activeContext?.sources.length ?? 0}</span>
          </div>
          <div className="source-list">
            {activeContext?.sources.map((source) => (
              <button
                className={`source-item ${
                  selectedSource?.sourceId === source.sourceId
                    ? "is-selected"
                    : ""
                }`}
                key={source.sourceId}
                type="button"
                onClick={() => setSelectedSourceId(source.sourceId)}
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
                <span className="item-summary">
                  内容摘要：{publicContentSummary(source.snippet)}
                </span>
              </button>
            ))}
            {activeContext && activeContext.sources.length === 0 ? (
              <p className="empty-state">未找到本地候选来源</p>
            ) : null}
          </div>
        </section>
      </aside>

      <section
        className="panel qa-answer-panel"
        aria-labelledby="qa-answer-title"
      >
        <div className="panel-heading">
          <h2 id="qa-answer-title">回答</h2>
          <span>
            {answer
              ? `${answer.citationReport.validCount} 条法条依据`
              : formatLegalAnswerStreamStatus(stream)}
          </span>
        </div>
        {answeredQuestion ? (
          <p className="answer-query" role="status">
            <strong>本次回答对应问题</strong>
            <span>{answeredQuestion}</span>
            {answeredScope ? (
              <span className="answer-query-meta">{answeredScope}</span>
            ) : null}
          </p>
        ) : null}
        {stream.status === "error" || stream.status === "cancelled" ? (
          <p className="error-text">
            {stream.status === "cancelled"
              ? "回答生成已取消。"
              : publicErrorMessage(
                  stream.message,
                  "回答生成未完成，请重试。",
                )}
          </p>
        ) : null}
        {answer ? (
          <>
            {answer.citationReport.unsupportedLegalConclusion ? (
              <p className="risk-banner">
                部分法律结论缺少可核对的法条依据，请补充依据后再使用。
              </p>
            ) : !answer.citationReport.semanticSupportVerified ? (
              <p className="risk-banner">
                本回答依据本地法律资料生成，请结合案件事实逐条核对并由律师审定。
              </p>
            ) : null}
            <article className="answer-box">
              <p>
                {segmentLegalAnswer(
                  answer.answer,
                  answer.citationReport.citations,
                ).map((segment) =>
                  segment.kind === "text" ? (
                    <span key={segment.key}>
                      {sanitizePublicGeneratedText(segment.text, "")}
                    </span>
                  ) : citationHasTrustedSource(segment.citation) ? (
                    <button
                      className="answer-citation answer-citation--valid"
                      key={segment.key}
                      type="button"
                      title="打开本地法条原文"
                      onClick={() =>
                        setSelectedSourceId(
                          segment.citation.source!.sourceId,
                        )
                      }
                    >
                      {segment.text}
                    </button>
                  ) : (
                    <span
                      className="answer-citation answer-citation--invalid"
                      key={segment.key}
                      title={formatCitationInvalidReason(
                        segment.citation.reason,
                      )}
                    >
                      {segment.text}
                    </span>
                  ),
                )}
              </p>
            </article>
            <div className="answer-meta-row">
              <span>
                {answer.recordId ? "回答已保存" : "本次回答尚未保存"}
              </span>
            </div>
            <section
              className="detail-section"
              aria-labelledby="qa-citation-title"
            >
              <div className="section-heading">
                <h3 id="qa-citation-title">法律依据与案例引用表</h3>
                <span>
                  {formatCitationValidationSummary(answer.citationReport)}
                </span>
              </div>
              <p className="validation-scope-note">
                以下列明本回答采用的法律依据；适用结论仍应结合案件事实由律师审定。
              </p>
              <div className="citation-list">
                {answer.citationReport.citations.map((citation, index) => {
                  const key = `${citation.rawMarker}-${citation.sourceId}-${index}`;
                  const content = (
                    <>
                      <strong>
                        {citation.source
                          ? formatLegalSourceLabel(citation.source)
                          : `第 ${index + 1} 条依据`}
                      </strong>
                      <span>
                        {citation.status === "valid"
                          ? "查看法条原文"
                          : formatCitationInvalidReason(citation.reason)}
                      </span>
                    </>
                  );

                  return citationHasTrustedSource(citation) ? (
                    <button
                      className="citation-item citation-item--valid"
                      key={key}
                      type="button"
                      onClick={() =>
                        setSelectedSourceId(citation.source.sourceId)
                      }
                    >
                      {content}
                    </button>
                  ) : (
                    <div
                      className="citation-item citation-item--invalid"
                      key={key}
                    >
                      {content}
                    </div>
                  );
                })}
                {answer.citationReport.citations.length === 0 ? (
                  <p className="empty-state">本回答未列出法条或案例依据</p>
                ) : null}
              </div>
            </section>
          </>
        ) : stream.answer ? (
          <p className="risk-banner">
            {stream.status === "finalizing"
              ? "回答已保存，正在载入法条依据。"
              : "回答正在生成，完成后将在此显示。"}
          </p>
        ) : (
          <p className="empty-state">
            先检索本地法律资料；完成模型服务和访问凭据设置后再生成回答。
          </p>
        )}
      </section>

      <aside
        className="panel qa-source-detail"
        aria-labelledby="qa-detail-title"
      >
        <div className="panel-heading">
          <h2 id="qa-detail-title">本地原文</h2>
          <span>{selectedSource ? "可追溯" : "未选择"}</span>
        </div>
        {selectedSource ? (
          <article className="article-detail">
            <h3>{formatLegalSourceLabel(selectedSource)}</h3>
            <p className="article-content">{selectedSource.content}</p>
            <dl className="meta-grid">
              <div>
                <dt>版本</dt>
                <dd>{selectedSource.versionLabel}</dd>
              </div>
              <div>
                <dt>效力期间</dt>
                <dd>
                  {formatEffectiveWindow(
                    selectedSource.effectiveFrom,
                    selectedSource.effectiveTo,
                  )}
                </dd>
              </div>
              <div>
                <dt>状态</dt>
                <dd>{formatStatus(selectedSource.versionStatus)}</dd>
              </div>
            </dl>
            <button
              type="button"
              onClick={() => openLawGraph(selectedSource.documentId)}
            >
              查看该法律关系图
            </button>
          </article>
        ) : (
          <p className="empty-state">选择候选来源或有效引用查看原文</p>
        )}
      </aside>
    </section>
  );
}
