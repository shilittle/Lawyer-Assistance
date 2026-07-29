import {
  formatConfirmationStatus,
  formatGapKind,
  formatGapSeverity,
} from "../../ipc/case/format";
import { extractionLocksSources } from "../../ipc/case/extractionReview";
import type { PartyRole } from "../../ipc/case/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import { publicErrorMessage } from "../../publicOutput";
import { publicCaseBusinessText } from "./model";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseGapExtractionPanelProps {
  controller: CaseWorkspaceController;
  providerProfiles: readonly ProviderProfile[];
}

export function CaseGapExtractionPanel({
  controller,
  providerProfiles,
}: CaseGapExtractionPanelProps) {
  const {
    caseWorkspace,
    selectedCaseProjectId,
    caseValidationTargetId,
    caseMutationInFlight,
    activeCaseEntityEditor,
    caseNavigationLocked,
    caseProjectMutationLocked,
    caseChildrenReady,
    removeCaseEntity,
  } = controller;
  const {
    providerId: extractionProviderId,
    setProviderId: setExtractionProviderId,
    fileIds: extractionFileIds,
    state: extractionState,
    confirmPreparing: extractionConfirmPreparing,
    discarding: extractionDiscarding,
    discardError: extractionDiscardError,
    draftSaveState: extractionDraftSaveState,
    reviewReloadRequired: extractionReviewReloadRequired,
    closePreparing: extractionClosePreparing,
    pendingReviewRecoveryBlock,
    reviewRef: extractionReviewRef,
    runStructuredExtraction,
    updateDraft: updateExtractionDraft,
    cancelReview: cancelExtractionReview,
    discardUnrestorablePendingReview,
    reloadServerDraft: reloadServerExtractionDraft,
    resetResult: resetExtractionResult,
    confirmReview: confirmExtractionReview,
  } = controller.extraction;

  return (
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
                    <strong>
                      {publicCaseBusinessText(
                        uncertainty.description,
                        "相关事项需要核实",
                      )}
                    </strong>
                    <span>
                      {uncertainty.status === "open" ? "待核实" : "已解决"} ·{" "}
                      {formatConfirmationStatus(uncertainty.confirmationStatus)}
                    </span>
                    <button
                      disabled={
                        caseNavigationLocked ||
                        activeCaseEntityEditor !== null
                      }
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
              <h3>材料信息整理</h3>
              <p className="privacy-note">
                仅处理已勾选材料的摘要，不会读取原始文件。整理结果须经你逐项审阅，确认前不会改动案件内容。
              </p>
              {pendingReviewRecoveryBlock?.projectId ===
              selectedCaseProjectId ? (
                <div className="risk-banner" role="alert">
                  <p>{pendingReviewRecoveryBlock.message}</p>
                  <button
                    disabled={extractionDiscarding || caseMutationInFlight}
                    type="button"
                    onClick={() =>
                      pendingReviewRecoveryBlock.reloadRequired
                        ? void reloadServerExtractionDraft(
                            pendingReviewRecoveryBlock.projectId,
                          )
                        : void discardUnrestorablePendingReview()
                    }
                  >
                    {pendingReviewRecoveryBlock.reloadRequired
                      ? caseMutationInFlight
                        ? "正在重新加载…"
                        : "重新加载最新草稿"
                      : extractionDiscarding
                        ? "正在放弃…"
                        : "放弃该待审阅草稿并解锁案件"}
                  </button>
                </div>
              ) : null}
              <label>
                <span>Provider</span>
                <select
                  id="extraction-provider"
                  aria-describedby="case-workbench-error"
                  aria-invalid={
                    caseValidationTargetId === "extraction-provider"
                  }
                  disabled={caseProjectMutationLocked}
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
                  !caseChildrenReady ||
                  caseProjectMutationLocked ||
                  activeCaseEntityEditor !== null ||
                  extractionLocksSources(extractionState)
                }
                type="button"
                onClick={() => void runStructuredExtraction()}
              >
                {extractionState.kind === "generating"
                  ? "正在请求并严格校验…"
                  : `生成待审阅内容（已选 ${extractionFileIds.length} 份材料）`}
              </button>

              {extractionState.kind === "reviewing" ||
              extractionState.kind === "committing" ? (
                <div
                  className="extraction-review"
                  role="region"
                  aria-labelledby="extraction-review-title"
                  aria-describedby="extraction-review-description"
                  onKeyDown={(event) => {
                    if (
                      event.key === "Escape" &&
                      extractionState.kind === "reviewing" &&
                      !extractionConfirmPreparing &&
                      !extractionDiscarding &&
                      !extractionReviewReloadRequired.current
                    ) {
                      event.preventDefault();
                      void cancelExtractionReview();
                    }
                  }}
                  ref={extractionReviewRef}
                  tabIndex={-1}
                >
                  <div className="review-banner" aria-live="polite">
                    <strong id="extraction-review-title">
                      待审阅整理结果，尚未保存
                    </strong>
                    <span>
                      <span id="extraction-review-description" className="sr-only">
                        请逐项审阅整理结果。按 Escape 可取消且不会保存。
                      </span>
                      {extractionState.restored
                        ? `已从本地恢复待审阅草稿（创建于 ${extractionState.restoredCreatedAt ?? "未知时间"}，到期于 ${extractionState.restoredExpiresAt ?? "未知时间"}）。`
                        : extractionState.repaired
                          ? "初次结果未通过校验，系统已修正并重新校验。"
                          : "整理结果已通过系统校验。"}
                    </span>
                  </div>
                  <p
                    className={
                      extractionDraftSaveState.kind === "conflict"
                        ? "error-text"
                        : "privacy-note"
                    }
                    role={
                      extractionDraftSaveState.kind === "conflict"
                        ? "alert"
                        : "status"
                    }
                  >
                    {extractionDraftSaveState.kind === "pending"
                      ? "审阅修改等待自动保存…"
                      : extractionDraftSaveState.kind === "saving"
                        ? "正在保存审阅修改…"
                        : extractionDraftSaveState.kind === "saved"
                          ? `审阅修改已保存${
                              extractionDraftSaveState.expiresAt
                                ? `；草稿到期于 ${extractionDraftSaveState.expiresAt}`
                                : ""
                            }。`
                          : extractionDraftSaveState.kind === "conflict"
                            ? extractionDraftSaveState.message
                            : "模型原始建议已保存在本地；编辑后会自动保存。"}
                  </p>
                  {extractionDraftSaveState.kind === "conflict" ? (
                    <div className="risk-banner" role="alert">
                      <p>
                        为避免覆盖其他窗口或重复提交，必须放弃本窗口尚未确认的内容并重新读取最新草稿。
                      </p>
                      <button
                        disabled={caseMutationInFlight || extractionDiscarding}
                        type="button"
                        onClick={() =>
                          void reloadServerExtractionDraft(
                            extractionState.context.projectId,
                          )
                        }
                      >
                        {caseMutationInFlight
                          ? "正在重新加载…"
                          : "重新加载最新草稿"}
                      </button>
                    </div>
                  ) : null}

                  <fieldset
                    className="review-fields"
                    disabled={
                      extractionState.kind === "committing" ||
                      extractionConfirmPreparing ||
                      extractionDiscarding ||
                      extractionClosePreparing ||
                      extractionDraftSaveState.kind === "conflict"
                    }
                  >
                  <legend className="sr-only">材料信息审阅字段</legend>
                  <h4 id="extraction-parties-title">当事人</h4>
                  {extractionState.draft.parties.map((party, index) => (
                    <div
                      className="review-card"
                      key={`party-${index}`}
                      role="group"
                      aria-label={`建议当事人 ${index + 1}`}
                    >
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
                        移除建议当事人：{party.name || `第 ${index + 1} 项`}
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
                        aria-label={`建议当事人 ${index + 1} 的角色`}
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

                  <h4 id="extraction-facts-title">事实</h4>
                  {extractionState.draft.facts.map((fact, index) => (
                    <div
                      className="review-card"
                      key={`fact-${index}`}
                      role="group"
                      aria-label={`建议事实 ${index + 1}`}
                    >
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
                        移除建议事实：{fact.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议事实 ${index + 1} 的发生日期`}
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
                        aria-label={`建议事实 ${index + 1} 的标题`}
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
                        aria-label={`建议事实 ${index + 1} 的描述`}
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
                        aria-label={`建议事实 ${index + 1} 关联的证据编号，逗号分隔`}
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

                  <h4 id="extraction-evidence-title">证据</h4>
                  {extractionState.draft.evidence.map((item, index) => (
                    <div
                      className="review-card"
                      key={`evidence-${index}`}
                      role="group"
                      aria-label={`建议证据 ${index + 1}`}
                    >
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
                        移除建议证据：{item.evidenceNumber || item.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议证据 ${index + 1} 的编号`}
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
                        aria-label={`建议证据 ${index + 1} 的标题`}
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
                        aria-label={`建议证据 ${index + 1} 的来源`}
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
                        aria-label={`建议证据 ${index + 1} 的形成日期`}
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
                        aria-label={`建议证据 ${index + 1} 的摘要`}
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

                  <h4 id="extraction-issues-title">争点与主张</h4>
                  {extractionState.draft.legalIssues.map((issue, index) => (
                    <div
                      className="review-card"
                      key={`issue-${index}`}
                      role="group"
                      aria-label={`建议争点 ${index + 1}`}
                    >
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
                        移除建议争点：{issue.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议争点 ${index + 1} 的标题`}
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
                        aria-label={`建议争点 ${index + 1} 的描述`}
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
                        aria-label={`建议争点 ${index + 1} 的主张`}
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

                  <h4 id="extraction-uncertainties-title">待核实事项</h4>
                  {extractionState.draft.uncertainties.map(
                    (uncertainty, index) => (
                      <div
                        className="review-card"
                        key={`uncertainty-${index}`}
                        role="group"
                        aria-label={`建议待核实事项 ${index + 1}`}
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
                          移除建议待核实事项：{uncertainty.description || `第 ${index + 1} 项`}
                        </button>
                        <textarea
                          aria-label={`建议待核实事项 ${index + 1} 的描述`}
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
                          aria-label={`建议待核实事项 ${index + 1} 的关联实体类型`}
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
                          aria-label={`建议待核实事项 ${index + 1} 的关联名称或编号`}
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
                    <p className="error-text" role="alert">
                      {extractionState.commitError}
                    </p>
                  ) : null}
                  {extractionDiscardError ? (
                    <p className="error-text" role="alert">
                      {extractionDiscardError}
                    </p>
                  ) : null}

                  <div className="review-actions">
                    <button
                      className="secondary-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void cancelExtractionReview()}
                    >
                      {extractionDiscarding
                        ? "正在取消…"
                        : extractionClosePreparing
                          ? "正在保存并关闭…"
                          : "取消，不写入"}
                    </button>
                    <button
                      className="confirm-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void confirmExtractionReview()}
                    >
                      {extractionClosePreparing
                        ? "正在保存并关闭窗口…"
                        : extractionState.kind === "committing"
                        ? "正在保存审阅结果…"
                        : extractionConfirmPreparing
                          ? "正在保存并准备确认…"
                        : "确认并保存审阅结果"}
                    </button>
                  </div>
                </div>
              ) : null}

              {extractionState.kind === "failed" ? (
                <div className="extraction-failure">
                  <strong>
                    材料信息整理未完成：
                    {publicErrorMessage(
                      extractionState.message,
                      "请检查模型服务和网络后重试。",
                    )}
                  </strong>
                  <span>
                    {extractionState.repairAttempted
                      ? "系统已尝试修正，但结果仍未通过校验。"
                      : "模型服务或网络异常，未生成可审阅内容。"}
                  </span>
                  <button type="button" onClick={resetExtractionResult}>
                    关闭
                  </button>
                </div>
              ) : null}

              {extractionState.kind === "committed" ? (
                <div className="connection-summary">
                  <span className="status-dot status-dot--succeeded" />
                  <strong>审阅结果已写入案件。</strong>
                </div>
              ) : null}
            </section>
    </aside>
  );
}
