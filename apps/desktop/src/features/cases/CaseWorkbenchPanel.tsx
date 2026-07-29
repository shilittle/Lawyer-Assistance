import type { GraphTargetRequest } from "../../app/routes";
import {
  formatConfirmationStatus,
  formatLegalBasisInvalidReason,
  formatLegalBasisStatus,
  formatLegalIssueStatus,
  formatPartyRole,
} from "../../ipc/case/format";
import type {
  ConfirmationStatus,
  LegalIssueStatus,
  PartyRole,
} from "../../ipc/case/types";
import { formatLegalSourceLabel, formatStatus } from "../../ipc/legal/format";
import type { LegalSource } from "../../ipc/legal/types";
import {
  publicContentSummary,
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";
import {
  caseEntityEditorAllows,
  caseEntityEditorMatches,
  caseGraphNodeDomId,
  formatLegalBasisTitle,
  formatLegalBasisWindow,
  publicCaseBusinessText,
  publicEvidenceNumber,
} from "./model";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseWorkbenchPanelProps {
  controller: CaseWorkspaceController;
  legalSources: readonly LegalSource[];
  graphTarget: GraphTargetRequest | null;
  onContinueInAssistant: () => void;
  onOpenCaseGraph: () => void;
}

export function CaseWorkbenchPanel({
  controller,
  legalSources,
  graphTarget,
  onContinueInAssistant,
  onOpenCaseGraph,
}: CaseWorkbenchPanelProps) {
  const {
    caseState,
    selectedCaseProjectId,
    caseWorkspace,
    caseValidationTargetId,
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
    assistantActiveProject,
    startCaseEntityEdit,
    cancelCaseEntityEdit,
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
  } = controller;
  const {
    fileIds: extractionFileIds,
    setFileIds: setExtractionFileIds,
    sourcesLocked: extractionSourcesLocked,
  } = controller.extraction;

  return (
    <section className="panel case-workbench-panel" aria-labelledby="case-workbench-title">
            <div className="panel-heading">
              <h2 id="case-workbench-title">案件工作台 β</h2>
              <span>{caseState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={!assistantActiveProject || caseNavigationLocked}
                type="button"
                onClick={onContinueInAssistant}
              >
                在助理中继续
              </button>
            </div>
            <div className="case-scroll">
              {caseState.kind === "error" ? (
                <p
                  className="error-text"
                  id="case-workbench-error"
                  role="alert"
                  aria-live="assertive"
                >
                  {caseState.message}
                </p>
              ) : null}
              <form className="case-form" onSubmit={saveCaseProject}>
                <fieldset
                  className="case-entity-fields"
                  disabled={caseProjectMutationLocked}
                >
                <div className="form-grid">
                  <label>
                    <span>案件名称</span>
                    <input
                      id="case-project-title"
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
                  <button disabled={caseProjectMutationLocked} type="submit">
                    保存案件
                  </button>
                  <button
                    disabled={
                      !selectedCaseProjectId || caseProjectMutationLocked
                    }
                    type="button"
                    onClick={() => void removeCaseProject()}
                  >
                    删除案件
                  </button>
                  <button
                    disabled={!selectedCaseProjectId || caseProjectMutationLocked}
                    type="button"
                    onClick={onOpenCaseGraph}
                  >
                    查看案件关系图
                  </button>
                </div>
                </fieldset>
              </form>
              {!caseChildrenReady ? (
                <p className="privacy-note">
                  请先保存案件；保存成功后才能录入、关联或删除案件子项。
                </p>
              ) : null}

              <section className="case-section">
                <div className="section-heading">
                  <h3>案件材料</h3>
                  <span>{caseWorkspace?.files.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFile}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                    }
                  >
                  {editingFile ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的案件材料；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>标题</span>
                      <input
                        id="case-file-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-file-title"}
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
                  </div>
                  <label>
                    <span>材料摘要</span>
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
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                      }
                      type="submit"
                    >
                      {editingFile ? "更新材料" : "添加材料"}
                    </button>
                    {editingFile ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.files.map((file) => (
                    <div className="compact-row" key={file.fileId}>
                      <label className="material-select">
                        <input
                          checked={extractionFileIds.includes(file.fileId)}
                          disabled={caseProjectMutationLocked}
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
                        <strong>{publicTitle(file.title, "案件材料")}</strong>
                      </label>
                      <span>{publicTitle(file.fileType, "未分类")}</span>
                      <span>
                        {publicContentSummary(file.summary, "未填写材料摘要")}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "file", entity: file })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "file",
                            file.fileId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            extractionSourcesLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "file",
                              file.fileId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("file", file.fileId)
                          }
                        >
                          删除
                        </button>
                      </div>
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
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                    }
                  >
                  {editingParty ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的当事人；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>名称</span>
                      <input
                        id="case-party-name"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-party-name"}
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
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                      }
                      type="submit"
                    >
                      {editingParty ? "更新当事人" : "添加当事人"}
                    </button>
                    {editingParty ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.parties.map((party) => (
                    <div className="compact-row" key={party.partyId}>
                      <strong>{publicTitle(party.name, "案件当事人")}</strong>
                      <span>{formatPartyRole(party.role)}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "party",
                              entity: party,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "party",
                            party.partyId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "party",
                              party.partyId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("party", party.partyId)
                          }
                        >
                          删除
                        </button>
                      </div>
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
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                    }
                  >
                  {editingFact ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的事实；保存后将覆盖原记录。
                    </p>
                  ) : null}
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
                        id="case-fact-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-fact-title"}
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
                        <option value="model_suggested">待审阅建议</option>
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
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                      }
                      type="submit"
                    >
                      {editingFact ? "更新事实" : "添加事实"}
                    </button>
                    {editingFact ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.facts.map((fact) => (
                    <div
                      className={`compact-row ${
                        graphTarget?.sourceKind === "case_fact" &&
                        graphTarget.sourceId === fact.factId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("case_fact", fact.factId)}
                      key={fact.factId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(fact.title, "案件事实")}</strong>
                      <span>
                        {fact.occurredOn ?? "未登记日期"} ·{" "}
                        {formatConfirmationStatus(fact.confirmationStatus)}
                      </span>
                      <span>
                        {publicCaseBusinessText(
                          fact.description,
                          "未填写事实描述",
                        )}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "fact", entity: fact })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "fact",
                            fact.factId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "fact",
                              fact.factId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("fact", fact.factId)
                          }
                        >
                          删除
                        </button>
                      </div>
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
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                    }
                  >
                  {editingEvidence ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的证据；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>编号</span>
                      <input
                        id="case-evidence-number"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-number"
                        }
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
                        id="case-evidence-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-title"
                        }
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
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                      }
                      type="submit"
                    >
                      {editingEvidence ? "更新证据" : "添加证据"}
                    </button>
                    {editingEvidence ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.evidence.map((item) => (
                    <div
                      className={`compact-row ${
                        graphTarget?.sourceKind === "evidence_item" &&
                        graphTarget.sourceId === item.evidenceId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("evidence_item", item.evidenceId)}
                      key={item.evidenceId}
                      tabIndex={-1}
                    >
                      <strong>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </strong>
                      <span>
                        {publicCaseBusinessText(item.source, "缺少来源")} ·{" "}
                        {item.formedOn ?? "缺少形成时间"}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "evidence",
                              entity: item,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "evidence",
                            item.evidenceId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "evidence",
                              item.evidenceId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence", item.evidenceId)
                          }
                        >
                          删除
                        </button>
                      </div>
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
                    id="case-link-fact"
                    aria-label="要关联的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={caseValidationTargetId === "case-link-fact"}
                    disabled={caseProjectMutationLocked}
                    value={linkFactId}
                    onChange={(event) => setLinkFactId(event.target.value)}
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-link-evidence"
                    aria-label="要关联的证据"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-link-evidence"
                    }
                    disabled={caseProjectMutationLocked}
                    value={linkEvidenceId}
                    onChange={(event) => setLinkEvidenceId(event.target.value)}
                  >
                    <option value="">选择证据</option>
                    {caseWorkspace?.evidence.map((item) => (
                      <option key={item.evidenceId} value={item.evidenceId}>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkEvidenceToFact()}
                  >
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
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          {publicEvidenceNumber(
                            evidence?.evidenceNumber,
                            "相关证据",
                          )}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
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
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(
                        activeCaseEntityEditor,
                        "legal_issue",
                      )
                    }
                  >
                  {editingIssue ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的争点；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>争点</span>
                      <input
                        id="case-issue-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-issue-title"}
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
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(
                          activeCaseEntityEditor,
                          "legal_issue",
                        )
                      }
                      type="submit"
                    >
                      {editingIssue ? "更新争点" : "添加争点"}
                    </button>
                    {editingIssue ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalIssues.map((issue) => (
                    <div
                      className={`compact-row ${
                        graphTarget?.sourceKind === "legal_issue" &&
                        graphTarget.sourceId === issue.issueId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("legal_issue", issue.issueId)}
                      key={issue.issueId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(issue.title, "相关法律争点")}</strong>
                      <span>{formatLegalIssueStatus(issue.status)}</span>
                      <span>{publicCaseBusinessText(issue.claim, "尚未填写主张")}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "legal_issue",
                              entity: issue,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "legal_issue",
                            issue.issueId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "legal_issue",
                              issue.issueId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_issue", issue.issueId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <div>
                    <h3>事实—争点关联</h3>
                    <p className="muted">
                      仅保存你手动建立的关联，不会自动推断。
                    </p>
                  </div>
                  <span>{caseWorkspace?.factIssueLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    id="case-fact-issue-fact"
                    aria-label="要关联到争点的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-fact"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueFactId}
                    onChange={(event) =>
                      setFactIssueFactId(event.target.value)
                    }
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-fact-issue-issue"
                    aria-label="要关联到事实的争点"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-issue"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueIssueId}
                    onChange={(event) =>
                      setFactIssueIssueId(event.target.value)
                    }
                  >
                    <option value="">选择争点</option>
                    {caseWorkspace?.legalIssues.map((issue) => (
                      <option key={issue.issueId} value={issue.issueId}>
                        {publicTitle(issue.title, "相关法律争点")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkFactToIssue()}
                  >
                    建立显式关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.factIssueLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const issue = caseWorkspace.legalIssues.find(
                      (item) => item.issueId === link.issueId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          争点：{publicTitle(issue?.title, "相关法律争点")}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity(
                              "fact_issue_link",
                              link.linkId,
                            )
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.factIssueLinks.length === 0 ? (
                    <p className="muted">尚未手动建立事实—争点关联。</p>
                  ) : null}
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
                  <fieldset
                    className="case-entity-fields"
                    disabled={caseProjectMutationLocked}
                  >
                  <div className="form-grid">
                    <label>
                      <span>本地法律来源</span>
                      <select
                        id="case-basis-source-id"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-basis-source-id"
                        }
                        value={basisSourceId}
                        onChange={(event) => setBasisSourceId(event.target.value)}
                      >
                        <option value="">请选择已检索的法律来源</option>
                        {legalSources.map((source) => (
                          <option key={source.sourceId} value={source.sourceId}>
                            {formatLegalSourceLabel(source)}
                          </option>
                        ))}
                      </select>
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
                            {publicTitle(issue.title, "相关法律争点")}
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
                      <small>
                        留空将按当前有效性校验，不会使用立案/接案日期代替。
                      </small>
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
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="submit"
                  >
                    添加依据
                  </button>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalBasis.map((basis, basisIndex) => {
                    const linkedIssue = caseWorkspace.legalIssues.find(
                      (issue) => issue.issueId === basis.issueId,
                    );
                    const isFirstBasisForSource =
                      caseWorkspace.legalBasis.findIndex(
                        (item) => item.sourceId === basis.sourceId,
                      ) === basisIndex;

                    return (
                      <div
                        className={`compact-row legal-basis-row legal-basis-row--${basis.status} ${
                          graphTarget?.sourceKind === "verified_citation" &&
                          graphTarget.sourceId === basis.sourceId
                            ? "graph-jump-target"
                            : ""
                        }`}
                        id={
                          isFirstBasisForSource
                            ? caseGraphNodeDomId("verified_citation", basis.sourceId)
                            : undefined
                        }
                        key={basis.basisId}
                        tabIndex={-1}
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
                          {linkedIssue
                            ? `争点：${publicTitle(linkedIssue.title, "相关法律争点")}`
                            : "未关联争点"}{" "}
                          · {basis.caseDate ?? "未指定案件日期"}
                        </span>
                        {basis.excerpt ? (
                          <span>内容摘要：{publicContentSummary(basis.excerpt)}</span>
                        ) : null}
                        {basis.note ? (
                          <span>
                            {sanitizePublicGeneratedText(
                              basis.note,
                              "补充说明暂不可用。",
                            )}
                          </span>
                        ) : null}
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
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
  );
}
