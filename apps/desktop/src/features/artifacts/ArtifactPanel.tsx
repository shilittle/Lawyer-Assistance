import {
  useCallback,
  useEffect,
  useId,
  lazy,
  Suspense,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  bindAssistantArtifact,
  exportAssistantArtifact,
  getAssistantArtifact,
  rejectAssistantCaseChangeProposal,
} from "../../ipc/assistant/client";
import type {
  AssistantArtifact,
  AssistantArtifactExportFormat,
  AssistantArtifactVersion,
  AssistantCaseChangeProposal,
  AssistantConversationSource,
  GetAssistantArtifactResponse,
  JsonValue,
} from "../../ipc/assistant/types";
import {
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";
import { mapSpecFromArtifactVersion } from "./mapModel";
import { applyProposalAfterExplicitConfirmation } from "./proposalActions";
import { SafeArtifactMarkdown } from "./SafeArtifactMarkdown";
import "./artifacts.css";

const AssistantMapPreview = lazy(() =>
  import("./AssistantMapPreview").then((module) => ({
    default: module.AssistantMapPreview,
  })),
);

export interface ArtifactPanelActiveProject {
  projectId: string;
  title: string;
}

export interface ArtifactPanelProps {
  sources: AssistantConversationSource[];
  artifacts: AssistantArtifact[];
  proposals: AssistantCaseChangeProposal[];
  selectedArtifactId: string | null;
  activeProject: ArtifactPanelActiveProject | null;
  onSelectArtifact: (artifactId: string) => void;
  onConversationRefresh: () => void;
  onDraftDirtyChange?: (dirty: boolean) => void;
  onMutationActivityChange?: (active: boolean) => void;
  onProposalApplied?: (projectId: string) => void;
  proposalApplyBlockedReason?: string | null;
}

type ArtifactLoadState =
  | { phase: "idle"; artifactId: null; detail: null; message: "" }
  | { phase: "loading"; artifactId: string; detail: null; message: "" }
  | {
      phase: "ready";
      artifactId: string;
      detail: GetAssistantArtifactResponse;
      message: "";
    }
  | {
      phase: "error";
      artifactId: string;
      detail: null;
      message: string;
    };

function displayError(error: unknown): string {
  return publicErrorMessage(error);
}

function dateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN");
}

function jsonRecord(value: JsonValue): Record<string, JsonValue> | null {
  return value !== null && !Array.isArray(value) && typeof value === "object"
    ? value
    : null;
}

function numberField(
  value: Record<string, JsonValue> | null,
  field: string,
): number | null {
  const candidate = value?.[field];
  return typeof candidate === "number" ? candidate : null;
}

function booleanField(
  value: Record<string, JsonValue> | null,
  field: string,
): boolean | null {
  const candidate = value?.[field];
  return typeof candidate === "boolean" ? candidate : null;
}

function sourceRefLabel(
  sourceRef: string,
  sources: AssistantConversationSource[],
): string {
  const source = sources.find((entry) => entry.sourceId === sourceRef)?.source;
  return source
    ? publicTitle(
        source.canonicalLabel,
        `《${publicTitle(source.documentTitle, "法律文件")}》${publicTitle(source.articleNumber, "相关条文")}`,
      )
    : "来源记录暂不可用";
}

function artifactKindLabel(kind: AssistantArtifact["kind"]): string {
  switch (kind) {
    case "research":
      return "研究结论";
    case "document":
      return "文书草稿";
    case "map":
      return "分析图";
  }
}

function proposalStatusLabel(status: AssistantCaseChangeProposal["status"]): string {
  switch (status) {
    case "pending":
      return "待审阅";
    case "applied":
      return "已写入";
    case "rejected":
      return "已拒绝";
    case "stale":
      return "已过期";
  }
}

function publicLegalStatus(status: string): string {
  switch (status.trim().toLowerCase()) {
    case "effective":
    case "current":
    case "valid":
      return "现行有效";
    case "future":
    case "pending":
      return "尚未施行";
    case "expired":
    case "repealed":
    case "invalid":
      return "已失效";
    default:
      return "效力状态待核对";
  }
}

function exportFormats(
  kind: AssistantArtifact["kind"],
): { value: AssistantArtifactExportFormat; label: string }[] {
  switch (kind) {
    case "research":
      return [{ value: "research_markdown", label: "Markdown" }];
    case "document":
      return [
        { value: "document_docx", label: "DOCX" },
        { value: "document_markdown", label: "Markdown" },
      ];
    case "map":
      return [{ value: "map_summary", label: "文字摘要" }];
  }
}

function PersistedMapPreview({ version }: { version: AssistantArtifactVersion }) {
  const spec = useMemo(() => mapSpecFromArtifactVersion(version), [version]);
  return spec ? (
      <Suspense fallback={<p role="status">正在加载分析图预览…</p>}>
        <AssistantMapPreview spec={spec} />
      </Suspense>
    ) : (
      <p className="assistant-problem" role="alert">
        该版本的分析图数据无法识别，已停止显示。
      </p>
    );
}

function ArtifactPreview({
  artifact,
  version,
}: {
  artifact: AssistantArtifact;
  version: AssistantArtifactVersion;
}) {
  if (artifact.kind === "map") {
    return <PersistedMapPreview version={version} />;
  }
  return (
    <SafeArtifactMarkdown
      markdown={version.renderedText}
      label={`${publicTitle(artifact.title, artifactKindLabel(artifact.kind))}第 ${version.versionNumber} 版预览`}
    />
  );
}

function ProposalProvenance({
  proposal,
}: {
  proposal: AssistantCaseChangeProposal;
}) {
  return (
    <dl className="proposal-provenance" aria-label="建议来源说明">
      <div>
        <dt>建议来源</dt>
        <dd>{proposal.runId ? "案件助理整理" : "人工整理"}</dd>
      </div>
    </dl>
  );
}

function ProposalChanges({
  proposal,
  sources,
}: {
  proposal: AssistantCaseChangeProposal;
  sources: AssistantConversationSource[];
}) {
  const changes = proposal.changes;
  const sourcesById = new Map(sources.map((entry) => [entry.sourceId, entry]));
  const factLabels = new Map(
    changes.facts.map((fact, index) => [
      fact.id,
      publicTitle(fact.statement, `事实 ${index + 1}`),
    ]),
  );
  const issueLabels = new Map(
    changes.issues.map((issue, index) => [
      issue.id,
      publicTitle(issue.title, `法律争点 ${index + 1}`),
    ]),
  );
  const sourceCount = (sourceRefs: string[]) =>
    sourceRefs.length > 0 ? `已关联 ${sourceRefs.length} 项来源` : "未关联来源";
  return (
    <div className="proposal-changes">
      {changes.facts.length > 0 ? (
        <section>
          <h5>拟新增事实（{changes.facts.length}）</h5>
          <ul>
            {changes.facts.map((fact) => (
              <li key={fact.id}>
                <strong>{publicTitle(fact.statement, "待核对事实")}</strong>
                <span>发生日期：{fact.occurredOn ?? "未提供"}</span>
                <span>来源：{sourceCount(fact.sourceRefs)}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {changes.evidence.length > 0 ? (
        <section>
          <h5>拟新增证据（{changes.evidence.length}）</h5>
          <ul>
            {changes.evidence.map((evidence) => (
              <li key={evidence.id}>
                <strong>{publicTitle(evidence.title, "待核对证据")}</strong>：
                {sanitizePublicGeneratedText(evidence.summary, "内容摘要暂不可用。")}
                <span>
                  证明事实：
                  {evidence.provesFactIds.length > 0
                    ? evidence.provesFactIds
                        .map((factId) => factLabels.get(factId) ?? "相关事实")
                        .join("、")
                    : "无"}
                </span>
                <span>来源：{sourceCount(evidence.sourceRefs)}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {changes.issues.length > 0 ? (
        <section>
          <h5>拟新增争点（{changes.issues.length}）</h5>
          <ul>
            {changes.issues.map((issue) => (
              <li key={issue.id}>
                <strong>{publicTitle(issue.title, "待核对法律争点")}</strong>：
                {sanitizePublicGeneratedText(issue.analysis, "分析摘要暂不可用。")}
                <span>
                  关联事实：
                  {issue.relatedFactIds.length > 0
                    ? issue.relatedFactIds
                        .map((factId) => factLabels.get(factId) ?? "相关事实")
                        .join("、")
                    : "无"}
                </span>
                <span>
                  来源：
                  {sourceCount(issue.sourceRefs)}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {changes.legalBasis.length > 0 ? (
        <section>
          <h5>拟新增法律依据（{changes.legalBasis.length}）</h5>
          <ul>
            {changes.legalBasis.map((basis) => (
              <li key={basis.id}>
                <strong>
                  {sanitizePublicGeneratedText(basis.citation, "法律依据待核对")}
                </strong>
                ：{sanitizePublicGeneratedText(basis.proposition, "法律依据说明暂不可用。")}
                <span>
                  写入争点：
                  {basis.issueIds.length > 0
                    ? basis.issueIds
                        .map((issueId) => issueLabels.get(issueId) ?? "相关法律争点")
                        .join("、")
                    : "案件通用依据"}
                </span>
                <span>
                  效力状态：
                  {sourcesById.get(basis.sourceRef)?.source
                    ? `${publicLegalStatus(sourcesById.get(basis.sourceRef)!.source!.versionStatus)}；${sourcesById.get(basis.sourceRef)!.source!.effectiveFrom} 起${sourcesById.get(basis.sourceRef)!.source!.effectiveTo ? `，至 ${sourcesById.get(basis.sourceRef)!.source!.effectiveTo}` : ""}`
                    : "写入前将重新核验；未通过核验的依据不会写入"}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {changes.attachmentTransfers.length > 0 ? (
        <section>
          <h5>拟转入附件（{changes.attachmentTransfers.length}）</h5>
          <ul>
            {changes.attachmentTransfers.map((transfer) => (
              <li key={transfer.attachmentId}>
                {publicTitle(transfer.title, "待转入附件")}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {changes.artifactTransfers.length > 0 ? (
        <section>
          <h5>拟转入成果（{changes.artifactTransfers.length}）</h5>
          <ul>
            {changes.artifactTransfers.map((transfer) => (
              <li key={transfer.artifactId}>
                {publicTitle(transfer.title, "待转入成果")}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function ProposalCard({
  proposal,
  activeProject,
  onChanged,
  onOperationChange,
  sources,
  applyBlockedReason,
  onApplied,
}: {
  proposal: AssistantCaseChangeProposal;
  activeProject: ArtifactPanelActiveProject | null;
  onChanged: () => void;
  onOperationChange: (proposalId: string, active: boolean) => void;
  sources: AssistantConversationSource[];
  applyBlockedReason?: string | null;
  onApplied?: (projectId: string) => void;
}) {
  const confirmationId = useId();
  const [confirmed, setConfirmed] = useState(false);
  const [operation, setOperation] = useState<"apply" | "reject" | null>(null);
  const [status, setStatus] = useState("");
  const projectMatches = activeProject?.projectId === proposal.projectId;
  const pending = proposal.status === "pending";

  useEffect(() => {
    onOperationChange(proposal.proposalId, operation !== null);
  }, [onOperationChange, operation, proposal.proposalId]);

  useEffect(
    () => () => onOperationChange(proposal.proposalId, false),
    [onOperationChange, proposal.proposalId],
  );

  async function applyProposal() {
    setOperation("apply");
    setStatus("");
    try {
      const result = await applyProposalAfterExplicitConfirmation({
        proposalId: proposal.proposalId,
        projectId: proposal.projectId,
        explicitlyConfirmed: confirmed,
      });
      if (result.kind === "confirmation_required") {
        setStatus("请先勾选明确确认。" );
        return;
      }
      setStatus(
        result.response.stale
          ? "案件已发生变化，本建议已过期，未写入任何数据。"
          : result.response.applied
            ? "建议已写入案件。"
            : "建议未写入案件。",
      );
      if (result.response.applied) onApplied?.(proposal.projectId);
      onChanged();
    } catch (error: unknown) {
      setStatus(`写入失败：${displayError(error)}`);
    } finally {
      setOperation(null);
    }
  }

  async function rejectProposal() {
    setOperation("reject");
    setStatus("");
    try {
      await rejectAssistantCaseChangeProposal({
        proposalId: proposal.proposalId,
        projectId: proposal.projectId,
      });
      setStatus("建议已拒绝，案件数据未改变。" );
      onChanged();
    } catch (error: unknown) {
      setStatus(`拒绝失败：${displayError(error)}`);
    } finally {
      setOperation(null);
    }
  }

  return (
    <article className="proposal-card" data-proposal-status={proposal.status}>
      <header>
        <h4>案件变更建议</h4>
        <span>{proposalStatusLabel(proposal.status)}</span>
      </header>
      <p className="assistant-muted">
        创建于 {dateTime(proposal.createdAt)}。待审阅内容不会自动改动案件。
      </p>
      <ProposalProvenance proposal={proposal} />
      <ProposalChanges proposal={proposal} sources={sources} />
      {pending ? (
        projectMatches ? (
          <div className="proposal-decision">
            {applyBlockedReason ? (
              <p className="assistant-problem" role="note">
                {applyBlockedReason}
              </p>
            ) : null}
            <label htmlFor={confirmationId}>
              <input
                checked={confirmed}
                disabled={Boolean(applyBlockedReason)}
                id={confirmationId}
                type="checkbox"
                onChange={(event) => setConfirmed(event.currentTarget.checked)}
              />
              我已逐项审阅，并确认将上述内容写入案件“{publicTitle(activeProject.title, "当前案件")}”。
            </label>
            <div className="assistant-button-row">
              <button
                className="assistant-danger-action"
                disabled={
                  !confirmed || operation !== null || Boolean(applyBlockedReason)
                }
                type="button"
                onClick={() => void applyProposal()}
              >
                {operation === "apply" ? "正在写入…" : "确认写入案件"}
              </button>
              <button
                disabled={operation !== null}
                type="button"
                onClick={() => void rejectProposal()}
              >
                {operation === "reject" ? "正在拒绝…" : "拒绝建议"}
              </button>
            </div>
          </div>
        ) : (
          <p className="assistant-problem" role="note">
            请先切换到该建议绑定的案件，再审阅和决定是否写入。
          </p>
        )
      ) : null}
      {proposal.status === "stale" ? (
        <p className="assistant-problem" role="note">
          案件在建议生成后已变化。本建议未写入，需基于最新案件重新生成。
        </p>
      ) : null}
      {status ? <p className="assistant-inline-status" role="status">{status}</p> : null}
    </article>
  );
}

export function ArtifactPanel({
  sources,
  artifacts,
  proposals,
  selectedArtifactId,
  activeProject,
  onSelectArtifact,
  onConversationRefresh,
  onDraftDirtyChange,
  onMutationActivityChange,
  onProposalApplied,
  proposalApplyBlockedReason,
}: ArtifactPanelProps) {
  const loadEpoch = useRef(0);
  const reloadReason = useRef<"bind" | "conflict" | null>(null);
  const selectedArtifactIdRef = useRef(selectedArtifactId);
  const [load, setLoad] = useState<ArtifactLoadState>({
    phase: "idle",
    artifactId: null,
    detail: null,
    message: "",
  });
  const [versionNumber, setVersionNumber] = useState<number | null>(null);
  const [format, setFormat] = useState<AssistantArtifactExportFormat | null>(null);
  const [operation, setOperation] = useState<"export" | "bind" | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [activeProposalOperations, setActiveProposalOperations] = useState<
    ReadonlySet<string>
  >(() => new Set());
  const [status, setStatus] = useState("");

  useEffect(() => {
    selectedArtifactIdRef.current = selectedArtifactId;
  }, [selectedArtifactId]);

  const handleProposalOperationChange = useCallback(
    (proposalId: string, active: boolean) => {
      setActiveProposalOperations((current) => {
        const next = new Set(current);
        if (active) next.add(proposalId);
        else next.delete(proposalId);
        if (
          next.size === current.size &&
          [...next].every((id) => current.has(id))
        ) {
          return current;
        }
        return next;
      });
    },
    [],
  );

  useEffect(() => {
    onMutationActivityChange?.(
      operation !== null || activeProposalOperations.size > 0,
    );
  }, [activeProposalOperations, onMutationActivityChange, operation]);

  useEffect(
    () => () => onMutationActivityChange?.(false),
    [onMutationActivityChange],
  );

  useEffect(
    () => () => onDraftDirtyChange?.(false),
    [onDraftDirtyChange],
  );

  useEffect(() => {
    const epoch = loadEpoch.current + 1;
    loadEpoch.current = epoch;
    const reason = reloadReason.current;
    reloadReason.current = null;
    if (!selectedArtifactId) {
      setLoad({ phase: "idle", artifactId: null, detail: null, message: "" });
      setVersionNumber(null);
      setStatus("");
      return;
    }
    let cancelled = false;
    setLoad({
      phase: "loading",
      artifactId: selectedArtifactId,
      detail: null,
      message: "",
    });
    setStatus(reason ? "正在重新读取成果最新状态…" : "");
    void getAssistantArtifact({ artifactId: selectedArtifactId })
      .then((detail) => {
        if (cancelled || loadEpoch.current !== epoch) return;
        setLoad({
          phase: "ready",
          artifactId: selectedArtifactId,
          detail,
          message: "",
        });
        setVersionNumber(detail.artifact.currentVersion);
        setFormat(exportFormats(detail.artifact.kind)[0].value);
        if (reason === "bind") {
          setStatus("成果已关联到当前案件；它不会因此变成已确认案件事实。");
        } else if (reason === "conflict") {
          setStatus("已重新加载最新版本，请重新开始编辑。");
        }
      })
      .catch((error: unknown) => {
        if (cancelled || loadEpoch.current !== epoch) return;
        setLoad({
          phase: "error",
          artifactId: selectedArtifactId,
          detail: null,
          message: displayError(error),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [reloadNonce, selectedArtifactId]);

  const artifactDetail =
    load.phase === "ready" && load.artifactId === selectedArtifactId
      ? load.detail
      : null;
  const versions = useMemo(
    () =>
      artifactDetail
        ? [...artifactDetail.versions].sort(
            (left, right) => right.versionNumber - left.versionNumber,
          )
        : [],
    [artifactDetail],
  );
  const version =
    versions.find((candidate) => candidate.versionNumber === versionNumber) ??
    versions[0] ??
    null;
  const citationAudit = version ? jsonRecord(version.citationReport) : null;
  function selectArtifactWithDraftProtection(artifactId: string) {
    if (artifactId === selectedArtifactId) return;
    onDraftDirtyChange?.(false);
    onSelectArtifact(artifactId);
  }

  async function exportArtifact() {
    if (!artifactDetail || !version || !format) return;
    setOperation("export");
    setStatus("");
    try {
      const response = await exportAssistantArtifact({
        artifactId: artifactDetail.artifact.artifactId,
        versionNumber: version.versionNumber,
        format,
      });
      setStatus(response.cancelled ? "已取消导出。" : "已通过系统保存对话框导出。" );
    } catch (error: unknown) {
      setStatus(`导出失败：${displayError(error)}`);
    } finally {
      setOperation(null);
    }
  }

  async function bindArtifact() {
    if (!artifactDetail || !activeProject) return;
    const artifactTitle = publicTitle(
      artifactDetail.artifact.title,
      artifactKindLabel(artifactDetail.artifact.kind),
    );
    const projectTitle = publicTitle(activeProject.title, "当前案件");
    const confirmed = window.confirm(
      `确认将成果“${artifactTitle}”归属到案件“${projectTitle}”吗？\n\n该操作只关联成果，不会写入案件事实或证据；当前不提供改绑或撤销入口。`,
    );
    if (!confirmed) return;
    setOperation("bind");
    setStatus("");
    try {
      await bindAssistantArtifact({
        artifactId: artifactDetail.artifact.artifactId,
        projectId: activeProject.projectId,
        userConfirmed: true,
      });
      onConversationRefresh();
      reloadReason.current = "bind";
      setReloadNonce((current) => current + 1);
    } catch (error: unknown) {
      setStatus(`关联失败：${displayError(error)}`);
    } finally {
      setOperation(null);
    }
  }

  return (
    <aside className="artifact-panel" aria-label="来源、成果与案件建议">
      <section className="artifact-panel-section" aria-labelledby="assistant-sources-heading">
        <header className="artifact-section-heading">
          <h3 id="assistant-sources-heading">法律来源</h3>
          <span>{sources.length}</span>
        </header>
        {sources.length === 0 ? (
          <p className="assistant-empty">当前会话尚未保存本地法律来源。</p>
        ) : (
          <ul className="assistant-source-list">
            {sources.map((entry) => (
              <li key={entry.sourceId}>
                <strong>
                  {entry.source
                    ? sourceRefLabel(entry.sourceId, sources)
                    : "来源记录暂不可用"}
                </strong>
                <span>
                  内容摘要：{publicContentSummary(entry.source?.snippet)}
                </span>
                <small>{dateTime(entry.createdAt)}</small>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="artifact-panel-section" aria-labelledby="assistant-artifacts-heading">
        <header className="artifact-section-heading">
          <h3 id="assistant-artifacts-heading">成果</h3>
          <span>{artifacts.length}</span>
        </header>
        {artifacts.length === 0 ? (
          <p className="assistant-empty">运行完成后，研究、文书或分析图会保存在这里。</p>
        ) : (
          <div className="artifact-picker" role="list" aria-label="成果列表">
            {artifacts.map((artifact) => (
              <div key={artifact.artifactId} role="listitem">
                <button
                  aria-current={selectedArtifactId === artifact.artifactId ? "true" : undefined}
                  disabled={operation !== null}
                  type="button"
                  onClick={() =>
                    selectArtifactWithDraftProtection(artifact.artifactId)
                  }
                >
                  <strong>{publicTitle(artifact.title, artifactKindLabel(artifact.kind))}</strong>
                  <span>{artifactKindLabel(artifact.kind)} · 第 {artifact.currentVersion} 版</span>
                </button>
              </div>
            ))}
          </div>
        )}

        {load.phase === "loading" ? <p role="status">正在读取成果版本…</p> : null}
        {load.phase === "error" ? (
          <p className="assistant-problem" role="alert">成果读取失败：{load.message}</p>
        ) : null}
        {artifactDetail && version ? (
          <div className="artifact-detail">
            <div className="artifact-version-toolbar">
              <label>
                预览版本
                <select
                  value={version.versionNumber}
                  onChange={(event) => {
                    onDraftDirtyChange?.(false);
                    setVersionNumber(Number(event.currentTarget.value));
                    setStatus("");
                  }}
                >
                  {versions.map((candidate) => (
                    <option key={candidate.versionId} value={candidate.versionNumber}>
                      第 {candidate.versionNumber} 版 · {dateTime(candidate.createdAt)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <ArtifactPreview artifact={artifactDetail.artifact} version={version} />
            {artifactDetail.artifact.kind === "map" ? (
              <section className="artifact-map-editor" aria-label="分析图修订说明">
                <h4>修订分析图</h4>
                <p>如需修改，请补充要求后重新生成。</p>
              </section>
            ) : null}
            <details className="artifact-audit-detail">
              <summary>资料与法律依据</summary>
              <section>
                <h4>版本来源（{version.sourceRefs.length}）</h4>
                {version.sourceRefs.length > 0 ? (
                  <ul>
                    {version.sourceRefs.map((sourceRef) => (
                      <li key={sourceRef}>
                        {sourceRefLabel(sourceRef, sources)}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>该版本没有声明来源。</p>
                )}
              </section>
              <section>
                <h4>法律依据使用情况</h4>
                <p>
                  可核对依据：{numberField(citationAudit, "validCount") ?? "不适用"}；
                  需要补充核对：{numberField(citationAudit, "invalidCount") ?? "不适用"}；
                  是否有结论缺少法律依据：
                  {booleanField(citationAudit, "unsupportedLegalConclusion") === null
                    ? "不适用"
                    : booleanField(citationAudit, "unsupportedLegalConclusion")
                      ? "是"
                      : "否"}
                  ；是否已经律师审定：
                  {booleanField(citationAudit, "semanticSupportVerified") === null
                    ? "不适用"
                    : booleanField(citationAudit, "semanticSupportVerified")
                      ? "是"
                      : "否"}
                </p>
              </section>
            </details>
            <div className="artifact-actions">
              <label>
                导出格式
                <select
                  value={format ?? ""}
                  onChange={(event) =>
                    setFormat(event.currentTarget.value as AssistantArtifactExportFormat)
                  }
                >
                  {exportFormats(artifactDetail.artifact.kind).map((item) => (
                    <option key={item.value} value={item.value}>{item.label}</option>
                  ))}
                </select>
              </label>
              <button
                disabled={operation !== null}
                type="button"
                onClick={() => void exportArtifact()}
              >
                {operation === "export" ? "正在导出…" : "导出此版本"}
              </button>
              {artifactDetail.artifact.projectId === activeProject?.projectId ? (
                <span className="assistant-positive">已关联当前案件</span>
              ) : artifactDetail.artifact.projectId ? (
                <span className="assistant-muted">该成果已关联其他案件</span>
              ) : (
                <div className="artifact-bind-action">
                  <small>
                    关联会把成果归属到当前案件，但不会写入事实或证据；当前不提供改绑入口。
                  </small>
                  <button
                    disabled={!activeProject || operation !== null}
                    title={activeProject ? undefined : "请先选择案件"}
                    type="button"
                    onClick={() => void bindArtifact()}
                  >
                    {operation === "bind" ? "正在关联…" : "关联到当前案件"}
                  </button>
                </div>
              )}
            </div>
            {status ? <p className="assistant-inline-status" role="status">{status}</p> : null}
          </div>
        ) : null}
      </section>

      <section className="artifact-panel-section" aria-labelledby="assistant-proposals-heading">
        <header className="artifact-section-heading">
          <h3 id="assistant-proposals-heading">案件变更建议</h3>
          <span>{proposals.length}</span>
        </header>
        {proposals.length === 0 ? (
          <p className="assistant-empty">没有待审阅建议。助理不会直接写入案件。</p>
        ) : (
          <div className="proposal-list">
            {proposals.map((proposal) => (
              <ProposalCard
                activeProject={activeProject}
                applyBlockedReason={proposalApplyBlockedReason}
                key={proposal.proposalId}
                proposal={proposal}
                onChanged={onConversationRefresh}
                onApplied={onProposalApplied}
                onOperationChange={handleProposalOperationChange}
                sources={sources}
              />
            ))}
          </div>
        )}
      </section>
    </aside>
  );
}
