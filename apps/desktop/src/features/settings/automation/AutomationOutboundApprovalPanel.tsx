import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import { listProviderProfiles } from "../../../ipc/provider/client";
import type { ProviderProfile } from "../../../ipc/provider/types";
import {
  approveApprovedProviderTask,
  dispatchApprovedProvider,
  getProviderQualificationStatus,
  listApprovedProviderOutputs,
  loadApprovedProviderOutput,
  revokeApprovedProviderOutput,
  revokeProviderQualification,
  runProviderQualification,
} from "../../../ipc/privacy/client";
import type {
  ApprovedProviderOutput,
  ApprovedProviderOutputSummary,
  ApprovedProviderPriorOutputRef,
  ApprovedProviderTask,
  ApproveApprovedProviderTaskRequest,
  ApproveApprovedProviderTaskResponse,
  DispatchApprovedProviderRequest,
  DispatchApprovedProviderResponse,
  PrivacyReview,
  ProviderQualificationStatus,
} from "../../../ipc/privacy/types";
import "./automation-outbound-approval.css";

type ProviderOperation =
  | "loading"
  | "idle"
  | "refreshing"
  | "qualifying"
  | "revoking_qualification"
  | "approving"
  | "dispatching"
  | "loading_output"
  | "revoking_output";

export interface ApprovedProviderTaskOption {
  task: ApprovedProviderTask;
  purpose: string;
  label: string;
}

// Kept explicit so the browser can never submit a free-form Provider purpose.
// eslint-disable-next-line react-refresh/only-export-components
export const APPROVED_PROVIDER_TASK_OPTIONS: readonly ApprovedProviderTaskOption[] = [
  { task: "summary", purpose: "case_summary", label: "案件摘要" },
  { task: "legal_analysis", purpose: "case_legal_analysis", label: "法律分析" },
  { task: "chronology", purpose: "case_chronology", label: "时间线" },
  { task: "document_outline", purpose: "case_document_outline", label: "文书提纲" },
  {
    task: "structured_extraction",
    purpose: "case_structured_extraction",
    label: "结构化提取",
  },
  { task: "assistant", purpose: "assistant_case_response", label: "案件助理" },
  { task: "case_organization", purpose: "case_organization", label: "案件整理" },
  { task: "case_legal_qa", purpose: "case_legal_qa", label: "案件法律问答" },
  {
    task: "relationship_graph",
    purpose: "case_relationship_graph",
    label: "关系图",
  },
  {
    task: "document_generation",
    purpose: "case_document_generation",
    label: "文书生成",
  },
  { task: "regenerate", purpose: "case_regenerate", label: "重新生成" },
  { task: "repair", purpose: "case_repair", label: "修复结果" },
] as const;

export interface AutomationOutboundApprovalPanelProps {
  disabled?: boolean;
  onActivityChange?: (active: boolean) => void;
}

export interface AutomationOutboundApprovalPanelViewProps {
  disabled: boolean;
  operation: ProviderOperation;
  providers: readonly ProviderProfile[];
  review: PrivacyReview | null;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutputId: string;
  reviewer: string;
  ttlSeconds: string;
  maxTokens: string;
  confirmed: boolean;
  qualification: ProviderQualificationStatus | null;
  approval: ApproveApprovedProviderTaskResponse | null;
  dispatchResult: DispatchApprovedProviderResponse | null;
  outputs: readonly ApprovedProviderOutputSummary[];
  loadedOutput: ApprovedProviderOutput | null;
  notice: string;
  error: string;
  onProviderChange: (providerId: string) => void;
  onTaskChange: (task: ApprovedProviderTask) => void;
  onInstructionChange: (instruction: string) => void;
  onPriorOutputChange: (outputId: string) => void;
  onReviewerChange: (reviewer: string) => void;
  onTtlSecondsChange: (ttlSeconds: string) => void;
  onMaxTokensChange: (maxTokens: string) => void;
  onConfirmedChange: (confirmed: boolean) => void;
  onRefresh: () => void;
  onRunQualification: () => void;
  onRevokeQualification: () => void;
  onApprove: () => void;
  onDispatch: () => void;
  onLoadOutput: (output: ApprovedProviderOutputSummary) => void;
  onRevokeOutput: (outputId: string) => void;
}

interface PanelSnapshot {
  providers: ProviderProfile[];
  review: PrivacyReview | null;
  providerId: string;
  qualification: ProviderQualificationStatus | null;
  outputs: ApprovedProviderOutputSummary[];
}

// eslint-disable-next-line react-refresh/only-export-components
export function approvedProviderPurpose(task: ApprovedProviderTask): string {
  const option = APPROVED_PROVIDER_TASK_OPTIONS.find((entry) => entry.task === task);
  if (!option) throw new Error("不支持的 Provider 固定任务。");
  return option.purpose;
}

// eslint-disable-next-line react-refresh/only-export-components
export function effectiveProviderModel(profile: ProviderProfile): string {
  if (profile.kind === "volcengine_ark") {
    const endpointId = profile.options.endpointId?.trim();
    if (endpointId) return endpointId;
  }
  return profile.modelId;
}

function boundedInteger(
  label: string,
  value: string,
  minimum: number,
  maximum: number,
): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label}必须是 ${minimum}–${maximum} 的整数。`);
  }
  return parsed;
}

function normalizedProviderInstruction(value: string): string {
  const normalized = value.trim().replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const hasForbiddenControl = Array.from(normalized).some((character) => {
    if (character === "\n" || character === "\t") return false;
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
  });
  if (
    normalized.length === 0 ||
    new TextEncoder().encode(normalized).length > 32 * 1024 ||
    hasForbiddenControl
  ) {
    throw new Error("人工批准的任务指令不能为空、超过 32 KiB 或包含控制字符。");
  }
  return normalized;
}

// eslint-disable-next-line react-refresh/only-export-components
export function providerTaskRequiresPriorOutput(task: ApprovedProviderTask): boolean {
  return task === "regenerate" || task === "repair";
}
// This key is local UI state only; Rust remains the authority for the signed binding.
// eslint-disable-next-line react-refresh/only-export-components
export function providerApprovalUiBindingKey(input: {
  review: PrivacyReview | null;
  providerId: string;
  modelId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderOutputSummary | null;
  maxTokens: string;
  reviewer: string;
  ttlSeconds: string;
}): string {
  return JSON.stringify({
    redactionId: input.review?.redactionId ?? null,
    expectedSuggestedRedactedSha256:
      input.review?.suggestedRedactedContentSha256 ?? null,
    riskRevision: input.review?.riskReview?.revision ?? null,
    editedPages:
      input.review?.pages.map((page) => [
        page.pageNumber,
        page.redactedText,
      ]) ?? [],
    providerId: input.providerId,
    modelId: input.modelId,
    task: input.task,
    instruction: input.instruction,
    priorOutputId: input.priorOutput?.outputId ?? null,
    priorOutputTask: input.priorOutput?.task ?? null,
    priorTaskBindingSha256: input.priorOutput?.taskBindingSha256 ?? null,
    maxTokens: input.maxTokens,
    reviewer: input.reviewer,
    ttlSeconds: input.ttlSeconds,
  });
}

function selectedPriorOutputReference(
  review: PrivacyReview,
  task: ApprovedProviderTask,
  priorOutput: ApprovedProviderOutputSummary | null,
): ApprovedProviderPriorOutputRef | null {
  const required = providerTaskRequiresPriorOutput(task);
  if (required && !priorOutput) {
    throw new Error("重新生成和修复任务必须从受保护输出历史中选择一项当前可用输出。");
  }
  if (!required && priorOutput) {
    throw new Error("当前固定任务不允许携带历史输出。");
  }
  if (!priorOutput) return null;
  if (
    priorOutput.redactionId !== review.redactionId ||
    priorOutput.revoked ||
    !priorOutput.eligibleAsPrior ||
    !/^out_[A-Za-z0-9._-]+$/u.test(priorOutput.outputId)
  ) {
    throw new Error("所选历史输出已失效、已撤销或不属于当前脱敏 generation。");
  }
  return { outputId: priorOutput.outputId, task: priorOutput.task };
}

interface ProviderTaskBindingInput {
  review: PrivacyReview;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderOutputSummary | null;
  maxTokens: string;
}

function buildProviderTaskBinding(
  input: ProviderTaskBindingInput,
): DispatchApprovedProviderRequest {
  if (input.review.reviewState !== "approved") {
    throw new Error("当前脱敏 generation 尚未人工批准。");
  }
  const providerId = input.providerId.trim();
  if (!/^[A-Za-z0-9._-]{1,128}$/u.test(providerId)) {
    throw new Error("请选择有效的已保存 Provider profile。");
  }
  return {
    redactionId: input.review.redactionId,
    providerId,
    task: input.task,
    instruction: normalizedProviderInstruction(input.instruction),
    priorOutput: selectedPriorOutputReference(
      input.review,
      input.task,
      input.priorOutput,
    ),
    maxTokens: boundedInteger("最大输出 token", input.maxTokens, 128, 32_768),
  };
}
// eslint-disable-next-line react-refresh/only-export-components
export function buildProviderApprovalRequest(input: {
  review: PrivacyReview;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderOutputSummary | null;
  maxTokens: string;
  reviewer: string;
  ttlSeconds: string;
  confirmed: boolean;
}): ApproveApprovedProviderTaskRequest {
  if (input.review.reviewState !== "approved") {
    throw new Error("必须先在双栏复核区完成人工批准，再签发 Provider 精确用途批准。");
  }
  if (!input.confirmed) {
    throw new Error("请确认已经逐页核对当前脱敏 generation 与完整任务绑定。");
  }
  const binding = buildProviderTaskBinding(input);
  const reviewer = input.reviewer.trim();
  if (!reviewer || new TextEncoder().encode(reviewer).length > 256) {
    throw new Error("批准人不能为空且不得超过 256 字节。");
  }
  if (
    input.review.pages.length === 0 ||
    input.review.pages.some((page) => !page.redactedText.trim())
  ) {
    throw new Error("当前批准 generation 缺少完整脱敏页。");
  }
  const expectedRiskRevision = input.review.riskReview?.revision ?? null;
  if (input.review.caseId && expectedRiskRevision === null) {
    throw new Error("案件材料缺少当前风险复核 revision，请重新载入审阅后再签发 Provider 批准。");
  }
  return {
    ...binding,
    expectedRiskRevision,
    expectedSuggestedRedactedSha256:
      input.review.suggestedRedactedContentSha256,
    editedPages: input.review.pages.map((page) => ({
      pageNumber: page.pageNumber,
      redactedText: page.redactedText,
    })),
    reviewer,
    ttlSeconds: boundedInteger("批准有效期", input.ttlSeconds, 300, 604_800),
    confirmed: true,
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildProviderDispatchRequest(input: {
  review: PrivacyReview;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderOutputSummary | null;
  maxTokens: string;
}): DispatchApprovedProviderRequest {
  return buildProviderTaskBinding(input);
}

function displayError(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "Provider 批准链操作失败。";
}

async function readPanelSnapshot(preferredProviderId: string): Promise<PanelSnapshot> {
  const providerResponse = await listProviderProfiles();
  const providerId = providerResponse.profiles.some(
    (profile) => profile.id === preferredProviderId,
  )
    ? preferredProviderId
    : (providerResponse.profiles[0]?.id ?? "");
  const qualification = providerId
    ? await getProviderQualificationStatus({ providerId })
    : null;
  return {
    providers: providerResponse.profiles,
    review: null,
    providerId,
    qualification,
    outputs: [],
  };
}

function qualificationLabel(status: ProviderQualificationStatus | null): string {
  if (!status) return "未选择 Provider";
  return status.qualified ? "已资格化" : `未资格化：${status.reasonCode}`;
}

export function AutomationOutboundApprovalPanelView({
  disabled,
  operation,
  providers,
  review,
  providerId,
  task,
  instruction,
  priorOutputId,
  reviewer,
  ttlSeconds,
  maxTokens,
  confirmed,
  qualification,
  approval,
  dispatchResult,
  outputs,
  loadedOutput,
  notice,
  error,
  onProviderChange,
  onTaskChange,
  onInstructionChange,
  onPriorOutputChange,
  onReviewerChange,
  onTtlSecondsChange,
  onMaxTokensChange,
  onConfirmedChange,
  onRefresh,
  onRunQualification,
  onRevokeQualification,
  onApprove,
  onDispatch,
  onLoadOutput,
  onRevokeOutput,
}: AutomationOutboundApprovalPanelViewProps) {
  const busy = disabled || operation !== "idle";
  const selectedProfile = providers.find((profile) => profile.id === providerId);
  const exactPurpose = approvedProviderPurpose(task);
  const approvedGenerationReady = review?.reviewState === "approved";
  const priorRequired = providerTaskRequiresPriorOutput(task);
  const eligiblePriorOutputs = outputs.filter((output) => output.eligibleAsPrior);
  const selectedPriorOutput = eligiblePriorOutputs.find(
    (output) => output.outputId === priorOutputId,
  );
  let instructionReady = false;
  try {
    normalizedProviderInstruction(instruction);
    instructionReady = true;
  } catch {
    instructionReady = false;
  }
  const exactModel = selectedProfile
    ? effectiveProviderModel(selectedProfile)
    : "";
  const qualificationReady = Boolean(
    qualification?.qualified &&
      qualification.providerId === providerId &&
      qualification.modelId === exactModel,
  );
  const approvalReady = Boolean(
    approval &&
      approval.providerId === providerId &&
      approval.modelId === exactModel &&
      approval.task === task &&
      approval.purpose === exactPurpose &&
      /^[a-f0-9]{64}$/u.test(approval.taskBindingSha256),
  );
  const priorReady = priorRequired ? Boolean(selectedPriorOutput) : true;

  return (
    <section
      id="automation-outbound-approval"
      className="automation-outbound-panel"
      aria-labelledby="automation-outbound-title"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Approved Provider</p>
          <h2 id="automation-outbound-title">自动化出站批准</h2>
        </div>
        <button disabled={busy} type="button" onClick={onRefresh}>
          {operation === "refreshing" || operation === "loading"
            ? "正在刷新…"
            : "刷新 profile、批准与输出"}
        </button>
      </div>

      {notice ? <p className="automation-outbound-notice" aria-live="polite">{notice}</p> : null}

      <p>
        页面只提交脱敏记录 ID、已保存 Provider ID、固定任务枚举和输出上限。批准正文、签名凭据与本地映射均由 Rust
        从受保护存储恢复；任一资格、用途、模型、endpoint、hash、有效期或撤销状态不一致都会在网络前拒绝。
      </p>

      <div className="automation-outbound-grid">
        <label>
          <span>已保存 Provider profile</span>
          <select
            disabled={busy || providers.length === 0}
            value={providerId}
            onChange={(event) => onProviderChange(event.target.value)}
          >
            {providers.length === 0 ? <option value="">尚无 Provider profile</option> : null}
            {providers.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.displayName} · {effectiveProviderModel(profile)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>固定案件任务</span>
          <select
            disabled={busy}
            value={task}
            onChange={(event) =>
              onTaskChange(event.target.value as ApprovedProviderTask)
            }
          >
            {APPROVED_PROVIDER_TASK_OPTIONS.map((option) => (
              <option key={option.task} value={option.task}>{option.label}</option>
            ))}
          </select>
        </label>
        <div className="automation-outbound-binding">
          <span>后端固定用途</span>
          <code>{exactPurpose}</code>
        </div>
        <div className="automation-outbound-binding">
          <span>当前脱敏 generation</span>
          <code>{review?.redactionId ?? "尚未载入"}</code>
          <small>{approvedGenerationReady ? "已人工批准" : "必须先完成双栏人工批准"}</small>
        </div>
      </div>
      {!review ? (
        <p className="automation-outbound-risk-blocker" role="status">
          设置页不再自动读取未限定案件的“最近一次”脱敏记录。请从案件工作台的“材料与脱敏”
          进入已批准 generation；案件限定的 Provider 入口将在该工作流中提供。
        </p>
      ) : null}

      <section className="automation-outbound-qualification" aria-label="Provider 资格状态">
        <div className="panel-heading">
          <h3>Provider 案件出站资格</h3>
          <strong data-qualified={qualification?.qualified ?? false}>
            {qualificationLabel(qualification)}
          </strong>
        </div>
        <div className="automation-outbound-evidence">
          <span>App/工作区/策略：{qualification?.exactWorkspaceAppPolicyBinding ? "匹配" : "未匹配"}</span>
          <span>Provider/model/endpoint：{qualification?.exactProviderContractBinding ? "匹配" : "未匹配"}</span>
          <span>任务 contract：{qualification?.exactTaskContractBinding ? "匹配" : "未匹配"}</span>
          <span>真实 localhost wire：{qualification?.realLoopbackTransportPassed ? "通过" : "未通过"}</span>
          <span>原始 canary 不在 wire：{qualification?.rawCanaryAbsent ? "通过" : "未通过"}</span>
          <span>单次请求：{qualification?.exactlyOneRequest ? "通过" : "未通过"}</span>
        </div>
        <label className="automation-outbound-number">
          <span>资格与精确批准有效期（秒）</span>
          <input
            disabled={busy}
            inputMode="numeric"
            value={ttlSeconds}
            onChange={(event) => onTtlSecondsChange(event.target.value)}
          />
        </label>
        <div className="automation-outbound-actions">
          <button disabled={busy || !selectedProfile} type="button" onClick={onRunQualification}>
            {operation === "qualifying" ? "正在执行完整 canary…" : "运行并持久化资格"}
          </button>
          <button
            className="danger"
            disabled={busy || !selectedProfile || !qualification}
            type="button"
            onClick={onRevokeQualification}
          >
            {operation === "revoking_qualification" ? "正在撤销…" : "撤销 Provider 资格"}
          </button>
        </div>
      </section>

      <section aria-labelledby="automation-outbound-approval-title">
        <h3 id="automation-outbound-approval-title">签发精确批准并发送</h3>
        <p>
          当前绑定模型：<code>{exactModel || "尚未选择"}</code>。任务指令只应描述处理要求，不得粘贴未脱敏案情；
          指令会在本机先做残留扫描，再与当前脱敏正文一起签发。
        </p>
        <label className="automation-outbound-instruction">
          <span>人工批准的任务指令</span>
          <textarea
            autoComplete="off"
            disabled={busy}
            rows={5}
            value={instruction}
            onChange={(event) => onInstructionChange(event.target.value)}
          />
          <small>换行会规范化；审批与发送使用完全相同的规范化指令。</small>
        </label>
        <div className="automation-outbound-grid">
          <label>
            <span>批准人</span>
            <input
              autoComplete="off"
              disabled={busy}
              value={reviewer}
              onChange={(event) => onReviewerChange(event.target.value)}
            />
          </label>
          <label>
            <span>最大输出 token</span>
            <input
              disabled={busy}
              inputMode="numeric"
              value={maxTokens}
              onChange={(event) => onMaxTokensChange(event.target.value)}
            />
          </label>
          <label>
            <span>受保护历史输出</span>
            <select
              disabled={busy || !priorRequired}
              value={priorRequired ? priorOutputId : ""}
              onChange={(event) => onPriorOutputChange(event.target.value)}
            >
              <option value="">
                {priorRequired ? "请选择当前可用输出" : "当前任务不使用历史输出"}
              </option>
              {eligiblePriorOutputs.map((output) => (
                <option key={output.outputId} value={output.outputId}>
                  {output.outputId} · {approvedProviderPurpose(output.task)}
                </option>
              ))}
            </select>
            <small>
              {priorRequired
                ? "重新生成/修复只能选择后端确认仍绑定当前批准正文的输出。"
                : "只有重新生成和修复任务允许绑定历史输出。"}
            </small>
          </label>
        </div>
        <label className="automation-outbound-confirmation">
          <input
            checked={confirmed}
            disabled={
              busy ||
              !approvedGenerationReady ||
              !instructionReady ||
              !priorReady
            }
            type="checkbox"
            onChange={(event) => onConfirmedChange(event.target.checked)}
          />
          <span>
            我已逐页核对当前脱敏 generation，并确认上方 Provider、模型、任务、指令、历史输出和 token 上限。
          </span>
        </label>
        <div className="automation-outbound-actions">
          <button
            disabled={
              busy ||
              !selectedProfile ||
              !approvedGenerationReady ||
              !instructionReady ||
              !priorReady ||
              !confirmed
            }
            type="button"
            data-provider-approval-ready={instructionReady && priorReady && confirmed}
            onClick={onApprove}
          >
            {operation === "approving" ? "正在本机签发…" : "签发完整任务绑定批准"}
          </button>
          <button
            disabled={
              busy ||
              !selectedProfile ||
              !approvedGenerationReady ||
              !qualificationReady ||
              !approvalReady
            }
            type="button"
            data-provider-dispatch-ready={qualificationReady && approvalReady}
            onClick={onDispatch}
          >
            {operation === "dispatching" ? "正在执行批准传输…" : "按同一任务绑定发送"}
          </button>
        </div>
        {approvalReady && approval ? (
          <p className="automation-outbound-notice">
            精确批准已持久化；Provider <code>{approval.providerId}</code>，
            模型 <code>{approval.modelId}</code>，用途 <code>{approval.purpose}</code>，
            任务绑定 SHA-256 <code>{approval.taskBindingSha256}</code>，
            载荷 SHA-256 <code>{approval.approvedPayloadSha256}</code>，有效至{" "}
            {new Date(approval.expiresAtUnix * 1000).toLocaleString("zh-CN")}。
          </p>
        ) : null}
        {dispatchResult ? (
          <article className="automation-outbound-result">
            <h4>最新 Provider 结果</h4>
            <p>
              <code>{dispatchResult.resultId}</code> · {dispatchResult.purpose} ·{" "}
              {dispatchResult.modelId}
            </p>
            <pre>{dispatchResult.content}</pre>
            <small>
              任务绑定 SHA-256：{dispatchResult.taskBindingSha256} · 内容 SHA-256：
              {dispatchResult.contentSha256}
            </small>
          </article>
        ) : null}
      </section>

      <section aria-labelledby="automation-outbound-output-title">
        <h3 id="automation-outbound-output-title">受保护输出历史</h3>
        {outputs.length === 0 ? <p>当前脱敏记录没有 Provider 输出。</p> : (
          <ul className="automation-outbound-output-list">
            {outputs.map((output) => (
              <li key={output.outputId}>
                <div>
                  <strong>{output.outputId}</strong>
                  <span>{output.contentBytes} 字节 · {new Date(output.createdAtUnix * 1000).toLocaleString("zh-CN")}</span>
                  <code>{output.contentSha256}</code>
                </div>
                <div className="automation-outbound-actions">
                  <button disabled={busy || output.revoked} type="button" onClick={() => onLoadOutput(output)}>
                    读取精确绑定输出
                  </button>
                  <span>
                    {approvedProviderPurpose(output.task)} · {output.eligibleAsPrior ? "可作为历史输入" : "不可作为历史输入"}
                  </span>
                  <code>{output.taskBindingSha256}</code>
                  <button className="danger" disabled={busy || output.revoked} type="button" onClick={() => onRevokeOutput(output.outputId)}>
                    撤销
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
        {loadedOutput ? (
          <article className="automation-outbound-result">
            <h4>已读取输出 {loadedOutput.outputId}</h4>
            <pre>{loadedOutput.content}</pre>
            <small>内容 SHA-256：{loadedOutput.contentSha256}</small>
          </article>
        ) : null}
      </section>

      {error ? <p className="error-text" role="alert">{error}</p> : null}
    </section>
  );
}

export function AutomationOutboundApprovalPanel({
  disabled = false,
  onActivityChange,
}: AutomationOutboundApprovalPanelProps) {
  const [operation, setOperation] = useState<ProviderOperation>("loading");
  const [providers, setProviders] = useState<ProviderProfile[]>([]);
  const [review, setReview] = useState<PrivacyReview | null>(null);
  const [providerId, setProviderId] = useState("");
  const [task, setTask] = useState<ApprovedProviderTask>("summary");
  const [instruction, setInstruction] = useState("");
  const [priorOutputId, setPriorOutputId] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState("3600");
  const [maxTokens, setMaxTokens] = useState("1024");
  const [confirmed, setConfirmed] = useState(false);
  const [qualification, setQualification] =
    useState<ProviderQualificationStatus | null>(null);
  const [approval, setApproval] =
    useState<ApproveApprovedProviderTaskResponse | null>(null);
  const [approvedUiBindingKey, setApprovedUiBindingKey] = useState("");

  const [dispatchResult, setDispatchResult] =
    useState<DispatchApprovedProviderResponse | null>(null);
  const [outputs, setOutputs] = useState<ApprovedProviderOutputSummary[]>([]);
  const [loadedOutput, setLoadedOutput] =
    useState<ApprovedProviderOutput | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const invalidateBoundState = useCallback(() => {
    setApproval(null);
    setApprovedUiBindingKey("");
    setDispatchResult(null);
    setLoadedOutput(null);
    setConfirmed(false);
  }, []);

  const installSnapshot = useCallback(
    (snapshot: PanelSnapshot) => {
      setProviders(snapshot.providers);
      setReview(snapshot.review);
      setProviderId(snapshot.providerId);
      setQualification(snapshot.qualification);
      setOutputs(snapshot.outputs);
      setPriorOutputId("");
      invalidateBoundState();
    },
    [invalidateBoundState],
  );

  useEffect(() => {
    let mounted = true;
    void readPanelSnapshot("")
      .then((snapshot) => {
        if (!mounted) return;
        installSnapshot(snapshot);
      })
      .catch((reason: unknown) => {
        if (mounted) setError(displayError(reason));
      })
      .finally(() => {
        if (mounted) setOperation("idle");
      });
    return () => {
      mounted = false;
      onActivityChange?.(false);
    };
  }, [installSnapshot, onActivityChange]);

  const begin = useCallback(
    (next: ProviderOperation) => {
      setOperation(next);
      setError("");
      setNotice("");
      onActivityChange?.(true);
    },
    [onActivityChange],
  );
  const finish = useCallback(() => {
    setOperation("idle");
    onActivityChange?.(false);
  }, [onActivityChange]);

  const selectedProfile = useMemo(
    () => providers.find((profile) => profile.id === providerId) ?? null,
    [providerId, providers],
  );
  const selectedPriorOutput = useMemo(
    () =>
      outputs.find(
        (output) =>
          output.outputId === priorOutputId && output.eligibleAsPrior,
      ) ?? null,
    [outputs, priorOutputId],
  );
  const currentUiBindingKey = useMemo(
    () =>
      providerApprovalUiBindingKey({
        review,
        providerId,
        modelId: selectedProfile
          ? effectiveProviderModel(selectedProfile)
          : "",
        task,
        instruction,
        priorOutput: selectedPriorOutput,
        maxTokens,
        reviewer,
        ttlSeconds,
      }),
    [
      instruction,
      maxTokens,
      providerId,
      review,
      reviewer,
      selectedPriorOutput,
      selectedProfile,
      task,
      ttlSeconds,
    ],
  );
  const approvalIsCurrent =
    approval !== null && approvedUiBindingKey === currentUiBindingKey;

  const refresh = useCallback(async () => {
    if (disabled || operation !== "idle") return;
    begin("refreshing");
    try {
      installSnapshot(await readPanelSnapshot(providerId));
      setNotice(
        "已重新载入 Provider profile 与资格证据；设置页不会读取未限定案件的脱敏 generation。",
      );
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [begin, disabled, finish, installSnapshot, operation, providerId]);

  const changeProvider = useCallback(
    async (nextProviderId: string) => {
      if (disabled || operation !== "idle") return;
      begin("refreshing");
      setProviderId(nextProviderId);
      setPriorOutputId("");
      setOutputs([]);
      invalidateBoundState();
      try {
        const [nextQualification, nextOutputs] = await Promise.all([
          nextProviderId
            ? getProviderQualificationStatus({ providerId: nextProviderId })
            : Promise.resolve(null),
          nextProviderId && review
            ? listApprovedProviderOutputs({
                redactionId: review.redactionId,
                providerId: nextProviderId,
              })
            : Promise.resolve([]),
        ]);
        setQualification(nextQualification);
        setOutputs(nextOutputs);
      } catch (reason: unknown) {
        setQualification(null);
        setOutputs([]);
        setError(displayError(reason));
      } finally {
        finish();
      }
    },
    [
      begin,
      disabled,
      finish,
      invalidateBoundState,
      operation,
      review,
    ],
  );

  const runQualification = useCallback(async () => {
    if (disabled || operation !== "idle" || !selectedProfile) return;
    let ttl: number;
    try {
      ttl = boundedInteger("资格有效期", ttlSeconds, 300, 604_800);
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("qualifying");
    invalidateBoundState();
    try {
      const status = await runProviderQualification({
        providerId: selectedProfile.id,
        ttlSeconds: ttl,
      });
      setQualification(status);
      setNotice(
        "完整 App 批准、后端恢复、真实 localhost wire 与受保护输出 canary 已通过并签名持久化；请重新确认任务绑定。",
      );
    } catch (reason: unknown) {
      setQualification(null);
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    begin,
    disabled,
    finish,
    invalidateBoundState,
    operation,
    selectedProfile,
    ttlSeconds,
  ]);

  const revokeQualificationAction = useCallback(async () => {
    if (disabled || operation !== "idle" || !selectedProfile) return;
    if (
      !window.confirm(
        "撤销该 Provider 案件出站资格？撤销后后续请求将在网络前失败。",
      )
    ) {
      return;
    }
    begin("revoking_qualification");
    invalidateBoundState();
    try {
      setQualification(
        await revokeProviderQualification({ providerId: selectedProfile.id }),
      );
      setNotice("Provider 资格撤销 epoch 已轮换；后续案件出站立即失效。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    begin,
    disabled,
    finish,
    invalidateBoundState,
    operation,
    selectedProfile,
  ]);

  const approve = useCallback(async () => {
    if (disabled || operation !== "idle" || !selectedProfile || !review) return;
    let request: ApproveApprovedProviderTaskRequest;
    try {
      request = buildProviderApprovalRequest({
        review,
        providerId: selectedProfile.id,
        task,
        instruction,
        priorOutput: selectedPriorOutput,
        maxTokens,
        reviewer,
        ttlSeconds,
        confirmed,
      });
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("approving");
    try {
      const response = await approveApprovedProviderTask(request);
      if (
        response.providerId !== selectedProfile.id ||
        response.modelId !== effectiveProviderModel(selectedProfile) ||
        response.task !== task ||
        response.purpose !== approvedProviderPurpose(task) ||
        !/^[a-f0-9]{64}$/u.test(response.taskBindingSha256)
      ) {
        throw new Error("后端批准绑定与所选 Provider、模型或固定任务不一致。");
      }
      setApprovedUiBindingKey(currentUiBindingKey);
      setApproval(response);
      setDispatchResult(null);
      setLoadedOutput(null);
      setNotice(
        "完整 Provider 任务绑定已由 Rust 写入受保护存储；页面未接收签名凭据或批准正文。",
      );
    } catch (reason: unknown) {
      setApproval(null);
      setError(displayError(reason));
    } finally {
      finish();
    }
  }, [
    begin,
    confirmed,
    disabled,
    finish,
    instruction,
    maxTokens,
    operation,
    review,
    reviewer,
    selectedPriorOutput,
    currentUiBindingKey,
    selectedProfile,
    task,
    ttlSeconds,
  ]);

  const dispatch = useCallback(async () => {
    if (disabled || operation !== "idle" || !selectedProfile || !review) return;
    if (
      !approvalIsCurrent ||
      !approval ||
      approval.providerId !== selectedProfile.id ||
      approval.modelId !== effectiveProviderModel(selectedProfile) ||
      approval.task !== task
    ) {
      setError("当前任务绑定没有可用的精确批准，请重新核对并签发。");
      return;
    }
    if (
      !qualification?.qualified ||
      qualification.providerId !== selectedProfile.id ||
      qualification.modelId !== effectiveProviderModel(selectedProfile)
    ) {
      setError("当前 Provider、模型尚未通过精确出站资格化。");
      return;
    }
    let request: DispatchApprovedProviderRequest;
    try {
      request = buildProviderDispatchRequest({
        review,
        providerId: selectedProfile.id,
        task,
        instruction,
        priorOutput: selectedPriorOutput,
        maxTokens,
      });
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    begin("dispatching");
    try {
      const response = await dispatchApprovedProvider(request);
      if (
        response.providerId !== selectedProfile.id ||
        response.modelId !== effectiveProviderModel(selectedProfile) ||
        response.task !== task ||
        response.purpose !== approvedProviderPurpose(task) ||
        response.taskBindingSha256 !== approval.taskBindingSha256
      ) {
        throw new Error("Provider 返回的安全绑定与本机精确批准不一致。");
      }
      setDispatchResult(response);
      setLoadedOutput(null);
      setOutputs(
        await listApprovedProviderOutputs({
          redactionId: review.redactionId,
          providerId: selectedProfile.id,
        }),
      );
      setApprovedUiBindingKey("");
      setApproval(null);
      setConfirmed(false);
      setNotice(
        "Provider 响应已完成本地残留扫描并写入受保护输出；本次批准已消费，后续发送须重新确认。",
      );
    } catch (reason: unknown) {
      setDispatchResult(null);
      setApprovedUiBindingKey("");
      setApproval(null);
      setConfirmed(false);
      setError(
        `${displayError(reason)} 为避免不确定网络结果被重复发送，请重新核对并签发新的批准。`,
      );
    } finally {
      finish();
    }
  }, [
    approval,
    approvalIsCurrent,
    begin,
    disabled,
    finish,
    instruction,
    maxTokens,
    operation,
    qualification,
    review,
    selectedPriorOutput,
    selectedProfile,
    task,
  ]);

  const loadOutput = useCallback(
    async (output: ApprovedProviderOutputSummary) => {
      if (disabled || operation !== "idle" || !selectedProfile || !review) return;
      if (
        output.redactionId !== review.redactionId ||
        !outputs.some((candidate) => candidate.outputId === output.outputId)
      ) {
        setError("所选 Provider 输出不属于当前后端输出索引。");
        return;
      }
      begin("loading_output");
      try {
        setLoadedOutput(
          await loadApprovedProviderOutput({
            outputId: output.outputId,
            redactionId: review.redactionId,
            providerId: selectedProfile.id,
            modelId: effectiveProviderModel(selectedProfile),
            task: output.task,
          }),
        );
      } catch (reason: unknown) {
        setLoadedOutput(null);
        setError(displayError(reason));
      } finally {
        finish();
      }
    },
    [
      begin,
      disabled,
      finish,
      operation,
      outputs,
      review,
      selectedProfile,
    ],
  );

  const revokeOutput = useCallback(
    async (outputId: string) => {
      if (
        disabled ||
        operation !== "idle" ||
        !review ||
        !selectedProfile
      ) {
        return;
      }
      if (
        !window.confirm(
          "撤销该受保护 Provider 输出？撤销后将不能再次读取或作为历史输入。",
        )
      ) {
        return;
      }
      begin("revoking_output");
      try {
        await revokeApprovedProviderOutput({
          outputId,
          redactionId: review.redactionId,
        });
        if (priorOutputId === outputId) {
          setPriorOutputId("");
          invalidateBoundState();
        } else {
          setLoadedOutput((current) =>
            current?.outputId === outputId ? null : current,
          );
        }
        setOutputs(
          await listApprovedProviderOutputs({
            redactionId: review.redactionId,
            providerId: selectedProfile.id,
          }),
        );
        setNotice("受保护 Provider 输出已撤销。");
      } catch (reason: unknown) {
        setError(displayError(reason));
      } finally {
        finish();
      }
    },
    [
      begin,
      disabled,
      finish,
      invalidateBoundState,
      operation,
      priorOutputId,
      review,
      selectedProfile,
    ],
  );

  return (
    <AutomationOutboundApprovalPanelView
      disabled={disabled}
      operation={operation}
      providers={providers}
      review={review}
      providerId={providerId}
      task={task}
      instruction={instruction}
      priorOutputId={priorOutputId}
      reviewer={reviewer}
      ttlSeconds={ttlSeconds}
      maxTokens={maxTokens}
      confirmed={confirmed}
      qualification={qualification}
      approval={approvalIsCurrent ? approval : null}
      dispatchResult={dispatchResult}
      outputs={outputs}
      loadedOutput={loadedOutput}
      notice={notice}
      error={error}
      onProviderChange={(value) => void changeProvider(value)}
      onTaskChange={(value) => {
        setTask(value);
        setPriorOutputId("");
        invalidateBoundState();
      }}
      onInstructionChange={(value) => {
        setInstruction(value);
        invalidateBoundState();
      }}
      onPriorOutputChange={(value) => {
        setPriorOutputId(value);
        invalidateBoundState();
      }}
      onReviewerChange={(value) => {
        setReviewer(value);
        invalidateBoundState();
      }}
      onTtlSecondsChange={(value) => {
        setTtlSeconds(value);
        invalidateBoundState();
      }}
      onMaxTokensChange={(value) => {
        setMaxTokens(value);
        invalidateBoundState();
      }}
      onConfirmedChange={(value) => {
        if (!value) {
          setApproval(null);
          setDispatchResult(null);
          setLoadedOutput(null);
        }
        setConfirmed(value);
      }}
      onRefresh={() => void refresh()}
      onRunQualification={() => void runQualification()}
      onRevokeQualification={() => void revokeQualificationAction()}
      onApprove={() => void approve()}
      onDispatch={() => void dispatch()}
      onLoadOutput={(output) => void loadOutput(output)}
      onRevokeOutput={(outputId) => void revokeOutput(outputId)}
    />
  );
}
