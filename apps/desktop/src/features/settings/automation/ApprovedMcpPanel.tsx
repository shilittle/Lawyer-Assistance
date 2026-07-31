import { FormEvent, useCallback, useEffect, useState } from "react";

import {
  approveReviewForApprovedWorkspace,
  createStandaloneApprovedMcpSession,
  getApprovedMcpQualificationStatus,
  listApprovedGenerations,
  listApprovedPrivacyReviewSelections,
  listStandaloneApprovedMcpSessions,
  publishApprovedGeneration,
  revokeApprovedGeneration,
  revokeApprovedMcpQualification,
  revokeStandaloneApprovedMcpSession,
  runApprovedMcpQualification,
  type ApprovedGenerationHistory,
  type ApproveReviewForApprovedWorkspaceRequest,
  type ApprovedMcpConnectorId,
  type ApprovedMcpTransport,
  type ApprovedMcpQualificationStatus,
  type ApprovedPrivacyReviewSelection,
  type CreateStandaloneApprovedMcpSessionRequest,
  type PublishApprovedGenerationRequest,
  type StandaloneApprovedMcpSessionMetadata,
  type ProvisionedStandaloneApprovedMcpSession,
} from "../../../ipc/privacy/approved-mcp-client";
import "./approved-mcp.css";

type ApprovedMcpOperation =
  | "idle"
  | "refreshing"
  | "qualifying"
  | "revoking-qualification"
  | "approving-publication"
  | "publishing"
  | "revoking-generation"
  | "creating-session"
  | "copying-session-config"
  | "revoking-session";

const REDACTION_ID = /^red_[a-f0-9]{32}$/u;
const CASE_ID = /^case_[a-f0-9]{32}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SERVER_ID = /^srv_[a-f0-9]{32}$/u;
const HTTP_BEARER = /^mcp-http-[a-f0-9]{64}$/u;
const HTTP_ENDPOINT = /^http:\/\/127\.0\.0\.1:(\d{4,5})\/mcp$/u;
const APPROVED_TOOLS = [
  "system_status",
  "legal_search",
  "legal_get_article",
  "legal_get_versions",
  "legal_get_relations",
  "case_list",
  "case_get_public_metadata",
  "case_list_approved_materials",
  "case_read_approved_material",
  "case_search_approved_materials",
  "case_list_work_products",
  "case_read_work_product",
  "case_write_work_product",
  "case_update_work_product",
  "case_export_work_product_manifest",
  "diagram.list_templates",
  "diagram.get_schema",
  "diagram.validate",
  "diagram.render",
  "diagram.update",
  "diagram.export",
] as const;
const APPROVED_DESTINATION = "approved_case_workspace";
const APPROVED_READ_PURPOSE = "mcp.case_read_approved_material.v1";

export interface ApprovedMcpPanelProps {
  disabled?: boolean;
  onActivityChange?: (active: boolean) => void;
}

interface ApprovedMcpPanelViewProps {
  disabled: boolean;
  operation: ApprovedMcpOperation;
  qualification: ApprovedMcpQualificationStatus | null;
  reviewSelections: ApprovedPrivacyReviewSelection[];
  generations: ApprovedGenerationHistory[];
  sessions: StandaloneApprovedMcpSessionMetadata[];
  selectedRedactionId: string;
  selectedGenerationKey: string;
  historyCaseId: string;
  qualificationDays: string;
  connectorId: ApprovedMcpConnectorId;
  transport: ApprovedMcpTransport;
  httpPort: string;
  allowedOriginsInput: string;
  sessionMinutes: string;
  mcpApprovalReviewer: string;
  mcpApprovalMinutes: string;
  mcpApprovalConfirmed: boolean;
  oneTimeHttpProvisioning: ProvisionedStandaloneApprovedMcpSession | null;
  readGrantEnabled: boolean;
  writeGrantEnabled: boolean;
  diagramReadGrantEnabled: boolean;
  diagramWriteGrantEnabled: boolean;
  notice: string;
  error: string;
  onSelectedRedactionIdChange: (value: string) => void;
  onSelectedGenerationKeyChange: (value: string) => void;
  onHistoryCaseIdChange: (value: string) => void;
  onQualificationDaysChange: (value: string) => void;
  onConnectorIdChange: (value: ApprovedMcpConnectorId) => void;
  onTransportChange: (value: ApprovedMcpTransport) => void;
  onHttpPortChange: (value: string) => void;
  onAllowedOriginsInputChange: (value: string) => void;
  onSessionMinutesChange: (value: string) => void;
  onMcpApprovalReviewerChange: (value: string) => void;
  onMcpApprovalMinutesChange: (value: string) => void;
  onMcpApprovalConfirmedChange: (value: boolean) => void;
  onReadGrantEnabledChange: (value: boolean) => void;
  onWriteGrantEnabledChange: (value: boolean) => void;
  onDiagramReadGrantEnabledChange: (value: boolean) => void;
  onDiagramWriteGrantEnabledChange: (value: boolean) => void;
  onRefresh: () => void;
  onQualify: () => void;
  onRevokeQualification: () => void;
  onApprovePublication: () => void;
  onPublish: (event: FormEvent<HTMLFormElement>) => void;
  onRevokeGeneration: (generation: ApprovedGenerationHistory) => void;
  onCreateSession: (event: FormEvent<HTMLFormElement>) => void;
  onCopyServerId: (serverInstanceId: string) => void;
  onCopyHostConfig: (session: StandaloneApprovedMcpSessionMetadata) => void;
  onCopyHttpHostConfig: () => void;
  onRevokeSession: (serverInstanceId: string) => void;
}

function boundedInteger(
  label: string,
  value: string,
  minimum: number,
  maximum: number,
): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label}必须是 ${minimum}–${maximum} 之间的整数。`);
  }
  return parsed;
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildApprovedGenerationPublication(input: {
  redactionId: string;
  caseId: string;
  approvedPayloadSha256: string;
}): PublishApprovedGenerationRequest {
  const redactionId = input.redactionId.trim();
  const caseId = input.caseId.trim();
  const expectedApprovedPayloadSha256 = input.approvedPayloadSha256.trim();
  if (!REDACTION_ID.test(redactionId)) {
    throw new Error("脱敏记录 ID 必须是 App 生成的 red_ opaque ID。");
  }
  if (!CASE_ID.test(caseId)) {
    throw new Error("案件 ID 必须是 case_ 加 32 位小写十六进制 opaque ID。");
  }
  if (!SHA256.test(expectedApprovedPayloadSha256)) {
    throw new Error("批准载荷 SHA-256 必须是 64 位小写十六进制值。");
  }
  return { redactionId, caseId, expectedApprovedPayloadSha256 };
}

// eslint-disable-next-line react-refresh/only-export-components
export function normalizeAllowedOrigins(raw: string): string[] {
  const values = raw.split(/[\n,]/u).map((value) => value.trim()).filter(Boolean);
  if (values.length > 64) {
    throw new Error("HTTP Origin 最多允许 64 项。");
  }
  const normalized = values.map((value) => {
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`无效 HTTP Origin：${value}`);
    }
    if (
      !["http:", "https:"].includes(parsed.protocol)
      || !parsed.hostname
      || parsed.username
      || parsed.password
      || parsed.pathname !== "/"
      || parsed.search
      || parsed.hash
    ) {
      throw new Error(`HTTP Origin 只能是无凭据、无路径的 http(s) origin：${value}`);
    }
    return parsed.origin.toLowerCase();
  });
  return Array.from(new Set(normalized));
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildApprovedWorkspaceApproval(input: {
  redactionId: string;
  approvedPayloadSha256: string;
  reviewer: string;
  minutes: string;
  confirmed: boolean;
}): ApproveReviewForApprovedWorkspaceRequest {
  const redactionId = input.redactionId.trim();
  const expectedApprovedPayloadSha256 = input.approvedPayloadSha256.trim();
  const reviewer = input.reviewer.trim();
  if (!REDACTION_ID.test(redactionId) || !SHA256.test(expectedApprovedPayloadSha256)) {
    throw new Error("MCP 发布批准必须绑定 App 返回的 redaction ID 与批准载荷哈希。");
  }
  if (reviewer.length < 1 || reviewer.length > 160) {
    throw new Error("复核人标识必须是 1–160 个字符。");
  }
  if (!input.confirmed) {
    throw new Error("必须显式确认仅将当前批准载荷用于 approved MCP 发布。");
  }
  return {
    redactionId,
    expectedApprovedPayloadSha256,
    reviewer,
    ttlSeconds: boundedInteger("MCP 发布批准有效期（分钟）", input.minutes, 5, 7 * 24 * 60) * 60,
    confirmed: true,
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildStandaloneSession(input: {
  connectorId: ApprovedMcpConnectorId;
  transport: ApprovedMcpTransport;
  minutes: string;
  readEnabled: boolean;
  writeEnabled: boolean;
  diagramReadEnabled: boolean;
  diagramWriteEnabled: boolean;
  httpPort: string;
  allowedOriginsInput: string;
}): CreateStandaloneApprovedMcpSessionRequest {
  const maximumMinutes = input.transport === "streamable_http" ? 24 * 60 : 7 * 24 * 60;
  const minutes = boundedInteger("会话有效期（分钟）", input.minutes, 1, maximumMinutes);
  const grantGroups = [
    ...(input.readEnabled ? ["read" as const] : []),
    ...(input.writeEnabled ? ["write" as const] : []),
    ...(input.diagramReadEnabled ? ["diagram_read" as const] : []),
    ...(input.diagramWriteEnabled ? ["diagram_write" as const] : []),
  ];
  if (grantGroups.length === 0) {
    throw new Error("Select at least one fixed grant group (read, write, diagram_read or diagram_write).");
  }
  const httpPort = input.transport === "streamable_http"
    ? boundedInteger("HTTP loopback 端口", input.httpPort, 1024, 65535)
    : null;
  return {
    connectorId: input.connectorId,
    transport: input.transport,
    grantGroups,
    ttlSeconds: minutes * 60,
    httpPort,
    allowedOrigins: input.transport === "streamable_http"
      ? normalizeAllowedOrigins(input.allowedOriginsInput)
      : [],
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildStandaloneStdioSession(input: {
  connectorId: ApprovedMcpConnectorId;
  minutes: string;
  readEnabled: boolean;
  writeEnabled: boolean;
  diagramReadEnabled: boolean;
  diagramWriteEnabled: boolean;
}): CreateStandaloneApprovedMcpSessionRequest {
  return buildStandaloneSession({
    ...input,
    transport: "stdio",
    httpPort: "8787",
    allowedOriginsInput: "",
  });
}

function standaloneArgs(serverInstanceId: string): string[] {
  return [
    "--privacy-profile",
    "approved_case_workspace",
    "--approved-session-id",
    serverInstanceId,
    "stdio",
  ];
}

function assertStandaloneSession(session: StandaloneApprovedMcpSessionMetadata): void {
  if (!SERVER_ID.test(session.serverInstanceId)) {
    throw new Error("Only an App-issued opaque server ID can create host configuration.");
  }
  if (session.transport === "streamable_http") {
    const match = session.endpoint?.match(HTTP_ENDPOINT);
    const port = match ? Number(match[1]) : 0;
    if (!match || port < 1024 || port > 65535) {
      throw new Error("HTTP endpoint must be an App-issued 127.0.0.1 loopback /mcp URL.");
    }
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildStandaloneHostConfiguration(
  session: StandaloneApprovedMcpSessionMetadata,
  oneTimeHttpBearer?: string,
): string {
  assertStandaloneSession(session);
  if (session.transport === "streamable_http" && !HTTP_BEARER.test(oneTimeHttpBearer ?? "")) {
    throw new Error("HTTP host configuration requires the one-time App-issued bearer.");
  }
  const args = standaloneArgs(session.serverInstanceId);
  const authorization = `Bearer ${oneTimeHttpBearer ?? ""}`;
  if (session.connectorId === "workbuddy") {
    return JSON.stringify({
      mcpServers: {
        lawyer_assistance: session.transport === "stdio"
          ? { type: "stdio", command: "lawyer-assistance-mcp", args }
          : {
              type: "http",
              url: session.endpoint,
              headers: { Authorization: authorization },
            },
      },
    }, null, 2);
  }
  if (session.connectorId === "codex") {
    const tools = APPROVED_TOOLS.map((tool) => `  ${JSON.stringify(tool)},`).join("\n");
    const transport = session.transport === "stdio"
      ? `command = "lawyer-assistance-mcp"\nargs = ${JSON.stringify(args)}`
      : `url = ${JSON.stringify(session.endpoint)}\nhttp_headers = { Authorization = ${JSON.stringify(authorization)} }`;
    return `[mcp_servers.lawyer_assistance]\n${transport}\nenabled = true\nrequired = true\nstartup_timeout_sec = 20\ntool_timeout_sec = 120\nenabled_tools = [\n${tools}\n]\ndefault_tools_approval_mode = "writes"\n`;
  }
  if (session.connectorId === "opencode") {
    return JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      share: "disabled",
      mcp: {
        lawyer_assistance: session.transport === "stdio"
          ? { type: "local", command: ["lawyer-assistance-mcp", ...args], enabled: true, timeout: 30_000 }
          : {
              type: "remote",
              url: session.endpoint,
              headers: { Authorization: authorization },
              oauth: false,
              enabled: true,
              timeout: 30_000,
            },
      },
      permission: {
        "lawyer_assistance_*": "deny",
        ...Object.fromEntries(APPROVED_TOOLS.map((tool) => [`lawyer_assistance_${tool}`, "allow"])),
      },
    }, null, 2);
  }
  throw new Error("Unsupported approved MCP connector.");
}

// eslint-disable-next-line react-refresh/only-export-components
export function buildStandaloneHttpServerCommand(
  session: StandaloneApprovedMcpSessionMetadata,
): string {
  assertStandaloneSession(session);
  if (session.transport !== "streamable_http") {
    throw new Error("Only a Streamable HTTP session has a server launch command.");
  }
  return `lawyer-assistance-mcp --privacy-profile approved_case_workspace --approved-session-id ${session.serverInstanceId} serve`;
}

function displayError(reason: unknown): string {
  if (
    typeof reason === "object" &&
    reason !== null &&
    "message" in reason &&
    typeof reason.message === "string"
  ) {
    return reason.message;
  }
  return "approved MCP 本地操作失败。";
}

function localTime(value: number | null): string {
  return value ? new Date(value * 1_000).toLocaleString() : "无";
}

function approvedGenerationKey(generation: ApprovedGenerationHistory): string {
  return `${generation.publicationId}:${generation.documentVersion}`;
}

export function ApprovedMcpPanelView({
  disabled,
  operation,
  qualification,
  reviewSelections,
  generations,
  sessions,
  selectedRedactionId,
  selectedGenerationKey,
  historyCaseId,
  qualificationDays,
  connectorId,
  transport,
  httpPort,
  allowedOriginsInput,
  sessionMinutes,
  mcpApprovalReviewer,
  mcpApprovalMinutes,
  mcpApprovalConfirmed,
  oneTimeHttpProvisioning,
  readGrantEnabled,
  writeGrantEnabled,
  diagramReadGrantEnabled,
  diagramWriteGrantEnabled,
  notice,
  error,
  onSelectedRedactionIdChange,
  onSelectedGenerationKeyChange,
  onHistoryCaseIdChange,
  onQualificationDaysChange,
  onConnectorIdChange,
  onTransportChange,
  onHttpPortChange,
  onAllowedOriginsInputChange,
  onSessionMinutesChange,
  onMcpApprovalReviewerChange,
  onMcpApprovalMinutesChange,
  onMcpApprovalConfirmedChange,
  onReadGrantEnabledChange,
  onWriteGrantEnabledChange,
  onDiagramReadGrantEnabledChange,
  onDiagramWriteGrantEnabledChange,
  onRefresh,
  onQualify,
  onRevokeQualification,
  onApprovePublication,
  onPublish,
  onRevokeGeneration,
  onCreateSession,
  onCopyServerId,
  onCopyHostConfig,
  onCopyHttpHostConfig,
  onRevokeSession,
}: ApprovedMcpPanelViewProps) {
  const busy = operation !== "idle";
  const locked = disabled || busy;
  const qualified = qualification?.qualified === true;
  const selectedReview =
    reviewSelections.find((review) => review.redactionId === selectedRedactionId) ?? null;
  const selectedGeneration =
    generations.find((generation) => approvedGenerationKey(generation) === selectedGenerationKey)
      ?? null;
  const caseOptions = Array.from(new Set([
    ...reviewSelections.map((review) => review.caseId),
    ...generations.map((generation) => generation.caseId),
  ])).sort();

  return (
    <section className="approved-mcp-panel" aria-busy={busy}>
      <div className="panel-heading">
        <div>
          <p className="eyebrow">批准工作区 MCP</p>
          <h3>发布批准 generation、运行资格认证并管理宿主会话</h3>
        </div>
        <span className={`automation-approved-mcp-gate-badge ${qualified ? "is-ready" : ""}`}>
          {qualified ? "qualified" : "blocked"}
        </span>
      </div>

      <p className="approved-mcp-boundary">
        此处只接收 App 后端返回的 opaque ID 与批准载荷哈希。原件路径、文件名、OCR 正文、
        待复核内容、私有映射和批准票据不进入界面。HTTP bearer 只在创建成功响应中进入内存一次，
        不显示正文、不写入历史，并在复制、刷新或切换宿主/传输后立即清除。
      </p>

      <div className="approved-mcp-grid">
        <section>
          <h4>1. 本机资格</h4>
          <dl className="approved-mcp-status">
            <div><dt>状态</dt><dd>{qualification?.reasonCode ?? "尚未读取"}</dd></div>
            <div><dt>stdio canary</dt><dd>{qualification?.stdioCanaryPassed ? "通过" : "未通过"}</dd></div>
            <div><dt>HTTP canary</dt><dd>{qualification?.streamableHttpCanaryPassed ? "通过" : "未通过"}</dd></div>
            <div><dt>App/策略绑定</dt><dd>{qualification?.exactAppPolicyBinding ? "匹配" : "不匹配"}</dd></div>
            <div><dt>服务密钥绑定</dt><dd>{qualification?.exactServerKeyBinding ? "匹配" : "不匹配"}</dd></div>
            <div><dt>到期</dt><dd>{localTime(qualification?.expiresAtUnix ?? null)}</dd></div>
          </dl>
          <label>
            <span>资格有效期（天，1–7）</span>
            <input
              disabled={locked}
              inputMode="numeric"
              value={qualificationDays}
              onChange={(event) => onQualificationDaysChange(event.target.value)}
            />
          </label>
          <div className="approved-mcp-actions">
            <button disabled={locked} type="button" onClick={onRefresh}>刷新状态</button>
            <button disabled={locked} type="button" onClick={onQualify}>运行真实 canary 并签发资格</button>
            <button
              disabled={locked || !qualification?.evidenceId}
              type="button"
              onClick={onRevokeQualification}
            >撤销资格</button>
          </div>
        </section>

        <section>
          <h4>2. 选择并发布已批准审阅</h4>
          <form onSubmit={onPublish}>
            <label>
              <span>已批准审阅（最新在前）</span>
              <select
                disabled={locked || !qualified}
                value={selectedRedactionId}
                onChange={(event) => onSelectedRedactionIdChange(event.target.value)}
              >
                <option value="">请选择已批准且已绑定案件的审阅</option>
                {reviewSelections.map((review) => (
                  <option key={review.redactionId} value={review.redactionId}>
                    {review.caseId} / {review.materialId} / {review.redactionId}
                  </option>
                ))}
              </select>
            </label>
            {selectedReview ? (
              <dl className="approved-mcp-status">
                <div><dt>redaction</dt><dd><code>{selectedReview.redactionId}</code></dd></div>
                <div><dt>case</dt><dd><code>{selectedReview.caseId}</code></dd></div>
                <div><dt>material</dt><dd><code>{selectedReview.materialId}</code></dd></div>
                <div><dt>approved payload</dt><dd><code>{selectedReview.approvedPayloadSha256}</code></dd></div>
                <div><dt>MCP 发布批准</dt><dd>{selectedReview.mcpPublishApproved ? "有效" : "未签发或已过期"}</dd></div>
                <div><dt>MCP 批准到期</dt><dd>{localTime(selectedReview.mcpPublishApprovalExpiresAtUnix)}</dd></div>
              </dl>
            ) : (
              <p>当前没有可发布的 case-bound 已批准审阅。</p>
            )}
            <label>
              <span>MCP 发布复核人</span>
              <input
                disabled={locked || !qualified || !selectedReview}
                maxLength={160}
                value={mcpApprovalReviewer}
                onChange={(event) => onMcpApprovalReviewerChange(event.target.value)}
              />
            </label>
            <label>
              <span>MCP 发布批准有效期（分钟，5–10080）</span>
              <input
                disabled={locked || !qualified || !selectedReview}
                inputMode="numeric"
                value={mcpApprovalMinutes}
                onChange={(event) => onMcpApprovalMinutesChange(event.target.value)}
              />
            </label>
            <label className="approved-mcp-confirmation">
              <input
                checked={mcpApprovalConfirmed}
                disabled={locked || !qualified || !selectedReview}
                type="checkbox"
                onChange={(event) => onMcpApprovalConfirmedChange(event.target.checked)}
              />
              我确认这是独立的 approved MCP 发布批准，不以普通安全导出批准替代。
            </label>
            <button
              disabled={locked || !qualified || !selectedReview || !mcpApprovalConfirmed}
              type="button"
              onClick={onApprovePublication}
            >
              签发 approved MCP 发布批准
            </button>
            <button
              disabled={locked || !qualified || !selectedReview?.mcpPublishApproved}
              type="submit"
            >
              发布不可变 generation
            </button>
          </form>
        </section>
      </div>

      <section className="approved-mcp-history">
        <div className="approved-mcp-row">
          <h4>3. generation 历史与撤销</h4>
          <label>
            <span>案件筛选</span>
            <select
              disabled={locked}
              value={historyCaseId}
              onChange={(event) => onHistoryCaseIdChange(event.target.value)}
            >
              <option value="">全部已批准案件</option>
              {caseOptions.map((knownCaseId) => (
                <option key={knownCaseId} value={knownCaseId}>{knownCaseId}</option>
              ))}
            </select>
          </label>
          <button disabled={locked} type="button" onClick={onRefresh}>重新读取</button>
        </div>
        <label>
          <span>后端已验证 generation</span>
          <select
            disabled={locked || generations.length === 0}
            value={selectedGenerationKey}
            onChange={(event) => onSelectedGenerationKeyChange(event.target.value)}
          >
            <option value="">请选择 generation</option>
            {generations.map((generation) => (
              <option
                key={approvedGenerationKey(generation)}
                value={approvedGenerationKey(generation)}
              >
                {generation.caseId} / {generation.materialId} / {generation.publicationId} / v{generation.documentVersion}
              </option>
            ))}
          </select>
        </label>
        {selectedGeneration ? (
          <div className="approved-mcp-selected-generation">
            <code>{selectedGeneration.caseId}</code>
            <code>{selectedGeneration.materialId}</code>
            <code>{selectedGeneration.publicationId}</code>
            <span>v{selectedGeneration.documentVersion} · {selectedGeneration.revokedAtUnix ? "已撤销" : "有效"}</span>
            <span>content {selectedGeneration.contentSha256}</span>
            <span>manifest {selectedGeneration.manifestSha256}</span>
            <button
              disabled={locked || selectedGeneration.revokedAtUnix !== null}
              type="button"
              onClick={() => onRevokeGeneration(selectedGeneration)}
            >
              撤销所选 generation
            </button>
          </div>
        ) : (
          <p>没有可选择的已验证 generation。</p>
        )}
      </section>

      <section className="approved-mcp-sessions">
        <h4>4. WorkBuddy / Codex / OpenCode：stdio 与本机 Streamable HTTP</h4>
        <form className="approved-mcp-row" onSubmit={onCreateSession}>
          <label>
            <span>宿主</span>
            <select
              disabled={locked || !qualified}
              value={connectorId}
              onChange={(event) => onConnectorIdChange(event.target.value as ApprovedMcpConnectorId)}
            >
              <option value="workbuddy">WorkBuddy</option>
              <option value="codex">Codex</option>
              <option value="opencode">OpenCode</option>
            </select>
          </label>
          <label>
            <span>传输</span>
            <select
              disabled={locked || !qualified}
              value={transport}
              onChange={(event) => onTransportChange(event.target.value as ApprovedMcpTransport)}
            >
              <option value="stdio">stdio</option>
              <option value="streamable_http">Streamable HTTP（仅 127.0.0.1）</option>
            </select>
          </label>
          {transport === "streamable_http" ? (
            <>
              <label>
                <span>本机端口（1024–65535）</span>
                <input
                  disabled={locked || !qualified}
                  inputMode="numeric"
                  value={httpPort}
                  onChange={(event) => onHttpPortChange(event.target.value)}
                />
              </label>
              <label className="approved-mcp-origins">
                <span>允许的 Origin（可选，每行一项）</span>
                <textarea
                  disabled={locked || !qualified}
                  placeholder="http://127.0.0.1:3000"
                  rows={3}
                  value={allowedOriginsInput}
                  onChange={(event) => onAllowedOriginsInputChange(event.target.value)}
                />
              </label>
            </>
          ) : null}
          <label>
            <span>会话有效期（分钟）</span>
            <input
              disabled={locked || !qualified}
              inputMode="numeric"
              value={sessionMinutes}
              onChange={(event) => onSessionMinutesChange(event.target.value)}
            />
          </label>
          <fieldset className="approved-mcp-grants">
            <legend>{"\u56fa\u5b9a\u6388\u6743\u7ec4"}</legend>
            <label>
              <input
                checked={readGrantEnabled}
                disabled={locked || !qualified}
                type="checkbox"
                onChange={(event) => onReadGrantEnabledChange(event.target.checked)}
              />
              {"\u53ea\u8bfb\uff088 \u9879\u6279\u51c6\u5de5\u5177\uff09"}
            </label>
            <label>
              <input
                checked={writeGrantEnabled}
                disabled={locked || !qualified}
                type="checkbox"
                onChange={(event) => onWriteGrantEnabledChange(event.target.checked)}
              />
              {"\u5199\u5165\uff082 \u9879\u5de5\u4f5c\u6210\u679c\u5de5\u5177\uff09"}
            </label>
            <label>
              <input
                aria-label="图示只读授权组"
                checked={diagramReadGrantEnabled}
                disabled={locked || !qualified}
                type="checkbox"
                onChange={(event) => onDiagramReadGrantEnabledChange(event.target.checked)}
              />
              {"\u56fe\u793a\u53ea\u8bfb\uff084 \u9879\u6a21\u677f\u3001schema\u3001\u6821\u9a8c\u4e0e\u5bfc\u51fa\u5de5\u5177\uff09"}
            </label>
            <label>
              <input
                aria-label="图示写入授权组"
                checked={diagramWriteGrantEnabled}
                disabled={locked || !qualified}
                type="checkbox"
                onChange={(event) => onDiagramWriteGrantEnabledChange(event.target.checked)}
              />
              {"\u56fe\u793a\u5199\u5165\uff082 \u9879\u6e32\u67d3\u4e0e\u66f4\u65b0\u5de5\u5177\uff09"}
            </label>
          </fieldset>
          <button
            disabled={locked || !qualified || (
              !readGrantEnabled
              && !writeGrantEnabled
              && !diagramReadGrantEnabled
              && !diagramWriteGrantEnabled
            )}
            type="submit"
          >
            创建 App 签发会话
          </button>
        </form>
        {oneTimeHttpProvisioning ? (
          <aside className="approved-mcp-one-time">
            <strong>一次性 HTTP 宿主配置已就绪</strong>
            <p>
              bearer 短期有效且只在本次创建响应返回；列表与历史永不返回。界面不会显示 bearer 正文，
              复制完整宿主配置后立即从前端状态清除，无法再次读取。
            </p>
            <code>{oneTimeHttpProvisioning.session.endpoint}</code>
            <code>{buildStandaloneHttpServerCommand(oneTimeHttpProvisioning.session)}</code>
            <span>到期 {localTime(oneTimeHttpProvisioning.session.expiresAtUnix)}</span>
            <button disabled={locked} type="button" onClick={onCopyHttpHostConfig}>
              复制一次性 {oneTimeHttpProvisioning.session.connectorId} HTTP 宿主配置并清除
            </button>
          </aside>
        ) : null}
        {sessions.length ? (
          <ul className="approved-mcp-list">
            {sessions.map((session) => (
              <li key={session.serverInstanceId}>
                <div>
                  <strong>{session.connectorId} 路 {session.transport}</strong>
                  <code>{session.serverInstanceId}</code>
                  <span>{"\u6388\u6743\u7ec4 "}{session.grantGroups.join(" + ")}{" / "}{session.grants.length}{" \u9879\u7cbe\u786e\u5de5\u5177/\u7528\u9014\u6388\u6743"}</span>
                  <span>{session.active ? "有效" : session.reasonCode} · 到期 {localTime(session.expiresAtUnix)}</span>
                  {session.transport === "stdio" ? (
                    <code>{buildStandaloneHostConfiguration(session)}</code>
                  ) : (
                    <>
                      <code>{session.endpoint}</code>
                      <span>bearer 不会由列表或历史接口返回；只能在创建瞬间复制。</span>
                    </>
                  )}
                </div>
                <div className="approved-mcp-actions">
                  <button
                    disabled={locked}
                    type="button"
                    onClick={() => onCopyServerId(session.serverInstanceId)}
                  >{"\u590d\u5236 server ID"}</button>
                  <button
                    disabled={locked || session.transport !== "stdio"}
                    type="button"
                    onClick={() => onCopyHostConfig(session)}
                  >{"\u590d\u5236\u65e0\u8def\u5f84\u5bbf\u4e3b\u914d\u7f6e"}</button>
                  <button
                    disabled={locked || !session.active}
                    type="button"
                    onClick={() => onRevokeSession(session.serverInstanceId)}
                  >{"\u64a4\u9500\u4f1a\u8bdd"}</button>
                </div>
              </li>
            ))}
          </ul>
        ) : <p>当前没有 standalone approved MCP 会话。</p>}
      </section>

      <aside className="approved-mcp-host-policy">
        <strong>宿主硬边界</strong>
        <p>
          会话只能从 opaque ID 开始，并严格匹配 21 项 profile（5 项离线公共法律工具 +
          10 项批准工作区工具 + 6 项批准图示工具）。禁止附加或粘贴案件原文，禁止读取宿主文件、浏览器、搜索、
          其他 MCP、其他 Skill、memory、subagent、远程 OCR 或任何网络回退；上下文受污染时
          必须立即停止。资格、票据、撤销、到期、hash 或残留扫描失败时不得降级。
        </p>
      </aside>

      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="automation-approved-mcp-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}

export function ApprovedMcpPanel({
  disabled = false,
  onActivityChange,
}: ApprovedMcpPanelProps) {
  const [operation, setOperation] = useState<ApprovedMcpOperation>("idle");
  const [qualification, setQualification] = useState<ApprovedMcpQualificationStatus | null>(null);
  const [reviewSelections, setReviewSelections] = useState<ApprovedPrivacyReviewSelection[]>([]);
  const [generations, setGenerations] = useState<ApprovedGenerationHistory[]>([]);
  const [sessions, setSessions] = useState<StandaloneApprovedMcpSessionMetadata[]>([]);
  const [selectedRedactionId, setSelectedRedactionId] = useState("");
  const [selectedGenerationKey, setSelectedGenerationKey] = useState("");
  const [historyCaseId, setHistoryCaseId] = useState("");
  const [qualificationDays, setQualificationDays] = useState("1");
  const [connectorId, setConnectorId] = useState<ApprovedMcpConnectorId>("workbuddy");
  const [transport, setTransport] = useState<ApprovedMcpTransport>("stdio");
  const [httpPort, setHttpPort] = useState("8787");
  const [allowedOriginsInput, setAllowedOriginsInput] = useState("");
  const [sessionMinutes, setSessionMinutes] = useState("60");
  const [mcpApprovalReviewer, setMcpApprovalReviewer] = useState("");
  const [mcpApprovalMinutes, setMcpApprovalMinutes] = useState("60");
  const [mcpApprovalConfirmed, setMcpApprovalConfirmed] = useState(false);
  const [oneTimeHttpProvisioning, setOneTimeHttpProvisioning] = useState<ProvisionedStandaloneApprovedMcpSession | null>(null);
  const [readGrantEnabled, setReadGrantEnabled] = useState(true);
  const [writeGrantEnabled, setWriteGrantEnabled] = useState(true);
  const [diagramReadGrantEnabled, setDiagramReadGrantEnabled] = useState(false);
  const [diagramWriteGrantEnabled, setDiagramWriteGrantEnabled] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const loadState = useCallback(async (caseFilter: string) => {
    setOneTimeHttpProvisioning(null);
    const filter = caseFilter.trim();
    if (filter && !CASE_ID.test(filter)) {
      throw new Error("历史筛选只能使用后端返回的 case_ opaque ID。");
    }
    const [nextQualification, nextReviews, nextGenerations, nextSessions] = await Promise.all([
      getApprovedMcpQualificationStatus(),
      listApprovedPrivacyReviewSelections(),
      listApprovedGenerations(filter || undefined),
      listStandaloneApprovedMcpSessions(),
    ]);
    setQualification(nextQualification);
    setReviewSelections(nextReviews);
    setGenerations(nextGenerations);
    setSessions(nextSessions);
    setSelectedRedactionId((current) => (
      nextReviews.some((review) => review.redactionId === current)
        ? current
        : (nextReviews[0]?.redactionId ?? "")
    ));
    setSelectedGenerationKey((current) => (
      nextGenerations.some((generation) => approvedGenerationKey(generation) === current)
        ? current
        : (nextGenerations[0] ? approvedGenerationKey(nextGenerations[0]) : "")
    ));
  }, []);

  useEffect(() => {
    let active = true;
    setOperation("refreshing");
    onActivityChange?.(true);
    Promise.all([
      getApprovedMcpQualificationStatus(),
      listApprovedPrivacyReviewSelections(),
      listApprovedGenerations(),
      listStandaloneApprovedMcpSessions(),
    ])
      .then(([nextQualification, nextReviews, nextGenerations, nextSessions]) => {
        if (!active) return;
        setQualification(nextQualification);
        setReviewSelections(nextReviews);
        setGenerations(nextGenerations);
        setSessions(nextSessions);
        setSelectedRedactionId(nextReviews[0]?.redactionId ?? "");
        setSelectedGenerationKey(
          nextGenerations[0] ? approvedGenerationKey(nextGenerations[0]) : "",
        );
      })
      .catch((reason: unknown) => active && setError(displayError(reason)))
      .finally(() => {
        if (!active) return;
        setOperation("idle");
        onActivityChange?.(false);
      });
    return () => {
      active = false;
      onActivityChange?.(false);
    };
  }, [onActivityChange]);

  async function perform(
    nextOperation: ApprovedMcpOperation,
    task: () => Promise<void>,
    success: string,
  ) {
    if (disabled || operation !== "idle") return;
    setOperation(nextOperation);
    setError("");
    setNotice("");
    onActivityChange?.(true);
    try {
      await task();
      setNotice(success);
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      setOperation("idle");
      onActivityChange?.(false);
    }
  }

  const refresh = () => perform(
    "refreshing",
    () => loadState(historyCaseId),
    "已重新验证资格证据，并读取批准审阅、generation 与会话状态。",
  );

  const qualify = () => perform("qualifying", async () => {
    const days = boundedInteger("资格有效期（天）", qualificationDays, 1, 7);
    setQualification(await runApprovedMcpQualification(days * 24 * 60 * 60));
  }, "真实 stdio/HTTP canary 已完成，资格证据已持久化。");

  const revokeQualification = () => perform("revoking-qualification", async () => {
    setOneTimeHttpProvisioning(null);
    setQualification(await revokeApprovedMcpQualification());
    setSessions(await listStandaloneApprovedMcpSessions());
  }, "approved MCP 资格已撤销；既有调用将 fail closed。");

  const approvePublication = () => {
    void perform("approving-publication", async () => {
      const selectedReview = reviewSelections.find(
        (review) => review.redactionId === selectedRedactionId,
      );
      if (!selectedReview) {
        throw new Error("请选择后端返回的已批准审阅。");
      }
      const request = buildApprovedWorkspaceApproval({
        redactionId: selectedReview.redactionId,
        approvedPayloadSha256: selectedReview.approvedPayloadSha256,
        reviewer: mcpApprovalReviewer,
        minutes: mcpApprovalMinutes,
        confirmed: mcpApprovalConfirmed,
      });
      const receipt = await approveReviewForApprovedWorkspace(request);
      if (
        !receipt.mcpPublishApproved
        || receipt.approvedPayloadSha256 !== request.expectedApprovedPayloadSha256
        || receipt.destinationIdentifier !== APPROVED_DESTINATION
        || receipt.purpose !== APPROVED_READ_PURPOSE
      ) {
        throw new Error("后端返回的 MCP 发布批准绑定不匹配。");
      }
      const nextReviews = await listApprovedPrivacyReviewSelections();
      if (!nextReviews.some((review) => review.redactionId === request.redactionId && review.mcpPublishApproved)) {
        throw new Error("MCP 发布批准未通过后端状态复核。");
      }
      setReviewSelections(nextReviews);
      setMcpApprovalConfirmed(false);
    }, "approved MCP 发布批准已按当前载荷哈希、固定目的与有效期签发。");
  };

  const submitPublication = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void perform("publishing", async () => {
      const selectedReview = reviewSelections.find(
        (review) => review.redactionId === selectedRedactionId,
      );
      if (!selectedReview) {
        throw new Error("请选择后端返回的已批准审阅。");
      }
      const request = buildApprovedGenerationPublication({
        redactionId: selectedReview.redactionId,
        caseId: selectedReview.caseId,
        approvedPayloadSha256: selectedReview.approvedPayloadSha256,
      });
      const published = await publishApprovedGeneration(request);
      setHistoryCaseId(request.caseId);
      const nextGenerations = await listApprovedGenerations(request.caseId);
      setGenerations(nextGenerations);
      setSelectedGenerationKey(
        nextGenerations.some((generation) => (
          generation.publicationId === published.publicationId
            && generation.documentVersion === published.documentVersion
        ))
          ? `${published.publicationId}:${published.documentVersion}`
          : (nextGenerations[0] ? approvedGenerationKey(nextGenerations[0]) : ""),
      );
    }, "已发布与所选审阅 case/material/payload 精确绑定的不可变 generation。");
  };

  const revokeGeneration = (generation: ApprovedGenerationHistory) => {
    void perform("revoking-generation", async () => {
      await revokeApprovedGeneration(generation);
      const nextGenerations = await listApprovedGenerations(historyCaseId.trim() || undefined);
      setGenerations(nextGenerations);
      setSelectedGenerationKey(
        nextGenerations[0] ? approvedGenerationKey(nextGenerations[0]) : "",
      );
    }, "批准 generation 已撤销，后续读取与来源绑定写回将 fail closed。");
  };

  const createSession = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void perform("creating-session", async () => {
      setOneTimeHttpProvisioning(null);
      const provisioned = await createStandaloneApprovedMcpSession(buildStandaloneSession({
        connectorId,
        transport,
        minutes: sessionMinutes,
        readEnabled: readGrantEnabled,
        writeEnabled: writeGrantEnabled,
        diagramReadEnabled: diagramReadGrantEnabled,
        diagramWriteEnabled: diagramWriteGrantEnabled,
        httpPort,
        allowedOriginsInput,
      }));
      if (
        provisioned.session.connectorId !== connectorId
        || provisioned.session.transport !== transport
      ) {
        throw new Error("standalone session connector or transport mismatch");
      }
      if (transport === "streamable_http") {
        if (!HTTP_BEARER.test(provisioned.oneTimeHttpBearer ?? "")) {
          throw new Error("App did not return a valid one-time HTTP bearer");
        }
        assertStandaloneSession(provisioned.session);
        setOneTimeHttpProvisioning(provisioned);
      } else if (provisioned.oneTimeHttpBearer !== undefined) {
        throw new Error("stdio session must not return an HTTP bearer");
      }
      setSessions(await listStandaloneApprovedMcpSessions());
    }, "App 已签发固定工具授权会话；HTTP bearer 如有只可复制一次。");
  };

  const copyServerId = (serverInstanceId: string) => {
    void perform("copying-session-config", async () => {
      await navigator.clipboard.writeText(serverInstanceId);
      setOneTimeHttpProvisioning(null);
    }, "Copied opaque server ID.");
  };

  const copyHostConfig = (session: StandaloneApprovedMcpSessionMetadata) => {
    void perform("copying-session-config", async () => {
      await navigator.clipboard.writeText(buildStandaloneHostConfiguration(session));
      setOneTimeHttpProvisioning(null);
    }, "Copied local stdio host configuration without paths, secrets, or material content.");
  };

  const copyHttpHostConfig = () => {
    void perform("copying-session-config", async () => {
      const provisioned = oneTimeHttpProvisioning;
      if (!provisioned?.oneTimeHttpBearer) {
        throw new Error("One-time HTTP bearer was already cleared; revoke and create a new session.");
      }
      await navigator.clipboard.writeText(buildStandaloneHostConfiguration(
        provisioned.session,
        provisioned.oneTimeHttpBearer,
      ));
      setOneTimeHttpProvisioning(null);
    }, "Copied one-time HTTP host config and cleared the frontend bearer.");
  };

  const revokeSession = (serverInstanceId: string) => {
    void perform("revoking-session", async () => {
      await revokeStandaloneApprovedMcpSession(serverInstanceId);
      if (oneTimeHttpProvisioning?.session.serverInstanceId === serverInstanceId) {
        setOneTimeHttpProvisioning(null);
      }
      setSessions(await listStandaloneApprovedMcpSessions());
    }, "standalone approved MCP 会话已撤销。");
  };

  return (
    <ApprovedMcpPanelView
      disabled={disabled}
      operation={operation}
      qualification={qualification}
      reviewSelections={reviewSelections}
      generations={generations}
      sessions={sessions}
      selectedRedactionId={selectedRedactionId}
      selectedGenerationKey={selectedGenerationKey}
      historyCaseId={historyCaseId}
      qualificationDays={qualificationDays}
      connectorId={connectorId}
      transport={transport}
      httpPort={httpPort}
      allowedOriginsInput={allowedOriginsInput}
      sessionMinutes={sessionMinutes}
      mcpApprovalReviewer={mcpApprovalReviewer}
      mcpApprovalMinutes={mcpApprovalMinutes}
      mcpApprovalConfirmed={mcpApprovalConfirmed}
      oneTimeHttpProvisioning={oneTimeHttpProvisioning}
      readGrantEnabled={readGrantEnabled}
      writeGrantEnabled={writeGrantEnabled}
      diagramReadGrantEnabled={diagramReadGrantEnabled}
      diagramWriteGrantEnabled={diagramWriteGrantEnabled}
      notice={notice}
      error={error}
      onSelectedRedactionIdChange={setSelectedRedactionId}
      onSelectedGenerationKeyChange={setSelectedGenerationKey}
      onHistoryCaseIdChange={setHistoryCaseId}
      onQualificationDaysChange={setQualificationDays}
      onConnectorIdChange={(value) => {
        setOneTimeHttpProvisioning(null);
        setConnectorId(value);
      }}
      onTransportChange={(value) => {
        setOneTimeHttpProvisioning(null);
        setTransport(value);
      }}
      onHttpPortChange={setHttpPort}
      onAllowedOriginsInputChange={setAllowedOriginsInput}
      onSessionMinutesChange={setSessionMinutes}
      onMcpApprovalReviewerChange={setMcpApprovalReviewer}
      onMcpApprovalMinutesChange={setMcpApprovalMinutes}
      onMcpApprovalConfirmedChange={setMcpApprovalConfirmed}
      onReadGrantEnabledChange={setReadGrantEnabled}
      onWriteGrantEnabledChange={setWriteGrantEnabled}
      onDiagramReadGrantEnabledChange={setDiagramReadGrantEnabled}
      onDiagramWriteGrantEnabledChange={setDiagramWriteGrantEnabled}
      onRefresh={refresh}
      onQualify={qualify}
      onRevokeQualification={revokeQualification}
      onApprovePublication={approvePublication}
      onPublish={submitPublication}
      onRevokeGeneration={revokeGeneration}
      onCreateSession={createSession}
      onCopyServerId={copyServerId}
      onCopyHostConfig={copyHostConfig}
      onCopyHttpHostConfig={copyHttpHostConfig}
      onRevokeSession={revokeSession}
    />
  );
}
