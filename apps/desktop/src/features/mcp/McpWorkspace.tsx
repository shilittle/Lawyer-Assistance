import {
  type ChangeEvent,
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  deleteMcpBearerToken,
  getMcpServerConfig,
  getMcpServerStatus,
  saveMcpServerConfig,
  startMcpServer,
  stopMcpServer,
  writeMcpBearerToken,
} from "../../ipc/mcp/client";
import {
  MCP_SERVER_CONFIG_SCHEMA_VERSION,
  type McpServerConfig,
  type McpServerConfigDraft,
  type McpServerConfigResponse,
  type McpServerPhase,
  type McpServerStatus,
} from "../../ipc/mcp/types";
import { publicErrorMessage } from "../../publicOutput";
import "./mcp.css";

const STATUS_POLL_INTERVAL_MS = 2_500;
const MIN_BEARER_TOKEN_BYTES = 32;
const MAX_BEARER_TOKEN_BYTES = 512;

const PHASE_LABELS: Readonly<Record<McpServerPhase, string>> = {
  stopped: "已停止",
  starting: "正在启动",
  running: "运行中",
  stopping: "正在停止",
  failed: "启动失败",
};

type Operation = "idle" | "saving" | "starting" | "stopping" | "credential";

export interface McpWorkspaceProps {
  externalDisabled?: boolean;
  onDraftDirtyChange?: (dirty: boolean) => void;
  onMutationActivityChange?: (active: boolean) => void;
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpConfigToDraft(config: McpServerConfig): McpServerConfigDraft {
  return {
    autoStart: config.autoStart,
    port: String(config.port),
    allowedRoots: config.allowedRoots.join("\n"),
    outputRoot: config.outputRoot,
    allowedOrigins: config.allowedOrigins.join("\n"),
    maxBodyBytes: String(config.maxBodyBytes),
    requestTimeoutMs: String(config.requestTimeoutMs),
    maxConcurrency: String(config.maxConcurrency),
  };
}

function normalizedLines(value: string): string[] {
  return [...new Set(value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean))];
}

function parseBoundedInteger(
  label: string,
  value: string,
  minimum: number,
  maximum: number,
): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label}必须是 ${minimum} 到 ${maximum} 之间的整数。`);
  }
  return parsed;
}

function validateOrigin(value: string): boolean {
  try {
    const origin = new URL(value);
    return (
      (origin.protocol === "http:" || origin.protocol === "https:") &&
      origin.username === "" &&
      origin.password === "" &&
      origin.pathname === "/" &&
      origin.search === "" &&
      origin.hash === ""
    );
  } catch {
    return false;
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpDraftToConfig(draft: McpServerConfigDraft): McpServerConfig {
  const allowedRoots = normalizedLines(draft.allowedRoots);
  const allowedOrigins = normalizedLines(draft.allowedOrigins);
  const outputRoot = draft.outputRoot.trim();

  if (allowedRoots.length > 64) {
    throw new Error("案件材料允许目录最多为 64 项。");
  }
  if (allowedOrigins.length > 64) {
    throw new Error("Origin 允许列表最多为 64 项。");
  }
  const invalidOrigin = allowedOrigins.find((origin) => !validateOrigin(origin));
  if (invalidOrigin) {
    throw new Error("Origin 必须是无账号、路径、查询或片段的 HTTP(S) 源。");
  }
  if (!outputRoot) {
    throw new Error("必须配置文书导出目录。");
  }

  return {
    schemaVersion: MCP_SERVER_CONFIG_SCHEMA_VERSION,
    autoStart: draft.autoStart,
    port: parseBoundedInteger("端口", draft.port, 1_024, 65_535),
    allowedRoots,
    outputRoot,
    allowedOrigins,
    maxBodyBytes: parseBoundedInteger(
      "请求体上限",
      draft.maxBodyBytes,
      16 * 1_024,
      16 * 1_024 * 1_024,
    ),
    requestTimeoutMs: parseBoundedInteger(
      "请求超时",
      draft.requestTimeoutMs,
      100,
      120_000,
    ),
    maxConcurrency: parseBoundedInteger("最大并发数", draft.maxConcurrency, 1, 64),
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function validateMcpBearerToken(token: string): string | null {
  const bytes = new TextEncoder().encode(token);
  if (bytes.length < MIN_BEARER_TOKEN_BYTES || bytes.length > MAX_BEARER_TOKEN_BYTES) {
    return "Bearer Token 必须包含 32 到 512 个可见 ASCII 字符。";
  }
  if ([...bytes].some((byte) => byte < 0x21 || byte > 0x7e)) {
    return "Bearer Token 只能包含不含空格的可见 ASCII 字符。";
  }
  return null;
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpConfigsEqual(
  left: McpServerConfig,
  right: McpServerConfig,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpConfigDraftIsDirty(
  persisted: McpServerConfig,
  draft: McpServerConfigDraft,
): boolean {
  try {
    return !mcpConfigsEqual(persisted, mcpDraftToConfig(draft));
  } catch {
    return true;
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpWorkspaceHasUnsavedChanges(
  configDirty: boolean,
  bearerTokenDraft: string,
): boolean {
  return configDirty || bearerTokenDraft.length > 0;
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpStatusResponseIsCurrent(
  requestId: number,
  latestRequestId: number,
  mutationActive: boolean,
): boolean {
  return requestId === latestRequestId && !mutationActive;
}

// eslint-disable-next-line react-refresh/only-export-components
export function mcpWorkspaceMutationAllowed(
  externalDisabled: boolean,
  mutationActive: boolean,
): boolean {
  return !externalDisabled && !mutationActive;
}

// eslint-disable-next-line react-refresh/only-export-components
export function formatMcpError(error: unknown): string {
  return publicErrorMessage(
    error,
    "MCP 操作失败，请稍后重试或导出诊断报告。",
  );
}

interface McpWorkspaceViewProps {
  configResponse: McpServerConfigResponse;
  draft: McpServerConfigDraft;
  status: McpServerStatus;
  bearerToken: string;
  operation: Operation;
  dirty: boolean;
  notice: string;
  error: string;
  externalDisabled?: boolean;
  onDraftChange: (draft: McpServerConfigDraft) => void;
  onBearerTokenChange: (value: string) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  onStart: () => void;
  onStop: () => void;
  onWriteBearerToken: () => void;
  onDeleteBearerToken: () => void;
}

export function McpWorkspaceView({
  configResponse,
  draft,
  status,
  bearerToken,
  operation,
  dirty,
  notice,
  error,
  externalDisabled = false,
  onDraftChange,
  onBearerTokenChange,
  onSave,
  onStart,
  onStop,
  onWriteBearerToken,
  onDeleteBearerToken,
}: McpWorkspaceViewProps) {
  const busy = operation !== "idle";
  const lifecycleBusy = status.phase === "starting" || status.phase === "stopping";
  const running = status.phase === "running";
  const configurationLocked =
    externalDisabled || busy || lifecycleBusy || running;
  const bearerDraftDirty = bearerToken.length > 0;
  const setField = <K extends keyof McpServerConfigDraft>(
    field: K,
    value: McpServerConfigDraft[K],
  ) => onDraftChange({ ...draft, [field]: value });
  const replacePathList = (
    field: "allowedRoots" | "allowedOrigins",
    promptText: string,
  ) => {
    const value = window.prompt(promptText);
    if (value !== null) setField(field, value);
  };

  return (
    <section
      className="workspace-card mcp-workspace"
      aria-busy={busy || lifecycleBusy}
      aria-disabled={externalDisabled || undefined}
    >
      <header>
        <h2>本地 MCP 服务</h2>
        <p className="muted">
          为已授权的本机助手提供法律工具。服务仅限本机，不向局域网或公网开放。
        </p>
      </header>

      <dl
        className="mcp-workspace__status-grid"
        aria-label="MCP 服务状态"
        aria-live="polite"
      >
        <div>
          <dt>状态</dt>
          <dd>{PHASE_LABELS[status.phase]}</dd>
        </div>
        <div>
          <dt>访问范围</dt>
          <dd>仅本机应用可访问</dd>
        </div>
        <div>
          <dt>连接状态</dt>
          <dd>{running ? "可连接" : "尚未连接"}</dd>
        </div>
        <div>
          <dt>Bearer</dt>
          <dd>
            {configResponse.bearerTokenConfigured
              ? "已配置"
              : "未配置（启动前必须设置）"}
          </dd>
        </div>
      </dl>

      {status.lastError ? (
        <p className="mcp-workspace__error" role="alert">
          最近一次启动未完成，请检查配置后重试；如仍失败，请导出诊断报告。
        </p>
      ) : null}

      <form onSubmit={onSave} noValidate>
        <div className="mcp-workspace__form-grid">
          <label className="mcp-workspace__checkbox mcp-workspace__wide">
            <input
              type="checkbox"
              checked={draft.autoStart}
              disabled={configurationLocked}
              onChange={(event: ChangeEvent<HTMLInputElement>) =>
                setField("autoStart", event.target.checked)
              }
            />
            应用启动后自动启动 MCP 服务
          </label>

          <label>
            本机端口
            <input
              inputMode="numeric"
              value={draft.port}
              disabled={configurationLocked}
              onChange={(event) => setField("port", event.target.value)}
              aria-describedby="mcp-port-help"
            />
            <span className="muted" id="mcp-port-help">允许范围 1024–65535。</span>
          </label>

          <div>
            <strong>文书导出位置</strong>
            <p className="muted">{draft.outputRoot.trim() ? "已配置，本地位置已隐藏" : "尚未配置"}</p>
            <button
              type="button"
              disabled={configurationLocked}
              onClick={() => {
                const value = window.prompt("请输入新的文书导出位置：");
                if (value !== null) setField("outputRoot", value);
              }}
            >
              更改位置
            </button>
          </div>

          <div className="mcp-workspace__wide">
            <strong>案件材料允许位置</strong>
            <p className="muted">已配置 {normalizedLines(draft.allowedRoots).length} 项，本地位置已隐藏</p>
            <button
              type="button"
              disabled={configurationLocked}
              onClick={() =>
                replacePathList("allowedRoots", "请输入允许位置，每行一个：")
              }
            >
              更改允许位置
            </button>
          </div>

          <div className="mcp-workspace__wide">
            <strong>网页来源允许列表</strong>
            <p className="muted">已配置 {normalizedLines(draft.allowedOrigins).length} 项，具体地址已隐藏</p>
            <button
              type="button"
              disabled={configurationLocked}
              onClick={() =>
                replacePathList("allowedOrigins", "请输入允许的网页来源，每行一个：")
              }
            >
              更改允许列表
            </button>
          </div>
        </div>

        <details className="mcp-workspace__advanced">
          <summary>高级资源限制</summary>
          <div className="mcp-workspace__form-grid">
            <label>
              请求体上限（bytes）
              <input
                inputMode="numeric"
                value={draft.maxBodyBytes}
                disabled={configurationLocked}
                onChange={(event) => setField("maxBodyBytes", event.target.value)}
              />
            </label>
            <label>
              请求超时（ms）
              <input
                inputMode="numeric"
                value={draft.requestTimeoutMs}
                disabled={configurationLocked}
                onChange={(event) => setField("requestTimeoutMs", event.target.value)}
              />
            </label>
            <label>
              最大并发数
              <input
                inputMode="numeric"
                value={draft.maxConcurrency}
                disabled={configurationLocked}
                onChange={(event) => setField("maxConcurrency", event.target.value)}
              />
            </label>
          </div>
        </details>

        <div className="mcp-workspace__actions">
          <button type="submit" disabled={configurationLocked || !dirty}>
            {operation === "saving" ? "正在保存……" : "保存配置"}
          </button>
          <button
            type="button"
            disabled={
              externalDisabled ||
              busy ||
              lifecycleBusy ||
              running ||
              dirty ||
              bearerDraftDirty ||
              !configResponse.bearerTokenConfigured
            }
            onClick={onStart}
          >
            {operation === "starting" || status.phase === "starting" ? "正在启动……" : "启动 MCP"}
          </button>
          <button
            className="is-stop"
            type="button"
            disabled={
              externalDisabled || busy || lifecycleBusy || !running
            }
            onClick={onStop}
          >
            {operation === "stopping" || status.phase === "stopping" ? "正在停止……" : "停止 MCP"}
          </button>
        </div>
        {dirty ? <p className="muted">配置尚未保存；保存后才能启动服务。</p> : null}
        {bearerDraftDirty ? (
          <p className="muted">Bearer Token 尚未安全写入；写入或清空输入后才能启动服务。</p>
        ) : null}
        {!configResponse.bearerTokenConfigured ? (
          <p className="muted">请先在下方安全设置 Bearer Token，再启动服务。</p>
        ) : null}
      </form>

      <section className="mcp-workspace__credential" aria-labelledby="mcp-credential-title">
        <div>
          <h3 id="mcp-credential-title">Bearer 凭据</h3>
          <p className="muted">
            Token 单独写入 Windows 凭据管理器，不会进入 MCP 配置文件、诊断信息或状态响应。
          </p>
        </div>
        <div className="mcp-workspace__credential-row">
          <label>
            {configResponse.bearerTokenConfigured ? "替换 Token" : "设置 Token"}
            <input
              type="password"
              autoComplete="new-password"
              value={bearerToken}
              disabled={configurationLocked}
              onChange={(event) => onBearerTokenChange(event.target.value)}
              placeholder="至少 32 个可见 ASCII 字符"
              aria-describedby="mcp-bearer-token-help"
            />
            <span className="muted" id="mcp-bearer-token-help">
              仅在点击“安全写入”后更新服务凭据；输入内容不会随配置一起保存。
            </span>
          </label>
          <button
            type="button"
            disabled={configurationLocked || bearerToken.length === 0}
            onClick={onWriteBearerToken}
          >
            {operation === "credential" ? "正在写入……" : "安全写入"}
          </button>
          <button
            className="is-delete"
            type="button"
            disabled={configurationLocked || !configResponse.bearerTokenConfigured}
            onClick={onDeleteBearerToken}
          >
            删除 Token
          </button>
        </div>
      </section>

      <p className="muted">法律库与用户数据由桌面应用统一管理，不会在服务状态中公开本地位置。</p>

      {error ? <p className="mcp-workspace__error" role="alert" aria-live="assertive">{error}</p> : null}
      {notice ? <p className="mcp-workspace__notice" role="status" aria-live="polite">{notice}</p> : null}
    </section>
  );
}

export function McpWorkspace({
  externalDisabled = false,
  onDraftDirtyChange,
  onMutationActivityChange,
}: McpWorkspaceProps) {
  const [configResponse, setConfigResponse] = useState<McpServerConfigResponse | null>(null);
  const [draft, setDraft] = useState<McpServerConfigDraft | null>(null);
  const [status, setStatus] = useState<McpServerStatus | null>(null);
  const [bearerToken, setBearerToken] = useState("");
  const [operation, setOperation] = useState<Operation>("idle");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const operationRef = useRef<Operation>("idle");
  const statusRequestSequence = useRef(0);
  const mounted = useRef(true);

  const refreshStatus = useCallback(async (reportError: boolean) => {
    if (!mounted.current || operationRef.current !== "idle") return;
    const requestId = statusRequestSequence.current + 1;
    statusRequestSequence.current = requestId;
    try {
      const nextStatus = await getMcpServerStatus();
      if (
        mounted.current &&
        mcpStatusResponseIsCurrent(
          requestId,
          statusRequestSequence.current,
          operationRef.current !== "idle",
        )
      ) {
        setStatus(nextStatus);
      }
    } catch (statusError) {
      if (
        reportError &&
        mounted.current &&
        requestId === statusRequestSequence.current
      ) {
        setError(`读取 MCP 状态失败：${formatMcpError(statusError)}`);
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    let disposed = false;
    const initialStatusRequestId = statusRequestSequence.current + 1;
    statusRequestSequence.current = initialStatusRequestId;
    void Promise.all([getMcpServerConfig(), getMcpServerStatus()])
      .then(([response, initialStatus]) => {
        if (disposed) return;
        setConfigResponse(response);
        setDraft(mcpConfigToDraft(response.config));
        if (
          mcpStatusResponseIsCurrent(
            initialStatusRequestId,
            statusRequestSequence.current,
            operationRef.current !== "idle",
          )
        ) {
          setStatus(initialStatus);
        }
      })
      .catch((loadError: unknown) => {
        if (!disposed) setError(`加载 MCP 设置失败：${formatMcpError(loadError)}`);
      });
    return () => {
      disposed = true;
      mounted.current = false;
      statusRequestSequence.current += 1;
    };
  }, []);

  useEffect(() => {
    const interval = window.setInterval(() => {
      void refreshStatus(false);
    }, STATUS_POLL_INTERVAL_MS);
    return () => window.clearInterval(interval);
  }, [refreshStatus]);

  const dirty = Boolean(
    configResponse &&
      draft &&
      mcpConfigDraftIsDirty(configResponse.config, draft),
  );
  const hasUnsavedChanges = mcpWorkspaceHasUnsavedChanges(dirty, bearerToken);

  useEffect(
    () => onDraftDirtyChange?.(hasUnsavedChanges),
    [hasUnsavedChanges, onDraftDirtyChange],
  );

  function beginOperation(nextOperation: Exclude<Operation, "idle">): boolean {
    if (
      !mcpWorkspaceMutationAllowed(
        externalDisabled,
        operationRef.current !== "idle",
      )
    ) {
      return false;
    }
    operationRef.current = nextOperation;
    // Invalidate any status read that began before this mutation. Its response
    // must never overwrite the authoritative lifecycle response below.
    statusRequestSequence.current += 1;
    onMutationActivityChange?.(true);
    setOperation(nextOperation);
    return true;
  }

  function finishOperation() {
    operationRef.current = "idle";
    onMutationActivityChange?.(false);
    if (mounted.current) setOperation("idle");
  }

  function changeDraft(nextDraft: McpServerConfigDraft) {
    if (externalDisabled) return;
    setDraft(nextDraft);
    if (configResponse) {
      onDraftDirtyChange?.(
        mcpWorkspaceHasUnsavedChanges(
          mcpConfigDraftIsDirty(configResponse.config, nextDraft),
          bearerToken,
        ),
      );
    }
  }

  function changeBearerToken(nextToken: string) {
    if (externalDisabled) return;
    setBearerToken(nextToken);
    onDraftDirtyChange?.(mcpWorkspaceHasUnsavedChanges(dirty, nextToken));
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      !mcpWorkspaceMutationAllowed(
        externalDisabled,
        operationRef.current !== "idle",
      ) ||
      !draft
    ) {
      return;
    }
    let config: McpServerConfig;
    try {
      config = mcpDraftToConfig(draft);
    } catch (validationError) {
      setError(
        validationError instanceof Error
          ? validationError.message
          : "配置内容不符合要求，请检查后重试。",
      );
      return;
    }
    if (!beginOperation("saving")) return;
    setError("");
    setNotice("");
    try {
      const response = await saveMcpServerConfig({ config });
      const nextDraft = mcpConfigToDraft(response.config);
      setConfigResponse(response);
      setDraft(nextDraft);
      onDraftDirtyChange?.(
        mcpWorkspaceHasUnsavedChanges(false, bearerToken),
      );
      setNotice("MCP 配置已保存。服务未自动重启。");
    } catch (saveError) {
      setError(`保存 MCP 配置失败：${formatMcpError(saveError)}`);
    } finally {
      finishOperation();
      void refreshStatus(false);
    }
  }

  async function runLifecycle(
    nextOperation: "starting" | "stopping",
    action: () => Promise<McpServerStatus>,
  ) {
    if (
      !mcpWorkspaceMutationAllowed(
        externalDisabled,
        operationRef.current !== "idle",
      )
    ) {
      return;
    }
    if (
      nextOperation === "starting" &&
      mcpWorkspaceHasUnsavedChanges(dirty, bearerToken)
    ) {
      setError("请先保存 MCP 配置，并安全写入或清空 Bearer Token 输入。");
      return;
    }
    if (!beginOperation(nextOperation)) return;
    setError("");
    setNotice("");
    try {
      const nextStatus = await action();
      statusRequestSequence.current += 1;
      setStatus(nextStatus);
      setNotice(nextOperation === "starting" ? "MCP 服务已启动。" : "MCP 服务已安全停止。");
    } catch (lifecycleError) {
      setError(`${nextOperation === "starting" ? "启动" : "停止"} MCP 失败：${formatMcpError(lifecycleError)}`);
    } finally {
      finishOperation();
      void refreshStatus(false);
    }
  }

  async function writeBearer() {
    if (
      !mcpWorkspaceMutationAllowed(
        externalDisabled,
        operationRef.current !== "idle",
      )
    ) {
      return;
    }
    const validationError = validateMcpBearerToken(bearerToken);
    if (validationError) {
      setError(validationError);
      return;
    }
    if (!beginOperation("credential")) return;
    setError("");
    setNotice("");
    try {
      const response = await writeMcpBearerToken({ token: bearerToken });
      setConfigResponse(response);
      setBearerToken("");
      onDraftDirtyChange?.(
        Boolean(draft && mcpConfigDraftIsDirty(response.config, draft)),
      );
      setNotice("Bearer Token 已写入 Windows 凭据管理器。输入框已清空。");
    } catch (credentialError) {
      setError(`写入 Bearer Token 失败：${formatMcpError(credentialError)}`);
    } finally {
      finishOperation();
      void refreshStatus(false);
    }
  }

  async function deleteBearer() {
    if (
      !mcpWorkspaceMutationAllowed(
        externalDisabled,
        operationRef.current !== "idle",
      )
    ) {
      return;
    }
    if (!window.confirm("确定删除 MCP Bearer Token 吗？删除后客户端现有认证配置将失效。")) {
      return;
    }
    if (!beginOperation("credential")) return;
    setError("");
    setNotice("");
    try {
      const response = await deleteMcpBearerToken({ userConfirmed: true });
      setConfigResponse(response);
      setBearerToken("");
      onDraftDirtyChange?.(
        Boolean(draft && mcpConfigDraftIsDirty(response.config, draft)),
      );
      setNotice("Bearer Token 已删除。");
    } catch (credentialError) {
      setError(`删除 Bearer Token 失败：${formatMcpError(credentialError)}`);
    } finally {
      finishOperation();
      void refreshStatus(false);
    }
  }

  if (!configResponse || !draft || !status) {
    return (
      <section className="workspace-card mcp-workspace" aria-busy="true">
        <h2>本地 MCP 服务</h2>
        {error ? (
          <p className="mcp-workspace__error" role="alert" aria-live="assertive">{error}</p>
        ) : (
          <p role="status" aria-live="polite">正在读取 MCP 配置与运行状态……</p>
        )}
      </section>
    );
  }

  return (
    <McpWorkspaceView
      configResponse={configResponse}
      draft={draft}
      status={status}
      bearerToken={bearerToken}
      operation={operation}
      dirty={dirty}
      notice={notice}
      error={error}
      externalDisabled={externalDisabled}
      onDraftChange={changeDraft}
      onBearerTokenChange={changeBearerToken}
      onSave={(event) => void save(event)}
      onStart={() => void runLifecycle("starting", startMcpServer)}
      onStop={() => void runLifecycle("stopping", stopMcpServer)}
      onWriteBearerToken={() => void writeBearer()}
      onDeleteBearerToken={() => void deleteBearer()}
    />
  );
}
