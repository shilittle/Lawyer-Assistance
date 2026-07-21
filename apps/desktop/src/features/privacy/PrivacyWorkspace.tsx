import {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getLocalOcrStatus,
  getPrivacyConfig,
  savePrivacyConfig,
} from "../../ipc/privacy/client";
import {
  PRIVACY_CONFIG_SCHEMA_VERSION,
  type PrivacyConfig,
  type PrivacyConfigDraft,
  type PrivacyConfigResponse,
} from "../../ipc/privacy/types";
import "./privacy.css";
import { PrivacyReviewWorkbench } from "./PrivacyReviewWorkbench";

type PrivacyOperation = "loading" | "idle" | "saving" | "refreshing";

export interface PrivacyWorkspaceProps {
  onDraftDirtyChange?: (dirty: boolean) => void;
  onMutationActivityChange?: (active: boolean) => void;
}

export interface PrivacyWorkspaceViewProps {
  configResponse: PrivacyConfigResponse;
  draft: PrivacyConfigDraft;
  operation: PrivacyOperation;
  dirty: boolean;
  notice: string;
  error: string;
  onDraftChange: (draft: PrivacyConfigDraft) => void;
  onSave: () => void;
  onReset: () => void;
  onRefreshStatus: () => void;
}

const WINDOWS_LOCAL_ABSOLUTE_PATH = /^[A-Za-z]:[\\/]/u;
const DEVICE = /^(?:auto|cpu|cuda|cuda:\d+)$/u;
const LANGUAGE = /^[A-Za-z0-9_-]{2,16}$/u;

// eslint-disable-next-line react-refresh/only-export-components
export function privacyConfigToDraft(config: PrivacyConfig): PrivacyConfigDraft {
  return {
    privacyMode: config.privacyMode,
    ocrMode: config.ocr.mode,
    workerPath: config.ocr.workerPath ?? "",
    modelDirectory: config.ocr.modelDirectory ?? "",
    device: config.ocr.device,
    languages: config.ocr.languages.join(", "),
    timeoutSeconds: String(config.ocr.timeoutSeconds),
    maxPages: String(config.ocr.maxPages),
  };
}

function parseBoundedInteger(
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

function optionalAbsolutePath(label: string, value: string): string | null {
  const normalized = value.trim();
  if (!normalized) return null;
  if (
    !WINDOWS_LOCAL_ABSOLUTE_PATH.test(normalized) ||
    /(?:^|[\\/])\.\.?(?:[\\/]|$)/u.test(normalized)
  ) {
    throw new Error(`${label}必须位于本机盘符路径，且不能包含 . 或 .. 片段；UNC/网络路径已禁用。`);
  }
  return normalized;
}

function normalizedLanguages(value: string): string[] {
  const languages = value
    .split(/[\s,，;；]+/u)
    .map((language) => language.trim().toLowerCase())
    .filter(Boolean);
  const unique = [...new Set(languages)];
  if (
    unique.length === 0 ||
    unique.length > 16 ||
    unique.some((language) => !LANGUAGE.test(language))
  ) {
    throw new Error(
      "OCR 语言必须包含 1–16 个唯一标识，并仅使用字母、数字、连字符或下划线。",
    );
  }
  return unique;
}

// eslint-disable-next-line react-refresh/only-export-components
export function privacyDraftToConfig(draft: PrivacyConfigDraft): PrivacyConfig {
  const device = draft.device.trim().toLowerCase();
  if (!DEVICE.test(device)) {
    throw new Error("OCR 设备必须为 auto、cpu、cuda 或 cuda:<编号>。");
  }
  return {
    schemaVersion: PRIVACY_CONFIG_SCHEMA_VERSION,
    privacyMode: draft.privacyMode,
    ocr: {
      mode: draft.ocrMode,
      workerPath: optionalAbsolutePath("MinerU worker 路径", draft.workerPath),
      modelDirectory: optionalAbsolutePath("模型目录", draft.modelDirectory),
      device,
      languages: normalizedLanguages(draft.languages),
      timeoutSeconds: parseBoundedInteger(
        "OCR 超时",
        draft.timeoutSeconds,
        10,
        7_200,
      ),
      maxPages: parseBoundedInteger("最大页数", draft.maxPages, 1, 500),
      // These invariants are deliberately not represented as editable draft
      // fields. The backend independently rejects either value if false.
      strictOffline: true,
      forbidCloudFallback: true,
      forbidRemoteUpload: true,
      forbidTelemetry: true,
    },
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function privacyConfigsEqual(
  left: PrivacyConfig,
  right: PrivacyConfig,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

// eslint-disable-next-line react-refresh/only-export-components
export function privacyConfigDraftIsDirty(
  baseline: PrivacyConfig,
  draft: PrivacyConfigDraft,
): boolean {
  try {
    return !privacyConfigsEqual(baseline, privacyDraftToConfig(draft));
  } catch {
    return true;
  }
}

function statusLabel(code: PrivacyConfigResponse["ocrStatus"]["code"]): string {
  switch (code) {
    case "disabled":
      return "已关闭";
    case "not_configured":
      return "尚未配置";
    case "unavailable":
      return "本地组件不可用";
    case "configured_unverified":
      return "已配置，尚未实机验证";
  }
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
  return "隐私配置操作失败。";
}

export function PrivacyWorkspaceView({
  configResponse,
  draft,
  operation,
  dirty,
  notice,
  error,
  onDraftChange,
  onSave,
  onReset,
  onRefreshStatus,
}: PrivacyWorkspaceViewProps) {
  const busy = operation !== "idle";
  const ocrEnabled = draft.ocrMode !== "off";
  const status = configResponse.ocrStatus;
  const qualificationChecks = [
    [
      "processingChainQualified",
      configResponse.qualification.processingChainQualified,
    ],
    [
      "exactWorkerModelMatch",
      configResponse.qualification.exactWorkerModelMatch,
    ],
    [
      "networkIsolationEnforced",
      configResponse.qualification.networkIsolationEnforced,
    ],
    [
      "modelManifestTrustEstablished",
      configResponse.qualification.modelManifestTrustEstablished,
    ],
    [
      "appAutoEnableAuthorized",
      configResponse.qualification.appAutoEnableAuthorized,
    ],
    [
      "productionCaseOcrAuthorized",
      configResponse.qualification.productionCaseOcrAuthorized,
    ],
  ] as const;
  const productionCapabilities = [
    ["扫描件 OCR", configResponse.capabilities.scannedCaseOcrEnabled],
    ["自动批准", configResponse.capabilities.automaticApprovalEnabled],
    ["approved MCP", configResponse.capabilities.approvedCaseMcpEnabled],
  ] as const;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSave();
  };

  return (
    <section className="privacy-workspace" aria-busy={busy}>
      <header className="privacy-heading">
        <div>
          <p className="eyebrow">本机策略与组件检查</p>
          <h2>隐私与本地处理</h2>
        </div>
        <span className={`privacy-config-state ${configResponse.configValid ? "is-valid" : "is-invalid"}`}>
          {configResponse.configValid ? "配置有效" : "配置失效，外发应保持关闭"}
        </span>
      </header>

      <div className="privacy-boundary-warning" role="note">
        <strong>当前强制边界</strong>
        <p>
          本地脱敏审阅、精确回执和安全 PDF 重建已经可用。案件 Provider 与生产 MCP
          正向链尚未开放，后端默认拒绝（fail closed）；目前只有不携带案件材料的公开法律工具可以外发请求。
          真实案件原件与获批脱敏案件材料均不得据此发送。
        </p>
      </div>

      <section
        className="privacy-vnext-gates"
        aria-labelledby="privacy-vnext-gates-title"
      >
        <div className="panel-heading">
          <div>
            <p className="eyebrow">风险优先 · 后端资格快照</p>
            <h3 id="privacy-vnext-gates-title">生产能力门全部保持阻断</h3>
          </div>
          <span className="privacy-gate-badge">fail closed</span>
        </div>
        <dl className="privacy-qualification-list">
          {qualificationChecks.map(([name, value]) => (
            <div className={value ? "is-qualified" : "is-blocked"} key={name}>
              <dt><code>{name}={String(value)}</code></dt>
              <dd>{value ? "已取得当前证据" : "未取得当前证据"}</dd>
            </div>
          ))}
        </dl>
        <p className="privacy-qualification-note">
          qualificationReportId: <code>{configResponse.qualification.qualificationReportId ?? "none"}</code>
          {" · "}
          qualificationReportSha256: <code>{configResponse.qualification.qualificationReportSha256 ?? "none"}</code>
        </p>
        <ul className="privacy-capability-list">
          {productionCapabilities.map(([label, enabled]) => (
            <li className={enabled ? "is-qualified" : "is-blocked"} key={label}>
              <strong>{label}</strong>
              <span>{enabled ? "后端已授权" : "后端不可启用"}</span>
            </li>
          ))}
        </ul>
        <p className="privacy-qualification-note">
          可以保存本地 worker、模型和 GPU 偏好，但这不构成来源认证、OS
          网络隔离证据或生产授权；不得据此处理真实扫描案件、自动批准或启动案件材料 MCP。
        </p>
      </section>

      {!configResponse.configValid && configResponse.loadError ? (
        <p className="error-text" role="alert">
          {configResponse.loadError}
        </p>
      ) : null}

      <form className="privacy-form" onSubmit={submit}>
        <fieldset disabled={busy}>
          <legend>案件材料处理模式</legend>
          <label className="privacy-choice">
            <input
              checked={draft.privacyMode === "external_redacted"}
              name="privacy-mode"
              type="radio"
              value="external_redacted"
              onChange={() =>
                onDraftChange({ ...draft, privacyMode: "external_redacted" })
              }
            />
            <span>
              <strong>外发仅使用脱敏副本</strong>
              <small>外部目标只应接收经本地脱敏、复核并批准的材料。</small>
            </span>
          </label>
          <label className="privacy-choice">
            <input
              checked={draft.privacyMode === "raw_native"}
              name="privacy-mode"
              type="radio"
              value="raw_native"
              onChange={() =>
                onDraftChange({ ...draft, privacyMode: "raw_native" })
              }
            />
            <span>
              <strong>原件仅在本机原生流程处理</strong>
              <small>未生成获批脱敏副本时，不应进入任何外部发送流程。</small>
            </span>
          </label>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>本地 MinerU OCR</legend>
          <div className="privacy-grid">
            <label>
              <span>OCR 模式</span>
              <select
                value={draft.ocrMode}
                onChange={(event) =>
                  onDraftChange({
                    ...draft,
                    ocrMode: event.target.value as PrivacyConfigDraft["ocrMode"],
                  })
                }
              >
                <option value="off">关闭</option>
                <option value="auto_local">
                  保存本地自动路由偏好（生产 OCR 仍受资格门阻断）
                </option>
                <option value="force_local">
                  保存强制本地 OCR 偏好（生产 OCR 仍受资格门阻断）
                </option>
              </select>
            </label>
            <label>
              <span>计算设备</span>
              <input
                disabled={!ocrEnabled}
                value={draft.device}
                placeholder="auto 或 cuda:0"
                onChange={(event) =>
                  onDraftChange({ ...draft, device: event.target.value })
                }
              />
            </label>
            <label className="privacy-wide-field">
              <span>MinerU worker 绝对路径</span>
              <input
                disabled={!ocrEnabled}
                value={draft.workerPath}
                placeholder="C:\\Program Files\\Lawyer Assistance\\mineru-worker.exe"
                onChange={(event) =>
                  onDraftChange({ ...draft, workerPath: event.target.value })
                }
              />
            </label>
            <label className="privacy-wide-field">
              <span>模型目录</span>
              <input
                disabled={!ocrEnabled}
                value={draft.modelDirectory}
                placeholder="C:\\ProgramData\\Lawyer Assistance\\MinerU\\models"
                onChange={(event) =>
                  onDraftChange({
                    ...draft,
                    modelDirectory: event.target.value,
                  })
                }
              />
            </label>
            <label>
              <span>语言</span>
              <input
                disabled={!ocrEnabled}
                value={draft.languages}
                placeholder="zh, en"
                onChange={(event) =>
                  onDraftChange({ ...draft, languages: event.target.value })
                }
              />
            </label>
            <label>
              <span>超时（秒）</span>
              <input
                disabled={!ocrEnabled}
                inputMode="numeric"
                value={draft.timeoutSeconds}
                onChange={(event) =>
                  onDraftChange({
                    ...draft,
                    timeoutSeconds: event.target.value,
                  })
                }
              />
            </label>
            <label>
              <span>单次最大页数</span>
              <input
                disabled={!ocrEnabled}
                inputMode="numeric"
                value={draft.maxPages}
                onChange={(event) =>
                  onDraftChange({ ...draft, maxPages: event.target.value })
                }
              />
            </label>
          </div>

          <div className="privacy-fixed-invariants" aria-label="不可关闭的案件安全约束">
            <span>✓ 严格离线模式（固定开启）</span>
            <span>✓ 禁止云端 OCR 回退（真实案件不可关闭）</span>
            <span>✓ 禁止远端上传原件、OCR 正文与中间产物（固定开启）</span>
            <span>✓ 禁止 OCR 遥测与隐式模型下载（固定开启）</span>
            <span>✓ 页面不提供原件外发许可开关</span>
          </div>
        </fieldset>

        <div className="privacy-actions">
          <button disabled={!dirty || busy} type="submit">
            {operation === "saving" ? "正在保存…" : "保存隐私配置"}
          </button>
          <button disabled={!dirty || busy} type="button" onClick={onReset}>
            放弃未保存修改
          </button>
        </div>
      </form>

      <section className="privacy-status" aria-labelledby="local-ocr-status-title">
        <div className="panel-heading">
          <h3 id="local-ocr-status-title">本地组件状态</h3>
          <button disabled={busy || dirty} type="button" onClick={onRefreshStatus}>
            {operation === "refreshing" ? "正在检查…" : "重新检查"}
          </button>
        </div>
        <p>{status.message}</p>
        <dl>
          <div>
            <dt>状态</dt>
            <dd>{statusLabel(status.code)}</dd>
          </div>
          <div>
            <dt>worker 版本</dt>
            <dd>{status.workerVersion ?? "未读取"}</dd>
          </div>
          <div>
            <dt>模型版本</dt>
            <dd>{status.modelVersion ?? "未读取"}</dd>
          </div>
          <div>
            <dt>worker SHA-256</dt>
            <dd><code>{status.workerSha256 ?? "未生成"}</code></dd>
          </div>
          <div>
            <dt>模型 manifest SHA-256</dt>
            <dd><code>{status.modelManifestSha256 ?? "未生成"}</code></dd>
          </div>
          <div>
            <dt>来源/完整性认证</dt>
            <dd>{status.integrityVerified ? "已验证" : "未验证"}</dd>
          </div>
          <div>
            <dt>网络隔离实机验证</dt>
            <dd>{status.networkIsolationVerified ? "已验证" : "未验证，不作隔离声明"}</dd>
          </div>
        </dl>
      </section>

      {dirty ? <p className="privacy-dirty" role="status">配置尚未保存。</p> : null}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="privacy-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}

export function PrivacyWorkspace({
  onDraftDirtyChange,
  onMutationActivityChange,
}: PrivacyWorkspaceProps) {
  const [configResponse, setConfigResponse] =
    useState<PrivacyConfigResponse | null>(null);
  const [draft, setDraft] = useState<PrivacyConfigDraft | null>(null);
  const [operation, setOperation] = useState<PrivacyOperation>("loading");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [workflowActive, setWorkflowActive] = useState(false);

  useEffect(() => {
    let mounted = true;
    getPrivacyConfig()
      .then((response) => {
        if (!mounted) return;
        setConfigResponse(response);
        setDraft(privacyConfigToDraft(response.config));
        setOperation("idle");
      })
      .catch((reason: unknown) => {
        if (!mounted) return;
        setError(displayError(reason));
        setOperation("idle");
      });
    return () => {
      mounted = false;
    };
  }, []);

  const dirty = useMemo(
    () =>
      configResponse !== null &&
      draft !== null &&
      privacyConfigDraftIsDirty(configResponse.config, draft),
    [configResponse, draft],
  );

  useEffect(() => {
    onDraftDirtyChange?.(dirty);
    return () => onDraftDirtyChange?.(false);
  }, [dirty, onDraftDirtyChange]);

  const mutationActive = operation === "saving" || workflowActive;
  useEffect(() => {
    onMutationActivityChange?.(mutationActive);
    return () => onMutationActivityChange?.(false);
  }, [mutationActive, onMutationActivityChange]);

  const save = useCallback(async () => {
    if (!configResponse || !draft || operation !== "idle") return;
    let config: PrivacyConfig;
    try {
      config = privacyDraftToConfig(draft);
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    setOperation("saving");
    setError("");
    setNotice("");
    try {
      const response = await savePrivacyConfig({ config });
      setConfigResponse(response);
      setDraft(privacyConfigToDraft(response.config));
      setNotice("隐私配置已在本机原子保存；本地组件状态已重新检查。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      setOperation("idle");
    }
  }, [configResponse, draft, operation]);

  const reset = useCallback(() => {
    if (!configResponse || operation !== "idle") return;
    setDraft(privacyConfigToDraft(configResponse.config));
    setError("");
    setNotice("已放弃未保存修改。");
  }, [configResponse, operation]);

  const refreshStatus = useCallback(async () => {
    if (!configResponse || operation !== "idle" || dirty) return;
    setOperation("refreshing");
    setError("");
    setNotice("");
    try {
      const status = await getLocalOcrStatus();
      setConfigResponse((current) =>
        current ? { ...current, ocrStatus: status } : current,
      );
      setNotice("本地组件状态已刷新；未执行 OCR 或网络隔离验证。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      setOperation("idle");
    }
  }, [configResponse, dirty, operation]);

  if (!configResponse || !draft) {
    return (
      <section className="privacy-workspace" aria-busy={operation === "loading"}>
        <h2>隐私与本地处理</h2>
        {error ? (
          <p className="error-text" role="alert">{error}</p>
        ) : (
          <p>正在读取本机隐私配置…</p>
        )}
      </section>
    );
  }

  return (
    <>
      <PrivacyWorkspaceView
        configResponse={configResponse}
        draft={draft}
        operation={operation}
        dirty={dirty}
        notice={notice}
        error={error}
        onDraftChange={setDraft}
        onSave={() => void save()}
        onReset={reset}
        onRefreshStatus={() => void refreshStatus()}
      />
      <PrivacyReviewWorkbench
        disabled={!configResponse.configValid || dirty || operation !== "idle"}
        onActivityChange={setWorkflowActive}
      />
    </>
  );
}
