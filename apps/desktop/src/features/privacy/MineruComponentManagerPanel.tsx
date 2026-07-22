import { useEffect, useMemo, useState } from "react";

import {
  downloadInstallMineruPackage,
  getMineruComponentStatus,
  importMineruComponentCatalog,
  installMineruOfflinePackage,
  rollbackMineruComponent,
  uninstallMineruComponent,
  type MineruCatalogEntry,
  type MineruComponentOperationResponse,
  type MineruComponentStatus,
} from "../../ipc/privacy/mineru-component-client";
import type {
  LocalOcrStatus,
  PrivacyConfigResponse,
  PrivacyVNextQualificationStatus,
} from "../../ipc/privacy/types";
import "./mineru-components.css";

type ComponentOperation =
  | "idle"
  | "loading"
  | "catalog"
  | "offline-install"
  | `download:${string}`
  | `rollback:${string}`
  | `uninstall:${string}`;

interface WorkerRuntimeEvidence {
  workerProtocolVersion?: string | null;
  workerProtocolIdentitySha256?: string | null;
  workerHealthEvidenceSha256?: string | null;
  pythonVersion?: string | null;
  mineruVersion?: string | null;
  pytorchVersion?: string | null;
  cudaRuntimeVersion?: string | null;
  gpuDriverVersion?: string | null;
}

interface GpuQualificationEvidence {
  selectedCudaDevice?: number | null;
  selectedGpuMemoryMib?: number | null;
  selectedGpuName?: string | null;
}

export interface MineruComponentManagerPanelProps {
  snapshot: PrivacyConfigResponse;
  disabled: boolean;
  onSnapshot: (snapshot: PrivacyConfigResponse) => void;
  onActivityChange?: (active: boolean) => void;
}

interface MineruComponentManagerPanelViewProps {
  snapshot: PrivacyConfigResponse;
  status: MineruComponentStatus | null;
  operation: ComponentOperation;
  confirmations: ReadonlySet<string>;
  notice: string;
  error: string;
  disabled: boolean;
  onRefresh: () => void;
  onImportCatalog: () => void;
  onOfflineInstall: () => void;
  onDownload: (entry: MineruCatalogEntry) => void;
  onRollback: (version: string) => void;
  onConfirmationChange: (version: string, checked: boolean) => void;
  onUninstall: (version: string) => void;
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
  return "本地 MinerU 组件操作失败；OCR 仍保持阻断。";
}

function displayValue(value: string | number | null | undefined): string {
  return value === null || value === undefined || value === ""
    ? "未取得真实证据"
    : String(value);
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "无效大小";
  const gib = bytes / 1024 ** 3;
  if (gib >= 1) return `${gib.toFixed(2)} GiB (${bytes.toLocaleString()} bytes)`;
  const mib = bytes / 1024 ** 2;
  return `${mib.toFixed(2)} MiB (${bytes.toLocaleString()} bytes)`;
}

function qualificationLabel(snapshot: PrivacyConfigResponse): string {
  if (snapshot.qualification.revoked) return "已撤销";
  if (snapshot.capabilities.scannedCaseOcrEnabled) return "真实案卷 OCR 已获资格";
  if (snapshot.qualification.processingChainQualified) return "处理链已检查，生产资格仍阻断";
  return "未资格化（fail closed）";
}

function hasCompleteWorkerEvidence(runtime: WorkerRuntimeEvidence): boolean {
  return Boolean(
    runtime.workerProtocolVersion &&
      runtime.workerProtocolIdentitySha256 &&
      runtime.workerHealthEvidenceSha256 &&
      runtime.pythonVersion &&
      runtime.mineruVersion &&
      runtime.pytorchVersion,
  );
}

// Exported for server-rendered tests: no Tauri call occurs in this view.
export function MineruComponentManagerPanelView({
  snapshot,
  status,
  operation,
  confirmations,
  notice,
  error,
  disabled,
  onRefresh,
  onImportCatalog,
  onOfflineInstall,
  onDownload,
  onRollback,
  onConfirmationChange,
  onUninstall,
}: MineruComponentManagerPanelViewProps) {
  const busy = operation !== "idle";
  const controlsDisabled = disabled || busy;
  const runtime = snapshot.ocrStatus as LocalOcrStatus & WorkerRuntimeEvidence;
  const gpu = snapshot.qualification as PrivacyVNextQualificationStatus &
    GpuQualificationEvidence;
  const workerEvidenceComplete = hasCompleteWorkerEvidence(runtime);
  const activeComponent = status?.installedVersions.find((component) => component.active);
  const gpuMemory = gpu.selectedGpuMemoryMib;
  const oomRisk = gpuMemory !== null && gpuMemory !== undefined && gpuMemory < 6144;

  return (
    <section className="mineru-component-manager" aria-busy={busy}>
      <div className="panel-heading">
        <div>
          <p className="eyebrow">应用托管的本地 OCR 组件</p>
          <h3>MinerU 安装、证据、升级、回滚与卸载</h3>
        </div>
        <span
          className={`mineru-component-badge ${
            status?.activeIntegrityValid ? "is-ready" : "is-blocked"
          }`}
        >
          {status?.activeIntegrityValid ? "组件完整" : "OCR blocked"}
        </span>
      </div>

      <div className="mineru-boundary-note" role="note">
        <strong>联网边界</strong>
        <p>
          下载功能只取得已签名目录中固定 URL、大小和 SHA-256 的组件包，绝不下载、上传或远程
          OCR 任何案件材料。无云 OCR、SSH OCR、HTTP OCR、遥测或联网回退。
        </p>
      </div>

      <div className="mineru-component-actions">
        <button disabled={controlsDisabled} type="button" onClick={onRefresh}>
          {operation === "loading" ? "正在复测…" : "刷新组件状态"}
        </button>
        <button disabled={controlsDisabled} type="button" onClick={onImportCatalog}>
          {operation === "catalog" ? "正在验证目录…" : "导入签名组件目录"}
        </button>
        <button disabled={controlsDisabled} type="button" onClick={onOfflineInstall}>
          {operation === "offline-install" ? "正在安装…" : "导入离线 .laocrpkg"}
        </button>
      </div>

      <section className="mineru-evidence" aria-labelledby="mineru-evidence-title">
        <h4 id="mineru-evidence-title">当前安装与真实运行证据</h4>
        <dl>
          <div>
            <dt>安装 / 当前组件</dt>
            <dd>{status?.activeVersion ?? "未激活"}</dd>
          </div>
          <div>
            <dt>MinerU</dt>
            <dd>{displayValue(runtime.mineruVersion ?? activeComponent?.mineruVersion)}</dd>
          </div>
          <div>
            <dt>Python</dt>
            <dd>{displayValue(runtime.pythonVersion)}</dd>
          </div>
          <div>
            <dt>PyTorch</dt>
            <dd>{displayValue(runtime.pytorchVersion)}</dd>
          </div>
          <div>
            <dt>CUDA runtime / driver</dt>
            <dd>
              {displayValue(runtime.cudaRuntimeVersion)} / {displayValue(runtime.gpuDriverVersion)}
            </dd>
          </div>
          <div>
            <dt>CUDA 可用性</dt>
            <dd>
              {runtime.cudaRuntimeVersion && gpu.selectedCudaDevice != null
                ? "已由本机 qualification 证据确认"
                : "未取得真实可用性证据（阻断）"}
            </dd>
          </div>
          <div>
            <dt>GPU 选择</dt>
            <dd>
              配置 {snapshot.config.ocr.device}；实测设备 {displayValue(gpu.selectedCudaDevice)}
              {gpu.selectedGpuName ? `（${gpu.selectedGpuName}）` : ""}
            </dd>
          </div>
          <div>
            <dt>GPU 显存</dt>
            <dd>{gpuMemory == null ? "未取得真实 nvidia-smi 证据" : `${gpuMemory} MiB`}</dd>
          </div>
          <div>
            <dt>worker version</dt>
            <dd>{displayValue(snapshot.ocrStatus.workerVersion)}</dd>
          </div>
          <div>
            <dt>worker SHA-256</dt>
            <dd><code>{displayValue(snapshot.ocrStatus.workerSha256)}</code></dd>
          </div>
          <div>
            <dt>worker protocol / identity</dt>
            <dd>
              {displayValue(runtime.workerProtocolVersion)}<br />
              <code>{displayValue(runtime.workerProtocolIdentitySha256)}</code>
            </dd>
          </div>
          <div>
            <dt>health evidence SHA-256</dt>
            <dd><code>{displayValue(runtime.workerHealthEvidenceSha256)}</code></dd>
          </div>
          <div>
            <dt>组件 package manifest SHA-256</dt>
            <dd><code>{displayValue(status?.activeManifestSha256)}</code></dd>
          </div>
          <div>
            <dt>模型包完整性 / 模型 manifest SHA-256</dt>
            <dd>
              {snapshot.ocrStatus.integrityVerified && status?.activeIntegrityValid
                ? "双重校验通过"
                : "未通过，保持阻断"}
              <br />
              <code>{displayValue(snapshot.ocrStatus.modelManifestSha256)}</code>
            </dd>
          </div>
          <div>
            <dt>最近一次 qualification 结果</dt>
            <dd>
              {qualificationLabel(snapshot)}
              <br />
              <code>{displayValue(snapshot.qualification.qualificationReportId)}</code>
            </dd>
          </div>
          <div>
            <dt>当前模式 / 真实案卷批准</dt>
            <dd>
              {snapshot.config.ocr.mode === "off"
                ? "禁用"
                : snapshot.config.ocr.device === "cpu"
                  ? `CPU (${snapshot.config.ocr.mode})`
                  : `GPU ${snapshot.config.ocr.device} (${snapshot.config.ocr.mode})`} / {snapshot.qualification.productionCaseOcrAuthorized
                ? "已显式授权"
                : "未授权"}
            </dd>
          </div>
        </dl>
        {!workerEvidenceComplete ? (
          <p className="mineru-warning" role="status">
            尚未取得完整的真实 worker hello + health 证据；Python、CUDA 或版本空缺不能推定为可用，
            OCR 保持 fail closed。
          </p>
        ) : null}
        <p className={`mineru-warning ${oomRisk ? "is-danger" : ""}`} role="note">
          {oomRisk
            ? "当前实测显存低于 6144 MiB，资格检查必须失败；不得改用云端或远程 OCR。"
            : "若发生 CUDA OOM，任务会终止整棵 worker 进程树、清理作业明文并返回阻断；不会降级到云端、SSH 或 HTTP OCR。"}
        </p>
      </section>

      <section className="mineru-catalog" aria-labelledby="mineru-catalog-title">
        <div className="panel-heading">
          <div>
            <h4 id="mineru-catalog-title">签名目录与可下载版本</h4>
            <p>
              {status?.catalogTrusted
                ? `目录 ${status.catalogId ?? "（无标识）"} 已验证`
                : "尚无受信目录；联网下载保持禁用"}
            </p>
          </div>
        </div>
        {status?.availablePackages.length ? (
          <ul className="mineru-package-list">
            {status.availablePackages.map((entry) => (
              <li key={entry.packageId}>
                <div>
                  <strong>
                    MinerU {entry.mineruVersion} / 组件 {entry.componentVersion}
                  </strong>
                  <dl>
                    <div>
                      <dt>固定 HTTPS 来源</dt>
                      <dd><code>{entry.downloadUrl}</code></dd>
                    </div>
                    <div>
                      <dt>精确大小</dt>
                      <dd>{formatBytes(entry.packageSizeBytes)}</dd>
                    </div>
                    <div>
                      <dt>包 SHA-256</dt>
                      <dd><code>{entry.packageSha256}</code></dd>
                    </div>
                    <div>
                      <dt>manifest SHA-256</dt>
                      <dd><code>{entry.packageManifestSha256}</code></dd>
                    </div>
                  </dl>
                </div>
                <button
                  disabled={controlsDisabled || !status.catalogTrusted}
                  type="button"
                  onClick={() => onDownload(entry)}
                >
                  {operation === `download:${entry.packageId}`
                    ? "正在下载并验证…"
                    : "按上述固定信息下载并安装"}
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p>目录中没有可用且未撤销的 Windows x86_64 组件包。</p>
        )}
      </section>

      <section className="mineru-installed" aria-labelledby="mineru-installed-title">
        <h4 id="mineru-installed-title">已安装版本</h4>
        {status?.installedVersions.length ? (
          <ul className="mineru-installed-list">
            {status.installedVersions.map((component) => {
              const confirmed = confirmations.has(component.componentVersion);
              return (
                <li key={component.componentVersion}>
                  <div>
                    <strong>
                      {component.componentVersion} / MinerU {component.mineruVersion ?? "未知"}
                    </strong>
                    <span>
                      {component.active ? "当前激活" : "未激活"} · {component.lifecycleState} ·
                      {component.integrityValid ? " 完整性有效" : " 完整性失败"}
                    </span>
                    <code>{displayValue(component.manifestSha256)}</code>
                  </div>
                  <div className="mineru-version-actions">
                    {!component.active ? (
                      <button
                        disabled={controlsDisabled || !component.integrityValid}
                        type="button"
                        onClick={() => onRollback(component.componentVersion)}
                      >
                        {operation === `rollback:${component.componentVersion}`
                          ? "正在回滚…"
                          : "回滚并重新资格化"}
                      </button>
                    ) : null}
                    <label>
                      <input
                        checked={confirmed}
                        disabled={controlsDisabled}
                        type="checkbox"
                        onChange={(event) =>
                          onConfirmationChange(
                            component.componentVersion,
                            event.target.checked,
                          )
                        }
                      />
                      我确认卸载该版本；Windows Firewall 隔离规则保留
                    </label>
                    <button
                      className="danger"
                      disabled={controlsDisabled || !confirmed}
                      type="button"
                      onClick={() => onUninstall(component.componentVersion)}
                    >
                      {operation === `uninstall:${component.componentVersion}`
                        ? "正在卸载…"
                        : "卸载版本"}
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <p>尚未安装应用托管的 MinerU 组件。</p>
        )}
        <p className="mineru-firewall-note">
          卸载只删除精确组件目录，绝不顺带删除 Windows Firewall 隔离规则。任何导入、安装、升级、
          回滚或卸载都会先撤销旧 qualification；新版本必须重新建立信任、复测隔离并运行 canary。
        </p>
      </section>

      {status?.reasonCodes.length ? (
        <p className="mineru-reason-codes">
          组件阻断原因：<code>{status.reasonCodes.join(", ")}</code>
        </p>
      ) : null}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="privacy-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}

export function MineruComponentManagerPanel({
  snapshot,
  disabled,
  onSnapshot,
  onActivityChange,
}: MineruComponentManagerPanelProps) {
  const [status, setStatus] = useState<MineruComponentStatus | null>(null);
  const [operation, setOperation] = useState<ComponentOperation>("loading");
  const [confirmations, setConfirmations] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const active = operation !== "idle" && operation !== "loading";

  useEffect(() => {
    onActivityChange?.(active);
    return () => onActivityChange?.(false);
  }, [active, onActivityChange]);

  useEffect(() => {
    let mounted = true;
    getMineruComponentStatus()
      .then((next) => {
        if (!mounted) return;
        setStatus(next);
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

  const installedVersions = useMemo(
    () => new Set(status?.installedVersions.map((item) => item.componentVersion)),
    [status],
  );

  function applyResponse(response: MineruComponentOperationResponse, success: string) {
    setStatus(response.status);
    setConfirmations(new Set());
    if (response.privacy) onSnapshot(response.privacy);
    setNotice(response.cancelled ? "操作已取消，未修改组件状态。" : success);
  }

  async function perform(
    nextOperation: ComponentOperation,
    action: () => Promise<MineruComponentOperationResponse>,
    success: string,
  ) {
    if (disabled || operation !== "idle") return;
    setOperation(nextOperation);
    setError("");
    setNotice("");
    try {
      applyResponse(await action(), success);
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      setOperation("idle");
    }
  }

  async function refresh() {
    if (disabled || operation !== "idle") return;
    setOperation("loading");
    setError("");
    setNotice("");
    try {
      setStatus(await getMineruComponentStatus());
      setNotice("组件目录、当前绑定和已安装文件全集已重新测量。未执行案件 OCR。");
    } catch (reason: unknown) {
      setError(displayError(reason));
    } finally {
      setOperation("idle");
    }
  }

  function updateConfirmation(version: string, checked: boolean) {
    setConfirmations((current) => {
      const next = new Set(current);
      if (checked) next.add(version);
      else next.delete(version);
      return next;
    });
  }

  return (
    <MineruComponentManagerPanelView
      snapshot={snapshot}
      status={status}
      operation={operation}
      confirmations={confirmations}
      notice={notice}
      error={error}
      disabled={disabled}
      onRefresh={() => void refresh()}
      onImportCatalog={() =>
        void perform(
          "catalog",
          importMineruComponentCatalog,
          "签名组件目录已验证并导入；旧 qualification 已撤销。",
        )
      }
      onOfflineInstall={() =>
        void perform(
          "offline-install",
          installMineruOfflinePackage,
          "离线组件包已按目录哈希安装并原子激活；请重新资格化。",
        )
      }
      onDownload={(entry) =>
        void perform(
          `download:${entry.packageId}`,
          () => downloadInstallMineruPackage(entry.packageId),
          installedVersions.has(entry.componentVersion)
            ? "组件已重新测量并激活；请重新资格化。"
            : "组件已按显示的固定来源、大小和哈希下载、安装并激活；请重新资格化。",
        )
      }
      onRollback={(version) =>
        void perform(
          `rollback:${version}`,
          () => rollbackMineruComponent(version),
          "已原子回滚到完整且未撤销的版本；请重新资格化。",
        )
      }
      onConfirmationChange={updateConfirmation}
      onUninstall={(version) => {
        if (!confirmations.has(version)) return;
        void perform(
          `uninstall:${version}`,
          () => uninstallMineruComponent(version),
          "组件版本已卸载；Windows Firewall 隔离规则保持不变。",
        );
      }}
    />
  );
}
