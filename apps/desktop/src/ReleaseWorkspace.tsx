import { useEffect, useState } from "react";
import {
  exportDiagnosticReport,
  getVersionInfo,
  type VersionInfo,
} from "./ipc/release/client";
import {
  checkForApplicationUpdate,
  formatIpcError,
  installApplicationUpdate,
  type ApplicationUpdate,
  type DownloadEvent,
} from "./ipc/release/updater";

type ReleaseOperation = "idle" | "checking" | "installing" | "maintenance" | "restarting";

function formatBuildTime(buildUnix: number): string {
  if (!Number.isFinite(buildUnix) || buildUnix <= 0) return "未知";
  return new Date(buildUnix * 1000).toLocaleString("zh-CN", { hour12: false });
}

function formatReleaseDate(value?: string): string {
  if (!value) return "未提供";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleString("zh-CN", { hour12: false });
}

export function ReleaseWorkspace() {
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [versionInfoError, setVersionInfoError] = useState("");
  const [status, setStatus] = useState("");
  const [operation, setOperation] = useState<ReleaseOperation>("idle");
  const [availableUpdate, setAvailableUpdate] = useState<ApplicationUpdate | null>(null);
  const [downloadedBytes, setDownloadedBytes] = useState(0);
  const [totalBytes, setTotalBytes] = useState<number | null>(null);

  useEffect(() => {
    void getVersionInfo().then(setInfo).catch((error: unknown) => {
      setVersionInfoError(formatIpcError(error));
    });
  }, []);

  async function exportDiagnostics() {
    if (operation !== "idle") return;
    setOperation("maintenance");
    try {
      const result = await exportDiagnosticReport(null);
      setStatus(
        result.cancelled ? "已取消诊断导出。" : "诊断报告已导出。",
      );
    } catch (error) {
      setStatus(formatIpcError(error));
    } finally {
      setOperation("idle");
    }
  }

  async function checkForUpdates() {
    if (operation !== "idle") return;
    setOperation("checking");
    setStatus("正在检查签名更新……");
    setDownloadedBytes(0);
    setTotalBytes(null);

    setAvailableUpdate(null);

    try {
      const update = await checkForApplicationUpdate();
      setAvailableUpdate(update);
      setStatus(update ? `发现新版本 ${update.version}。` : "当前已是最新版本。");
    } catch (error) {
      setStatus(`检查更新失败：${formatIpcError(error)}`);
    } finally {
      setOperation("idle");
    }
  }

  function onDownloadEvent(event: DownloadEvent) {
    switch (event.event) {
      case "Started":
        setDownloadedBytes(0);
        setTotalBytes(
          event.data.contentLength && event.data.contentLength > 0
            ? event.data.contentLength
            : null,
        );
        setStatus("正在下载并校验更新包……");
        break;
      case "Progress":
        setDownloadedBytes((current) => current + event.data.chunkLength);
        break;
      case "Finished":
        setStatus("下载校验完成，正在安装并重启……");
        break;
    }
  }

  async function installUpdate() {
    if (!availableUpdate || operation !== "idle") return;
    setOperation("installing");
    setDownloadedBytes(0);
    setTotalBytes(null);

    try {
      await installApplicationUpdate(availableUpdate, onDownloadEvent);
      setOperation("restarting");
      setStatus("更新安装完成，正在重启……");
    } catch (error) {
      setOperation("idle");
      setStatus(`更新失败，当前版本未被替换：${formatIpcError(error)}`);
    }
  }

  const progressValue = totalBytes
    ? Math.min(downloadedBytes, totalBytes)
    : undefined;

  return (
    <section className="workspace-card release-workspace">
      <h2>版本与数据维护</h2>
      {info ? (
        <dl className="metadata-list">
          <div><dt>应用版本</dt><dd>{info.appVersion}</dd></div>
          <div><dt>构建时间</dt><dd>{formatBuildTime(info.buildUnix)}</dd></div>
          <div><dt>法律库版本</dt><dd>{info.legalDatabaseVersion}</dd></div>
          <div><dt>数据范围</dt><dd>{info.legalDataScope}</dd></div>
        </dl>
      ) : versionInfoError ? (
        <p className="notice warning" role="alert">
          版本信息读取失败：{versionInfoError}。请重启应用重试，或导出诊断报告。
        </p>
      ) : (
        <p role="status">正在读取版本信息……</p>
      )}

      <h3>应用更新</h3>
      <div className="button-row">
        <button
          type="button"
          disabled={operation !== "idle"}
          onClick={() => void checkForUpdates()}
        >
          {operation === "checking" ? "正在检查……" : "检查更新"}
        </button>
        {availableUpdate ? (
          <button
            type="button"
            disabled={operation !== "idle"}
            onClick={() => void installUpdate()}
          >
            下载、安装并重启
          </button>
        ) : null}
      </div>
      {availableUpdate ? (
        <dl className="metadata-list">
          <div><dt>当前版本</dt><dd>{availableUpdate.currentVersion}</dd></div>
          <div><dt>可用版本</dt><dd>{availableUpdate.version}</dd></div>
          <div><dt>发布时间</dt><dd>{formatReleaseDate(availableUpdate.date)}</dd></div>
          {availableUpdate.body ? <div><dt>更新说明</dt><dd>{availableUpdate.body}</dd></div> : null}
        </dl>
      ) : null}
      {operation === "installing" ? (
        <div>
          <progress
            aria-label="更新下载进度"
            max={totalBytes ?? undefined}
            value={progressValue}
          />
          {totalBytes ? (
            <span> {Math.min(100, Math.floor((downloadedBytes / totalBytes) * 100))}%</span>
          ) : null}
        </div>
      ) : null}
      <p className="muted">更新包必须通过内置公钥验签；安装完成后应用会立即重启。</p>

      <h3>完整应用加密备份与恢复</h3>
      <p className="muted">
        备份操作已统一迁移到“隐私与本地处理 → 隐私生命周期、映射与加密备份”。
        该入口只使用原生文件对话框处理 <code>.lavbackup</code>，并把用户数据库、加密隐私 bundle、加密案件 Vault、已批准工作区归档与加密 work products 绑定为同一五组件认证备份集；
        五组件会在重启时原子恢复或整体回滚；V2 三组件仅保留读取/恢复兼容，V1 与旧版明文单库恢复均 fail closed。
      </p>

      <h3>隐私安全诊断</h3>
      <p className="muted">通过系统文件对话框选择保存位置；页面不会显示本地位置。</p>
      <button
        type="button"
        disabled={operation !== "idle"}
        onClick={() => void exportDiagnostics()}
      >
        导出诊断报告
      </button>
      <p className="muted">诊断报告只包含排障所需的脱敏运行信息，不记录请求正文、响应正文或案件材料。</p>
      {status ? <p role="status" className="notice">{status}</p> : null}
    </section>
  );
}
