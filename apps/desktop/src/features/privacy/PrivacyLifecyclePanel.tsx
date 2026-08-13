import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import {
  createPrivacyBackup,
  destroyPrivacyMappingKey,
  exportApplicationBackup,
  exportPrivacyBackupBundle,
  getPrivacyLifecycleStatus,
  importPrivacyBackupBundle,
  revealPrivacyMapping,
  revokePrivacyBackup,
  revokePrivacyMapping,
  rotatePrivacyMappingKey,
  runPrivacyRetentionSweep,
  setPrivacyLegalHold,
  setPrivacyRetentionPolicy,
  stageApplicationRestore,
  stagePrivacyRestore,
  stageV031MigrationRecovery,
  verifyApplicationBackup,
  verifyPrivacyBackup,
} from "../../ipc/privacy/client";
import type {
  ApplicationBackupResponse,
  CleanupReportView,
  LifecycleStatusView,
  MappingKeyView,
  MappingRevisionView,
  RevealMappingResponse,
  StageV031MigrationRecoveryRequest,
  VerifiedBackupView,
} from "../../ipc/privacy/types";
import "./privacy-lifecycle.css";

export const MAPPING_REVEAL_NATIVE_CONFIRMATION_NOTICE = "显示前会弹出系统原生确认窗口；确认后才会在本机单次解密。";
export const REVOKE_MAPPING_CONFIRMATION = "撤销映射";
export const ROTATE_MAPPING_KEY_CONFIRMATION = "轮换映射密钥";
export const DESTROY_MAPPING_KEY_CONFIRMATION = "销毁映射密钥";
export const RUN_RETENTION_CONFIRMATION = "执行到期清理";
export const RESTORE_BACKUP_CONFIRMATION = "恢复隐私备份";
export const RESTORE_APPLICATION_BACKUP_CONFIRMATION = "恢复完整应用备份";
export const V031_MIGRATION_RECOVERY_CONFIRMATION = "恢复到 v0.3.1 并退出当前应用";
export const V031_MIGRATION_RECOVERY_STAGED_NOTICE =
  "受保护的 v0.3.1 migration recovery 请求已安装；应用将受控重启。下一 recovery-only 进程完成恢复后会退出，且不会运行普通初始化。";

const MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60;

type LifecycleOperation =
  | "loading"
  | "idle"
  | "retention"
  | "hold"
  | "reveal"
  | "mapping"
  | "key"
  | "sweep"
  | "backup"
  | "migration-recovery";

interface RetentionDraft {
  reviewRetentionSeconds: string;
  mappingRetentionSeconds: string;
  receiptGraceSeconds: string;
  backupRetentionSeconds: string;
}

export interface ApplicationBackupOutcome {
  action: "export" | "verify" | "restore";
  response: ApplicationBackupResponse;
}

export interface PrivacyLifecyclePanelProps {
  disabled?: boolean;
  onActivityChange?: (active: boolean) => void;
}

// eslint-disable-next-line react-refresh/only-export-components
export function parseRetentionSeconds(
  label: string,
  value: string,
  minimum = 0,
): number {
  const parsed = Number(value);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < minimum ||
    parsed > MAX_RETENTION_SECONDS
  ) {
    throw new Error(
      `${label}必须是 ${minimum}–${MAX_RETENTION_SECONDS} 之间的整数秒。`,
    );
  }
  return parsed;
}

// eslint-disable-next-line react-refresh/only-export-components
export function applicationBackupOutcomeMessage(
  outcome: ApplicationBackupOutcome,
): string {
  const { action, response } = outcome;
  if (response.cancelled) {
    if (action === "export") return "已取消完整应用备份导出；未创建或覆盖文件。";
    if (action === "verify") return "已取消完整应用备份验证；未读取备份内容。";
    return "已取消完整应用备份恢复；未暂存任何恢复内容。";
  }
  if (!response.metadata) {
    return "完整应用备份未返回认证清单，已拒绝显示为成功。";
  }
  if (action === "restore" && !response.restartRequired) {
    return "完整应用恢复未进入重启待处理状态，已拒绝显示为成功。";
  }
  if (action === "export") {
    return "用户数据库、加密隐私 bundle、加密案件 Vault、已批准工作区与加密 work products 五组件已作为同一认证备份集导出并重读验证。";
  }
  if (action === "verify") {
    return "完整应用备份已完成身份、环境、期限、哈希与认证校验。";
  }
  return "用户数据库、加密隐私 bundle、加密案件 Vault、已批准工作区与加密 work products 五组件已作为同一认证备份集暂存；restart_required=true。";
}

export function ApplicationBackupOutcomeView({
  outcome,
}: {
  outcome: ApplicationBackupOutcome | null;
}) {
  if (!outcome) return null;
  const { response } = outcome;
  const metadata = response.metadata;
  return (
    <div className="privacy-application-backup-outcome" data-cancelled={response.cancelled}>
      <p className="privacy-notice" role="status">{applicationBackupOutcomeMessage(outcome)}</p>
      {metadata ? (
        <dl className="privacy-lifecycle-facts">
          <div><dt>完整备份 / 隐私备份绑定</dt><dd><code>{metadata.backupId}</code><br /><code>{metadata.privacyBackupId}</code></dd></div>
          <div><dt>工作区 / 应用 / 用户库 schema</dt><dd><code>{metadata.workspaceInstanceId}</code><br />{metadata.appVersion} / {metadata.userSchemaVersion}</dd></div>
          <div><dt>用户数据库字节 / SHA-256 / chunks</dt><dd>{metadata.userDatabaseBytes}<br /><code>{metadata.userDatabaseSha256}</code><br />{metadata.userDatabaseChunkCount}</dd></div>
          <div><dt>隐私数据库加密组件字节 / SHA-256 / chunks</dt><dd>{metadata.encryptedPrivacyBundleBytes}<br /><code>{metadata.encryptedPrivacyBundleSha256}</code><br />{metadata.privacyBundleChunkCount}</dd></div>
          <div><dt>加密案件 Vault 字节 / SHA-256 / chunks</dt><dd>{metadata.encryptedVaultBundleBytes}<br /><code>{metadata.encryptedVaultBundleSha256}</code><br />{metadata.vaultBundleChunkCount}</dd></div>
          <div><dt>Vault manifest SHA-256</dt><dd><code>{metadata.vaultManifestSha256}</code></dd></div>
          <div><dt>创建 / 到期 / 总分块</dt><dd>{formatTime(metadata.createdAtUnix)} / {formatTime(metadata.expiresAtUnix)} / {metadata.chunkCount}</dd></div>
          <div><dt>五组件认证包 SHA-256</dt><dd><code>{metadata.bundleSha256}</code></dd></div>
        </dl>
      ) : null}
      {response.restartRequired ? <p className="privacy-restart-required"><strong>restart_required=true</strong>：五组件认证备份集仅已暂存；请正常重启应用完成用户数据库、加密隐私 bundle、加密案件 Vault、已批准工作区与加密 work products 的原子安装和启动时复核，任一组件失败将整体回滚。</p> : null}
    </div>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export async function submitV031MigrationRecovery(
  confirmation: string,
  stage: (request: StageV031MigrationRecoveryRequest) => Promise<void>,
): Promise<boolean> {
  if (confirmation !== V031_MIGRATION_RECOVERY_CONFIRMATION) return false;
  await stage({ confirmation });
  return true;
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldReleaseLifecycleBusy(
  succeeded: boolean,
  holdBusyOnSuccess: boolean,
): boolean {
  return !succeeded || !holdBusyOnSuccess;
}

export function V031MigrationRecoveryControl({
  busy,
  confirmation,
  onConfirmationChange,
  onStage,
}: {
  busy: boolean;
  confirmation: string;
  onConfirmationChange: (value: string) => void;
  onStage: () => void;
}) {
  const confirmed = confirmation === V031_MIGRATION_RECOVERY_CONFIRMATION;
  return (
    <section className="privacy-lifecycle-card">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">显式旧态恢复 · apply-and-exit</p>
          <h3>恢复到 v0.3.1 原态五槽</h3>
        </div>
        <span>recovery-only</span>
      </div>
      <p className="privacy-help">
        此操作会先建立 current v0.4 五组件安全备份，再安装受保护恢复请求并受控重启。
        下一 recovery-only 进程会在任何普通 manager、后台任务或 UI 初始化前完成五槽恢复；
        成功后退出当前应用且不运行普通初始化。原态 bundle 不能通过普通恢复入口打开。
      </p>
      <div className="privacy-sensitive-action">
        <label>
          <span>显式恢复前输入：<strong>{V031_MIGRATION_RECOVERY_CONFIRMATION}</strong></span>
          <input
            autoComplete="off"
            disabled={busy}
            value={confirmation}
            onChange={(event) => onConfirmationChange(event.target.value)}
          />
        </label>
        <button
          className="danger"
          disabled={busy || !confirmed}
          type="button"
          onClick={() => {
            if (!busy && confirmed) onStage();
          }}
        >
          安装受保护恢复请求并受控重启
        </button>
      </div>
    </section>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldClearRevealedMapping(
  eventType: "blur" | "pagehide" | "visibilitychange",
  visibilityState: DocumentVisibilityState,
): boolean {
  return eventType !== "visibilitychange" || visibilityState !== "visible";
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
  return "隐私生命周期操作失败。";
}

function formatTime(unix: number | null): string {
  if (unix === null) return "—";
  return new Date(unix * 1000).toLocaleString("zh-CN", { hour12: false });
}

function retentionDraft(status: LifecycleStatusView): RetentionDraft {
  return {
    reviewRetentionSeconds: String(status.retentionPolicy.reviewRetentionSeconds),
    mappingRetentionSeconds: String(status.retentionPolicy.mappingRetentionSeconds),
    receiptGraceSeconds: String(status.retentionPolicy.receiptGraceSeconds),
    backupRetentionSeconds: String(status.retentionPolicy.backupRetentionSeconds),
  };
}

function safeOpaqueId(value: string, prefix: string): string {
  const normalized = value.trim();
  const pattern = new RegExp(`^${prefix}[a-f0-9]{32}$`, "u");
  if (!pattern.test(normalized)) {
    throw new Error(`请输入有效的 ${prefix}… 不透明标识。`);
  }
  return normalized;
}

function StatusFacts({ status }: { status: LifecycleStatusView }) {
  return (
    <dl className="privacy-lifecycle-facts">
      <div>
        <dt>工作区实例</dt>
        <dd><code>{status.workspaceInstanceId}</code></dd>
      </div>
      <div>
        <dt>当前密钥 epoch</dt>
        <dd>{status.keyEpoch}</dd>
      </div>
      <div>
        <dt>清理日志已验证事件</dt>
        <dd>{status.cleanupJournalEvents}</dd>
      </div>
      <div>
        <dt>映射访问审计已验证事件</dt>
        <dd>{status.mappingAccessEvents}</dd>
      </div>
    </dl>
  );
}

export function PrivacyLifecycleSafetyNotice({ erasureDisclosure }: { erasureDisclosure: string }) {
  return (
    <div className="privacy-erasure-warning" role="note">
      <strong>删除语义必须准确</strong>
      <p>
        本功能只声明逻辑删除与密码学删除，不声明 SSD、备份介质或文件系统层面的取证擦除。
        映射明文仅在你输入显式确认短语后单次显示；窗口失焦、页面隐藏或离开页面会立即从界面状态清除。
      </p>
      <code>{erasureDisclosure}</code>
    </div>
  );
}

export function PrivacyLifecyclePanel({
  disabled = false,
  onActivityChange,
}: PrivacyLifecyclePanelProps) {
  const [status, setStatus] = useState<LifecycleStatusView | null>(null);
  const [draft, setDraft] = useState<RetentionDraft | null>(null);
  const [operation, setOperation] = useState<LifecycleOperation>("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [legalHoldRedactionId, setLegalHoldRedactionId] = useState("");
  const [legalHoldEnabled, setLegalHoldEnabled] = useState(true);
  const [selectedMapping, setSelectedMapping] = useState<MappingRevisionView | null>(null);
  const [revokeConfirmation, setRevokeConfirmation] = useState("");
  const [revealed, setRevealed] = useState<RevealMappingResponse | null>(null);
  const [selectedKey, setSelectedKey] = useState<MappingKeyView | null>(null);
  const [rotateConfirmation, setRotateConfirmation] = useState("");
  const [destroyConfirmation, setDestroyConfirmation] = useState("");
  const [sweepConfirmation, setSweepConfirmation] = useState("");
  const [cleanupReport, setCleanupReport] = useState<CleanupReportView | null>(null);
  const [backupId, setBackupId] = useState("");
  const [backup, setBackup] = useState<VerifiedBackupView | null>(null);
  const [restoreConfirmation, setRestoreConfirmation] = useState("");
  const [applicationBackupOutcome, setApplicationBackupOutcome] = useState<ApplicationBackupOutcome | null>(null);
  const [applicationRestoreConfirmation, setApplicationRestoreConfirmation] = useState("");
  const [migrationRecoveryConfirmation, setMigrationRecoveryConfirmation] = useState("");

  const busy = disabled || operation !== "idle";
  const clearReveal = useCallback(() => {
    setRevealed(null);
  }, []);

  const loadStatus = useCallback(async () => {
    const next = await getPrivacyLifecycleStatus({ redactionId: null });
    setStatus(next);
    setDraft(retentionDraft(next));
  }, []);

  useEffect(() => {
    let mounted = true;
    getPrivacyLifecycleStatus({ redactionId: null })
      .then((next) => {
        if (!mounted) return;
        setStatus(next);
        setDraft(retentionDraft(next));
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

  useEffect(() => {
    onActivityChange?.(operation !== "idle" && operation !== "loading");
    return () => onActivityChange?.(false);
  }, [onActivityChange, operation]);

  useEffect(() => {
    const onBlur = () => {
      if (shouldClearRevealedMapping("blur", document.visibilityState)) clearReveal();
    };
    const onPageHide = () => {
      if (shouldClearRevealedMapping("pagehide", document.visibilityState)) clearReveal();
    };
    const onVisibility = () => {
      if (shouldClearRevealedMapping("visibilitychange", document.visibilityState)) {
        clearReveal();
      }
    };
    window.addEventListener("blur", onBlur);
    window.addEventListener("pagehide", onPageHide);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("pagehide", onPageHide);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [clearReveal]);

  const run = useCallback(
    async (
      nextOperation: Exclude<LifecycleOperation, "loading" | "idle">,
      action: () => Promise<void>,
      success: string,
      refresh = true,
      holdBusyOnSuccess = false,
    ) => {
      if (disabled || operation !== "idle") return;
      setOperation(nextOperation);
      setError("");
      setNotice("");
      let succeeded = false;
      try {
        await action();
        if (refresh) await loadStatus();
        setNotice(success);
        succeeded = true;
      } catch (reason: unknown) {
        setError(displayError(reason));
      } finally {
        if (shouldReleaseLifecycleBusy(succeeded, holdBusyOnSuccess)) {
          setOperation("idle");
        }
      }
    },
    [disabled, loadStatus, operation],
  );

  const saveRetention = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!draft) return;
    let request;
    try {
      request = {
        reviewRetentionSeconds: parseRetentionSeconds("复核稿保留期限", draft.reviewRetentionSeconds, 1),
        mappingRetentionSeconds: parseRetentionSeconds("映射保留期限", draft.mappingRetentionSeconds, 1),
        receiptGraceSeconds: parseRetentionSeconds("回执宽限期", draft.receiptGraceSeconds),
        backupRetentionSeconds: parseRetentionSeconds("备份保留期限", draft.backupRetentionSeconds, 1),
      };
    } catch (reason: unknown) {
      setError(displayError(reason));
      return;
    }
    void run(
      "retention",
      async () => { await setPrivacyRetentionPolicy(request); },
      "保留策略已在本机更新并重新绑定后续生命周期操作。",
    );
  };

  const mappingRows = useMemo(
    () => status?.mappingRevisions ?? [],
    [status?.mappingRevisions],
  );

  if (!status || !draft) {
    return (
      <section className="privacy-lifecycle-panel" aria-busy={operation === "loading"}>
        <h2>隐私生命周期、映射与加密备份</h2>
        {error ? <p className="error-text" role="alert">{error}</p> : <p>正在验证本机生命周期状态…</p>}
      </section>
    );
  }

  return (
    <section className="privacy-lifecycle-panel" aria-busy={busy}>
      <header className="privacy-heading">
        <div>
          <p className="eyebrow">本机密钥、保留与恢复边界</p>
          <h2>隐私生命周期、映射与加密备份</h2>
        </div>
        <button disabled={busy} type="button" onClick={() => void run("mapping", async () => undefined, "状态与审计链已重新验证。")}>重新验证</button>
      </header>

      <PrivacyLifecycleSafetyNotice erasureDisclosure={status.erasureDisclosure} />

      <StatusFacts status={status} />

      <form className="privacy-lifecycle-card" onSubmit={saveRetention}>
        <div className="panel-heading">
          <div><p className="eyebrow">策略 revision {status.retentionPolicy.revision}</p><h3>保留期限（秒）</h3></div>
          <span>更新于 {formatTime(status.retentionPolicy.updatedAtUnix)}</span>
        </div>
        <fieldset className="privacy-lifecycle-grid" disabled={busy}>
          {([
            ["reviewRetentionSeconds", "复核稿"],
            ["mappingRetentionSeconds", "敏感映射"],
            ["receiptGraceSeconds", "回执宽限期"],
            ["backupRetentionSeconds", "加密备份"],
          ] as const).map(([field, label]) => (
            <label key={field}><span>{label}</span><input inputMode="numeric" value={draft[field]} onChange={(event) => setDraft({ ...draft, [field]: event.target.value })} /></label>
          ))}
        </fieldset>
        <button disabled={busy} type="submit">保存保留策略</button>
      </form>

      <section className="privacy-lifecycle-card">
        <h3>法律保留</h3>
        <p className="privacy-help">法律保留阻止到期清理，但不授予外发、明文查看或恢复权限。</p>
        <div className="privacy-lifecycle-inline">
          <label><span>redaction_id</span><input disabled={busy} placeholder="red_…" value={legalHoldRedactionId} onChange={(event) => setLegalHoldRedactionId(event.target.value)} /></label>
          <label className="privacy-check"><input checked={legalHoldEnabled} disabled={busy} type="checkbox" onChange={(event) => setLegalHoldEnabled(event.target.checked)} /><span>启用法律保留</span></label>
          <button disabled={busy} type="button" onClick={() => void run("hold", async () => {
            await setPrivacyLegalHold({ redactionId: safeOpaqueId(legalHoldRedactionId, "red_"), enabled: legalHoldEnabled });
          }, legalHoldEnabled ? "法律保留已启用。" : "法律保留已解除。")}>应用</button>
        </div>
        <ul className="privacy-lifecycle-list">
          {status.retentionBindings.map((binding) => <li key={binding.redactionId}><code>{binding.redactionId}</code><span>到期 {formatTime(binding.expiresAtUnix)}</span><strong>{binding.legalHold ? "法律保留中" : "按策略保留"}</strong></li>)}
        </ul>
      </section>

      <section className="privacy-lifecycle-card">
        <div className="panel-heading"><div><p className="eyebrow">仅显示哈希与状态</p><h3>敏感映射历史</h3></div><span>{mappingRows.length} 个 revision</span></div>
        <ul className="privacy-lifecycle-list">
          {mappingRows.map((mapping) => (
            <li className={selectedMapping?.mappingId === mapping.mappingId ? "is-selected" : ""} key={mapping.mappingId}>
              <button disabled={busy} type="button" onClick={() => { clearReveal(); setSelectedMapping(mapping); }}><code>{mapping.mappingId}</code></button>
              <span><code>{mapping.mappingRevisionSha256}</code></span>
              <span>rev {mapping.revision} · key {mapping.keyVersion} · {mapping.revoked ? "已撤销" : `到期 ${formatTime(mapping.expiresAtUnix)}`}</span>
            </li>
          ))}
        </ul>
        {selectedMapping ? (
          <div className="privacy-sensitive-action">
            <p>当前选择：<code>{selectedMapping.mappingId}</code> / <code>{selectedMapping.redactionId}</code></p>
            <p className="privacy-help">{MAPPING_REVEAL_NATIVE_CONFIRMATION_NOTICE}</p>
            <div className="privacy-actions">
              <button disabled={busy || selectedMapping.revoked} type="button" onClick={() => void run("reveal", async () => {
                const response = await revealPrivacyMapping({ mappingId: selectedMapping.mappingId, redactionId: selectedMapping.redactionId });
                setRevealed(response);
              }, "映射已单次显示；离开或隐藏页面将立即清除。", false)}>单次显示映射</button>
              <button disabled={revealed === null} type="button" onClick={clearReveal}>立即隐藏</button>
            </div>            {revealed ? <div className="privacy-revealed-mapping" role="region" aria-label="单次显示的敏感映射"><strong>敏感内容（不可复制到外部）</strong><dl>{revealed.entries.map((entry) => <div key={entry.alias}><dt>{entry.alias}</dt><dd>{entry.sensitiveValue}</dd></div>)}</dl></div> : null}
            <label><span>撤销前输入：<strong>{REVOKE_MAPPING_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={revokeConfirmation} onChange={(event) => setRevokeConfirmation(event.target.value)} /></label>
            <button className="danger" disabled={busy || revokeConfirmation !== REVOKE_MAPPING_CONFIRMATION || selectedMapping.revoked} type="button" onClick={() => void run("mapping", async () => {
              clearReveal();
              await revokePrivacyMapping({ mappingId: selectedMapping.mappingId, confirmation: revokeConfirmation });
              setRevokeConfirmation("");
            }, "映射已撤销；该操作不声称取证擦除。")}>撤销映射</button>
          </div>
        ) : null}
      </section>

      <section className="privacy-lifecycle-card">
        <h3>映射密钥</h3>
        <ul className="privacy-lifecycle-list">
          {status.mappingKeys.map((key) => <li className={selectedKey?.keyVersion === key.keyVersion ? "is-selected" : ""} key={key.keyVersion}><button disabled={busy} type="button" onClick={() => setSelectedKey(key)}>版本 {key.keyVersion}</button><code>{key.protectedKeySha256}</code><strong>{key.state}</strong></li>)}
        </ul>
        <div className="privacy-sensitive-action">
          <label><span>轮换前输入：<strong>{ROTATE_MAPPING_KEY_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={rotateConfirmation} onChange={(event) => setRotateConfirmation(event.target.value)} /></label>
          <button disabled={busy || rotateConfirmation !== ROTATE_MAPPING_KEY_CONFIRMATION} type="button" onClick={() => void run("key", async () => {
            await rotatePrivacyMappingKey({ confirmation: rotateConfirmation });
            setRotateConfirmation("");
          }, "已创建新的当前映射密钥版本。")}>轮换当前密钥</button>
          {selectedKey ? <><label><span>销毁版本 {selectedKey.keyVersion} 前输入：<strong>{DESTROY_MAPPING_KEY_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={destroyConfirmation} onChange={(event) => setDestroyConfirmation(event.target.value)} /></label><button className="danger" disabled={busy || destroyConfirmation !== DESTROY_MAPPING_KEY_CONFIRMATION || selectedKey.state === "destroyed"} type="button" onClick={() => void run("key", async () => {
            await destroyPrivacyMappingKey({ keyVersion: selectedKey.keyVersion, expectedProtectedKeySha256: selectedKey.protectedKeySha256, confirmation: destroyConfirmation });
            setDestroyConfirmation("");
          }, "映射密钥已撤销并执行密码学销毁；不声称介质取证擦除。")}>销毁所选密钥</button></> : null}
        </div>
      </section>

      <section className="privacy-lifecycle-card">
        <h3>到期清理</h3>
        <label><span>执行前输入：<strong>{RUN_RETENTION_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={sweepConfirmation} onChange={(event) => setSweepConfirmation(event.target.value)} /></label>
        <button className="danger" disabled={busy || sweepConfirmation !== RUN_RETENTION_CONFIRMATION} type="button" onClick={() => void run("sweep", async () => {
          const report = await runPrivacyRetentionSweep({ confirmation: sweepConfirmation });
          setCleanupReport(report);
          setSweepConfirmation("");
        }, "到期清理完成；哈希链日志已重新验证。")}>执行到期清理</button>
        {cleanupReport ? <dl className="privacy-lifecycle-facts"><div><dt>清理 ID</dt><dd><code>{cleanupReport.cleanupId}</code></dd></div><div><dt>候选 / 移除</dt><dd>{cleanupReport.candidates} / {cleanupReport.removed}</dd></div><div><dt>销毁密钥</dt><dd>{cleanupReport.keysDestroyed}</dd></div><div><dt>事件哈希</dt><dd><code>{cleanupReport.eventHash}</code></dd></div></dl> : null}
      </section>

      <section className="privacy-lifecycle-card">
        <div className="panel-heading"><div><p className="eyebrow">用户数据库 + 加密隐私 bundle + 加密案件 Vault + 已批准工作区 + 加密 work products · 单一认证备份集</p><h3>完整应用加密备份</h3></div><span>.lavbackup V3</span></div>
        <p className="privacy-help">导出、验证与恢复选取均只使用本机原生文件对话框，前端不发送或接收文件路径。V3 完整备份把五个组件绑定到同一备份 ID、隐私备份 ID、工作区、应用版本、schema、期限、清单和哈希；V2 三组件只保留读取/恢复兼容，V1 与旧版明文或单库恢复均 fail closed。</p>
        <div className="privacy-actions">
          <button disabled={busy} type="button" onClick={() => void run("backup", async () => {
            const response = await exportApplicationBackup();
            const outcome = { action: "export", response } as const;
            setApplicationBackupOutcome(outcome);
            if (!response.cancelled && !response.metadata) throw new Error(applicationBackupOutcomeMessage(outcome));
          }, "", false)}>导出完整加密备份</button>
          <button disabled={busy} type="button" onClick={() => void run("backup", async () => {
            const response = await verifyApplicationBackup();
            const outcome = { action: "verify", response } as const;
            setApplicationBackupOutcome(outcome);
            if (!response.cancelled && !response.metadata) throw new Error(applicationBackupOutcomeMessage(outcome));
          }, "", false)}>选择并验证完整备份</button>
        </div>
        <div className="privacy-sensitive-action">
          <label><span>五组件恢复前输入：<strong>{RESTORE_APPLICATION_BACKUP_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={applicationRestoreConfirmation} onChange={(event) => setApplicationRestoreConfirmation(event.target.value)} /></label>
          <button className="danger" disabled={busy || applicationRestoreConfirmation !== RESTORE_APPLICATION_BACKUP_CONFIRMATION} type="button" onClick={() => void run("backup", async () => {
            try {
              const response = await stageApplicationRestore({ confirmation: applicationRestoreConfirmation });
              const outcome = { action: "restore", response } as const;
              setApplicationBackupOutcome(outcome);
              if (!response.cancelled && (!response.metadata || !response.restartRequired)) throw new Error(applicationBackupOutcomeMessage(outcome));
            } finally {
              setApplicationRestoreConfirmation("");
            }
          }, "", false)}>选择完整备份并暂存五组件恢复</button>
          <p className="privacy-help">暂存不会热覆盖当前数据。只有 <code>restart_required=true</code> 才表示五组件认证恢复集已准备就绪；应用重启时再次验证并原子安装用户数据库、加密隐私 bundle、加密案件 Vault、已批准工作区与加密 work products，任一组件失败即整体回滚。</p>
        </div>
        <ApplicationBackupOutcomeView outcome={applicationBackupOutcome} />
      </section>

      <V031MigrationRecoveryControl
        busy={busy}
        confirmation={migrationRecoveryConfirmation}
        onConfirmationChange={setMigrationRecoveryConfirmation}
        onStage={() => {
          if (
            busy ||
            migrationRecoveryConfirmation !== V031_MIGRATION_RECOVERY_CONFIRMATION
          ) {
            return;
          }
          void run(
            "migration-recovery",
            async () => {
              try {
                await submitV031MigrationRecovery(
                  migrationRecoveryConfirmation,
                  stageV031MigrationRecovery,
                );
              } finally {
                setMigrationRecoveryConfirmation("");
              }
            },
            V031_MIGRATION_RECOVERY_STAGED_NOTICE,
            false,
            true,
          );
        }}
      />

      <section className="privacy-lifecycle-card">
        <div className="panel-heading"><div><p className="eyebrow">DPAPI 当前用户 + 认证加密</p><h3>隐私库独立备份与重启恢复</h3></div><span>.lavprivacy</span></div>
        <p className="privacy-help">文件路径由本机对话框选择，前端不接收路径。UNC、映射网络盘、链接、reparse point、云端占位、硬链接与覆盖写入均由后端拒绝；保存后会重新读取 SHA-256。</p>
        <div className="privacy-actions">
          <button disabled={busy} type="button" onClick={() => void run("backup", async () => {
            const created = await createPrivacyBackup();
            setBackup(created);
            setBackupId(created.backupId);
          }, "已创建并验证本机加密备份。", false)}>创建备份</button>
          <button disabled={busy} type="button" onClick={() => void run("backup", async () => {
            const imported = await importPrivacyBackupBundle();
            if (imported.backup) {
              setBackup(imported.backup);
              setBackupId(imported.backup.backupId);
            }
          }, "加密备份包已导入并完成身份、签名、哈希与环境绑定验证。", false)}>从 .lavprivacy 导入</button>
        </div>
        <label><span>backup_id</span><input disabled={busy} placeholder="bkp_…" value={backupId} onChange={(event) => setBackupId(event.target.value)} /></label>
        <div className="privacy-actions">
          <button disabled={busy || !backupId} type="button" onClick={() => void run("backup", async () => {
            const verified = await verifyPrivacyBackup({ backupId: safeOpaqueId(backupId, "bkp_") });
            setBackup(verified);
          }, "备份已重新验证。", false)}>验证</button>
          <button disabled={busy || !backupId} type="button" onClick={() => void run("backup", async () => {
            await exportPrivacyBackupBundle({ backupId: safeOpaqueId(backupId, "bkp_") });
          }, "加密备份包已使用 create-new 保存并通过重读哈希验证。", false)}>导出 .lavprivacy</button>
          <button className="danger" disabled={busy || !backupId} type="button" onClick={() => void run("backup", async () => {
            await revokePrivacyBackup({ backupId: safeOpaqueId(backupId, "bkp_") });
            setBackup(null);
          }, "备份已撤销，后续验证和恢复将 fail closed。", false)}>撤销备份</button>
        </div>
        {backup ? <dl className="privacy-lifecycle-facts"><div><dt>备份 ID</dt><dd><code>{backup.backupId}</code></dd></div><div><dt>创建 / 到期</dt><dd>{formatTime(backup.createdAtUnix)} / {formatTime(backup.expiresAtUnix)}</dd></div><div><dt>数据库 SHA-256</dt><dd><code>{backup.databaseSha256}</code></dd></div><div><dt>信封 SHA-256</dt><dd><code>{backup.envelopeSha256}</code></dd></div></dl> : null}
        <div className="privacy-sensitive-action">
          <label><span>恢复前输入：<strong>{RESTORE_BACKUP_CONFIRMATION}</strong></span><input autoComplete="off" disabled={busy} value={restoreConfirmation} onChange={(event) => setRestoreConfirmation(event.target.value)} /></label>
          <button className="danger" disabled={busy || !backupId || restoreConfirmation !== RESTORE_BACKUP_CONFIRMATION} type="button" onClick={() => void run("backup", async () => {
            const staged = await stagePrivacyRestore({ backupId: safeOpaqueId(backupId, "bkp_"), confirmation: restoreConfirmation });
            setBackup(staged);
            setRestoreConfirmation("");
          }, "恢复已安全暂存并等待重启；restart_required=true。", false)}>暂存恢复</button>
          {backup?.restartRequired ? <p className="privacy-restart-required" role="status"><strong>restart_required=true</strong>：请正常重启应用完成原子安装与启动时复核；失败将回滚。</p> : null}
        </div>
      </section>

      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="privacy-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}
