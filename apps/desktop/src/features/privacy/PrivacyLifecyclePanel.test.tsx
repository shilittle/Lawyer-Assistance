import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  ApplicationBackupOutcomeView,
  DESTROY_MAPPING_KEY_CONFIRMATION,
  PrivacyLifecycleSafetyNotice,
  RESTORE_APPLICATION_BACKUP_CONFIRMATION,
  RESTORE_BACKUP_CONFIRMATION,
  MAPPING_REVEAL_NATIVE_CONFIRMATION_NOTICE,
  REVOKE_MAPPING_CONFIRMATION,
  ROTATE_MAPPING_KEY_CONFIRMATION,
  RUN_RETENTION_CONFIRMATION,
  V031_MIGRATION_RECOVERY_CONFIRMATION,
  V031_MIGRATION_RECOVERY_STAGED_NOTICE,
  V031MigrationRecoveryControl,
  applicationBackupOutcomeMessage,
  parseRetentionSeconds,
  shouldClearRevealedMapping,
  shouldReleaseLifecycleBusy,
  submitV031MigrationRecovery,
} from "./PrivacyLifecyclePanel";

describe("PrivacyLifecyclePanel safety boundaries", () => {
  it("states logical and cryptographic deletion without claiming forensic wiping", () => {
    const markup = renderToStaticMarkup(
      <PrivacyLifecycleSafetyNotice
        erasureDisclosure="logical_and_cryptographic_erasure_only_not_forensic_media_wipe"
      />,
    );
    expect(markup).toContain("只声明逻辑删除与密码学删除");
    expect(markup).toContain("不声明 SSD、备份介质或文件系统层面的取证擦除");
    expect(markup).toContain("窗口失焦、页面隐藏或离开页面会立即从界面状态清除");
    expect(markup).toContain("not_forensic_media_wipe");
  });

  it("clears a revealed mapping on every boundary event except visible visibilitychange", () => {
    expect(shouldClearRevealedMapping("blur", "visible")).toBe(true);
    expect(shouldClearRevealedMapping("pagehide", "visible")).toBe(true);
    expect(shouldClearRevealedMapping("visibilitychange", "hidden")).toBe(true);
    expect(shouldClearRevealedMapping("visibilitychange", "visible")).toBe(false);
  });

  it("states that mapping reveal is authorized by a native system dialog", () => {
    expect(MAPPING_REVEAL_NATIVE_CONFIRMATION_NOTICE).toContain("系统原生确认窗口");
    expect(MAPPING_REVEAL_NATIVE_CONFIRMATION_NOTICE).toContain("单次解密");
  });

  it("requires exact backend confirmation phrases for destructive actions", () => {
    expect([
      REVOKE_MAPPING_CONFIRMATION,
      ROTATE_MAPPING_KEY_CONFIRMATION,
      DESTROY_MAPPING_KEY_CONFIRMATION,
      RUN_RETENTION_CONFIRMATION,
      RESTORE_BACKUP_CONFIRMATION,
      RESTORE_APPLICATION_BACKUP_CONFIRMATION,
      V031_MIGRATION_RECOVERY_CONFIRMATION,
    ]).toEqual([
      "撤销映射",
      "轮换映射密钥",
      "销毁映射密钥",
      "执行到期清理",
      "恢复隐私备份",
      "恢复完整应用备份",
      "恢复到 v0.3.1 并退出当前应用",
    ]);
  });

  it("does not stage migration recovery when the confirmation is not exact", async () => {
    const stage = vi.fn(async () => undefined);

    await expect(
      submitV031MigrationRecovery("恢复到 v0.3.1", stage),
    ).resolves.toBe(false);

    expect(stage).not.toHaveBeenCalled();
  });

  it("stages only the exact confirmation and states the recovery-only sequence", async () => {
    const stage = vi.fn(async () => undefined);

    await expect(
      submitV031MigrationRecovery(V031_MIGRATION_RECOVERY_CONFIRMATION, stage),
    ).resolves.toBe(true);
    expect(stage).toHaveBeenCalledWith({
      confirmation: V031_MIGRATION_RECOVERY_CONFIRMATION,
    });

    const markup = renderToStaticMarkup(
      <V031MigrationRecoveryControl
        busy={false}
        confirmation={V031_MIGRATION_RECOVERY_CONFIRMATION}
        onConfirmationChange={() => undefined}
        onStage={() => undefined}
      />,
    );
    expect(markup).toContain("先建立 current v0.4 五组件安全备份");
    expect(markup).toContain("安装受保护恢复请求并受控重启");
    expect(markup).toContain("下一 recovery-only 进程");
    expect(markup).toContain("退出当前应用且不运行普通初始化");
    expect(V031_MIGRATION_RECOVERY_STAGED_NOTICE).toContain("受保护的 v0.3.1 migration recovery 请求已安装");
    expect(V031_MIGRATION_RECOVERY_STAGED_NOTICE).toContain("不会运行普通初始化");
  });

  it("keeps the recovery confirmation and action disabled while busy", () => {
    const markup = renderToStaticMarkup(
      <V031MigrationRecoveryControl
        busy
        confirmation={V031_MIGRATION_RECOVERY_CONFIRMATION}
        onConfirmationChange={() => undefined}
        onStage={() => undefined}
      />,
    );

    expect(markup.match(/disabled=""/gu)).toHaveLength(2);
    expect(markup).toContain("安装受保护恢复请求并受控重启");
  });

  it("keeps the lifecycle busy only after a successful terminal recovery stage", () => {
    expect(shouldReleaseLifecycleBusy(true, true)).toBe(false);
    expect(shouldReleaseLifecycleBusy(false, true)).toBe(true);
    expect(shouldReleaseLifecycleBusy(true, false)).toBe(true);
  });

  it("accepts only bounded integer retention seconds", () => {
    expect(parseRetentionSeconds("复核稿", "86400")).toBe(86400);
    expect(parseRetentionSeconds("回执宽限期", "0")).toBe(0);
    expect(parseRetentionSeconds("复核稿", "1", 1)).toBe(1);
    expect(() => parseRetentionSeconds("复核稿", "0", 1)).toThrow("1–");
    expect(() => parseRetentionSeconds("复核稿", "-1")).toThrow("0–");
    expect(() => parseRetentionSeconds("复核稿", "1.5")).toThrow("整数秒");
    expect(() => parseRetentionSeconds("复核稿", String(11 * 365 * 24 * 60 * 60))).toThrow("0–");
  });

  it("renders the authenticated user/privacy/Vault set and restart requirement", () => {
    const outcome = {
      action: "restore" as const,
      response: {
        cancelled: false,
        restartRequired: true,
        metadata: {
          backupId: `appbkp_${"a".repeat(32)}`,
          privacyBackupId: `bkp_${"b".repeat(32)}`,
          workspaceInstanceId: "workspace-test",
          appVersion: "1.2.3",
          userSchemaVersion: 7,
          createdAtUnix: 1_700_000_000,
          expiresAtUnix: 1_700_086_400,
          userDatabaseBytes: 1024,
          userDatabaseSha256: "c".repeat(64),
          encryptedPrivacyBundleBytes: 2048,
          encryptedPrivacyBundleSha256: "d".repeat(64),
          encryptedVaultBundleBytes: 4096,
          encryptedVaultBundleSha256: "f".repeat(64),
          vaultManifestSha256: "9".repeat(64),
          userDatabaseChunkCount: 1,
          privacyBundleChunkCount: 1,
          vaultBundleChunkCount: 1,
          chunkCount: 3,
          bundleSha256: "e".repeat(64),
        },
      },
    };
    const markup = renderToStaticMarkup(
      <ApplicationBackupOutcomeView outcome={outcome} />,
    );
    expect(markup).toContain("完整备份 / 隐私备份绑定");
    expect(markup).toContain(outcome.response.metadata.backupId);
    expect(markup).toContain(outcome.response.metadata.privacyBackupId);
    expect(markup).toContain("用户数据库字节 / SHA-256 / chunks");
    expect(markup).toContain("隐私数据库加密组件字节 / SHA-256 / chunks");
    expect(markup).toContain("加密案件 Vault 字节 / SHA-256 / chunks");
    expect(markup).toContain("Vault manifest SHA-256");
    expect(markup).toContain(outcome.response.metadata.encryptedVaultBundleSha256);
    expect(markup).toContain(outcome.response.metadata.vaultManifestSha256);
    expect(markup).toContain("五组件认证包 SHA-256");
    expect(markup).toContain("restart_required=true");
    expect(markup).toContain("原子安装");
  });

  it("shows native-dialog cancellation without claiming backup or restore success", () => {
    const outcome = {
      action: "restore" as const,
      response: {
        cancelled: true,
        metadata: null,
        restartRequired: false,
      },
    };
    const markup = renderToStaticMarkup(
      <ApplicationBackupOutcomeView outcome={outcome} />,
    );
    expect(applicationBackupOutcomeMessage(outcome)).toBe(
      "已取消完整应用备份恢复；未暂存任何恢复内容。",
    );
    expect(markup).toContain('data-cancelled="true"');
    expect(markup).toContain("已取消完整应用备份恢复");
    expect(markup).not.toContain("restart_required=true");
    expect(markup).not.toContain("成对包 SHA-256");
  });
});
