import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

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
  verifyApplicationBackup,
  verifyPrivacyBackup,
} from "./client";

describe("privacy lifecycle IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses exact status, retention and legal-hold command contracts", async () => {
    await getPrivacyLifecycleStatus({ redactionId: null });
    await setPrivacyRetentionPolicy({
      reviewRetentionSeconds: 10,
      mappingRetentionSeconds: 20,
      receiptGraceSeconds: 30,
      backupRetentionSeconds: 40,
    });
    await setPrivacyLegalHold({ redactionId: `red_${"a".repeat(32)}`, enabled: true });

    expect(invoke).toHaveBeenNthCalledWith(1, "get_privacy_lifecycle_status", {
      request: { redactionId: null },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "set_privacy_retention_policy", {
      request: {
        reviewRetentionSeconds: 10,
        mappingRetentionSeconds: 20,
        receiptGraceSeconds: 30,
        backupRetentionSeconds: 40,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "set_privacy_legal_hold", {
      request: { redactionId: `red_${"a".repeat(32)}`, enabled: true },
    });
  });

  it("keeps reveal confirmation native while binding destructive mapping actions", async () => {
    await revealPrivacyMapping({
      mappingId: `map_${"b".repeat(32)}`,
      redactionId: `red_${"a".repeat(32)}`,
    });
    await revokePrivacyMapping({
      mappingId: `map_${"b".repeat(32)}`,
      confirmation: "撤销映射",
    });
    await rotatePrivacyMappingKey({ confirmation: "轮换映射密钥" });
    await destroyPrivacyMappingKey({
      keyVersion: 7,
      expectedProtectedKeySha256: "c".repeat(64),
      confirmation: "销毁映射密钥",
    });
    await runPrivacyRetentionSweep({ confirmation: "执行到期清理" });

    expect(invoke).toHaveBeenNthCalledWith(1, "reveal_privacy_mapping", {
      request: {
        mappingId: "map_" + "b".repeat(32),
        redactionId: "red_" + "a".repeat(32),
      },
    });
    expect(JSON.stringify(invoke.mock.calls[0])).not.toContain("confirmation");
    expect(invoke.mock.calls.map(([name]) => name)).toEqual([
      "reveal_privacy_mapping",
      "revoke_privacy_mapping",
      "rotate_privacy_mapping_key",
      "destroy_privacy_mapping_key",
      "run_privacy_retention_sweep",
    ]);
    const wire = JSON.stringify(invoke.mock.calls);
    expect(wire).not.toContain("receiptToken");
    expect(wire).not.toContain("approvedPayloadJson");
    expect(wire).not.toContain("path");
    expect(wire).not.toContain("sensitiveValue");
  });

  it("uses native file-dialog backup commands with no frontend path", async () => {
    const backupId = `bkp_${"d".repeat(32)}`;
    await createPrivacyBackup();
    await verifyPrivacyBackup({ backupId });
    await exportPrivacyBackupBundle({ backupId });
    await importPrivacyBackupBundle();
    await revokePrivacyBackup({ backupId });
    await stagePrivacyRestore({ backupId, confirmation: "恢复隐私备份" });

    expect(invoke.mock.calls.map(([name]) => name)).toEqual([
      "create_privacy_backup",
      "verify_privacy_backup",
      "export_privacy_backup_bundle",
      "import_privacy_backup_bundle",
      "revoke_privacy_backup",
      "stage_privacy_restore",
    ]);
    const wire = JSON.stringify(invoke.mock.calls);
    expect(wire).not.toContain("C:/");
    expect(wire).not.toContain("\\\\server");
    expect(wire).not.toContain('"path"');
    expect(wire).not.toContain("backupKey");
  });

  it("uses native-dialog paired application backup commands without paths or database bytes", async () => {
    await exportApplicationBackup();
    await verifyApplicationBackup();
    await stageApplicationRestore({ confirmation: "恢复完整应用备份" });

    expect(invoke.mock.calls).toEqual([
      ["export_application_backup"],
      ["verify_application_backup"],
      [
        "stage_application_restore",
        { request: { confirmation: "恢复完整应用备份" } },
      ],
    ]);
    const wire = JSON.stringify(invoke.mock.calls);
    expect(wire).not.toContain('"path"');
    expect(wire).not.toContain("fileName");
    expect(wire).not.toContain("userDatabase");
    expect(wire).not.toContain("privacyDatabase");
    expect(wire).not.toContain("backupKey");
  });
});
