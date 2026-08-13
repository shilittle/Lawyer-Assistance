import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  approvePrivacyReview,
  deletePrivacyReview,
  discoverLocalMineru,
  exportApprovedPrivacyReview,
  loadLatestPrivacyReview,
  loadPrivacyReview,
  preparePrivacyMaterial,
  inspectLocalMineruQualificationReport,
  getLocalOcrStatus,
  getPrivacyConfig,
  savePrivacyConfig,
  stageV031MigrationRecovery,
} from "./client";
import type { PrivacyConfig } from "./types";

const config: PrivacyConfig = {
  schemaVersion: 1,
  privacyMode: "external_redacted",
  ocr: {
    mode: "auto_local",
    workerPath: "C:/Local/MinerU/mineru-worker.exe",
    modelDirectory: "C:/Local/MinerU/models",
    toolsConfigPath: "C:/Local/MinerU/magic-pdf.json",
    runtimeExecutablePaths: ["C:/Local/MinerU/mineru-worker.exe"],
    device: "cuda:0",
    languages: ["zh", "en"],
    timeoutSeconds: 300,
    maxPages: 200,
    strictOffline: true,
    forbidCloudFallback: true,
    forbidRemoteUpload: true,
    forbidTelemetry: true,
  },
};

describe("privacy IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses exact read and local status command names", async () => {
    await getPrivacyConfig();
    await getLocalOcrStatus();

    expect(invoke).toHaveBeenNthCalledWith(1, "get_privacy_config");
    expect(invoke).toHaveBeenNthCalledWith(2, "get_local_ocr_status");
  });

  it("prepares privacy material without sending a case id", async () => {
    await preparePrivacyMaterial({ customTerms: ["内部代号"] });

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("prepare_privacy_material", {
      request: { customTerms: ["内部代号"] },
    });
  });

  it("discovers local MinerU through a parameter-free command", async () => {
    await discoverLocalMineru();

    expect(invoke.mock.calls[0]).toEqual(["discover_local_mineru"]);
    const wire = JSON.stringify(invoke.mock.calls[0]);
    expect(wire).not.toContain("http://");
    expect(wire).not.toContain("https://");
    expect(wire).not.toContain("workerPath");
    expect(wire).not.toContain("modelDirectory");
    expect(wire).not.toContain("toolsConfigPath");
    expect(wire).not.toContain("userInput");
  });
  it("saves a closed strict configuration without a raw-cloud override", async () => {
    await savePrivacyConfig({ config });

    expect(invoke).toHaveBeenCalledWith("save_privacy_config", {
      request: { config },
    });
    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).toContain('"forbidCloudFallback":true');
    expect(payload).toContain('"strictOffline":true');
    expect(payload).toContain('"forbidRemoteUpload":true');
    expect(payload).toContain('"forbidTelemetry":true');
    expect(payload).not.toContain("allowRawCloud");
    expect(payload).not.toContain("cloudFallbackUrl");
    expect(payload).not.toContain("telemetryEndpoint");
    expect(payload).not.toContain("remoteUploadUrl");
  });
  it("uses native-picker workflow commands without accepting paths or frontend export authority", async () => {
    await preparePrivacyMaterial({ customTerms: ["内部代号"] });
    await loadPrivacyReview({ redactionId: "red_1" });
    await loadLatestPrivacyReview();
    await approvePrivacyReview({
      redactionId: "red_1",
      expectedRiskRevision: 4,
      expectedSuggestedRedactedSha256: "a".repeat(64),
      editedPages: [{ pageNumber: 1, redactedText: "[姓名1]" }],
      reviewer: "reviewer",
      destination: {
        kind: "verified_local_provider",
        identifier: "local-safe-docx-export-v1",
      },
      purpose: "local_safe_docx_export",
      ttlSeconds: 3600,
    });
    await exportApprovedPrivacyReview({
      redactionId: "red_1",
      format: "docx",
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "prepare_privacy_material", {
      request: { customTerms: ["内部代号"] },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "load_privacy_review", {
      request: { redactionId: "red_1" },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "load_latest_privacy_review");
    expect(invoke).toHaveBeenNthCalledWith(
      4,
      "approve_privacy_review",
      expect.objectContaining({
        request: expect.objectContaining({
          expectedRiskRevision: 4,
        }),
      }),
    );
    expect(invoke).toHaveBeenNthCalledWith(5, "export_approved_privacy_review", {
      request: { redactionId: "red_1", format: "docx" },
    });
    const exportWire = JSON.stringify(invoke.mock.calls[4]);
    expect(exportWire).not.toContain("receiptToken");
    expect(exportWire).not.toContain("approvedPayloadJson");
    expect(exportWire).not.toContain("destination");
    expect(exportWire).not.toContain("purpose");
    expect(exportWire).not.toContain("path");
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("case/raw.pdf");
  });

  it("binds local review deletion to the exact redaction and immutable hashes", async () => {
    await deletePrivacyReview({
      redactionId: "red_1",
      expectedSourceSha256: "a".repeat(64),
      expectedExtractionSha256: "b".repeat(64),
    });

    expect(invoke).toHaveBeenCalledWith("delete_privacy_review", {
      request: {
        redactionId: "red_1",
        expectedSourceSha256: "a".repeat(64),
        expectedExtractionSha256: "b".repeat(64),
      },
    });
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("receiptToken");
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("originalText");
  });

  it("inspects a local MinerU qualification report without passing case paths", async () => {
    await inspectLocalMineruQualificationReport({
      reportJson: "{\"schemaVersion\":1,\"scope\":\"fixed_synthetic_canary_only\"}",
    });

    expect(invoke).toHaveBeenCalledWith(
      "inspect_local_mineru_qualification_report",
      {
        request: {
          reportJson: "{\"schemaVersion\":1,\"scope\":\"fixed_synthetic_canary_only\"}",
        },
      },
    );
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("case/raw.pdf");
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("workerPath");
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("modelDirectory");
  });

  it("stages v0.3.1 migration recovery with only the exact confirmation", async () => {
    const confirmation = "恢复到 v0.3.1 并退出当前应用";

    await stageV031MigrationRecovery({ confirmation });

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("stage_v031_migration_recovery", {
      request: { confirmation },
    });
  });
});
