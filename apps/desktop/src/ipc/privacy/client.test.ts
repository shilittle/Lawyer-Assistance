import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  approvePrivacyReview,
  deletePrivacyReview,
  exportApprovedReviewPdf,
  loadLatestPrivacyReview,
  loadPrivacyReview,
  preparePrivacyMaterial,
  inspectLocalMineruQualificationReport,
  getLocalOcrStatus,
  getPrivacyConfig,
  savePrivacyConfig,
} from "./client";
import type { PrivacyConfig } from "./types";

const config: PrivacyConfig = {
  schemaVersion: 1,
  privacyMode: "external_redacted",
  ocr: {
    mode: "auto_local",
    workerPath: "C:/Local/MinerU/mineru-worker.exe",
    modelDirectory: "C:/Local/MinerU/models",
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
  it("uses native-picker workflow commands without accepting a frontend path", async () => {
    await preparePrivacyMaterial({ customTerms: ["内部代号"] });
    await loadPrivacyReview({ redactionId: "red_1" });
    await loadLatestPrivacyReview();
    await approvePrivacyReview({
      redactionId: "red_1",
      expectedSuggestedRedactedSha256: "a".repeat(64),
      editedPages: [{ pageNumber: 1, redactedText: "[姓名1]" }],
      reviewer: "reviewer",
      destination: {
        kind: "verified_local_provider",
        identifier: "local-safe-pdf-export-v1",
      },
      purpose: "local_safe_pdf_export",
      ttlSeconds: 3600,
    });
    await exportApprovedReviewPdf({
      redactionId: "red_1",
      receiptToken: "rct_v1.token",
      approvedPayloadJson: "{\"schemaVersion\":1}",
      destination: {
        kind: "verified_local_provider",
        identifier: "local-safe-pdf-export-v1",
      },
      purpose: "local_safe_pdf_export",
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
      expect.objectContaining({ request: expect.any(Object) }),
    );
    expect(invoke).toHaveBeenNthCalledWith(
      5,
      "export_approved_review_pdf",
      expect.objectContaining({ request: expect.any(Object) }),
    );
    expect(JSON.stringify(invoke.mock.calls)).not.toContain('"path"');
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
});
