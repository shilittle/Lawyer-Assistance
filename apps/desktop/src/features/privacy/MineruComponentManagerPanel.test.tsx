import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { MineruComponentStatus } from "../../ipc/privacy/mineru-component-client";
import type { PrivacyConfigResponse } from "../../ipc/privacy/types";
import { MineruComponentManagerPanelView } from "./MineruComponentManagerPanel";

const snapshot = {
  config: {
    schemaVersion: 1,
    privacyMode: "external_redacted",
    ocr: {
      mode: "auto_local",
      workerPath: "C:\\ProgramData\\Lawyer Assistance\\worker.exe",
      modelDirectory: "C:\\ProgramData\\Lawyer Assistance\\models",
      toolsConfigPath: "C:\\ProgramData\\Lawyer Assistance\\tools.json",
      runtimeExecutablePaths: [],
      device: "cuda:0",
      languages: ["zh", "en"],
      timeoutSeconds: 600,
      maxPages: 100,
      strictOffline: true,
      forbidCloudFallback: true,
      forbidRemoteUpload: true,
      forbidTelemetry: true,
    },
  },
  configValid: true,
  loadError: null,
  enforcementState:
    "local_review_safe_exports_approved_paths_qualification_gated",
  ocrStatus: {
    code: "ready",
    message: "synthetic status",
    workerVersion: "1.2.3",
    modelVersion: "2026.07",
    workerSha256: "a".repeat(64),
    modelManifestSha256: "b".repeat(64),
    workerPresent: true,
    modelDirectoryPresent: true,
    integrityVerified: true,
    networkIsolationVerified: true,
    workerProtocolVersion: "la-mineru-worker-v1",
    workerProtocolIdentitySha256: "c".repeat(64),
    workerHealthEvidenceSha256: "d".repeat(64),
    pythonVersion: "3.12.4",
    mineruVersion: "2.1.0",
    pytorchVersion: "2.6.0",
    cudaRuntimeVersion: "12.6",
    gpuDriverVersion: "560.35",
  },
  qualification: {
    qualificationId: "qual_synthetic",
    qualificationReportId: "qrep_00000000000000000000000000000000",
    qualificationReportSha256: "e".repeat(64),
    syntheticCanaryQualified: true,
    processingChainQualified: true,
    exactWorkerModelMatch: true,
    networkIsolationEnforced: true,
    modelManifestTrustEstablished: true,
    appAutoEnableAuthorized: true,
    productionCaseOcrAuthorized: true,
    expiresAtUnix: 2_000_000_000,
    revoked: false,
    reasonCodes: [],
    selectedCudaDevice: 0,
    selectedGpuMemoryMib: 12_288,
    selectedGpuName: "Synthetic GPU",
  },
  capabilities: {
    localGpuPreferenceConfigurable: true,
    scannedCaseOcrEnabled: true,
    automaticApprovalEnabled: false,
    appAutoOcrEnabled: true,
    remoteOcrFallbackAllowed: false,
    telemetryAllowed: false,
    rawMaterialUploadAllowed: false,
    blockingReasonCodes: [],
  },
} as PrivacyConfigResponse;

const status: MineruComponentStatus = {
  catalogId: "mineru-windows-stable-v1",
  catalogExpiresAtUnix: 2_000_000_000,
  catalogTrusted: true,
  availablePackages: [
    {
      packageId: "mineru-windows-1-2-3",
      componentVersion: "1.2.3",
      mineruVersion: "2.1.0",
      packageSizeBytes: 8_589_934_592,
      packageSha256: "f".repeat(64),
      packageManifestSha256: "1".repeat(64),
      downloadUrl:
        "https://github.com/shilittle/Lawyer-Assistance/releases/download/mineru-components-v1.2.3/lawyer-assistance-mineru-1.2.3-windows-x86_64.laocrpkg",
    },
  ],
  installedVersions: [
    {
      componentVersion: "1.2.3",
      mineruVersion: "2.1.0",
      manifestSha256: "1".repeat(64),
      active: true,
      integrityValid: true,
      lifecycleState: "active",
      reasonCodes: [],
    },
  ],
  activeVersion: "1.2.3",
  activeManifestSha256: "1".repeat(64),
  activeIntegrityValid: true,
  qualificationRecheckRequired: true,
  remoteOcrAllowed: false,
  caseMaterialDownloadedOrUploaded: false,
  reasonCodes: [],
};

describe("MineruComponentManagerPanelView", () => {
  it("renders all evidence, pinned download facts and destructive safeguards", () => {
    const markup = renderToStaticMarkup(
      <MineruComponentManagerPanelView
        snapshot={snapshot}
        status={status}
        operation="idle"
        confirmations={new Set()}
        notice=""
        error=""
        disabled={false}
        onRefresh={vi.fn()}
        onImportCatalog={vi.fn()}
        onOfflineInstall={vi.fn()}
        onDownload={vi.fn()}
        onRollback={vi.fn()}
        onConfirmationChange={vi.fn()}
        onUninstall={vi.fn()}
      />,
    );

    for (const required of [
      "MinerU 安装、证据、升级、回滚与卸载",
      "Python",
      "PyTorch",
      "CUDA runtime / driver",
      "CUDA 可用性",
      "GPU 显存",
      "worker SHA-256",
      "health evidence SHA-256",
      "组件 package manifest SHA-256",
      "模型 manifest SHA-256",
      "最近一次 qualification 结果",
      "当前模式 / 真实案卷批准",
      "GPU cuda:0 (auto_local)",
      "固定 HTTPS 来源",
      "精确大小",
      "包 SHA-256",
      "manifest SHA-256",
      "按上述固定信息下载并安装",
      "Windows Firewall 隔离规则保留",
      "不会降级到云端、SSH 或 HTTP OCR",
    ]) {
      expect(markup).toContain(required);
    }
    expect(markup).toContain(status.availablePackages[0].downloadUrl);
    expect(markup).toContain(status.availablePackages[0].packageSha256);
    expect(markup).not.toContain("removeFirewallRules");
    expect(markup).not.toContain("casePath");
  });

  it("shows an explicit fail-closed OOM warning for insufficient measured VRAM", () => {
    const lowMemory = {
      ...snapshot,
      qualification: {
        ...snapshot.qualification,
        selectedGpuMemoryMib: 4096,
      },
      capabilities: {
        ...snapshot.capabilities,
        scannedCaseOcrEnabled: false,
      },
    } as PrivacyConfigResponse;
    const markup = renderToStaticMarkup(
      <MineruComponentManagerPanelView
        snapshot={lowMemory}
        status={status}
        operation="idle"
        confirmations={new Set()}
        notice=""
        error=""
        disabled={false}
        onRefresh={vi.fn()}
        onImportCatalog={vi.fn()}
        onOfflineInstall={vi.fn()}
        onDownload={vi.fn()}
        onRollback={vi.fn()}
        onConfirmationChange={vi.fn()}
        onUninstall={vi.fn()}
      />,
    );
    expect(markup).toContain("低于 6144 MiB");
    expect(markup).toContain("不得改用云端或远程 OCR");
  });
});
