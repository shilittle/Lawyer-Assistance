import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  LocalMineruDiscoveryResult,
  PrivacyConfig,
  PrivacyConfigResponse,
} from "../../../ipc/privacy/types";
import {
  LocalProcessingWorkspaceView,
  applyLocalMineruDiscoveryToDraft,
  localProcessingComponentIsDisabled,
  localProcessingConfigIsDisabled,
  localProcessingMutationIsActive,
  localProcessingQualificationIsDisabled,
  privacyConfigDraftIsDirty,
  privacyConfigToDraft,
  privacyDraftToConfig,
} from "./LocalProcessingWorkspace";

const config: PrivacyConfig = {
  schemaVersion: 1,
  privacyMode: "external_redacted",
  ocr: {
    mode: "force_local",
    workerPath: "C:/Local/MinerU/mineru-worker.exe",
    modelDirectory: "C:/Local/MinerU/models",
    toolsConfigPath: "C:/Local/MinerU/tools.json",
    runtimeExecutablePaths: ["C:/Local/MinerU/runtime/python.exe"],
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

const response: PrivacyConfigResponse = {
  config,
  configValid: true,
  loadError: null,
  enforcementState: "local_review_safe_exports_approved_paths_qualification_gated",
  ocrStatus: {
    code: "configured_unverified",
    message: "本地文件已配置并可读取；尚未执行实机验证。",
    workerVersion: "3.4.3-local",
    modelVersion: "model-2026-07",
    workerSha256: "a".repeat(64),
    modelManifestSha256: "b".repeat(64),
    workerPresent: true,
    modelDirectoryPresent: true,
    integrityVerified: false,
    networkIsolationVerified: false,
  },
  qualification: {
    qualificationId: null,
    qualificationReportId: null,
    qualificationReportSha256: null,
    syntheticCanaryQualified: false,
    processingChainQualified: false,
    exactWorkerModelMatch: false,
    networkIsolationEnforced: false,
    modelManifestTrustEstablished: false,
    appAutoEnableAuthorized: false,
    productionCaseOcrAuthorized: false,
    expiresAtUnix: null,
    revoked: false,
    reasonCodes: ["qualification_missing"],
  },
  capabilities: {
    localGpuPreferenceConfigurable: true,
    scannedCaseOcrEnabled: false,
    automaticApprovalEnabled: false,
    appAutoOcrEnabled: false,
    remoteOcrFallbackAllowed: false,
    telemetryAllowed: false,
    rawMaterialUploadAllowed: false,
    blockingReasonCodes: [
      "network_isolation_not_enforced",
      "model_manifest_trust_not_established",
      "app_auto_enable_not_authorized",
      "production_case_ocr_not_authorized",
      "approved_case_workspace_profile_not_qualified",
    ],
  },
};

describe("LocalProcessingWorkspace configuration", () => {
  it("keeps configuration, component, and qualification operations mutually exclusive", () => {
    expect(localProcessingConfigIsDisabled("idle", false, false)).toBe(false);
    expect(localProcessingConfigIsDisabled("idle", true, false)).toBe(true);
    expect(localProcessingConfigIsDisabled("idle", false, true)).toBe(true);
    expect(localProcessingComponentIsDisabled(false, "idle", false)).toBe(
      false,
    );
    expect(localProcessingComponentIsDisabled(true, "idle", false)).toBe(
      true,
    );
    expect(localProcessingComponentIsDisabled(false, "saving", false)).toBe(
      true,
    );
    expect(localProcessingComponentIsDisabled(false, "idle", true)).toBe(
      true,
    );
    expect(
      localProcessingQualificationIsDisabled(false, "idle", false),
    ).toBe(false);
    expect(
      localProcessingQualificationIsDisabled(false, "idle", true),
    ).toBe(true);
  });

  it("aggregates independent mutation bits without treating status refresh as a write", () => {
    expect(localProcessingMutationIsActive("idle", false, false)).toBe(false);
    expect(localProcessingMutationIsActive("refreshing", false, false)).toBe(
      false,
    );
    expect(localProcessingMutationIsActive("discovering", false, false)).toBe(
      true,
    );
    expect(localProcessingMutationIsActive("idle", true, false)).toBe(true);
    expect(localProcessingMutationIsActive("idle", false, true)).toBe(true);
  });

  it("round-trips normalized strict settings", () => {
    const draft = privacyConfigToDraft(config);
    draft.languages = "ZH, en, zh";
    const normalized = privacyDraftToConfig(draft);

    expect(normalized).toEqual(config);
    expect(normalized.ocr.strictOffline).toBe(true);
    expect(normalized.ocr.forbidCloudFallback).toBe(true);
    expect(normalized.ocr.forbidRemoteUpload).toBe(true);
    expect(normalized.ocr.forbidTelemetry).toBe(true);
    expect(privacyConfigDraftIsDirty(config, draft)).toBe(false);
    expect(JSON.stringify(normalized)).not.toContain("allowRawCloud");
  });

  it("applies discovered local paths as an unsaved auto-local draft and preserves privacy mode", () => {
    const current = {
      ...privacyConfigToDraft(config),
      privacyMode: "raw_native" as const,
      device: "cuda:7",
    };
    const discovery: LocalMineruDiscoveryResult = {
      source: "uv_tool",
      ocrConfig: {
        ...config.ocr,
        mode: "auto_local",
        workerPath: "C:/Users/example/AppData/Roaming/uv/tools/mineru/Scripts/mineru.exe",
        modelDirectory: "C:/Users/example/.cache/modelscope/models",
        toolsConfigPath: "C:/Users/example/AppData/Local/Lawyer-Assistance/mineru-local-offline.json",
        runtimeExecutablePaths: [
          "C:/Users/example/AppData/Roaming/uv/tools/mineru/Scripts/python.exe",
        ],
        device: "auto",
      },
      appManagedToolsConfig: true,
      requiresUserSave: true,
      trustInstalled: false,
      networkIsolationInstalled: false,
      qualified: false,
    };

    const discovered = applyLocalMineruDiscoveryToDraft(current, discovery);
    expect(discovered.privacyMode).toBe("raw_native");
    expect(discovered.ocrMode).toBe("auto_local");
    expect(discovered.workerPath).toBe(discovery.ocrConfig.workerPath);
    expect(discovered.modelDirectory).toBe(discovery.ocrConfig.modelDirectory);
    expect(discovered.toolsConfigPath).toBe(discovery.ocrConfig.toolsConfigPath);
    expect(discovered.runtimeExecutablePaths).toBe(
      discovery.ocrConfig.runtimeExecutablePaths.join("\n"),
    );
    expect(discovered.device).toBe("auto");
  });
  it("rejects relative paths, arbitrary devices, and unsafe limits before IPC", () => {
    const draft = privacyConfigToDraft(config);
    expect(() =>
      privacyDraftToConfig({ ...draft, workerPath: "mineru-worker.exe" }),
    ).toThrow("本机盘符路径");
    expect(() =>
      privacyDraftToConfig({
        ...draft,
        workerPath: "\\\\server\\share\\mineru-worker.exe",
      }),
    ).toThrow("UNC/网络路径");
    expect(() =>
      privacyDraftToConfig({ ...draft, device: "http://gpu.example" }),
    ).toThrow("OCR 设备");
    expect(() =>
      privacyDraftToConfig({ ...draft, maxPages: "0" }),
    ).toThrow("最大页数");
    expect(() =>
      privacyDraftToConfig({ ...draft, maxPages: "501" }),
    ).toThrow("最大页数");
    expect(() =>
      privacyDraftToConfig({ ...draft, languages: "zh, 中文" }),
    ).toThrow("OCR 语言");
  });
});

describe("LocalProcessingWorkspaceView", () => {
  it("shows strict fixed boundaries, versions and hashes without a raw-cloud switch", () => {
    const markup = renderToStaticMarkup(
      <LocalProcessingWorkspaceView
        configResponse={response}
        draft={privacyConfigToDraft(config)}
        operation="idle"
        dirty={false}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onDiscover={vi.fn()}
        onSave={vi.fn()}
        onReset={vi.fn()}
        onRefreshStatus={vi.fn()}
      />,
    );

    expect(markup).toContain("本地处理环境与 OCR 组件");
    expect(markup).toContain("自动发现本机 MinerU");
    expect(markup).toContain("不执行 MinerU、Python、shell");
    expect(markup).toContain("任何网络命令");
    expect(markup).toContain("包含 pipeline/vlm 路径的最小离线配置");
    expect(markup).toContain("禁止云端 OCR 回退（真实案件不可关闭）");
    expect(markup).toContain("页面不提供原件外发许可开关");
    expect(markup).toContain("3.4.3-local");
    expect(markup).toContain("model-2026-07");
    expect(markup).toContain("a".repeat(64));
    expect(markup).toContain("未验证，不作隔离声明");
    expect(markup).toContain("原件、OCR 中间产物和未获批准的案件内容始终禁止外发");
    expect(markup).toContain("并且对应后端能力显示“已授权”的副本");
    expect(markup).toContain("任一资格、哈希、目标、用途、时效或消费状态不匹配都会 fail closed");
    expect(markup).toContain("才能进入 approved MCP");
    expect(markup).toContain("外部目标只应接收经本地脱敏、复核并批准的材料");
    expect(markup).toContain("networkIsolationEnforced=false");
    expect(markup).toContain("modelManifestTrustEstablished=false");
    expect(markup).toContain("appAutoEnableAuthorized=false");
    expect(markup).toContain("productionCaseOcrAuthorized=false");
    expect(markup).toContain("扫描件 OCR");
    expect(markup).toContain("自动批准");
    expect(markup).toContain("approved MCP");
    expect(markup.match(/后端不可启用/gu)).toHaveLength(3);
    expect(markup).toContain("禁止远端上传原件、OCR 正文与中间产物");
    expect(markup).toContain("禁止 OCR 遥测与隐式模型下载");
    expect(markup).toContain("这不构成来源认证、OS");
    expect(markup).toContain("不得据此处理真实扫描案件或自动批准");
    expect(markup).toContain("各自独立、持久化且可撤销的资格面板");
    expect(markup).not.toContain("第一阶段边界");
    expect(markup).not.toContain("允许原件上云");
    expect(markup).not.toContain("allowRawCloud");
  });

  it("locks status refresh while an unsaved configuration is visible", () => {
    const markup = renderToStaticMarkup(
      <LocalProcessingWorkspaceView
        configResponse={response}
        draft={{ ...privacyConfigToDraft(config), device: "cuda:1" }}
        operation="idle"
        dirty={true}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onDiscover={vi.fn()}
        onSave={vi.fn()}
        onReset={vi.fn()}
        onRefreshStatus={vi.fn()}
      />,
    );

    expect(markup).toContain("配置尚未保存");
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>重新检查<\/button>/u);
    expect(markup).toMatch(/<button[^>]*>保存隐私配置<\/button>/u);
  });
});
