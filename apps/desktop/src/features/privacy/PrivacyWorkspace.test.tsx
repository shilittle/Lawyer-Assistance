import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  PrivacyConfig,
  PrivacyConfigResponse,
} from "../../ipc/privacy/types";
import {
  PrivacyWorkspaceView,
  privacyConfigDraftIsDirty,
  privacyConfigToDraft,
  privacyDraftToConfig,
} from "./PrivacyWorkspace";

const config: PrivacyConfig = {
  schemaVersion: 1,
  privacyMode: "external_redacted",
  ocr: {
    mode: "force_local",
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

const response: PrivacyConfigResponse = {
  config,
  configValid: true,
  loadError: null,
  enforcementState: "local_review_safe_pdf_ready_case_provider_production_mcp_fail_closed_public_legal_tools_only",
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
    networkIsolationEnforced: false,
    modelManifestTrustEstablished: false,
    appAutoEnableAuthorized: false,
    productionCaseOcrAuthorized: false,
  },
  capabilities: {
    localGpuPreferenceConfigurable: true,
    scannedCaseOcrEnabled: false,
    automaticApprovalEnabled: false,
    approvedCaseMcpEnabled: false,
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

describe("PrivacyWorkspace configuration", () => {
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

describe("PrivacyWorkspaceView", () => {
  it("shows strict fixed boundaries, versions and hashes without a raw-cloud switch", () => {
    const markup = renderToStaticMarkup(
      <PrivacyWorkspaceView
        configResponse={response}
        draft={privacyConfigToDraft(config)}
        operation="idle"
        dirty={false}
        notice=""
        error=""
        onDraftChange={vi.fn()}
        onSave={vi.fn()}
        onReset={vi.fn()}
        onRefreshStatus={vi.fn()}
      />,
    );

    expect(markup).toContain("隐私与本地处理");
    expect(markup).toContain("禁止云端 OCR 回退（真实案件不可关闭）");
    expect(markup).toContain("页面不提供原件外发许可开关");
    expect(markup).toContain("3.4.3-local");
    expect(markup).toContain("model-2026-07");
    expect(markup).toContain("a".repeat(64));
    expect(markup).toContain("未验证，不作隔离声明");
    expect(markup).toContain("本地脱敏审阅、精确回执和安全 PDF 重建已经可用");
    expect(markup).toContain("案件 Provider 与生产 MCP");
    expect(markup).toContain("后端默认拒绝（fail closed）");
    expect(markup).toContain("只有不携带案件材料的公开法律工具可以外发请求");
    expect(markup).toContain("获批脱敏案件材料均不得据此发送");
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
    expect(markup).toContain(
      "不得据此处理真实扫描案件、自动批准或启动案件材料 MCP",
    );
    expect(markup).not.toContain("第一阶段边界");
    expect(markup).not.toContain("允许原件上云");
    expect(markup).not.toContain("allowRawCloud");
  });

  it("locks status refresh while an unsaved configuration is visible", () => {
    const markup = renderToStaticMarkup(
      <PrivacyWorkspaceView
        configResponse={response}
        draft={{ ...privacyConfigToDraft(config), device: "cuda:1" }}
        operation="idle"
        dirty={true}
        notice=""
        error=""
        onDraftChange={vi.fn()}
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
