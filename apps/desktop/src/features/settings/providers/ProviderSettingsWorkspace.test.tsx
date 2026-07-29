import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { createProviderProfileDraft } from "../../../ipc/provider/catalog";
import type { ProviderProfile } from "../../../ipc/provider/types";
import { ProviderSettingsWorkspace } from "./ProviderSettingsWorkspace";
import type { ProviderSettingsController } from "./useProviderSettingsController";

function controllerFor(
  profile: ProviderProfile,
  patch: Partial<ProviderSettingsController> = {},
): ProviderSettingsController {
  const keyStatus = {
    providerId: profile.id,
    accountId: profile.credentialAccountId,
    configured: true,
    maskedKey: "sk-****",
  };

  return {
    state: { kind: "idle" },
    profiles: [profile],
    draft: profile,
    selectedProviderId: profile.id,
    apiKeyInput: "",
    keyStatuses: { [profile.id]: keyStatus },
    currentKeyStatus: keyStatus,
    currentConnectionResult: undefined,
    busy: false,
    isSaved: true,
    draftIsDirty: false,
    hasKey: true,
    hasUnsavedChanges: false,
    hasUnsavedChangesRef: { current: false },
    mutationInFlightRef: { current: false },
    setApiKeyInput: vi.fn(),
    updateDraft: vi.fn(),
    updateKind: vi.fn(),
    updateOptions: vi.fn(),
    startNewProvider: vi.fn(),
    selectProvider: vi.fn(),
    discardDraftChanges: vi.fn(),
    saveProvider: vi.fn(async () => undefined),
    saveApiKey: vi.fn(async () => undefined),
    removeApiKey: vi.fn(async () => undefined),
    removeProvider: vi.fn(async () => undefined),
    runConnectionTest: vi.fn(async () => undefined),
    ...patch,
  };
}

describe("ProviderSettingsWorkspace", () => {
  it("preserves the extracted profile, credential, and connection sections", () => {
    const profile = createProviderProfileDraft("deep_seek", "provider-1");
    const markup = renderToStaticMarkup(
      <ProviderSettingsWorkspace controller={controllerFor(profile)} />,
    );

    expect(markup).toContain('aria-label="Provider 与凭据设置"');
    expect(markup).toContain(profile.displayName);
    expect(markup).toContain("API Key");
    expect(markup).toContain("测试连接");
    expect(markup).toContain("首个响应 token");
  });

  it("keeps the explicit private-network risk warning for custom providers", () => {
    const profile = {
      ...createProviderProfileDraft("custom", "provider-custom"),
      options: { allowPrivateNetwork: true },
    };
    const markup = renderToStaticMarkup(
      <ProviderSettingsWorkspace controller={controllerFor(profile)} />,
    );

    expect(markup).toContain("我确认允许访问 localhost、私网或链路本地地址");
    expect(markup).toContain(
      "高风险：该 Provider 可访问本机及内网服务。",
    );
  });
});
