import { describe, expect, it } from "vitest";

import {
  createProviderProfileDraft,
  CUSTOM_PROVIDER_KIND,
  DEFAULT_PROVIDER_KIND,
  OTHER_BUILTIN_PROVIDER_KINDS,
  providerCapabilities,
  SELECTABLE_PROVIDER_KINDS,
} from "./catalog";

describe("provider catalog", () => {
  it("keeps DeepSeek as the only primary preset", () => {
    expect(DEFAULT_PROVIDER_KIND).toBe("deep_seek");
    expect(OTHER_BUILTIN_PROVIDER_KINDS).toEqual([
      "qwen",
      "silicon_flow",
      "volcengine_ark",
    ]);
    expect(OTHER_BUILTIN_PROVIDER_KINDS).not.toContain(DEFAULT_PROVIDER_KIND);
    expect(SELECTABLE_PROVIDER_KINDS).toEqual([
      "deep_seek",
      "qwen",
      "silicon_flow",
      "volcengine_ark",
      "custom",
    ]);
  });

  it("creates an intentionally incomplete custom draft", () => {
    const draft = createProviderProfileDraft(CUSTOM_PROVIDER_KIND, "custom-1");

    expect(draft).toMatchObject({
      id: "custom-1",
      displayName: "自定义提供商",
      kind: "custom",
      modelId: "",
      baseUrl: "",
      credentialAccountId: "default",
      options: { allowPrivateNetwork: false },
    });
    expect(draft.capabilities).toMatchObject({
      chat: true,
      streaming: true,
      customModelId: true,
      customBaseUrl: true,
      reasoning: false,
    });
  });

  it("retains the current DeepSeek defaults", () => {
    expect(createProviderProfileDraft("deep_seek", "deepseek-1")).toMatchObject({
      displayName: "DeepSeek",
      modelId: "deepseek-v4-flash",
      baseUrl: "https://api.deepseek.com",
      options: { thinking: false },
    });
  });

  it("keeps custom capabilities isolated from built-in profiles", () => {
    expect(providerCapabilities("custom").reasoning).toBe(false);
    expect(providerCapabilities("deep_seek").reasoning).toBe(true);
  });
});
