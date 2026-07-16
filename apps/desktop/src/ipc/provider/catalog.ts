import type {
  ProviderCapabilities,
  ProviderKind,
  ProviderOptions,
  ProviderProfile,
} from "./types";

export const DEFAULT_PROVIDER_KIND: ProviderKind = "deep_seek";

export const OTHER_BUILTIN_PROVIDER_KINDS = [
  "qwen",
  "silicon_flow",
  "volcengine_ark",
] as const satisfies readonly ProviderKind[];

export const CUSTOM_PROVIDER_KIND: ProviderKind = "custom";

export const SELECTABLE_PROVIDER_KINDS = [
  DEFAULT_PROVIDER_KIND,
  ...OTHER_BUILTIN_PROVIDER_KINDS,
  CUSTOM_PROVIDER_KIND,
] as const satisfies readonly ProviderKind[];

const DEFAULT_CAPABILITIES: ProviderCapabilities = {
  chat: true,
  streaming: true,
  customModelId: true,
  customBaseUrl: true,
  reasoning: true,
};

export function providerCapabilities(kind: ProviderKind): ProviderCapabilities {
  return {
    ...DEFAULT_CAPABILITIES,
    reasoning: kind !== CUSTOM_PROVIDER_KIND,
  };
}

const PROVIDER_DEFAULTS: Record<
  ProviderKind,
  { displayName: string; modelId: string; baseUrl: string }
> = {
  deep_seek: {
    displayName: "DeepSeek",
    modelId: "deepseek-v4-flash",
    baseUrl: "https://api.deepseek.com",
  },
  qwen: {
    displayName: "Qwen",
    modelId: "qwen-plus",
    baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  },
  silicon_flow: {
    displayName: "SiliconFlow",
    modelId: "deepseek-ai/DeepSeek-V3.2",
    baseUrl: "https://api.siliconflow.cn/v1",
  },
  volcengine_ark: {
    displayName: "Volcengine Ark",
    modelId: "doubao-seed-2-0-lite-260215",
    baseUrl: "https://ark.cn-beijing.volces.com/api/v3",
  },
  custom: {
    displayName: "自定义提供商",
    modelId: "",
    baseUrl: "",
  },
};

export function providerDefaults(kind: ProviderKind) {
  return PROVIDER_DEFAULTS[kind];
}

export function defaultProviderOptions(kind: ProviderKind): ProviderOptions {
  if (kind === "deep_seek" || kind === "volcengine_ark") {
    return { thinking: false };
  }
  if (kind === "qwen" || kind === "silicon_flow") {
    return { enableThinking: false };
  }
  return { allowPrivateNetwork: false };
}

export function createProviderProfileDraft(
  kind: ProviderKind,
  id: string,
): ProviderProfile {
  const defaults = providerDefaults(kind);

  return {
    id,
    displayName: defaults.displayName,
    kind,
    modelId: defaults.modelId,
    baseUrl: defaults.baseUrl,
    credentialAccountId: "default",
    capabilities: providerCapabilities(kind),
    options: defaultProviderOptions(kind),
  };
}
