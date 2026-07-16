import type {
  ProviderApiKeyStatus,
  ProviderOptions,
  ProviderProfile,
} from "./types";

export function normalizeProviderProfile(
  profile: ProviderProfile,
): ProviderProfile {
  return {
    ...profile,
    id: profile.id.trim(),
    displayName: profile.displayName.trim(),
    modelId: profile.modelId.trim(),
    baseUrl: profile.baseUrl.trim(),
    credentialAccountId: profile.credentialAccountId.trim() || "default",
    options: normalizeProviderOptions(profile.options, profile.kind),
  };
}

export function providerProfilesEqual(
  left: ProviderProfile,
  right: ProviderProfile,
): boolean {
  return (
    JSON.stringify(normalizeProviderProfile(left)) ===
    JSON.stringify(normalizeProviderProfile(right))
  );
}

export function providerKeyStatusForSavedDraft(
  saved: ProviderProfile | undefined,
  draft: ProviderProfile,
  status: ProviderApiKeyStatus | undefined,
): ProviderApiKeyStatus | undefined {
  const normalizedDraft = normalizeProviderProfile(draft);
  if (
    saved === undefined ||
    status === undefined ||
    !providerProfilesEqual(saved, normalizedDraft) ||
    status.providerId !== normalizedDraft.id ||
    status.accountId !== normalizedDraft.credentialAccountId
  ) {
    return undefined;
  }

  return status;
}

export async function loadProviderKeyStatusesSettled(
  profiles: ProviderProfile[],
  loadStatus: (profile: ProviderProfile) => Promise<ProviderApiKeyStatus>,
): Promise<{
  statuses: Record<string, ProviderApiKeyStatus>;
  failedCount: number;
}> {
  const results = await Promise.allSettled(
    profiles.map(async (profile) => [profile.id, await loadStatus(profile)] as const),
  );
  const fulfilled = results.flatMap((result) =>
    result.status === "fulfilled" ? [result.value] : [],
  );

  return {
    statuses: Object.fromEntries(fulfilled),
    failedCount: results.length - fulfilled.length,
  };
}

function normalizeProviderOptions(
  options: ProviderOptions,
  kind: ProviderProfile["kind"],
): ProviderOptions {
  const reasoningEffort =
    kind === "deep_seek" &&
    (options.reasoningEffort === "low" ||
      options.reasoningEffort === "medium")
      ? "high"
      : (options.reasoningEffort ?? null);
  return {
    thinking: options.thinking ?? null,
    enableThinking: options.enableThinking ?? null,
    thinkingBudget: options.thinkingBudget ?? null,
    reasoningEffort,
    endpointId: options.endpointId?.trim() || null,
    workspaceId: options.workspaceId?.trim() || null,
    allowPrivateNetwork:
      kind === "custom" ? (options.allowPrivateNetwork ?? false) : false,
  };
}
