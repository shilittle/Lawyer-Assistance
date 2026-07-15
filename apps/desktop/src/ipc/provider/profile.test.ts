import { describe, expect, it } from "vitest";

import {
  loadProviderKeyStatusesSettled,
  normalizeProviderProfile,
  providerKeyStatusForSavedDraft,
  providerProfilesEqual,
} from "./profile";
import type { ProviderApiKeyStatus, ProviderProfile } from "./types";

const saved: ProviderProfile = {
  id: "qwen-main",
  displayName: "Qwen",
  kind: "qwen",
  modelId: "qwen-plus",
  baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  credentialAccountId: "default",
  capabilities: {
    chat: true,
    streaming: true,
    customModelId: true,
    customBaseUrl: true,
    reasoning: true,
  },
  options: {},
};

describe("provider profile normalization", () => {
  it("normalizes editable text and optional fields before persistence", () => {
    const normalized = normalizeProviderProfile({
      ...saved,
      displayName: "  Qwen  ",
      credentialAccountId: " ",
      options: { workspaceId: " workspace-1 " },
    });

    expect(normalized.displayName).toBe("Qwen");
    expect(normalized.credentialAccountId).toBe("default");
    expect(normalized.options.workspaceId).toBe("workspace-1");
    expect(normalized.options.thinkingBudget).toBeNull();
  });

  it("distinguishes a visible unsaved configuration from the tested profile", () => {
    expect(
      providerProfilesEqual(saved, { ...saved, displayName: " Qwen " }),
    ).toBe(true);
    expect(
      providerProfilesEqual(saved, { ...saved, modelId: "qwen-max" }),
    ).toBe(false);
    expect(
      providerProfilesEqual(saved, {
        ...saved,
        baseUrl: "https://example.invalid/v1",
      }),
    ).toBe(false);
  });

  it("normalizes legacy DeepSeek effort and keeps private-network access opt-in", () => {
    const deepSeek = normalizeProviderProfile({
      ...saved,
      kind: "deep_seek",
      options: { reasoningEffort: "medium" },
    });
    const custom = normalizeProviderProfile({
      ...saved,
      kind: "custom",
      options: { allowPrivateNetwork: true },
    });

    expect(deepSeek.options.reasoningEffort).toBe("high");
    expect(deepSeek.options.allowPrivateNetwork).toBe(false);
    expect(custom.options.allowPrivateNetwork).toBe(true);
  });

  it("hides stale key status for dirty profiles and mismatched accounts", () => {
    const status: ProviderApiKeyStatus = {
      providerId: saved.id,
      accountId: saved.credentialAccountId,
      configured: true,
      maskedKey: "****1234",
    };

    expect(providerKeyStatusForSavedDraft(saved, saved, status)).toEqual(
      status,
    );
    expect(
      providerKeyStatusForSavedDraft(
        saved,
        { ...saved, credentialAccountId: "secondary" },
        status,
      ),
    ).toBeUndefined();
    expect(
      providerKeyStatusForSavedDraft(saved, saved, {
        ...status,
        accountId: "secondary",
      }),
    ).toBeUndefined();
    expect(
      providerKeyStatusForSavedDraft(
        saved,
        { ...saved, baseUrl: "https://example.invalid/v1" },
        status,
      ),
    ).toBeUndefined();
  });

  it("waits for all initial statuses and preserves successes on partial failure", async () => {
    const second = { ...saved, id: "qwen-secondary" };
    let releaseStatus: ((status: ProviderApiKeyStatus) => void) | undefined;
    const deferred = new Promise<ProviderApiKeyStatus>((resolve) => {
      releaseStatus = resolve;
    });
    let settled = false;
    const pending = loadProviderKeyStatusesSettled(
      [saved, second],
      (profile) =>
        profile.id === saved.id
          ? deferred
          : Promise.reject(new Error("credential status unavailable")),
    ).then((result) => {
      settled = true;
      return result;
    });

    await Promise.resolve();
    expect(settled).toBe(false);
    releaseStatus?.({
      providerId: saved.id,
      accountId: saved.credentialAccountId,
      configured: true,
      maskedKey: "****1234",
    });
    const result = await pending;

    expect(result.failedCount).toBe(1);
    expect(result.statuses[saved.id]?.configured).toBe(true);
    expect(result.statuses[second.id]).toBeUndefined();
  });
});
