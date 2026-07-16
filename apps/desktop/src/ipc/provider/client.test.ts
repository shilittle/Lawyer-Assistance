import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  deleteProviderApiKey,
  deleteProviderProfile,
  getProviderApiKeyStatus,
  listProviderProfiles,
  testProviderConnection,
  upsertProviderProfile,
  writeProviderApiKey,
} from "./client";
import type { ProviderProfile } from "./types";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const profile: ProviderProfile = {
  id: "deepseek-main",
  displayName: "DeepSeek",
  kind: "deep_seek",
  modelId: "deepseek-v4-flash",
  baseUrl: "https://api.deepseek.com",
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

describe("provider IPC client", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
    vi.mocked(invoke).mockResolvedValue({});
  });

  it("uses the typed profile command names and request envelope", async () => {
    await listProviderProfiles();
    await upsertProviderProfile({ profile });
    await deleteProviderProfile({ providerId: profile.id });

    expect(invoke).toHaveBeenNthCalledWith(1, "list_provider_profiles");
    expect(invoke).toHaveBeenNthCalledWith(2, "upsert_provider_profile", {
      request: { profile },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "delete_provider_profile", {
      request: { providerId: profile.id },
    });
  });

  it("has one write-only key payload and no command that reads a complete key", async () => {
    const statusRequest = {
      providerId: profile.id,
      accountId: profile.credentialAccountId,
    };
    const dummySecret = "not-a-real-provider-secret-1234";

    await getProviderApiKeyStatus(statusRequest);
    await writeProviderApiKey({ ...statusRequest, apiKey: dummySecret });
    await deleteProviderApiKey(statusRequest);

    expect(invoke).toHaveBeenNthCalledWith(1, "get_provider_api_key_status", {
      request: statusRequest,
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "write_provider_api_key", {
      request: { ...statusRequest, apiKey: dummySecret },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "delete_provider_api_key", {
      request: statusRequest,
    });
    expect(JSON.stringify(vi.mocked(invoke).mock.calls[0])).not.toContain(
      dummySecret,
    );
    expect(JSON.stringify(vi.mocked(invoke).mock.calls[2])).not.toContain(
      dummySecret,
    );
  });

  it("tests a saved profile by ID without transmitting a key", async () => {
    await testProviderConnection({ providerId: profile.id });

    expect(invoke).toHaveBeenCalledWith("test_provider_connection", {
      request: { providerId: profile.id },
    });
    expect(JSON.stringify(vi.mocked(invoke).mock.calls[0])).not.toContain(
      "apiKey",
    );
  });
});
