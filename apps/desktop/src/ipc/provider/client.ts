import { invoke } from "@tauri-apps/api/core";

import type {
  DeleteProviderApiKeyRequest,
  DeleteProviderProfileRequest,
  DeleteProviderProfileResponse,
  ProviderApiKeyStatusRequest,
  ProviderApiKeyStatusResponse,
  ProviderProfileResponse,
  ProviderProfilesResponse,
  TestProviderConnectionRequest,
  TestProviderConnectionResponse,
  UpsertProviderProfileRequest,
  WriteProviderApiKeyRequest,
} from "./types";

export function listProviderProfiles(): Promise<ProviderProfilesResponse> {
  return invoke<ProviderProfilesResponse>("list_provider_profiles");
}

export function upsertProviderProfile(
  request: UpsertProviderProfileRequest,
): Promise<ProviderProfileResponse> {
  return invoke<ProviderProfileResponse>("upsert_provider_profile", {
    request,
  });
}

export function deleteProviderProfile(
  request: DeleteProviderProfileRequest,
): Promise<DeleteProviderProfileResponse> {
  return invoke<DeleteProviderProfileResponse>("delete_provider_profile", {
    request,
  });
}

export function getProviderApiKeyStatus(
  request: ProviderApiKeyStatusRequest,
): Promise<ProviderApiKeyStatusResponse> {
  return invoke<ProviderApiKeyStatusResponse>("get_provider_api_key_status", {
    request,
  });
}

export function writeProviderApiKey(
  request: WriteProviderApiKeyRequest,
): Promise<ProviderApiKeyStatusResponse> {
  return invoke<ProviderApiKeyStatusResponse>("write_provider_api_key", {
    request,
  });
}

export function deleteProviderApiKey(
  request: DeleteProviderApiKeyRequest,
): Promise<ProviderApiKeyStatusResponse> {
  return invoke<ProviderApiKeyStatusResponse>("delete_provider_api_key", {
    request,
  });
}

export function testProviderConnection(
  request: TestProviderConnectionRequest,
): Promise<TestProviderConnectionResponse> {
  return invoke<TestProviderConnectionResponse>("test_provider_connection", {
    request,
  });
}
