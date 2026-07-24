import { invoke } from "@tauri-apps/api/core";

import type { PrivacyConfigResponse } from "./types";

export interface MineruCatalogEntry {
  packageId: string;
  componentVersion: string;
  mineruVersion: string;
  packageSizeBytes: number;
  packageSha256: string;
  packageManifestSha256: string;
  downloadUrl: string;
}

export interface InstalledMineruComponent {
  componentVersion: string;
  mineruVersion: string | null;
  manifestSha256: string | null;
  active: boolean;
  integrityValid: boolean;
  lifecycleState: "active" | "inactive" | "drifted" | "quarantined";
  reasonCodes: string[];
}

export interface MineruComponentStatus {
  catalogId: string | null;
  catalogExpiresAtUnix: number | null;
  catalogTrusted: boolean;
  availablePackages: MineruCatalogEntry[];
  installedVersions: InstalledMineruComponent[];
  activeVersion: string | null;
  activeManifestSha256: string | null;
  activeIntegrityValid: boolean;
  qualificationRecheckRequired: boolean;
  remoteOcrAllowed: false;
  caseMaterialDownloadedOrUploaded: false;
  reasonCodes: string[];
}

export interface MineruComponentOperationResponse {
  cancelled: boolean;
  status: MineruComponentStatus;
  privacy: PrivacyConfigResponse | null;
}

export function getMineruComponentStatus(): Promise<MineruComponentStatus> {
  return invoke<MineruComponentStatus>("get_mineru_component_status");
}

export function importMineruComponentCatalog(): Promise<MineruComponentOperationResponse> {
  return invoke<MineruComponentOperationResponse>(
    "import_mineru_component_catalog",
  );
}

export function installMineruOfflinePackage(): Promise<MineruComponentOperationResponse> {
  return invoke<MineruComponentOperationResponse>(
    "install_mineru_offline_package",
  );
}

export function downloadInstallMineruPackage(
  packageId: string,
): Promise<MineruComponentOperationResponse> {
  return invoke<MineruComponentOperationResponse>(
    "download_install_mineru_package",
    { request: { packageId } },
  );
}

export function rollbackMineruComponent(
  componentVersion: string,
): Promise<MineruComponentOperationResponse> {
  return invoke<MineruComponentOperationResponse>("rollback_mineru_component", {
    request: { componentVersion },
  });
}

export function uninstallMineruComponent(
  componentVersion: string,
): Promise<MineruComponentOperationResponse> {
  return invoke<MineruComponentOperationResponse>("uninstall_mineru_component", {
    request: { componentVersion },
  });
}
