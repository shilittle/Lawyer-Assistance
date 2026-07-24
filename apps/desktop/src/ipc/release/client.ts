import { invoke } from "@tauri-apps/api/core";

export interface VersionInfo {
  appVersion: string;
  buildUnix: number;
  userSchemaVersion: number;
  legalDatabaseVersion: string;
  legalDataScope: string;
  sourceManifestHash: string;
}

export interface FileOperationResponse {
  completed: boolean;
  cancelled: boolean;
  path?: string | null;
  restartRequired: boolean;
}

export const getVersionInfo = (): Promise<VersionInfo> => invoke("get_version_info");

export const exportDiagnosticReport = (
  destinationPath: string | null,
): Promise<FileOperationResponse> =>
  invoke("export_diagnostic_report", { request: { destinationPath } });
