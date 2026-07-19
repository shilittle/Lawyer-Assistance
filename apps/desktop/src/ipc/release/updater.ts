import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { publicErrorMessage } from "../../publicOutput";

const UPDATE_PROGRESS_EVENT = "lawyer-assistance://updater-progress";

export interface ApplicationUpdate {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
}

export type DownloadEvent =
  | {
      event: "Started";
      data: { contentLength?: number | null };
    }
  | {
      event: "Progress";
      data: { chunkLength: number };
    }
  | {
      event: "Finished";
    };

export interface UpdaterDependencies {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  listen<T>(
    event: string,
    handler: (event: { payload: T }) => void,
  ): Promise<() => void>;
}

const defaultDependencies: UpdaterDependencies = {
  invoke: <T>(command: string, args?: Record<string, unknown>) =>
    invoke<T>(command, args),
  listen: <T>(event: string, handler: (event: { payload: T }) => void) =>
    listen<T>(event, (received) => handler({ payload: received.payload })),
};

export async function checkForApplicationUpdate(
  dependencies: UpdaterDependencies = defaultDependencies,
): Promise<ApplicationUpdate | null> {
  return dependencies.invoke<ApplicationUpdate | null>(
    "check_for_application_update",
  );
}

export async function installApplicationUpdate(
  update: ApplicationUpdate,
  onEvent?: (event: DownloadEvent) => void,
  dependencies: UpdaterDependencies = defaultDependencies,
): Promise<void> {
  const unlisten = await dependencies.listen<DownloadEvent>(
    UPDATE_PROGRESS_EVENT,
    ({ payload }) => onEvent?.(payload),
  );
  try {
    await dependencies.invoke<void>("download_install_application_update", {
      request: { version: update.version },
    });
  } finally {
    unlisten();
  }
}

export async function relaunchApplication(
  dependencies: UpdaterDependencies = defaultDependencies,
): Promise<void> {
  await dependencies.invoke<void>("relaunch_application");
}

export function formatIpcError(error: unknown): string {
  return publicErrorMessage(error);
}
