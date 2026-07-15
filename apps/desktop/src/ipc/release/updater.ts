import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

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

function parseMessage(value: string): { message: string; code?: string } | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object") {
      const record = parsed as Record<string, unknown>;
      const message = [record.message, record.error, record.details].find(
        (candidate): candidate is string =>
          typeof candidate === "string" && candidate.trim().length > 0,
      );
      if (message) {
        const code = [record.errorType, record.code].find(
          (candidate): candidate is string =>
            typeof candidate === "string" && candidate.trim().length > 0,
        );
        return {
          message: message.trim(),
          code: code?.trim(),
        };
      }
    }
  } catch {
    // Plain Rust/Tauri command errors are commonly returned as strings.
  }

  return { message: trimmed };
}

export function formatIpcError(error: unknown): string {
  if (error instanceof Error) {
    const parsed = parseMessage(error.message);
    if (parsed) return parsed.code ? `${parsed.message}（${parsed.code}）` : parsed.message;
  }

  if (typeof error === "string") {
    const parsed = parseMessage(error);
    if (parsed) return parsed.code ? `${parsed.message}（${parsed.code}）` : parsed.message;
  }

  if (error && typeof error === "object") {
    const record = error as Record<string, unknown>;
    const message = [record.message, record.error, record.details].find(
      (candidate): candidate is string =>
        typeof candidate === "string" && candidate.trim().length > 0,
    );
    if (message) {
      const code = [record.errorType, record.code].find(
        (candidate): candidate is string =>
          typeof candidate === "string" && candidate.trim().length > 0,
      );
      return code ? `${message.trim()}（${code.trim()}）` : message.trim();
    }
  }

  return "操作失败，请稍后重试或导出诊断报告。";
}
