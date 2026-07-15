import { describe, expect, it, vi } from "vitest";

import {
  checkForApplicationUpdate,
  formatIpcError,
  installApplicationUpdate,
  relaunchApplication,
  type ApplicationUpdate,
  type DownloadEvent,
  type UpdaterDependencies,
} from "./updater";

function createDependencies(result: ApplicationUpdate | null): {
  dependencies: UpdaterDependencies;
  invoke: ReturnType<typeof vi.fn>;
  listen: ReturnType<typeof vi.fn>;
  unlisten: ReturnType<typeof vi.fn>;
} {
  const invoke = vi.fn(async (command: string) => {
    if (command === "check_for_application_update") return result;
    return undefined;
  });
  const unlisten = vi.fn();
  const listen = vi.fn().mockResolvedValue(unlisten);
  return {
    dependencies: { invoke, listen } as unknown as UpdaterDependencies,
    invoke,
    listen,
    unlisten,
  };
}

function createUpdate(): ApplicationUpdate {
  return {
    currentVersion: "0.2.0",
    version: "0.2.1",
    date: "2026-07-16T00:00:00Z",
    body: "修复更新。",
  };
}

describe("release updater", () => {
  it("checks for an update through the hardened Rust command", async () => {
    const update = createUpdate();
    const { dependencies, invoke } = createDependencies(update);

    await expect(checkForApplicationUpdate(dependencies)).resolves.toBe(update);
    expect(invoke).toHaveBeenCalledWith("check_for_application_update");
  });

  it("returns null when the installed version is current", async () => {
    const { dependencies } = createDependencies(null);
    await expect(checkForApplicationUpdate(dependencies)).resolves.toBeNull();
  });

  it("relays progress while Rust downloads, verifies and launches the installer", async () => {
    const update = createUpdate();
    const { dependencies, invoke, listen, unlisten } = createDependencies(update);
    const onEvent = vi.fn();

    await installApplicationUpdate(update, onEvent, dependencies);

    expect(listen).toHaveBeenCalledWith(
      "lawyer-assistance://updater-progress",
      expect.any(Function),
    );
    const handler = listen.mock.calls[0][1] as (event: {
      payload: DownloadEvent;
    }) => void;
    const event: DownloadEvent = {
      event: "Progress",
      data: { chunkLength: 4096 },
    };
    handler({ payload: event });
    expect(onEvent).toHaveBeenCalledWith(event);
    expect(invoke).toHaveBeenCalledWith("download_install_application_update", {
      request: { version: "0.2.1" },
    });
    expect(unlisten).toHaveBeenCalledOnce();
  });

  it("always removes the progress listener after a rejected update", async () => {
    const update = createUpdate();
    const { dependencies, invoke, unlisten } = createDependencies(update);
    invoke.mockRejectedValueOnce(new Error("signature invalid"));

    await expect(
      installApplicationUpdate(update, undefined, dependencies),
    ).rejects.toThrow("signature invalid");
    expect(unlisten).toHaveBeenCalledOnce();
  });

  it("relaunches through the Rust lifecycle command after a database restore", async () => {
    const { dependencies, invoke } = createDependencies(null);
    await relaunchApplication(dependencies);
    expect(invoke).toHaveBeenCalledWith("relaunch_application");
  });

  it("renders structured IPC failures without exposing object dumps", () => {
    expect(
      formatIpcError(
        '{"errorType":"backup_invalid","message":"备份文件无效"}',
      ),
    ).toBe("备份文件无效（backup_invalid）");
    expect(formatIpcError({ error: "网络不可用", code: "updater_offline" })).toBe(
      "网络不可用（updater_offline）",
    );
    expect(formatIpcError(null)).toBe("操作失败，请稍后重试或导出诊断报告。");
  });
});
