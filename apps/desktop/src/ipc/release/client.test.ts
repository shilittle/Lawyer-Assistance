import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  backupUserDatabase,
  exportDiagnosticReport,
  restoreUserDatabase,
} from "./client";

describe("release IPC", () => {
  beforeEach(() => invoke.mockReset());

  it("wraps backup and restore paths in typed request envelopes", async () => {
    invoke.mockResolvedValue({ completed: true, cancelled: false, path: "C:/backup.sqlite" });
    await backupUserDatabase("C:/backup.sqlite");
    await restoreUserDatabase("C:/backup.sqlite");
    expect(invoke).toHaveBeenNthCalledWith(1, "backup_user_database", {
      request: { destinationPath: "C:/backup.sqlite" },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "restore_user_database", {
      request: { sourcePath: "C:/backup.sqlite" },
    });
  });

  it("does not send frontend event text in diagnostic requests", async () => {
    invoke.mockResolvedValue({ completed: true, cancelled: false, path: "C:/diagnostics.txt" });
    await exportDiagnosticReport("C:/diagnostics.txt");
    expect(invoke).toHaveBeenCalledWith("export_diagnostic_report", {
      request: { destinationPath: "C:/diagnostics.txt" },
    });
  });
});
