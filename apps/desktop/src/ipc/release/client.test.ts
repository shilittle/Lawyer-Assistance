import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { exportDiagnosticReport } from "./client";

describe("release IPC", () => {
  beforeEach(() => invoke.mockReset());

  it("does not send frontend event text in diagnostic requests", async () => {
    invoke.mockResolvedValue({ completed: true, cancelled: false, path: "C:/diagnostics.txt" });
    await exportDiagnosticReport("C:/diagnostics.txt");
    expect(invoke).toHaveBeenCalledWith("export_diagnostic_report", {
      request: { destinationPath: "C:/diagnostics.txt" },
    });
  });
});
