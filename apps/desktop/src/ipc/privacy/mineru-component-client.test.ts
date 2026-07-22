import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  downloadInstallMineruPackage,
  getMineruComponentStatus,
  importMineruComponentCatalog,
  installMineruOfflinePackage,
  rollbackMineruComponent,
  uninstallMineruComponent,
} from "./mineru-component-client";

describe("MinerU component IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses native dialogs for local files and never accepts a case path", async () => {
    await getMineruComponentStatus();
    await importMineruComponentCatalog();
    await installMineruOfflinePackage();

    expect(invoke).toHaveBeenNthCalledWith(1, "get_mineru_component_status");
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "import_mineru_component_catalog",
    );
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      "install_mineru_offline_package",
    );
    expect(JSON.stringify(invoke.mock.calls)).not.toMatch(
      /case|material|path|url|firewall/i,
    );
  });

  it("sends only catalog package IDs or component versions", async () => {
    await downloadInstallMineruPackage("mineru-windows-1-2-3");
    await rollbackMineruComponent("1.2.2");
    await uninstallMineruComponent("1.2.1");

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "download_install_mineru_package",
      { request: { packageId: "mineru-windows-1-2-3" } },
    );
    expect(invoke).toHaveBeenNthCalledWith(2, "rollback_mineru_component", {
      request: { componentVersion: "1.2.2" },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "uninstall_mineru_component", {
      request: { componentVersion: "1.2.1" },
    });
    expect(JSON.stringify(invoke.mock.calls)).not.toMatch(
      /caseMaterial|removeFirewall|sourcePath|destinationPath/i,
    );
  });
});
