import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  decideLocalProcessingRouteNavigation,
  decideWorkspaceClose,
} from "../../../app/navigationGuards";
import { VIEW_METADATA, VIEW_MODES } from "../../../app/views";
import { SettingsWorkspace } from "../SettingsWorkspace";

describe("local-processing settings integration", () => {
  it("registers the local-processing view inside settings without changing the main product area", () => {
    expect(VIEW_MODES).toContain("local-processing");
    expect(VIEW_METADATA["local-processing"].futureArea).toBe("settings");
    const markup = renderToStaticMarkup(
      <SettingsWorkspace mode="local-processing">本地处理设置</SettingsWorkspace>,
    );
    expect(markup).toContain('aria-label="本地处理环境与 OCR 组件设置"');
    expect(markup).toContain('class="settings-maintenance-workspace"');
  });

  it("protects an active save and an unsaved local-processing draft on close", () => {
    const active = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      localProcessingMutationInFlight: true,
    });
    expect(active.kind).toBe("block");
    expect("message" in active ? active.message : "").toContain(
      "本地处理配置或组件操作",
    );

    const dirty = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      localProcessingDraftDirty: true,
    });
    expect(dirty.kind).toBe("confirm_discard");
    expect("message" in dirty ? dirty.message : "").toContain(
      "本地处理与 OCR 配置",
    );
  });

  it("guards only navigation away from the local-processing workspace", () => {
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "local-processing" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "providers" },
        { area: "assistant", page: "chat" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "mcp" },
        true,
        false,
      ).kind,
    ).toBe("block");
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "maintenance" },
        false,
        true,
      ).kind,
    ).toBe("confirm_discard");
  });
});
