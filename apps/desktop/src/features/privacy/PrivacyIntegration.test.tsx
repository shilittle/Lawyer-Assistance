import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  decidePrivacyWorkspaceNavigation,
  decideWorkspaceClose,
} from "../../App";
import { VIEW_METADATA, VIEW_MODES } from "../../app/views";
import { SettingsWorkspace } from "../settings/SettingsWorkspace";

describe("privacy settings integration", () => {
  it("registers the privacy view inside settings without changing the main product area", () => {
    expect(VIEW_MODES).toContain("privacy");
    expect(VIEW_METADATA.privacy.futureArea).toBe("settings");
    const markup = renderToStaticMarkup(
      <SettingsWorkspace mode="privacy">隐私设置</SettingsWorkspace>,
    );
    expect(markup).toContain('aria-label="隐私与本地处理设置"');
    expect(markup).toContain('class="settings-maintenance-workspace"');
  });

  it("protects an active save and an unsaved privacy draft on close", () => {
    const active = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      privacyMutationInFlight: true,
    });
    expect(active.kind).toBe("block");
    expect("message" in active ? active.message : "").toContain(
      "隐私与本地处理配置写入",
    );

    const dirty = decideWorkspaceClose({
      dirtyCaseDrafts: [],
      providerDraftDirty: false,
      caseMutationInFlight: false,
      providerMutationInFlight: false,
      extractionMutationInFlight: false,
      privacyDraftDirty: true,
    });
    expect(dirty.kind).toBe("confirm_discard");
    expect("message" in dirty ? dirty.message : "").toContain(
      "隐私与本地 OCR 配置",
    );
  });

  it("guards only navigation away from the privacy workspace", () => {
    expect(
      decidePrivacyWorkspaceNavigation("privacy", "privacy", true, true),
    ).toEqual({ kind: "proceed" });
    expect(
      decidePrivacyWorkspaceNavigation("providers", "assistant", true, true),
    ).toEqual({ kind: "proceed" });
    expect(
      decidePrivacyWorkspaceNavigation("privacy", "mcp", true, false).kind,
    ).toBe("block");
    expect(
      decidePrivacyWorkspaceNavigation("privacy", "release", false, true)
        .kind,
    ).toBe("confirm_discard");
  });
});
