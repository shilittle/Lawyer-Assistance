import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const childSpies = vi.hoisted(() => ({
  release: vi.fn(
    (props: {
      disabled?: boolean;
      onActivityChange?: (active: boolean) => void;
    }) => (
      <div
        data-child="release"
        data-disabled={String(Boolean(props.disabled))}
      />
    ),
  ),
  privacyLifecycle: vi.fn(
    (props: {
      disabled?: boolean;
      onActivityChange?: (active: boolean) => void;
    }) => (
      <div
        data-child="privacy-lifecycle"
        data-disabled={String(Boolean(props.disabled))}
      />
    ),
  ),
}));

vi.mock("../../../ReleaseWorkspace", () => ({
  ReleaseWorkspace: childSpies.release,
}));
vi.mock("../../privacy/PrivacyLifecyclePanel", () => ({
  PrivacyLifecyclePanel: childSpies.privacyLifecycle,
}));

import {
  maintenanceActivityIsActive,
  MaintenanceWorkspaceView,
  updateMaintenanceActivity,
  type MaintenanceActivity,
} from "./MaintenanceWorkspace";

const IDLE_ACTIVITY: MaintenanceActivity = {
  release: false,
  privacyLifecycle: false,
};

function renderView(
  activity: MaintenanceActivity = IDLE_ACTIVITY,
  disabled = false,
) {
  return renderToStaticMarkup(
    <MaintenanceWorkspaceView
      activity={activity}
      disabled={disabled}
      onReleaseActivityChange={vi.fn()}
      onPrivacyLifecycleActivityChange={vi.fn()}
    />,
  );
}

describe("MaintenanceWorkspace activity boundary", () => {
  beforeEach(() => {
    childSpies.release.mockClear();
    childSpies.privacyLifecycle.mockClear();
  });

  it("keeps aggregate protection active across interleaved child transitions", () => {
    let activity = IDLE_ACTIVITY;
    expect(maintenanceActivityIsActive(activity)).toBe(false);

    activity = updateMaintenanceActivity(activity, "release", true);
    expect(maintenanceActivityIsActive(activity)).toBe(true);
    activity = updateMaintenanceActivity(
      activity,
      "privacyLifecycle",
      true,
    );
    activity = updateMaintenanceActivity(activity, "release", false);
    expect(maintenanceActivityIsActive(activity)).toBe(true);
    activity = updateMaintenanceActivity(
      activity,
      "privacyLifecycle",
      false,
    );
    expect(maintenanceActivityIsActive(activity)).toBe(false);
  });

  it.each([
    [
      "release",
      { release: true, privacyLifecycle: false },
      { release: false, privacyLifecycle: true },
    ],
    [
      "privacy lifecycle",
      { release: false, privacyLifecycle: true },
      { release: true, privacyLifecycle: false },
    ],
  ] as const)(
    "disables the other maintenance surface while %s is active",
    (_label, activity, expected) => {
      renderView(activity);

      expect(childSpies.release.mock.calls.at(-1)?.[0]).toMatchObject({
        disabled: expected.release,
      });
      expect(
        childSpies.privacyLifecycle.mock.calls.at(-1)?.[0],
      ).toMatchObject({
        disabled: expected.privacyLifecycle,
      });
    },
  );

  it("preserves both independent activity bits and honors an external disable", () => {
    const bothActive = {
      release: true,
      privacyLifecycle: true,
    } as const;
    const markup = renderView(bothActive, true);

    expect(maintenanceActivityIsActive(bothActive)).toBe(true);
    expect(markup).toContain('aria-busy="true"');
    expect(childSpies.release.mock.calls.at(-1)?.[0]).toMatchObject({
      disabled: true,
    });
    expect(
      childSpies.privacyLifecycle.mock.calls.at(-1)?.[0],
    ).toMatchObject({
      disabled: true,
    });
  });

  it("wires separate activity callbacks to the two maintenance owners", () => {
    renderView();

    const releaseCallback = childSpies.release.mock.calls.at(-1)?.[0]
      .onActivityChange;
    const lifecycleCallback = childSpies.privacyLifecycle.mock.calls.at(-1)?.[0]
      .onActivityChange;
    expect(releaseCallback).toEqual(expect.any(Function));
    expect(lifecycleCallback).toEqual(expect.any(Function));
    expect(releaseCallback).not.toBe(lifecycleCallback);
  });
});
