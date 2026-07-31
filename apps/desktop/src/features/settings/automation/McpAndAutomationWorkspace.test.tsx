import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const childSpies = vi.hoisted(() => ({
  mcp: vi.fn(
    (props: {
      externalDisabled?: boolean;
    }) => (
      <div
        data-child="mcp"
        data-disabled={String(Boolean(props.externalDisabled))}
      />
    ),
  ),
  outbound: vi.fn(
    (props: { disabled?: boolean }) => (
      <div
        data-child="outbound"
        data-disabled={String(Boolean(props.disabled))}
      />
    ),
  ),
  approvedMcp: vi.fn(
    (props: { disabled?: boolean }) => (
      <div
        data-child="approved-mcp"
        data-disabled={String(Boolean(props.disabled))}
      />
    ),
  ),
}));

vi.mock("../../mcp/McpWorkspace", () => ({
  McpWorkspace: childSpies.mcp,
}));
vi.mock("./AutomationOutboundApprovalPanel", () => ({
  AutomationOutboundApprovalPanel: childSpies.outbound,
}));
vi.mock("./ApprovedMcpPanel", () => ({
  ApprovedMcpPanel: childSpies.approvedMcp,
}));

import {
  automationActivityIsActive,
  automationPanelsMayMount,
  McpAndAutomationWorkspaceView,
  updateAutomationActivity,
  type AutomationActivity,
  type AutomationPrivacyGate,
} from "./McpAndAutomationWorkspace";

const IDLE_ACTIVITY: AutomationActivity = {
  mcp: false,
  outbound: false,
  approvedMcp: false,
};

const READY_GATE: AutomationPrivacyGate = {
  phase: "ready",
  configValid: true,
};

function renderView(
  gate: AutomationPrivacyGate,
  activity: AutomationActivity = IDLE_ACTIVITY,
) {
  return renderToStaticMarkup(
    <McpAndAutomationWorkspaceView
      gate={gate}
      activity={activity}
      onDraftDirtyChange={vi.fn()}
      onMcpActivityChange={vi.fn()}
      onOutboundActivityChange={vi.fn()}
      onApprovedMcpActivityChange={vi.fn()}
    />,
  );
}

describe("MCP and automation activity boundary", () => {
  beforeEach(() => {
    childSpies.mcp.mockClear();
    childSpies.outbound.mockClear();
    childSpies.approvedMcp.mockClear();
  });

  it("keeps the aggregate active across interleaved child transitions", () => {
    let activity = IDLE_ACTIVITY;
    expect(automationActivityIsActive(activity)).toBe(false);

    activity = updateAutomationActivity(activity, "outbound", true);
    expect(automationActivityIsActive(activity)).toBe(true);
    activity = updateAutomationActivity(activity, "approvedMcp", true);
    activity = updateAutomationActivity(activity, "outbound", false);
    expect(automationActivityIsActive(activity)).toBe(true);
    activity = updateAutomationActivity(activity, "mcp", true);
    activity = updateAutomationActivity(activity, "approvedMcp", false);
    expect(automationActivityIsActive(activity)).toBe(true);
    activity = updateAutomationActivity(activity, "mcp", false);
    expect(automationActivityIsActive(activity)).toBe(false);
  });

  it("always renders local MCP but does not mount or consume automation before a successful privacy read", () => {
    for (const gate of [
      { phase: "loading" },
      { phase: "error" },
    ] as const) {
      const markup = renderView(gate);
      expect(markup).toContain('data-child="mcp"');
      expect(markup).not.toContain('data-child="outbound"');
      expect(markup).not.toContain('data-child="approved-mcp"');
    }

    expect(childSpies.outbound).not.toHaveBeenCalled();
    expect(childSpies.approvedMcp).not.toHaveBeenCalled();
    expect(automationPanelsMayMount({ phase: "error" })).toBe(false);
  });

  it("keeps both automation panels unmounted when the loaded privacy config is invalid", () => {
    const markup = renderView({
      phase: "ready",
      configValid: false,
    });

    expect(markup).toContain('data-child="mcp"');
    expect(markup).not.toContain('data-child="outbound"');
    expect(markup).not.toContain('data-child="approved-mcp"');
    expect(markup).toContain("自动化面板保持关闭");
    expect(childSpies.outbound).not.toHaveBeenCalled();
    expect(childSpies.approvedMcp).not.toHaveBeenCalled();
    expect(
      automationPanelsMayMount({
        phase: "ready",
        configValid: false,
      }),
    ).toBe(false);
    expect(automationPanelsMayMount(READY_GATE)).toBe(true);
  });

  it("passes dirty state only to local MCP and injects no legacy task into automation", () => {
    const dirty = vi.fn();
    renderToStaticMarkup(
      <McpAndAutomationWorkspaceView
        gate={READY_GATE}
        activity={IDLE_ACTIVITY}
        onDraftDirtyChange={dirty}
        onMcpActivityChange={vi.fn()}
        onOutboundActivityChange={vi.fn()}
        onApprovedMcpActivityChange={vi.fn()}
      />,
    );

    expect(childSpies.mcp.mock.calls.at(-1)?.[0]).toMatchObject({
      onDraftDirtyChange: dirty,
    });
    expect(childSpies.outbound.mock.calls.at(-1)?.[0]).not.toHaveProperty(
      "taskRequest",
    );
    expect(childSpies.approvedMcp.mock.calls.at(-1)?.[0]).not.toHaveProperty(
      "taskRequest",
    );
  });

  it.each([
    [
      "local MCP",
      { mcp: true, outbound: false, approvedMcp: false },
      { mcp: false, outbound: true, approvedMcp: true },
    ],
    [
      "outbound automation",
      { mcp: false, outbound: true, approvedMcp: false },
      { mcp: true, outbound: false, approvedMcp: true },
    ],
    [
      "approved MCP",
      { mcp: false, outbound: false, approvedMcp: true },
      { mcp: true, outbound: true, approvedMcp: false },
    ],
  ] as const)(
    "disables the other two mutation surfaces while %s is active",
    (_label, activity, expected) => {
      renderView(READY_GATE, activity);

      expect(childSpies.mcp.mock.calls.at(-1)?.[0]).toMatchObject({
        externalDisabled: expected.mcp,
      });
      expect(childSpies.outbound.mock.calls.at(-1)?.[0]).toMatchObject({
        disabled: expected.outbound,
      });
      expect(childSpies.approvedMcp.mock.calls.at(-1)?.[0]).toMatchObject({
        disabled: expected.approvedMcp,
      });
    },
  );
});
