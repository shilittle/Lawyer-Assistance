import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import { AppErrorBoundary } from "./AppErrorBoundary";

describe("AppErrorBoundary", () => {
  it("uses a fail-closed fallback without exposing exception text", () => {
    const boundary = new AppErrorBoundary({
      children: "正常内容",
      resetKey: "assistant:chat",
    });
    boundary.state = AppErrorBoundary.getDerivedStateFromError();

    const fallback = boundary.render() as ReactElement<{
      children: ReactElement[];
    }>;
    const serialized = JSON.stringify(fallback);

    expect(serialized).toContain("当前工作区暂时无法显示");
    expect(serialized).toContain("错误边界不会发起外部请求");
    expect(serialized).toContain("不会自动读取案件材料");
    expect(serialized).not.toContain("secret exception");
  });

  it("clears the failure after an explicit retry", () => {
    const boundary = new AppErrorBoundary({
      children: "正常内容",
      resetKey: "assistant:chat",
    });
    boundary.state = { failed: true };
    boundary.setState = vi.fn((next: { failed: boolean }) => {
      boundary.state = next;
    }) as typeof boundary.setState;

    const fallback = boundary.render() as ReactElement<{
      children: ReactElement[];
    }>;
    const retryButton = fallback.props.children[2] as ReactElement<{
      onClick: () => void;
    }>;
    retryButton.props.onClick();

    expect(boundary.state).toEqual({ failed: false });
  });
});
