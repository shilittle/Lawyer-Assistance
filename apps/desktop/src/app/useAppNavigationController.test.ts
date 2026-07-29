import { beforeEach, describe, expect, it, vi } from "vitest";

const hookHarness = vi.hoisted(() => {
  let stateSlots: unknown[] = [];
  let refSlots: Array<{ current: unknown }> = [];
  let callbackSlots: Array<{
    callback: (...args: never[]) => unknown;
    dependencies: readonly unknown[];
  }> = [];
  let stateIndex = 0;
  let refIndex = 0;
  let callbackIndex = 0;

  function dependenciesEqual(
    left: readonly unknown[],
    right: readonly unknown[],
  ): boolean {
    return (
      left.length === right.length &&
      left.every((value, index) => Object.is(value, right[index]))
    );
  }

  return {
    reset() {
      stateSlots = [];
      refSlots = [];
      callbackSlots = [];
      stateIndex = 0;
      refIndex = 0;
      callbackIndex = 0;
    },
    render<T>(renderHook: () => T): T {
      stateIndex = 0;
      refIndex = 0;
      callbackIndex = 0;
      return renderHook();
    },
    useState<T>(
      initial: T | (() => T),
    ): [T, (next: T | ((current: T) => T)) => void] {
      const index = stateIndex;
      stateIndex += 1;
      if (!(index in stateSlots)) {
        stateSlots[index] =
          typeof initial === "function"
            ? (initial as () => T)()
            : initial;
      }
      return [
        stateSlots[index] as T,
        (next: T | ((current: T) => T)) => {
          stateSlots[index] =
            typeof next === "function"
              ? (next as (current: T) => T)(stateSlots[index] as T)
              : next;
        },
      ];
    },
    useRef<T>(initial: T): { current: T } {
      const index = refIndex;
      refIndex += 1;
      if (!(index in refSlots)) {
        refSlots[index] = { current: initial };
      }
      return refSlots[index] as { current: T };
    },
    useCallback<T extends (...args: never[]) => unknown>(
      callback: T,
      dependencies: readonly unknown[],
    ): T {
      const index = callbackIndex;
      callbackIndex += 1;
      const current = callbackSlots[index];
      if (
        !current ||
        !dependenciesEqual(current.dependencies, dependencies)
      ) {
        callbackSlots[index] = { callback, dependencies };
      }
      return callbackSlots[index].callback as T;
    },
  };
});

vi.mock("react", () => ({
  useCallback: hookHarness.useCallback,
  useRef: hookHarness.useRef,
  useState: hookHarness.useState,
}));

import type { AppRoute } from "./routes";
import {
  useAppNavigationController,
  type AppNavigationController,
  type NavigationProtectionChannel,
  type UseAppNavigationControllerOptions,
} from "./useAppNavigationController";

interface BooleanBox {
  current: boolean;
}

function booleanRef(current = false): BooleanBox {
  return { current };
}

function protectionChannel(
  mutationInFlight = booleanRef(),
  draftDirty = booleanRef(),
): NavigationProtectionChannel {
  return {
    readMutationInFlight: () => mutationInFlight.current,
    readDraftDirty: () => draftDirty.current,
    discardDraft: () => {
      draftDirty.current = false;
    },
  };
}

function controllerOptions(
  patch: Partial<UseAppNavigationControllerOptions> = {},
): UseAppNavigationControllerOptions {
  return {
    mcp: protectionChannel(),
    privacy: protectionChannel(),
    confirmDiscard: vi.fn(() => true),
    ...patch,
  };
}

function renderController(
  options: UseAppNavigationControllerOptions,
): AppNavigationController {
  return hookHarness.render(() => useAppNavigationController(options));
}

describe("useAppNavigationController", () => {
  beforeEach(() => {
    hookHarness.reset();
  });

  it("keeps callbacks stable while reading the latest protection refs", () => {
    const latestMcpMutation = booleanRef(false);
    const initialOptions = controllerOptions({
      mcp: protectionChannel(latestMcpMutation),
    });
    const initial = renderController(initialOptions);
    const callbacks = {
      navigate: initial.navigate,
      clearProtectionMessage: initial.clearProtectionMessage,
      handoffAssistantCase: initial.handoffAssistantCase,
      handoffApprovedProvider: initial.handoffApprovedProvider,
      handoffGraphTarget: initial.handoffGraphTarget,
      handoffLegalCitation: initial.handoffLegalCitation,
      consumeRouteState: initial.consumeRouteState,
    };
    latestMcpMutation.current = true;
    const latestOptions: UseAppNavigationControllerOptions = {
      ...initialOptions,
      mcp: { ...initialOptions.mcp },
      privacy: { ...initialOptions.privacy },
    };
    const rerendered = renderController(latestOptions);

    for (const [name, callback] of Object.entries(callbacks)) {
      expect(rerendered[name as keyof typeof callbacks]).toBe(callback);
    }

    expect(
      rerendered.navigate({ area: "cases", page: "overview" }),
    ).toBe(false);
    const blocked = renderController(latestOptions);
    expect(blocked.route).toEqual({ area: "assistant", page: "chat" });
    expect(blocked.protectionMessage).toBe(
      "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    );
  });

  it("changes only route state at one location without invoking leave confirmation", () => {
    const confirmDiscard = vi.fn(() => false);
    const mcpMutation = booleanRef(true);
    const mcpDraft = booleanRef(true);
    const privacyMutation = booleanRef(true);
    const privacyDraft = booleanRef(true);
    const options = controllerOptions({
      initialRoute: {
        area: "settings",
        page: "privacy",
        state: {
          kind: "approved-provider-task",
          request: {
            task: "case_legal_qa",
            notice: "第一次",
            requestId: 1,
          },
        },
      },
      mcp: protectionChannel(mcpMutation, mcpDraft),
      privacy: protectionChannel(privacyMutation, privacyDraft),
      confirmDiscard,
    });
    const controller = renderController(options);
    const nextRoute = {
      area: "settings",
      page: "privacy",
      state: {
        kind: "approved-provider-task",
        request: {
          task: "document_generation",
          notice: "第二次",
          requestId: 2,
        },
      },
    } as const satisfies AppRoute;

    expect(controller.navigate(nextRoute)).toBe(true);
    const rerendered = renderController(options);
    expect(rerendered.route).toEqual(nextRoute);
    expect(rerendered.protectionMessage).toBeNull();
    expect(confirmDiscard).not.toHaveBeenCalled();
    expect(mcpDraft.current).toBe(true);
    expect(privacyDraft.current).toBe(true);
  });

  it("preserves block, decline, and confirmed-discard navigation messages", () => {
    const mcpMutation = booleanRef(true);
    const mcpDraft = booleanRef(false);
    const confirmDiscard = vi.fn(() => false);
    const options = controllerOptions({
      mcp: protectionChannel(mcpMutation, mcpDraft),
      confirmDiscard,
    });
    let controller = renderController(options);
    const casesRoute = {
      area: "cases",
      page: "overview",
    } as const satisfies AppRoute;

    expect(controller.navigate(casesRoute)).toBe(false);
    controller = renderController(options);
    expect(controller.protectionMessage).toBe(
      "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    );

    mcpMutation.current = false;
    mcpDraft.current = true;
    expect(controller.navigate(casesRoute)).toBe(false);
    controller = renderController(options);
    expect(controller.protectionMessage).toBe(
      "已取消切换；未保存的 MCP 设置仍保留在当前工作区。",
    );
    expect(mcpDraft.current).toBe(true);

    confirmDiscard.mockReturnValue(true);
    expect(controller.navigate(casesRoute)).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual(casesRoute);
    expect(controller.protectionMessage).toBeNull();
    expect(mcpDraft.current).toBe(false);
  });

  it("protects Privacy only when leaving its typed location", () => {
    const privacyMutation = booleanRef(true);
    const privacyDraft = booleanRef(true);
    const outsideOptions = controllerOptions({
      initialRoute: { area: "settings", page: "providers" },
      privacy: protectionChannel(privacyMutation, privacyDraft),
      confirmDiscard: vi.fn(() => false),
    });
    const outside = renderController(outsideOptions);

    expect(
      outside.navigate({ area: "assistant", page: "chat" }),
    ).toBe(true);

    hookHarness.reset();
    const privacyOptions = controllerOptions({
      initialRoute: { area: "settings", page: "privacy" },
      privacy: protectionChannel(privacyMutation, privacyDraft),
    });
    let privacy = renderController(privacyOptions);
    expect(
      privacy.navigate({ area: "settings", page: "providers" }),
    ).toBe(false);
    privacy = renderController(privacyOptions);
    expect(privacy.route).toEqual({
      area: "settings",
      page: "privacy",
    });
    expect(privacy.protectionMessage).toBe(
      "隐私与本地处理配置正在写入；为避免结果不明，已阻止切换工作区。请等待保存完成后重试。",
    );
  });

  it("creates monotonic Assistant handoffs and retains the host route while hidden", () => {
    const options = controllerOptions();
    let controller = renderController(options);

    expect(
      controller.handoffAssistantCase({
        projectId: "case-1",
        title: "案件一",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({
      area: "assistant",
      page: "chat",
      state: {
        kind: "assistant-case-handoff",
        request: {
          projectId: "case-1",
          title: "案件一",
          requestId: 1,
        },
      },
    });
    const retainedRoute = controller.assistantHostRoute;

    expect(
      controller.navigate({ area: "cases", page: "overview" }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({ area: "cases", page: "overview" });
    expect(controller.assistantHostRoute).toEqual(retainedRoute);

    expect(
      controller.handoffAssistantCase({
        projectId: "case-2",
        title: "案件二",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.assistantHostRoute.state?.request).toEqual({
      projectId: "case-2",
      title: "案件二",
      requestId: 2,
    });
  });

  it("constructs approved Provider, graph-target, and legal-citation routes", () => {
    const options = controllerOptions();
    let controller = renderController(options);

    expect(
      controller.handoffApprovedProvider({
        task: "case_legal_qa",
        notice: "必须先批准",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({
      area: "settings",
      page: "privacy",
      state: {
        kind: "approved-provider-task",
        request: {
          task: "case_legal_qa",
          notice: "必须先批准",
          requestId: 1,
        },
      },
    });
    expect(controller.consumeRouteState(controller.route)).toBe(true);
    controller = renderController(options);

    expect(
      controller.handoffApprovedProvider({
        task: "summary",
        notice: "第二次批准",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route.state?.request).toMatchObject({ requestId: 2 });

    expect(
      controller.handoffGraphTarget({
        sourceKind: "case_fact",
        sourceId: "fact-1",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({
      area: "cases",
      page: "work",
      state: {
        kind: "graph-target",
        request: {
          sourceKind: "case_fact",
          sourceId: "fact-1",
        },
      },
    });

    expect(
      controller.handoffLegalCitation({
        sourceId: "citation-1",
        documentId: "document-1",
        versionId: "version-1",
        articleId: "article-1",
      }),
    ).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({
      area: "legal-library",
      page: "library",
      state: {
        kind: "legal-citation",
        request: {
          sourceId: "citation-1",
          documentId: "document-1",
          versionId: "version-1",
          articleId: "article-1",
        },
      },
    });
  });

  it("consumes non-Assistant state only when location and request still match", () => {
    const options = controllerOptions();
    let controller = renderController(options);
    const citationRequest = {
      sourceId: "citation-1",
      documentId: "document-1",
      versionId: "version-1",
      articleId: "article-1",
    } as const;

    expect(controller.handoffLegalCitation(citationRequest)).toBe(true);
    controller = renderController(options);
    const capturedCitationRoute = controller.route;

    expect(
      controller.handoffGraphTarget({
        sourceKind: "case_fact",
        sourceId: "fact-current",
      }),
    ).toBe(true);
    controller = renderController(options);
    const currentGraphRoute = controller.route;

    expect(controller.consumeRouteState(capturedCitationRoute)).toBe(false);
    expect(renderController(options).route).toEqual(currentGraphRoute);

    const wrongGraphRoute = {
      area: "cases",
      page: "work",
      state: {
        kind: "graph-target",
        request: {
          sourceKind: "case_fact",
          sourceId: "fact-stale",
        },
      },
    } as const satisfies AppRoute;
    expect(controller.consumeRouteState(wrongGraphRoute)).toBe(false);
    expect(controller.consumeRouteState(currentGraphRoute)).toBe(true);
    controller = renderController(options);
    expect(controller.route).toEqual({ area: "cases", page: "work" });

    expect(
      controller.handoffAssistantCase({
        projectId: "case-assistant",
        title: "助理案件",
      }),
    ).toBe(true);
    controller = renderController(options);
    const assistantRoute = controller.route;
    expect(controller.consumeRouteState(assistantRoute)).toBe(false);
    expect(renderController(options).route).toEqual(assistantRoute);
  });

  it("rejects a stale Provider acknowledgement after a newer request replaces it", () => {
    const options = controllerOptions();
    let controller = renderController(options);

    expect(
      controller.handoffApprovedProvider({
        task: "case_legal_qa",
        notice: "第一次批准",
      }),
    ).toBe(true);
    controller = renderController(options);
    const firstRoute = controller.route;

    expect(
      controller.handoffApprovedProvider({
        task: "document_generation",
        notice: "第二次批准",
      }),
    ).toBe(true);
    controller = renderController(options);
    const secondRoute = controller.route;

    expect(controller.consumeRouteState(firstRoute)).toBe(false);
    expect(renderController(options).route).toEqual(secondRoute);
    expect(controller.consumeRouteState(secondRoute)).toBe(true);
    expect(renderController(options).route).toEqual({
      area: "settings",
      page: "privacy",
    });
  });
});
