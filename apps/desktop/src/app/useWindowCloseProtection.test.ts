import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const hookHarness = vi.hoisted(() => {
  type Cleanup = (() => void) | undefined;
  interface EffectSlot {
    cleanup: Cleanup;
    dependencies: readonly unknown[] | undefined;
  }
  interface PendingEffect {
    effect: () => void | (() => void);
    index: number;
    dependencies: readonly unknown[] | undefined;
  }

  let stateSlots: unknown[] = [];
  let refSlots: Array<{ current: unknown }> = [];
  let effectSlots: Array<EffectSlot | undefined> = [];
  let pendingEffects: PendingEffect[] = [];
  let stateIndex = 0;
  let refIndex = 0;
  let effectIndex = 0;

  function dependenciesEqual(
    left: readonly unknown[] | undefined,
    right: readonly unknown[] | undefined,
  ): boolean {
    return (
      left !== undefined &&
      right !== undefined &&
      left.length === right.length &&
      left.every((value, index) => Object.is(value, right[index]))
    );
  }

  function cleanupEffects(): void {
    for (const slot of effectSlots) {
      slot?.cleanup?.();
    }
  }

  return {
    reset(): void {
      cleanupEffects();
      stateSlots = [];
      refSlots = [];
      effectSlots = [];
      pendingEffects = [];
      stateIndex = 0;
      refIndex = 0;
      effectIndex = 0;
    },
    render<T>(renderHook: () => T): T {
      stateIndex = 0;
      refIndex = 0;
      effectIndex = 0;
      pendingEffects = [];
      const result = renderHook();
      for (const pending of pendingEffects) {
        effectSlots[pending.index]?.cleanup?.();
        const cleanup = pending.effect();
        effectSlots[pending.index] = {
          cleanup: typeof cleanup === "function" ? cleanup : undefined,
          dependencies: pending.dependencies,
        };
      }
      return result;
    },
    useCallback<T extends (...args: never[]) => unknown>(callback: T): T {
      return callback;
    },
    useEffect(
      effect: () => void | (() => void),
      dependencies?: readonly unknown[],
    ): void {
      const index = effectIndex;
      effectIndex += 1;
      const current = effectSlots[index];
      if (
        !current ||
        !dependenciesEqual(current.dependencies, dependencies)
      ) {
        pendingEffects.push({ effect, index, dependencies });
      }
    },
    useRef<T>(initial: T): { current: T } {
      const index = refIndex;
      refIndex += 1;
      if (!(index in refSlots)) {
        refSlots[index] = { current: initial };
      }
      return refSlots[index] as { current: T };
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
  };
});

const tauriWindowMock = vi.hoisted(() => ({
  getCurrentWindow: vi.fn(),
}));

vi.mock("react", () => ({
  useCallback: hookHarness.useCallback,
  useEffect: hookHarness.useEffect,
  useRef: hookHarness.useRef,
  useState: hookHarness.useState,
}));

vi.mock("@tauri-apps/api/window", () => tauriWindowMock);

import type { AssistantActivityPort } from "../features/assistant/useAssistantController";
import type {
  CaseCloseGuardPort,
  CaseCloseSnapshot,
} from "../features/cases/caseCloseGuard";
import {
  useWindowCloseProtection,
  type BooleanActivityReader,
  type WindowCloseProtectionOptions,
} from "./useWindowCloseProtection";

const CLEAN_CASE_SNAPSHOT: CaseCloseSnapshot = {
  dirtyDrafts: [],
  caseMutationInFlight: false,
  extractionMutationInFlight: false,
  extractionNeedsFlush: false,
  extractionCloseInProgress: false,
};

function assistantActivity(
  patch: Partial<ReturnType<AssistantActivityPort["read"]>> = {},
): AssistantActivityPort {
  return {
    read: () => ({
      draftDirty: false,
      mutationActive: false,
      runActive: false,
      ...patch,
    }),
  };
}

function activityReader(
  draftDirty = false,
  mutationInFlight = false,
): BooleanActivityReader {
  return {
    readDraftDirty: () => draftDirty,
    readMutationInFlight: () => mutationInFlight,
  };
}

function caseCloseGuard(
  snapshot: CaseCloseSnapshot = CLEAN_CASE_SNAPSHOT,
): CaseCloseGuardPort {
  return {
    read: () => snapshot,
    requestControlledClose: vi.fn(async () => "allow" as const),
  };
}

function options(
  patch: Partial<WindowCloseProtectionOptions> = {},
): WindowCloseProtectionOptions {
  return {
    assistantActivity: assistantActivity(),
    caseCloseGuard: caseCloseGuard(),
    provider: activityReader(),
    mcp: activityReader(),
    privacy: activityReader(),
    caseMaterials: activityReader(),
    readLegalBridgeMutationInFlight: () => false,
    onCaseCloseBlocked: vi.fn(),
    ...patch,
  };
}

function beforeUnloadEvent(): BeforeUnloadEvent {
  return {
    preventDefault: vi.fn(),
    returnValue: undefined,
  } as unknown as BeforeUnloadEvent;
}

describe("useWindowCloseProtection", () => {
  type NativeCloseHandler = (event: {
    preventDefault: () => void;
  }) => Promise<void>;

  let listener: ((event: BeforeUnloadEvent) => void) | undefined;
  let addEventListener: ReturnType<typeof vi.fn>;
  let removeEventListener: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    hookHarness.reset();
    tauriWindowMock.getCurrentWindow.mockReset();
    listener = undefined;
    addEventListener = vi.fn(
      (
        type: string,
        nextListener: (event: BeforeUnloadEvent) => void,
      ) => {
        if (type === "beforeunload") listener = nextListener;
      },
    );
    removeEventListener = vi.fn();
    vi.stubGlobal("window", {
      addEventListener,
      removeEventListener,
    });
  });

  afterEach(() => {
    hookHarness.reset();
    vi.unstubAllGlobals();
  });

  it("registers once and evaluates beforeunload with the latest activity ports", () => {
    const initialOptions = options();
    hookHarness.render(() =>
      useWindowCloseProtection(initialOptions),
    );

    expect(addEventListener).toHaveBeenCalledTimes(1);
    const cleanEvent = beforeUnloadEvent();
    listener?.(cleanEvent);
    expect(cleanEvent.preventDefault).not.toHaveBeenCalled();

    const activeOptions: WindowCloseProtectionOptions = {
      ...initialOptions,
      assistantActivity: assistantActivity({ runActive: true }),
    };
    hookHarness.render(() =>
      useWindowCloseProtection(activeOptions),
    );

    expect(addEventListener).toHaveBeenCalledTimes(1);
    const activeEvent = beforeUnloadEvent();
    listener?.(activeEvent);
    expect(activeEvent.preventDefault).toHaveBeenCalledTimes(1);
    expect(activeEvent.returnValue).toBe("");
  });

  it("blocks browser unload while an extraction draft still needs flushing", () => {
    hookHarness.render(() =>
      useWindowCloseProtection(
        options({
          caseCloseGuard: caseCloseGuard({
            ...CLEAN_CASE_SNAPSHOT,
            extractionNeedsFlush: true,
          }),
        }),
      ),
    );

    const event = beforeUnloadEvent();
    listener?.(event);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    expect(event.returnValue).toBe("");
  });

  it("protects browser unload for case-material edits and operations", () => {
    const hookOptions = options({
      caseMaterials: activityReader(true),
    });
    hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );

    const event = beforeUnloadEvent();
    listener?.(event);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);

    hookHarness.render(() =>
      useWindowCloseProtection({
        ...hookOptions,
        caseMaterials: activityReader(false, true),
      }),
    );
    const activeEvent = beforeUnloadEvent();
    listener?.(activeEvent);
    expect(activeEvent.preventDefault).toHaveBeenCalledTimes(1);
  });

  it("removes the registered browser listener on cleanup", () => {
    hookHarness.render(() => useWindowCloseProtection(options()));

    hookHarness.reset();

    expect(removeEventListener).toHaveBeenCalledTimes(1);
    expect(removeEventListener).toHaveBeenCalledWith(
      "beforeunload",
      listener,
    );
  });

  function installNativeWindow(confirmResult = true): {
    confirm: ReturnType<typeof vi.fn>;
    destroy: ReturnType<typeof vi.fn>;
    readCloseHandler: () => NativeCloseHandler | undefined;
    unlisten: ReturnType<typeof vi.fn>;
  } {
    let closeHandler: NativeCloseHandler | undefined;
    const confirm = vi.fn(() => confirmResult);
    const destroy = vi.fn(async () => undefined);
    const unlisten = vi.fn();
    tauriWindowMock.getCurrentWindow.mockReturnValue({
      destroy,
      onCloseRequested: vi.fn(
        async (handler: NativeCloseHandler) => {
          closeHandler = handler;
          return unlisten;
        },
      ),
    });
    vi.stubGlobal("window", {
      __TAURI_INTERNALS__: {},
      addEventListener,
      removeEventListener,
      confirm,
    });
    return {
      confirm,
      destroy,
      readCloseHandler: () => closeHandler,
      unlisten,
    };
  }

  it("blocks a native close while Assistant work is active", async () => {
    const native = installNativeWindow();
    const hookOptions = options({
      assistantActivity: assistantActivity({ runActive: true }),
    });
    let protection = hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );
    await Promise.resolve();

    const event = { preventDefault: vi.fn() };
    await native.readCloseHandler()?.(event);
    protection = hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );

    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    expect(protection.protectionMessage).toContain(
      "助理任务仍在运行",
    );
    expect(native.confirm).not.toHaveBeenCalled();
  });

  it("keeps native drafts when the user declines discard", async () => {
    const native = installNativeWindow(false);
    const hookOptions = options({
      provider: activityReader(true),
    });
    let protection = hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );
    await Promise.resolve();

    const event = { preventDefault: vi.fn() };
    await native.readCloseHandler()?.(event);
    protection = hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );

    expect(native.confirm).toHaveBeenCalledTimes(1);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    expect(protection.protectionMessage).toBe(
      "已取消关闭；未保存内容仍保留在当前窗口。",
    );
  });

  it("restores unload protection when an approved controlled close is blocked", async () => {
    const native = installNativeWindow(true);
    const guardedClose = caseCloseGuard({
      ...CLEAN_CASE_SNAPSHOT,
      extractionNeedsFlush: true,
    });
    vi.mocked(guardedClose.requestControlledClose).mockImplementation(
      async (request) => {
        request.preventDefault();
        return "blocked";
      },
    );
    const hookOptions = options({
      caseCloseGuard: guardedClose,
      provider: activityReader(true),
    });
    hookHarness.render(() =>
      useWindowCloseProtection(hookOptions),
    );
    await Promise.resolve();

    const nativeEvent = { preventDefault: vi.fn() };
    await native.readCloseHandler()?.(nativeEvent);
    expect(native.confirm).toHaveBeenCalledTimes(1);
    expect(
      guardedClose.requestControlledClose,
    ).toHaveBeenCalledWith(
      expect.objectContaining({ forceControlledClose: true }),
    );

    const browserEvent = beforeUnloadEvent();
    listener?.(browserEvent);
    expect(browserEvent.preventDefault).toHaveBeenCalledTimes(1);
  });
});
