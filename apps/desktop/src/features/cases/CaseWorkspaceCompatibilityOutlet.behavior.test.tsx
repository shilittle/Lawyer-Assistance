import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const hookHarness = vi.hoisted(() => {
  interface EffectSlot {
    cleanup: (() => void) | undefined;
    dependencies: readonly unknown[] | undefined;
  }
  interface PendingEffect {
    effect: () => void | (() => void);
    index: number;
    dependencies: readonly unknown[] | undefined;
  }

  let stateSlots: unknown[] = [];
  let effectSlots: Array<EffectSlot | undefined> = [];
  let pendingEffects: PendingEffect[] = [];
  let stateIndex = 0;
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

  return {
    reset(): void {
      for (const slot of effectSlots) {
        slot?.cleanup?.();
      }
      stateSlots = [];
      effectSlots = [];
      pendingEffects = [];
      stateIndex = 0;
      effectIndex = 0;
    },
    render<T>(renderComponent: () => T): T {
      stateIndex = 0;
      effectIndex = 0;
      pendingEffects = [];
      const result = renderComponent();
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

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useEffect: hookHarness.useEffect,
    useState: hookHarness.useState,
  };
});

import type { GraphTargetRequest } from "../../app/routes";
import {
  CaseWorkspaceCompatibilityOutlet,
  type CaseWorkspaceCompatibilityOutletProps,
} from "./CaseWorkspaceCompatibilityOutlet";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

const CONTROLLER = {
  caseState: { kind: "idle" },
} as CaseWorkspaceController;

function props(
  graphTarget: GraphTargetRequest | null,
  onGraphTargetConsumed: (
    target: GraphTargetRequest,
  ) => void = vi.fn(),
): CaseWorkspaceCompatibilityOutletProps {
  return {
    controller: CONTROLLER,
    providerProfiles: [],
    legalSources: [],
    graphTarget,
    onGraphTargetConsumed,
    onContinueInAssistant: vi.fn(),
    onOpenCaseGraph: vi.fn(),
  };
}

function renderedGraphTarget(
  element: ReturnType<typeof CaseWorkspaceCompatibilityOutlet>,
): GraphTargetRequest | null {
  const children = (
    element as unknown as {
      props: {
        children: Array<{
          props: { graphTarget?: GraphTargetRequest | null };
        }>;
      };
    }
  ).props.children;
  return children[1].props.graphTarget ?? null;
}

describe("CaseWorkspaceCompatibilityOutlet graph handoff", () => {
  let scrollIntoView: ReturnType<typeof vi.fn>;
  let focus: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    hookHarness.reset();
    scrollIntoView = vi.fn();
    focus = vi.fn();
    vi.stubGlobal("document", {
      getElementById: vi.fn(() => ({ scrollIntoView, focus })),
    });
    vi.stubGlobal("window", {
      requestAnimationFrame: vi.fn(
        (callback: FrameRequestCallback) =>
          globalThis.setTimeout(() => callback(0), 0),
      ),
      cancelAnimationFrame: vi.fn((handle: ReturnType<typeof setTimeout>) =>
        globalThis.clearTimeout(handle),
      ),
      setTimeout: globalThis.setTimeout,
      clearTimeout: globalThis.clearTimeout,
    });
  });

  afterEach(() => {
    hookHarness.reset();
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("retains the copied target for exactly four seconds after acknowledgement", () => {
    const target = {
      sourceKind: "case_fact",
      sourceId: "fact-1",
    } as const satisfies GraphTargetRequest;
    const acknowledge = vi.fn();
    let outletProps = props(target, acknowledge);
    let element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toBeNull();

    vi.advanceTimersByTime(0);
    expect(acknowledge).toHaveBeenCalledTimes(1);
    expect(acknowledge).toHaveBeenCalledWith(target);

    outletProps = { ...outletProps, graphTarget: null };
    element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toEqual(target);
    vi.advanceTimersByTime(0);
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
    expect(focus).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(3999);
    element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toEqual(target);

    vi.advanceTimersByTime(1);
    element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toBeNull();
    expect(acknowledge).toHaveBeenCalledTimes(1);
  });

  it("restarts the highlight lifetime when a newer graph target arrives", () => {
    const first = {
      sourceKind: "case_fact",
      sourceId: "fact-1",
    } as const satisfies GraphTargetRequest;
    const second = {
      sourceKind: "case_evidence",
      sourceId: "evidence-2",
    } as const satisfies GraphTargetRequest;
    const acknowledge = vi.fn();
    let outletProps = props(first, acknowledge);

    hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    vi.advanceTimersByTime(0);
    outletProps = { ...outletProps, graphTarget: null };
    hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    vi.advanceTimersByTime(0);
    vi.advanceTimersByTime(2000);

    outletProps = { ...outletProps, graphTarget: second };
    hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    vi.advanceTimersByTime(0);
    expect(acknowledge).toHaveBeenNthCalledWith(2, second);

    outletProps = { ...outletProps, graphTarget: null };
    let element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toEqual(second);

    vi.advanceTimersByTime(2000);
    element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toEqual(second);

    vi.advanceTimersByTime(2000);
    element = hookHarness.render(() =>
      CaseWorkspaceCompatibilityOutlet(outletProps),
    );
    expect(renderedGraphTarget(element)).toBeNull();
    expect(acknowledge).toHaveBeenCalledTimes(2);
  });
});
