import { beforeEach, describe, expect, it, vi } from "vitest";

const assistantIpc = vi.hoisted(() => ({
  addAssistantLegalSource: vi.fn(() => Promise.resolve(undefined)),
  proposeAssistantLegalBasis: vi.fn(() => Promise.resolve(undefined)),
}));

const hookHarness = vi.hoisted(() => {
  type StateSlot = {
    value: unknown;
    setValue: (next: unknown) => void;
  };
  type MemoSlot = {
    dependencies: readonly unknown[];
    value: unknown;
  };

  const states: StateSlot[] = [];
  const refs: Array<{ current: unknown }> = [];
  const callbacks: MemoSlot[] = [];
  const memos: MemoSlot[] = [];
  const effects: Array<
    MemoSlot & { cleanup?: (() => void) | undefined }
  > = [];
  let stateCursor = 0;
  let refCursor = 0;
  let callbackCursor = 0;
  let memoCursor = 0;
  let effectCursor = 0;

  const dependenciesEqual = (
    left: readonly unknown[],
    right: readonly unknown[],
  ) =>
    left.length === right.length &&
    left.every((value, index) => Object.is(value, right[index]));

  return {
    beginRender() {
      stateCursor = 0;
      refCursor = 0;
      callbackCursor = 0;
      memoCursor = 0;
      effectCursor = 0;
    },
    reset() {
      states.length = 0;
      refs.length = 0;
      callbacks.length = 0;
      memos.length = 0;
      effects.length = 0;
      this.beginRender();
    },
    useState(initial: unknown) {
      const index = stateCursor;
      stateCursor += 1;
      if (!states[index]) {
        const slot: StateSlot = {
          value:
            typeof initial === "function"
              ? (initial as () => unknown)()
              : initial,
          setValue: () => undefined,
        };
        slot.setValue = (next: unknown) => {
          slot.value =
            typeof next === "function"
              ? (next as (current: unknown) => unknown)(slot.value)
              : next;
        };
        states[index] = slot;
      }
      return [states[index].value, states[index].setValue];
    },
    useRef(initial: unknown) {
      const index = refCursor;
      refCursor += 1;
      if (!refs[index]) {
        refs[index] = { current: initial };
      }
      return refs[index];
    },
    useCallback(callback: unknown, dependencies: readonly unknown[]) {
      const index = callbackCursor;
      callbackCursor += 1;
      const current = callbacks[index];
      if (
        !current ||
        !dependenciesEqual(current.dependencies, dependencies)
      ) {
        callbacks[index] = { dependencies, value: callback };
      }
      return callbacks[index].value;
    },
    useMemo(factory: () => unknown, dependencies: readonly unknown[]) {
      const index = memoCursor;
      memoCursor += 1;
      const current = memos[index];
      if (
        !current ||
        !dependenciesEqual(current.dependencies, dependencies)
      ) {
        memos[index] = { dependencies, value: factory() };
      }
      return memos[index].value;
    },
    useEffect(
      effect: () => void | (() => void),
      dependencies: readonly unknown[],
    ) {
      const index = effectCursor;
      effectCursor += 1;
      const current = effects[index];
      if (
        current &&
        dependenciesEqual(current.dependencies, dependencies)
      ) {
        return;
      }
      current?.cleanup?.();
      const cleanup = effect() ?? undefined;
      effects[index] = {
        dependencies,
        value: undefined,
        cleanup,
      };
    },
  };
});

vi.mock("react", () => ({
  useCallback: hookHarness.useCallback,
  useEffect: hookHarness.useEffect,
  useMemo: hookHarness.useMemo,
  useRef: hookHarness.useRef,
  useState: hookHarness.useState,
}));

vi.mock("../../ipc/assistant/client", () => assistantIpc);

import type { AssistantConversation } from "../../ipc/assistant/types";
import {
  useAssistantController,
  type AssistantController,
} from "./useAssistantController";

function renderController(): AssistantController {
  hookHarness.beginRender();
  // The React exports are replaced by the deterministic hook harness above.
  // eslint-disable-next-line react-hooks/rules-of-hooks
  return useAssistantController();
}

function conversation(
  projectId: string | null = null,
): AssistantConversation {
  return {
    conversationId: "conversation-1",
    projectId,
    title: "测试会话",
    status: "open",
    createdAt: "2026-07-30T00:00:00Z",
    updatedAt: "2026-07-30T00:00:00Z",
  };
}

describe("useAssistantController", () => {
  beforeEach(() => {
    hookHarness.reset();
    assistantIpc.addAssistantLegalSource.mockReset();
    assistantIpc.addAssistantLegalSource.mockResolvedValue(undefined);
    assistantIpc.proposeAssistantLegalBasis.mockReset();
    assistantIpc.proposeAssistantLegalBasis.mockResolvedValue(undefined);
  });

  it("owns stable workspace callbacks and exposes current activity", () => {
    const first = renderController();
    const callbacks = first.workspaceCallbacks;
    const activity = first.activity;
    const addLegalSource = first.addLegalSource;
    const proposeLegalBasisForCase = first.proposeLegalBasisForCase;

    expect(first.conversation).toBeNull();
    expect(first.refreshKey).toBe(0);
    expect(activity.read()).toEqual({
      draftDirty: false,
      mutationActive: false,
      runActive: false,
    });

    callbacks.onConversationChange(conversation());
    callbacks.onDraftDirtyChange(true);
    callbacks.onMutationActivityChange(true);
    callbacks.onRunActivityChange(true);
    const second = renderController();

    expect(second.conversation).toEqual(conversation());
    expect(second.workspaceCallbacks).toBe(callbacks);
    expect(second.activity).toBe(activity);
    expect(second.addLegalSource).toBe(addLegalSource);
    expect(second.proposeLegalBasisForCase).toBe(
      proposeLegalBasisForCase,
    );
    expect(second.activity.read()).toEqual({
      draftDirty: true,
      mutationActive: true,
      runActive: true,
    });
  });

  it("rejects adding a legal source when there is no active conversation", async () => {
    const controller = renderController();

    await expect(controller.addLegalSource("source-1")).rejects.toThrow(
      "当前没有可接收法律来源的助理会话",
    );
    expect(assistantIpc.addAssistantLegalSource).not.toHaveBeenCalled();
  });

  it("adds a legal source to the active conversation and refreshes after success", async () => {
    const first = renderController();
    first.workspaceCallbacks.onConversationChange(conversation());
    const active = renderController();

    await active.addLegalSource("source-1");

    expect(assistantIpc.addAssistantLegalSource).toHaveBeenCalledOnce();
    expect(assistantIpc.addAssistantLegalSource).toHaveBeenCalledWith({
      conversationId: "conversation-1",
      sourceId: "source-1",
    });
    expect(renderController().refreshKey).toBe(1);
  });

  it("does not refresh when adding a legal source fails", async () => {
    const failure = new Error("bridge failed");
    assistantIpc.addAssistantLegalSource.mockRejectedValueOnce(failure);
    const first = renderController();
    first.workspaceCallbacks.onConversationChange(conversation());
    const active = renderController();

    await expect(active.addLegalSource("source-1")).rejects.toBe(failure);
    expect(renderController().refreshKey).toBe(0);
  });

  it("rejects a case proposal without an explicitly matching project", async () => {
    const first = renderController();
    first.workspaceCallbacks.onConversationChange(conversation("case-1"));
    const active = renderController();

    await expect(
      active.proposeLegalBasisForCase("source-1", null),
    ).rejects.toThrow("当前助理会话未绑定所选案件");
    await expect(
      active.proposeLegalBasisForCase("source-1", "case-2"),
    ).rejects.toThrow("当前助理会话未绑定所选案件");
    expect(assistantIpc.proposeAssistantLegalBasis).not.toHaveBeenCalled();
  });

  it("proposes a legal basis for the explicitly matching project", async () => {
    const first = renderController();
    first.workspaceCallbacks.onConversationChange(conversation("case-1"));
    const active = renderController();

    await active.proposeLegalBasisForCase("source-1", "case-1");

    expect(assistantIpc.proposeAssistantLegalBasis).toHaveBeenCalledOnce();
    expect(assistantIpc.proposeAssistantLegalBasis).toHaveBeenCalledWith({
      conversationId: "conversation-1",
      projectId: "case-1",
      sourceId: "source-1",
    });
    expect(renderController().refreshKey).toBe(1);
  });
});
