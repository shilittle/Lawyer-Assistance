import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  addAssistantLegalSource,
  proposeAssistantLegalBasis,
} from "../../ipc/assistant/client";
import type { AssistantConversation } from "../../ipc/assistant/types";

export interface AssistantActivitySnapshot {
  readonly draftDirty: boolean;
  readonly mutationActive: boolean;
  readonly runActive: boolean;
}

export interface AssistantActivityPort {
  read(): AssistantActivitySnapshot;
}

export interface AssistantWorkspaceCallbacks {
  readonly onConversationChange: (
    conversation: AssistantConversation | null,
  ) => void;
  readonly onDraftDirtyChange: (dirty: boolean) => void;
  readonly onMutationActivityChange: (active: boolean) => void;
  readonly onRunActivityChange: (active: boolean) => void;
}

export interface AssistantController {
  readonly conversation: AssistantConversation | null;
  readonly refreshKey: number;
  readonly activity: AssistantActivityPort;
  readonly workspaceCallbacks: AssistantWorkspaceCallbacks;
  readonly addLegalSource: (sourceId: string) => Promise<void>;
  readonly proposeLegalBasisForCase: (
    sourceId: string,
    projectId: string | null,
  ) => Promise<void>;
}

export function useAssistantController(): AssistantController {
  const [conversation, setConversation] =
    useState<AssistantConversation | null>(null);
  const conversationRef = useRef(conversation);
  useEffect(() => {
    conversationRef.current = conversation;
  }, [conversation]);
  const [refreshKey, setRefreshKey] = useState(0);
  const draftDirtyRef = useRef(false);
  const mutationActiveRef = useRef(false);
  const runActiveRef = useRef(false);

  const onConversationChange = useCallback(
    (nextConversation: AssistantConversation | null) => {
      setConversation(nextConversation);
    },
    [],
  );
  const onDraftDirtyChange = useCallback((dirty: boolean) => {
    draftDirtyRef.current = dirty;
  }, []);
  const onMutationActivityChange = useCallback((active: boolean) => {
    mutationActiveRef.current = active;
  }, []);
  const onRunActivityChange = useCallback((active: boolean) => {
    runActiveRef.current = active;
  }, []);

  const workspaceCallbacks = useMemo<AssistantWorkspaceCallbacks>(
    () => ({
      onConversationChange,
      onDraftDirtyChange,
      onMutationActivityChange,
      onRunActivityChange,
    }),
    [
      onConversationChange,
      onDraftDirtyChange,
      onMutationActivityChange,
      onRunActivityChange,
    ],
  );

  const activity = useMemo<AssistantActivityPort>(
    () => ({
      read: () => ({
        draftDirty: draftDirtyRef.current,
        mutationActive: mutationActiveRef.current,
        runActive: runActiveRef.current,
      }),
    }),
    [],
  );

  const addLegalSource = useCallback(async (sourceId: string) => {
    const activeConversation = conversationRef.current;
    if (!activeConversation) {
      throw new Error("当前没有可接收法律来源的助理会话");
    }
    await addAssistantLegalSource({
      conversationId: activeConversation.conversationId,
      sourceId,
    });
    setRefreshKey((current) => current + 1);
  }, []);

  const proposeLegalBasisForCase = useCallback(
    async (sourceId: string, projectId: string | null) => {
      const activeConversation = conversationRef.current;
      if (
        !activeConversation ||
        !projectId ||
        activeConversation.projectId !== projectId
      ) {
        throw new Error("当前助理会话未绑定所选案件");
      }
      await proposeAssistantLegalBasis({
        conversationId: activeConversation.conversationId,
        projectId,
        sourceId,
      });
      setRefreshKey((current) => current + 1);
    },
    [],
  );

  return {
    conversation,
    refreshKey,
    activity,
    workspaceCallbacks,
    addLegalSource,
    proposeLegalBasisForCase,
  };
}
