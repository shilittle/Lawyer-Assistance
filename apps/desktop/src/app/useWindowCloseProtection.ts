import { useCallback, useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import type { AssistantActivityPort } from "../features/assistant/useAssistantController";
import type { CaseCloseGuardPort } from "../features/cases/caseCloseGuard";
import { publicErrorMessage } from "../publicOutput";
import {
  assistantWritesBlockClose,
  decideWorkspaceClose,
  workspaceCloseWasApproved,
} from "./navigationGuards";

export interface BooleanActivityReader {
  readonly readDraftDirty: () => boolean;
  readonly readMutationInFlight: () => boolean;
}

export interface WindowCloseProtectionOptions {
  readonly assistantActivity: AssistantActivityPort;
  readonly caseCloseGuard: CaseCloseGuardPort;
  readonly provider: BooleanActivityReader;
  readonly mcp: BooleanActivityReader;
  readonly privacy: BooleanActivityReader;
  readonly caseMaterials: BooleanActivityReader;
  readonly readLegalBridgeMutationInFlight: () => boolean;
  readonly onCaseCloseBlocked: (message: string) => void;
}

export interface WindowCloseProtection {
  readonly protectionMessage: string | null;
  readonly clearProtectionMessage: () => void;
}

export function useWindowCloseProtection({
  assistantActivity,
  caseCloseGuard,
  provider,
  mcp,
  privacy,
  caseMaterials,
  readLegalBridgeMutationInFlight,
  onCaseCloseBlocked,
}: WindowCloseProtectionOptions): WindowCloseProtection {
  const [protectionMessage, setProtectionMessage] = useState<string | null>(
    null,
  );
  const controlledCloseApproved = useRef(false);
  const ports = useRef({
    assistantActivity,
    caseCloseGuard,
    provider,
    mcp,
    privacy,
    caseMaterials,
    readLegalBridgeMutationInFlight,
    onCaseCloseBlocked,
  });

  useEffect(() => {
    ports.current = {
      assistantActivity,
      caseCloseGuard,
      provider,
      mcp,
      privacy,
      caseMaterials,
      readLegalBridgeMutationInFlight,
      onCaseCloseBlocked,
    };
  }, [
    assistantActivity,
    caseCloseGuard,
    mcp,
    onCaseCloseBlocked,
    privacy,
    caseMaterials,
    provider,
    readLegalBridgeMutationInFlight,
  ]);

  const clearProtectionMessage = useCallback(() => {
    setProtectionMessage(null);
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlistenCloseRequested: (() => void) | undefined;

    const currentCloseDecision = () => {
      const current = ports.current;
      const caseSnapshot = current.caseCloseGuard.read();
      const assistantSnapshot = current.assistantActivity.read();
      return decideWorkspaceClose({
        dirtyCaseDrafts: caseSnapshot.dirtyDrafts,
        providerDraftDirty: current.provider.readDraftDirty(),
        caseMutationInFlight: caseSnapshot.caseMutationInFlight,
        providerMutationInFlight:
          current.provider.readMutationInFlight(),
        extractionMutationInFlight:
          caseSnapshot.extractionMutationInFlight,
        assistantRunActive: assistantSnapshot.runActive,
        assistantMutationInFlight: assistantWritesBlockClose(
          assistantSnapshot.mutationActive,
          current.readLegalBridgeMutationInFlight(),
        ),
        assistantDraftDirty: assistantSnapshot.draftDirty,
        mcpMutationInFlight: current.mcp.readMutationInFlight(),
        mcpDraftDirty: current.mcp.readDraftDirty(),
        privacyMutationInFlight:
          current.privacy.readMutationInFlight(),
        privacyDraftDirty: current.privacy.readDraftDirty(),
        caseMaterialMutationInFlight:
          current.caseMaterials.readMutationInFlight(),
        caseMaterialDraftDirty:
          current.caseMaterials.readDraftDirty(),
      });
    };

    const blockBrowserUnload = (event: BeforeUnloadEvent) => {
      if (controlledCloseApproved.current) return;
      const caseSnapshot = ports.current.caseCloseGuard.read();
      if (
        !caseSnapshot.extractionNeedsFlush &&
        currentCloseDecision().kind === "proceed"
      ) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    };

    window.addEventListener("beforeunload", blockBrowserUnload);
    if ("__TAURI_INTERNALS__" in window) {
      const appWindow = getCurrentWindow();
      void appWindow
        .onCloseRequested(async (event) => {
          if (
            ports.current.caseCloseGuard.read()
              .extractionCloseInProgress
          ) {
            event.preventDefault();
            return;
          }

          const closeDecision = currentCloseDecision();
          if (closeDecision.kind === "block") {
            event.preventDefault();
            setProtectionMessage(closeDecision.message);
            return;
          }

          let forceControlledClose = false;
          if (closeDecision.kind === "confirm_discard") {
            event.preventDefault();
            if (
              !workspaceCloseWasApproved(closeDecision, (message) =>
                window.confirm(message),
              )
            ) {
              setProtectionMessage(
                "已取消关闭；未保存内容仍保留在当前窗口。",
              );
              return;
            }
            forceControlledClose = true;
            controlledCloseApproved.current = true;
          }

          if (
            ports.current.caseCloseGuard.read().extractionNeedsFlush ||
            forceControlledClose
          ) {
            setProtectionMessage(null);
          }
          const result =
            await ports.current.caseCloseGuard.requestControlledClose({
              forceControlledClose,
              preventDefault: () => event.preventDefault(),
              destroyWindow: () => appWindow.destroy(),
              onBlocked: (message) => {
                ports.current.onCaseCloseBlocked(message);
                setProtectionMessage(message);
              },
            });
          if (result === "blocked") {
            controlledCloseApproved.current = false;
          }
        })
        .then((unlisten) => {
          if (disposed) {
            unlisten();
          } else {
            unlistenCloseRequested = unlisten;
          }
        })
        .catch((error: unknown) => {
          if (!disposed) {
            setProtectionMessage(
              `无法注册关闭前草稿保护：${publicErrorMessage(error)}`,
            );
          }
        });
    }

    return () => {
      disposed = true;
      window.removeEventListener("beforeunload", blockBrowserUnload);
      unlistenCloseRequested?.();
    };
  }, []);

  return { protectionMessage, clearProtectionMessage };
}
