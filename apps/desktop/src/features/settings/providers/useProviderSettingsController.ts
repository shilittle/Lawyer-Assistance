import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  deleteProviderApiKey,
  deleteProviderProfile,
  getProviderApiKeyStatus,
  listProviderProfiles,
  testProviderConnection,
  upsertProviderProfile,
  writeProviderApiKey,
} from "../../../ipc/provider/client";
import {
  createProviderProfileDraft,
  DEFAULT_PROVIDER_KIND,
  defaultProviderOptions,
  providerCapabilities,
  providerDefaults,
} from "../../../ipc/provider/catalog";
import {
  loadProviderKeyStatusesSettled,
  normalizeProviderProfile,
  providerKeyStatusForSavedDraft,
  providerProfilesEqual,
} from "../../../ipc/provider/profile";
import type {
  ConnectionTest,
  ProviderApiKeyStatus,
  ProviderKind,
  ProviderOptions,
  ProviderProfile,
} from "../../../ipc/provider/types";
import { publicErrorMessage } from "../../../publicOutput";
import type { RunConfirmedDestructiveAction } from "./policies";

export type ProviderSettingsLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string };

export interface ProviderSettingsPolicies {
  hasUnsavedChanges: (
    baseline: ProviderProfile,
    draft: ProviderProfile,
    apiKeyInput: string,
  ) => boolean;
  providerDeletionConfirmation: (
    displayName: string,
    accountId: string,
  ) => string;
  apiKeyDeletionConfirmation: (
    displayName: string,
    accountId: string,
  ) => string;
  apiKeyOverwriteConfirmation: (
    displayName: string,
    accountId: string,
  ) => string;
  runConfirmedDestructiveAction: RunConfirmedDestructiveAction;
  confirmAction: (message: string) => boolean;
}

export interface UseProviderSettingsControllerOptions {
  policies: ProviderSettingsPolicies;
  deletionBlockedProviderId: string | null;
}

export interface ProviderSettingsController {
  state: ProviderSettingsLoadState;
  profiles: ProviderProfile[];
  draft: ProviderProfile;
  selectedProviderId: string | null;
  apiKeyInput: string;
  keyStatuses: Record<string, ProviderApiKeyStatus>;
  currentKeyStatus: ProviderApiKeyStatus | undefined;
  currentConnectionResult: ConnectionTest | undefined;
  busy: boolean;
  isSaved: boolean;
  draftIsDirty: boolean;
  hasKey: boolean;
  hasUnsavedChanges: boolean;
  hasUnsavedChangesRef: { current: boolean };
  mutationInFlightRef: { current: boolean };
  setApiKeyInput: (value: string) => void;
  updateDraft: (patch: Partial<ProviderProfile>) => void;
  updateKind: (kind: ProviderKind) => void;
  updateOptions: (patch: Partial<ProviderOptions>) => void;
  startNewProvider: (kind: ProviderKind) => void;
  selectProvider: (profile: ProviderProfile) => void;
  discardDraftChanges: () => void;
  saveProvider: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  saveApiKey: () => Promise<void>;
  removeApiKey: () => Promise<void>;
  removeProvider: () => Promise<void>;
  runConnectionTest: () => Promise<void>;
}

function createId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 7)}`;
}

function createProviderProfile(kind: ProviderKind): ProviderProfile {
  return createProviderProfileDraft(kind, createId(kind));
}

export function useProviderSettingsController({
  policies,
  deletionBlockedProviderId,
}: UseProviderSettingsControllerOptions): ProviderSettingsController {
  const [state, setState] = useState<ProviderSettingsLoadState>({
    kind: "idle",
  });
  const [profiles, setProfiles] = useState<ProviderProfile[]>([]);
  const [draft, setDraft] = useState<ProviderProfile>(() =>
    createProviderProfile(DEFAULT_PROVIDER_KIND),
  );
  const draftBaseline = useRef(draft);
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
    null,
  );
  const [apiKeyInput, setApiKeyInput] = useState("");
  const mutationInFlightRef = useRef(false);
  const [keyStatuses, setKeyStatuses] = useState<
    Record<string, ProviderApiKeyStatus>
  >({});
  const [connectionResults, setConnectionResults] = useState<
    Record<string, ConnectionTest>
  >({});

  const hasUnsavedChanges = policies.hasUnsavedChanges(
    draftBaseline.current,
    draft,
    apiKeyInput,
  );
  const hasUnsavedChangesRef = useRef(hasUnsavedChanges);
  hasUnsavedChangesRef.current = hasUnsavedChanges;

  const refreshKeyStatus = useCallback(async (profile: ProviderProfile) => {
    const response = await getProviderApiKeyStatus({
      providerId: profile.id,
      accountId: profile.credentialAccountId,
    });

    setKeyStatuses((current) => ({
      ...current,
      [profile.id]: response.status,
    }));
  }, []);

  useEffect(() => {
    let isMounted = true;
    setState({ kind: "loading" });

    listProviderProfiles()
      .then(async (response) => {
        if (!isMounted) {
          return;
        }

        setProfiles(response.profiles);
        if (response.profiles.length > 0) {
          const firstProfile = response.profiles[0];
          setSelectedProviderId(firstProfile.id);
          setDraft(firstProfile);
          draftBaseline.current = firstProfile;
        }

        const statusResult = await loadProviderKeyStatusesSettled(
          response.profiles,
          async (profile) => {
            const statusResponse = await getProviderApiKeyStatus({
              providerId: profile.id,
              accountId: profile.credentialAccountId,
            });

            return statusResponse.status;
          },
        );

        if (isMounted) {
          setKeyStatuses(statusResult.statuses);
          if (statusResult.failedCount > 0) {
            setState({
              kind: "error",
              message: `${statusResult.failedCount} 个 Provider 的凭据状态读取失败，可重试对应操作。`,
            });
          } else {
            setState({ kind: "idle" });
          }
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setState({ kind: "error", message: publicErrorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  function blockNavigationForDirtyDraft(action: string): boolean {
    if (!hasUnsavedChangesRef.current) {
      return false;
    }
    setState({
      kind: "error",
      message: `${action}会丢弃未保存的 Profile 或 API Key 输入。请先保存，或手动还原当前草稿。`,
    });
    return true;
  }

  function discardDraftChanges() {
    setDraft(draftBaseline.current);
    setApiKeyInput("");
    setState({ kind: "idle" });
  }

  function applyNewProviderDraft(kind: ProviderKind) {
    const profile = createProviderProfile(kind);
    setSelectedProviderId(null);
    setDraft(profile);
    draftBaseline.current = profile;
    setApiKeyInput("");
    setState({ kind: "idle" });
  }

  function startNewProvider(kind: ProviderKind) {
    if (blockNavigationForDirtyDraft("新建 Provider")) {
      return;
    }
    applyNewProviderDraft(kind);
  }

  function selectProvider(profile: ProviderProfile) {
    if (profile.id === selectedProviderId) {
      return;
    }
    if (blockNavigationForDirtyDraft("切换 Provider")) {
      return;
    }
    setSelectedProviderId(profile.id);
    setDraft(profile);
    draftBaseline.current = profile;
    setApiKeyInput("");
    setState({ kind: "idle" });
  }

  function updateDraft(patch: Partial<ProviderProfile>) {
    setDraft((current) => ({ ...current, ...patch }));
  }

  function updateKind(kind: ProviderKind) {
    const defaults = providerDefaults(kind);
    setDraft((current) => ({
      ...current,
      kind,
      displayName: defaults.displayName,
      modelId: defaults.modelId,
      baseUrl: defaults.baseUrl,
      capabilities: providerCapabilities(kind),
      options: defaultProviderOptions(kind),
    }));
  }

  function updateOptions(patch: Partial<ProviderOptions>) {
    setDraft((current) => ({
      ...current,
      options: {
        ...current.options,
        ...patch,
      },
    }));
  }

  function clearConnectionResult(profileId: string) {
    setConnectionResults((current) => {
      if (!(profileId in current)) {
        return current;
      }

      const next = { ...current };
      delete next[profileId];
      return next;
    });
  }

  async function saveProvider(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mutationInFlightRef.current) {
      return;
    }
    const profile = normalizeProviderProfile(draft);

    mutationInFlightRef.current = true;
    setState({ kind: "loading" });

    try {
      const response = await upsertProviderProfile({ profile });
      setProfiles((current) => {
        const others = current.filter((item) => item.id !== response.profile.id);
        return [response.profile, ...others];
      });
      setDraft(response.profile);
      draftBaseline.current = response.profile;
      setSelectedProviderId(response.profile.id);
      clearConnectionResult(response.profile.id);
      await refreshKeyStatus(response.profile);
      setState({ kind: "idle" });
    } catch (error: unknown) {
      setState({ kind: "error", message: publicErrorMessage(error) });
    } finally {
      mutationInFlightRef.current = false;
    }
  }

  async function saveApiKey() {
    const profile = normalizeProviderProfile(draft);
    const apiKey = apiKeyInput.trim();

    if (!apiKey) {
      return;
    }

    const save = async () => {
      if (mutationInFlightRef.current) {
        return;
      }
      mutationInFlightRef.current = true;
      setState({ kind: "loading" });
      try {
        const response = await writeProviderApiKey({
          providerId: profile.id,
          accountId: profile.credentialAccountId,
          apiKey,
        });
        setKeyStatuses((current) => ({
          ...current,
          [profile.id]: response.status,
        }));
        clearConnectionResult(profile.id);
        setApiKeyInput("");
        setState({ kind: "idle" });
      } catch (error: unknown) {
        setState({ kind: "error", message: publicErrorMessage(error) });
      } finally {
        mutationInFlightRef.current = false;
      }
    };
    const savedProfile = profiles.find((item) => item.id === profile.id);
    const keyStatus = providerKeyStatusForSavedDraft(
      savedProfile,
      profile,
      keyStatuses[profile.id],
    );
    if (!keyStatus) {
      setState({
        kind: "error",
        message:
          "尚未可靠读取当前凭据状态，已阻止写入以免无提示覆盖旧 Key。请先重新保存 Profile 刷新状态。",
      });
      return;
    }
    if (keyStatus.configured) {
      await policies.runConfirmedDestructiveAction(
        policies.apiKeyOverwriteConfirmation(
          profile.displayName,
          profile.credentialAccountId,
        ),
        policies.confirmAction,
        save,
      );
    } else {
      await save();
    }
  }

  async function removeApiKey() {
    const profile = normalizeProviderProfile(draft);
    await policies.runConfirmedDestructiveAction(
      policies.apiKeyDeletionConfirmation(
        profile.displayName,
        profile.credentialAccountId,
      ),
      policies.confirmAction,
      async () => {
        if (mutationInFlightRef.current) {
          return;
        }
        mutationInFlightRef.current = true;
        setState({ kind: "loading" });
        try {
          const response = await deleteProviderApiKey({
            providerId: profile.id,
            accountId: profile.credentialAccountId,
          });
          setKeyStatuses((current) => ({
            ...current,
            [profile.id]: response.status,
          }));
          clearConnectionResult(profile.id);
          setState({ kind: "idle" });
        } catch (error: unknown) {
          setState({ kind: "error", message: publicErrorMessage(error) });
        } finally {
          mutationInFlightRef.current = false;
        }
      },
    );
  }

  async function removeProvider() {
    if (blockNavigationForDirtyDraft("删除 Provider")) {
      return;
    }
    const profileId = draft.id;
    if (deletionBlockedProviderId === profileId) {
      setState({
        kind: "error",
        message: "请先取消当前案件抽取审阅，再删除本轮使用的 Provider。",
      });
      return;
    }
    await policies.runConfirmedDestructiveAction(
      policies.providerDeletionConfirmation(
        draft.displayName,
        draft.credentialAccountId,
      ),
      policies.confirmAction,
      async () => {
        if (mutationInFlightRef.current) {
          return;
        }
        mutationInFlightRef.current = true;
        setState({ kind: "loading" });
        try {
          await deleteProviderProfile({ providerId: profileId });
          const remaining = profiles.filter(
            (profile) => profile.id !== profileId,
          );
          setProfiles(remaining);
          setKeyStatuses((current) => {
            const next = { ...current };
            delete next[profileId];
            return next;
          });
          setConnectionResults((current) => {
            const next = { ...current };
            delete next[profileId];
            return next;
          });
          if (remaining[0]) {
            setSelectedProviderId(remaining[0].id);
            setDraft(remaining[0]);
            draftBaseline.current = remaining[0];
          } else {
            applyNewProviderDraft("deep_seek");
          }

          setState({ kind: "idle" });
        } catch (error: unknown) {
          setState({ kind: "error", message: publicErrorMessage(error) });
        } finally {
          mutationInFlightRef.current = false;
        }
      },
    );
  }

  async function runConnectionTest() {
    const profile = normalizeProviderProfile(draft);
    setState({ kind: "loading" });

    try {
      const response = await testProviderConnection({ providerId: profile.id });
      setConnectionResults((current) => ({
        ...current,
        [profile.id]: response.result,
      }));
      setState({ kind: "idle" });
    } catch (error: unknown) {
      setState({ kind: "error", message: publicErrorMessage(error) });
    }
  }

  const normalizedDraft = normalizeProviderProfile(draft);
  const savedProfile = profiles.find(
    (profile) => profile.id === normalizedDraft.id,
  );
  const isSaved = savedProfile !== undefined;
  const draftIsDirty =
    savedProfile !== undefined &&
    !providerProfilesEqual(savedProfile, normalizedDraft);
  const busy = state.kind === "loading";
  const currentKeyStatus = providerKeyStatusForSavedDraft(
    savedProfile,
    normalizedDraft,
    keyStatuses[normalizedDraft.id],
  );
  const currentConnectionResult = draftIsDirty
    ? undefined
    : connectionResults[draft.id];
  const hasKey = currentKeyStatus?.configured ?? false;

  return {
    state,
    profiles,
    draft,
    selectedProviderId,
    apiKeyInput,
    keyStatuses,
    currentKeyStatus,
    currentConnectionResult,
    busy,
    isSaved,
    draftIsDirty,
    hasKey,
    hasUnsavedChanges,
    hasUnsavedChangesRef,
    mutationInFlightRef,
    setApiKeyInput,
    updateDraft,
    updateKind,
    updateOptions,
    startNewProvider,
    selectProvider,
    discardDraftChanges,
    saveProvider,
    saveApiKey,
    removeApiKey,
    removeProvider,
    runConnectionTest,
  };
}
