import {
  normalizeProviderProfile,
  providerProfilesEqual,
} from "../../../ipc/provider/profile";
import type { ProviderProfile } from "../../../ipc/provider/types";

export function providerNavigationHasUnsavedChanges(
  baseline: ProviderProfile,
  draft: ProviderProfile,
  apiKeyInput: string,
): boolean {
  return (
    !providerProfilesEqual(baseline, normalizeProviderProfile(draft)) ||
    apiKeyInput.trim().length > 0
  );
}

export function providerDeletionConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `确定永久删除 Provider“${displayName}”吗？对应配置和已保存的访问凭据会一并删除；既有结果不受影响。`;
}

export function providerApiKeyDeletionConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `确定删除 Provider“${displayName}”的访问凭据吗？删除后需重新录入才能调用该服务。`;
}

export function providerApiKeyOverwriteConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `Provider“${displayName}”已经保存访问凭据。确定用当前输入覆盖旧凭据吗？旧凭据无法恢复。`;
}

export type ConfirmedDestructiveActionResult<T> =
  | { executed: false }
  | { executed: true; value: T };

export type RunConfirmedDestructiveAction = <T>(
  message: string,
  confirmAction: (message: string) => boolean,
  action: () => Promise<T>,
) => Promise<ConfirmedDestructiveActionResult<T>>;

export async function runConfirmedDestructiveAction<T>(
  message: string,
  confirmAction: (message: string) => boolean,
  action: () => Promise<T>,
): Promise<ConfirmedDestructiveActionResult<T>> {
  if (!confirmAction(message)) {
    return { executed: false };
  }
  return { executed: true, value: await action() };
}
