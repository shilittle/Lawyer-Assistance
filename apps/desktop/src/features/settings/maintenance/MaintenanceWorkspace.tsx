import {
  useCallback,
  useEffect,
  useState,
} from "react";

import { ReleaseWorkspace } from "../../../ReleaseWorkspace";
import { PrivacyLifecyclePanel } from "../../privacy/PrivacyLifecyclePanel";

export interface MaintenanceWorkspaceProps {
  disabled?: boolean;
  onMutationActivityChange?: (active: boolean) => void;
}

export interface MaintenanceActivity {
  readonly release: boolean;
  readonly privacyLifecycle: boolean;
}

export type MaintenanceActivityKey = keyof MaintenanceActivity;

const INITIAL_ACTIVITY: MaintenanceActivity = {
  release: false,
  privacyLifecycle: false,
};

// eslint-disable-next-line react-refresh/only-export-components
export function updateMaintenanceActivity(
  current: MaintenanceActivity,
  key: MaintenanceActivityKey,
  active: boolean,
): MaintenanceActivity {
  if (current[key] === active) return current;
  return { ...current, [key]: active };
}

// eslint-disable-next-line react-refresh/only-export-components
export function maintenanceActivityIsActive(
  activity: MaintenanceActivity,
): boolean {
  return activity.release || activity.privacyLifecycle;
}

export interface MaintenanceWorkspaceViewProps {
  readonly activity: MaintenanceActivity;
  readonly disabled?: boolean;
  readonly onReleaseActivityChange: (active: boolean) => void;
  readonly onPrivacyLifecycleActivityChange: (active: boolean) => void;
}

export function MaintenanceWorkspaceView({
  activity,
  disabled = false,
  onReleaseActivityChange,
  onPrivacyLifecycleActivityChange,
}: MaintenanceWorkspaceViewProps) {
  const active = maintenanceActivityIsActive(activity);

  return (
    <div
      className="maintenance-workspace"
      aria-busy={disabled || active}
    >
      <section aria-label="版本更新与诊断">
        <ReleaseWorkspace
          disabled={disabled || activity.privacyLifecycle}
          onActivityChange={onReleaseActivityChange}
        />
      </section>

      <section aria-label="隐私生命周期与备份维护">
        <PrivacyLifecyclePanel
          disabled={disabled || activity.release}
          onActivityChange={onPrivacyLifecycleActivityChange}
        />
      </section>
    </div>
  );
}

export function MaintenanceWorkspace({
  disabled = false,
  onMutationActivityChange,
}: MaintenanceWorkspaceProps = {}) {
  const [activity, setActivity] =
    useState<MaintenanceActivity>(INITIAL_ACTIVITY);

  const setActivityBit = useCallback(
    (key: MaintenanceActivityKey, active: boolean) => {
      setActivity((current) =>
        updateMaintenanceActivity(current, key, active),
      );
    },
    [],
  );
  const onReleaseActivityChange = useCallback(
    (active: boolean) => setActivityBit("release", active),
    [setActivityBit],
  );
  const onPrivacyLifecycleActivityChange = useCallback(
    (active: boolean) => setActivityBit("privacyLifecycle", active),
    [setActivityBit],
  );

  const mutationActive = maintenanceActivityIsActive(activity);
  useEffect(() => {
    onMutationActivityChange?.(mutationActive);
  }, [mutationActive, onMutationActivityChange]);
  useEffect(
    () => () => onMutationActivityChange?.(false),
    [onMutationActivityChange],
  );

  return (
    <MaintenanceWorkspaceView
      activity={activity}
      disabled={disabled}
      onReleaseActivityChange={onReleaseActivityChange}
      onPrivacyLifecycleActivityChange={onPrivacyLifecycleActivityChange}
    />
  );
}
