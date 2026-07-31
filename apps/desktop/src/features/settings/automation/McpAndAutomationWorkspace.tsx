import {
  useCallback,
  useEffect,
  useState,
} from "react";

import { McpWorkspace } from "../../mcp/McpWorkspace";
import { getPrivacyConfig } from "../../../ipc/privacy/client";
import {
  AutomationOutboundApprovalPanel,
  type ProviderTaskRequest,
} from "./AutomationOutboundApprovalPanel";
import { ApprovedMcpPanel } from "./ApprovedMcpPanel";
import "./McpAndAutomationWorkspace.css";

export interface McpAndAutomationWorkspaceProps {
  providerTaskRequest?: ProviderTaskRequest | null;
  onProviderTaskRequestConsumed?: (
    request: ProviderTaskRequest,
  ) => void;
  onDraftDirtyChange?: (dirty: boolean) => void;
  onMutationActivityChange?: (active: boolean) => void;
}

export interface AutomationActivity {
  readonly mcp: boolean;
  readonly outbound: boolean;
  readonly approvedMcp: boolean;
}

export type AutomationActivityKey = keyof AutomationActivity;

export type AutomationPrivacyGate =
  | { readonly phase: "loading" }
  | { readonly phase: "error" }
  | { readonly phase: "ready"; readonly configValid: boolean };

const INITIAL_ACTIVITY: AutomationActivity = {
  mcp: false,
  outbound: false,
  approvedMcp: false,
};

// eslint-disable-next-line react-refresh/only-export-components
export function updateAutomationActivity(
  current: AutomationActivity,
  key: AutomationActivityKey,
  active: boolean,
): AutomationActivity {
  if (current[key] === active) return current;
  return { ...current, [key]: active };
}

// eslint-disable-next-line react-refresh/only-export-components
export function automationActivityIsActive(
  activity: AutomationActivity,
): boolean {
  return activity.mcp || activity.outbound || activity.approvedMcp;
}

// eslint-disable-next-line react-refresh/only-export-components
export function automationPanelsMayMount(
  gate: AutomationPrivacyGate,
): gate is Extract<AutomationPrivacyGate, { readonly phase: "ready" }> {
  return gate.phase === "ready" && gate.configValid;
}

export interface McpAndAutomationWorkspaceViewProps
  extends Omit<
    McpAndAutomationWorkspaceProps,
    "onMutationActivityChange"
  > {
  readonly gate: AutomationPrivacyGate;
  readonly activity: AutomationActivity;
  readonly onMcpActivityChange: (active: boolean) => void;
  readonly onOutboundActivityChange: (active: boolean) => void;
  readonly onApprovedMcpActivityChange: (active: boolean) => void;
}

export function McpAndAutomationWorkspaceView({
  gate,
  activity,
  providerTaskRequest = null,
  onProviderTaskRequestConsumed,
  onDraftDirtyChange,
  onMcpActivityChange,
  onOutboundActivityChange,
  onApprovedMcpActivityChange,
}: McpAndAutomationWorkspaceViewProps) {
  const panelsReady = automationPanelsMayMount(gate);
  const configValid = gate.phase === "ready" && gate.configValid;

  return (
    <div className="mcp-and-automation-workspace">
      <header className="mcp-and-automation-workspace__header">
        <div>
          <p className="eyebrow">本地连接与受控自动化</p>
          <h2>MCP 与自动化</h2>
        </div>
        <span
          className="automation-gate-badge"
          data-gate-state={
            gate.phase === "ready"
              ? configValid
                ? "ready"
                : "blocked"
              : gate.phase
          }
        >
          {gate.phase === "loading"
            ? "正在核验隐私配置"
            : gate.phase === "error"
              ? "自动化已关闭"
              : configValid
                ? "自动化门禁已就绪"
                : "自动化配置无效"}
        </span>
      </header>

      <p className="automation-notice">
        本地 MCP 与受控外发、案件工作区自动化共享串行操作边界；任一写操作进行时，其余区域保持只读。
      </p>

      <section
        className="mcp-and-automation-workspace__section"
        aria-label="本地 MCP 服务"
      >
        <McpWorkspace
          externalDisabled={
            activity.outbound || activity.approvedMcp
          }
          onDraftDirtyChange={onDraftDirtyChange}
          onMutationActivityChange={onMcpActivityChange}
        />
      </section>

      {panelsReady ? (
        <div className="mcp-and-automation-workspace__automation-grid">
          <section
            className="mcp-and-automation-workspace__section"
            aria-label="受控 Provider 外发"
          >
            <AutomationOutboundApprovalPanel
              taskRequest={providerTaskRequest}
              onTaskRequestConsumed={onProviderTaskRequestConsumed}
              disabled={activity.mcp || activity.approvedMcp}
              onActivityChange={onOutboundActivityChange}
            />
          </section>

          <section
            className="mcp-and-automation-workspace__section"
            aria-label="批准案件工作区 MCP"
          >
            <ApprovedMcpPanel
              disabled={activity.mcp || activity.outbound}
              onActivityChange={onApprovedMcpActivityChange}
            />
          </section>
        </div>
      ) : (
        <p className="automation-notice" role="status" aria-live="polite">
          {gate.phase === "loading"
            ? "正在读取本机隐私配置；自动化面板在核验完成前不会初始化。"
            : gate.phase === "error"
              ? "无法核验本机隐私配置；自动化面板保持关闭，待处理任务未被消费。本地 MCP 仍可使用。"
              : "本机隐私配置无效；自动化面板保持关闭，待处理任务未被消费。请修复配置后重新发起该任务。"}
        </p>
      )}
    </div>
  );
}

export function McpAndAutomationWorkspace({
  providerTaskRequest = null,
  onProviderTaskRequestConsumed,
  onDraftDirtyChange,
  onMutationActivityChange,
}: McpAndAutomationWorkspaceProps) {
  const [gate, setGate] = useState<AutomationPrivacyGate>({
    phase: "loading",
  });
  const [activity, setActivity] =
    useState<AutomationActivity>(INITIAL_ACTIVITY);

  useEffect(() => {
    let mounted = true;
    void getPrivacyConfig()
      .then((response) => {
        if (mounted) {
          setGate({
            phase: "ready",
            configValid: response.configValid,
          });
        }
      })
      .catch(() => {
        if (mounted) setGate({ phase: "error" });
      });
    return () => {
      mounted = false;
    };
  }, []);

  const setActivityBit = useCallback(
    (key: AutomationActivityKey, active: boolean) => {
      setActivity((current) =>
        updateAutomationActivity(current, key, active),
      );
    },
    [],
  );
  const onMcpActivityChange = useCallback(
    (active: boolean) => setActivityBit("mcp", active),
    [setActivityBit],
  );
  const onOutboundActivityChange = useCallback(
    (active: boolean) => setActivityBit("outbound", active),
    [setActivityBit],
  );
  const onApprovedMcpActivityChange = useCallback(
    (active: boolean) => setActivityBit("approvedMcp", active),
    [setActivityBit],
  );

  const mutationActive = automationActivityIsActive(activity);
  useEffect(() => {
    onMutationActivityChange?.(mutationActive);
  }, [mutationActive, onMutationActivityChange]);
  useEffect(
    () => () => onMutationActivityChange?.(false),
    [onMutationActivityChange],
  );

  return (
    <McpAndAutomationWorkspaceView
      gate={gate}
      activity={activity}
      providerTaskRequest={providerTaskRequest}
      onProviderTaskRequestConsumed={
        onProviderTaskRequestConsumed
      }
      onDraftDirtyChange={onDraftDirtyChange}
      onMcpActivityChange={onMcpActivityChange}
      onOutboundActivityChange={onOutboundActivityChange}
      onApprovedMcpActivityChange={onApprovedMcpActivityChange}
    />
  );
}
