import type { CaseAssistantPendingOutput } from "../../../ipc/case-assistant/types";
import { CASE_ASSISTANT_OUTPUT_KIND_LABELS } from "./caseAssistantState";

export interface CaseAssistantPendingOutputsProps {
  outputs: readonly CaseAssistantPendingOutput[];
  busyOutputId: string | null;
  onConfirm: (output: CaseAssistantPendingOutput) => void;
}

function pendingStatusLabel(output: CaseAssistantPendingOutput): string {
  switch (output.status) {
    case "pending":
      return "待确认，尚未写入";
    case "confirmed":
      return "已确认并应用";
  }
}

export function CaseAssistantPendingOutputs({
  outputs,
  busyOutputId,
  onConfirm,
}: CaseAssistantPendingOutputsProps) {
  return (
    <section
      className="case-assistant-pending-outputs"
      aria-labelledby="case-assistant-pending-title"
    >
      <div className="section-heading">
        <div>
          <h3 id="case-assistant-pending-title">待确认输出</h3>
          <p>先审阅预览；只有单独确认且后端再次验证成功后才会写入。</p>
        </div>
        <span>{outputs.length}</span>
      </div>
      <div className="case-assistant-pending-list">
        {outputs.map((output) => (
          <article
            className="case-assistant-pending-card"
            key={output.pendingOutputId}
          >
            <header>
              <strong>
                {CASE_ASSISTANT_OUTPUT_KIND_LABELS[output.outputKind]}
              </strong>
              <span>{pendingStatusLabel(output)}</span>
            </header>
            <pre>{output.preview}</pre>
            <footer>
              <span>
                版本 {output.version} · 创建于 {output.createdAt}
              </span>
              {output.status === "pending" ? (
                <button
                  disabled={busyOutputId !== null}
                  type="button"
                  onClick={() => onConfirm(output)}
                >
                  {busyOutputId === output.pendingOutputId
                    ? "正在重新验证并应用…"
                    : "审阅后确认应用"}
                </button>
              ) : null}
            </footer>
          </article>
        ))}
        {outputs.length === 0 ? (
          <p className="empty-state">当前会话暂无待确认输出。</p>
        ) : null}
      </div>
    </section>
  );
}
