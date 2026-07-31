import type { ProviderProfile } from "../../../ipc/provider/types";
import type {
  CaseAssistantGeneration,
  CaseAssistantOutputKind,
} from "../../../ipc/case-assistant/types";
import { CASE_ASSISTANT_OUTPUT_KIND_LABELS } from "./caseAssistantState";

export const CASE_ASSISTANT_PROVIDER_WARNING =
  "本次内容将通过 API 发送至所选模型供应商服务器。仅发送你本次明确选择的已批准脱敏版本、最小已确认案件上下文、案件工作会话历史和当前指令。";

export interface CaseAssistantProviderNoticeProps {
  provider: Pick<ProviderProfile, "displayName"> | undefined;
  selectedGenerations: readonly CaseAssistantGeneration[];
  outputKind: CaseAssistantOutputKind;
}
export function CaseAssistantProviderNotice({
  provider,
  selectedGenerations,
  outputKind,
}: CaseAssistantProviderNoticeProps) {
  return (
    <section
      className="case-assistant-provider-notice"
      aria-label="案件助理模型外发提示"
      role="note"
    >
      <strong>案件助理模型外发提示</strong>
      <p>{CASE_ASSISTANT_PROVIDER_WARNING}</p>
      <dl>
        <div>
          <dt>当前模型服务</dt>
          <dd>{provider?.displayName ?? "尚未选择模型服务"}</dd>
        </div>
        <div>
          <dt>输出类型</dt>
          <dd>{CASE_ASSISTANT_OUTPUT_KIND_LABELS[outputKind]}</dd>
        </div>
        <div>
          <dt>本次明确选择</dt>
          <dd>
            {selectedGenerations.length === 0
              ? "尚未选择已批准脱敏版本"
              : selectedGenerations
                  .map(
                    (generation) =>
                      `${generation.displayName}（第 ${generation.generationNumber} 代）`,
                  )
                  .join("；")}
          </dd>
        </div>
      </dl>
      <p>
        不发送案件原件、Vault 对象、原文件路径、普通聊天附件、MCP
        授权或未选择的历史材料。每次发送都由后端重新验证来源，已撤销版本不能继续使用。
      </p>
      <p>
        模型响应会先在后端完整缓冲并完成残留敏感信息扫描，扫描通过后才一次性显示；未确认的输出不会写入案件或成果。
      </p>
    </section>
  );
}
