import type { AssistantAttachment } from "../../ipc/assistant/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import {
  buildInteractiveProviderDisclosure,
  INTERACTIVE_PROVIDER_EGRESS_WARNING,
} from "./providerEgressDisclosure";

export function ProviderEgressNotice({
  provider,
  selectedAttachments,
}: {
  provider: Pick<ProviderProfile, "displayName"> | undefined;
  selectedAttachments: readonly Pick<
    AssistantAttachment,
    "originalName" | "extension" | "detectedMime" | "sizeBytes"
  >[];
}) {
  const disclosure = buildInteractiveProviderDisclosure({
    provider,
    selectedAttachments,
  });
  return (
    <section
      className="assistant-provider-disclosure"
      aria-label="模型供应商外发提示"
    >
      <strong>模型供应商外发提示</strong>
      <p>{INTERACTIVE_PROVIDER_EGRESS_WARNING}</p>
      <p>当前模型服务：{disclosure.providerLabel}</p>
      <p>普通聊天只发送你填写的消息、同会话普通聊天历史和本次显式选择的附件正文；不会自动读取案件工作区。</p>
      <p>{disclosure.attachmentSummary}</p>
      <p>服务地域、留存期限及是否用于训练，以所选模型供应商的服务条款与配置为准。</p>
    </section>
  );
}
