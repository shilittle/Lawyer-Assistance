import type { AssistantAttachment } from "../../ipc/assistant/types";
import type { ProviderProfile } from "../../ipc/provider/types";

export const INTERACTIVE_PROVIDER_EGRESS_WARNING =
  "内容将通过 API 发送至所选模型供应商服务器。请勿输入或上传未脱敏的案件材料。案件文件请先到“案件工作台 → 材料与脱敏”处理。";

export interface InteractiveProviderDisclosure {
  providerLabel: string;
  attachmentSummary: string;
}
function byteSize(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

export function buildInteractiveProviderDisclosure(options: {
  provider: Pick<ProviderProfile, "displayName"> | undefined;
  selectedAttachments: readonly Pick<
    AssistantAttachment,
    "originalName" | "extension" | "detectedMime" | "sizeBytes"
  >[];
}): InteractiveProviderDisclosure {
  const attachmentLabels = options.selectedAttachments.map((attachment) => {
    const type =
      attachment.detectedMime.trim() ||
      attachment.extension.trim().toUpperCase() ||
      "未知类型";
    return `${attachment.originalName}（${type}，${byteSize(attachment.sizeBytes)}）`;
  });
  return {
    providerLabel: options.provider?.displayName ?? "尚未选择模型服务",
    attachmentSummary:
      attachmentLabels.length === 0
        ? "本次不发送附件正文或本地路径。"
        : `本次会把以下显式选择附件的本地提取正文发送给模型服务：${attachmentLabels.join(
            "、",
          )}；不会发送本地路径。`,
  };
}
