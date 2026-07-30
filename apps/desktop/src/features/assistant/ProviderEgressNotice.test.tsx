import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ProviderEgressNotice } from "./ProviderEgressNotice";
import {
  buildInteractiveProviderDisclosure,
  INTERACTIVE_PROVIDER_EGRESS_WARNING,
} from "./providerEgressDisclosure";

describe("ProviderEgressNotice", () => {
  it("is persistent and names the selected provider without technical routing data", () => {
    const markup = renderToStaticMarkup(
      <ProviderEgressNotice
        provider={{ displayName: "律师模型服务" }}
        selectedAttachments={[]}
      />,
    );

    expect(markup).toContain('aria-label="模型供应商外发提示"');
    expect(markup).toContain(INTERACTIVE_PROVIDER_EGRESS_WARNING);
    expect(markup).toContain("当前模型服务：律师模型服务");
    expect(markup).toContain("不会自动读取案件工作区");
    expect(markup).toContain("本次不发送附件正文或本地路径");
    expect(markup).not.toContain("baseUrl");
    expect(markup).not.toContain("modelId");
  });

  it("discloses every explicitly selected attachment name, type and size", () => {
    const disclosure = buildInteractiveProviderDisclosure({
      provider: { displayName: "律师模型服务" },
      selectedAttachments: [
        {
          originalName: "合同.txt",
          extension: "txt",
          detectedMime: "text/plain",
          sizeBytes: 512,
        },
        {
          originalName: "证据.pdf",
          extension: "pdf",
          detectedMime: "application/pdf",
          sizeBytes: 2048,
        },
      ],
    });

    expect(disclosure.attachmentSummary).toContain("合同.txt（text/plain，512 B）");
    expect(disclosure.attachmentSummary).toContain(
      "证据.pdf（application/pdf，2.0 KiB）",
    );
    expect(disclosure.attachmentSummary).toContain("本地提取正文发送给模型服务");
    expect(disclosure.attachmentSummary).toContain("不会发送本地路径");
  });
});
