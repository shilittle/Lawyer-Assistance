import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SafeArtifactMarkdown } from "./SafeArtifactMarkdown";

describe("SafeArtifactMarkdown", () => {
  it("does not activate raw HTML, links, or remote images", () => {
    const markup = renderToStaticMarkup(
      <SafeArtifactMarkdown
        label="安全预览"
        markdown={
          "<script>run()</script>\n\n[点击](javascript:run())\n\n![远程](https://example.test/a.png)"
        }
      />,
    );
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("href=");
    expect(markup).not.toContain("<img");
    expect(markup).toContain("未加载外部图片");
  });
});
