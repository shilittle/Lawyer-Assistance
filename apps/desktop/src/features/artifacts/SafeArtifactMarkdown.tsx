import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { sanitizePublicGeneratedText } from "../../publicOutput";

interface SafeArtifactMarkdownProps {
  markdown: string;
  label: string;
}

/**
 * Artifact Markdown is text-only: raw HTML is never enabled, arbitrary links
 * are rendered as inert text, and remote/data images are not loaded.
 */
export function SafeArtifactMarkdown({
  markdown,
  label,
}: SafeArtifactMarkdownProps) {
  const publicMarkdown = sanitizePublicGeneratedText(markdown);
  return (
    <div className="artifact-markdown" aria-label={label}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ children }) => <span className="artifact-inert-link">{children}</span>,
          img: ({ alt }) => (
            <span className="artifact-omitted-image">
              [未加载外部图片{alt ? `：${alt}` : ""}]
            </span>
          ),
        }}
      >
        {publicMarkdown}
      </ReactMarkdown>
    </div>
  );
}
