import {
  CUSTOM_PROVIDER_KIND,
  DEFAULT_PROVIDER_KIND,
  OTHER_BUILTIN_PROVIDER_KINDS,
} from "./catalog";
import { formatProviderKind } from "./format";
import type { ProviderKind } from "./types";

interface ProviderCreateMenuProps {
  disabled: boolean;
  onCreate: (kind: ProviderKind) => void;
}

export function ProviderCreateMenu({
  disabled,
  onCreate,
}: ProviderCreateMenuProps) {
  return (
    <div className="provider-create-row">
      <button
        className="provider-primary-create"
        data-provider-quick-create={DEFAULT_PROVIDER_KIND}
        disabled={disabled}
        type="button"
        onClick={() => onCreate(DEFAULT_PROVIDER_KIND)}
      >
        新建 DeepSeek
      </button>
      <details className="provider-more-create">
        <summary>其他提供商与自定义</summary>
        <div className="provider-more-create-actions">
          {OTHER_BUILTIN_PROVIDER_KINDS.map((kind) => (
            <button
              data-provider-secondary-create={kind}
              disabled={disabled}
              key={kind}
              type="button"
              onClick={() => onCreate(kind)}
            >
              新建 {formatProviderKind(kind)}
            </button>
          ))}
          <button
            data-provider-secondary-create={CUSTOM_PROVIDER_KIND}
            disabled={disabled}
            type="button"
            onClick={() => onCreate(CUSTOM_PROVIDER_KIND)}
          >
            添加自定义 OpenAI 兼容提供商
          </button>
        </div>
      </details>
    </div>
  );
}
