import { ProviderCreateMenu } from "../../../ipc/provider/ProviderCreateMenu";
import { SELECTABLE_PROVIDER_KINDS } from "../../../ipc/provider/catalog";
import {
  formatConnectionResult,
  formatHttpStatus,
  formatKeyStatus,
  formatLatency,
  formatProviderKind,
} from "../../../ipc/provider/format";
import type {
  ProviderKind,
  ReasoningEffort,
} from "../../../ipc/provider/types";
import { SettingsWorkspace } from "../SettingsWorkspace";
import type { ProviderSettingsController } from "./useProviderSettingsController";

export interface ProviderSettingsWorkspaceProps {
  controller: ProviderSettingsController;
}

export function ProviderSettingsWorkspace({
  controller,
}: ProviderSettingsWorkspaceProps) {
  const {
    apiKeyInput,
    busy,
    currentConnectionResult,
    currentKeyStatus,
    discardDraftChanges,
    draft,
    draftIsDirty,
    hasKey,
    hasUnsavedChanges,
    isSaved,
    keyStatuses,
    profiles,
    removeApiKey,
    removeProvider,
    runConnectionTest,
    saveApiKey,
    saveProvider,
    selectProvider,
    selectedProviderId,
    setApiKeyInput,
    startNewProvider,
    state,
    updateDraft,
    updateKind,
    updateOptions,
  } = controller;

  return (
    <SettingsWorkspace mode="providers" busy={busy}>
      <aside
        className="panel provider-list-panel"
        aria-labelledby="provider-list-title"
      >
        <div className="panel-heading">
          <h2 id="provider-list-title">Profiles</h2>
          <span>{profiles.length}</span>
        </div>
        <ProviderCreateMenu disabled={busy} onCreate={startNewProvider} />
        <div className="provider-list">
          {profiles.map((profile) => (
            <button
              className={`provider-item ${
                selectedProviderId === profile.id ? "is-selected" : ""
              }`}
              disabled={busy}
              key={profile.id}
              type="button"
              onClick={() => selectProvider(profile)}
            >
              <span className="item-title">{profile.displayName}</span>
              <span className="item-meta">
                {formatProviderKind(profile.kind)} · {profile.modelId}
              </span>
              <span className="item-summary">
                {formatKeyStatus(keyStatuses[profile.id])}
              </span>
            </button>
          ))}
          {profiles.length === 0 ? (
            <p className="empty-state">暂无 Provider profile</p>
          ) : null}
        </div>
      </aside>

      <section
        className="panel provider-editor-panel"
        aria-labelledby="provider-editor-title"
      >
        <div className="panel-heading">
          <h2 id="provider-editor-title">Profile</h2>
          <span>{state.kind === "loading" ? "处理中" : "本地"}</span>
        </div>
        {state.kind === "error" ? (
          <p className="error-text" role="alert">
            {state.message}
          </p>
        ) : null}

        <form className="provider-form" onSubmit={saveProvider}>
          <fieldset className="provider-profile-fields" disabled={busy}>
            <legend className="sr-only">Provider Profile 配置</legend>
            {draft.kind === "custom" ? (
              <p className="provider-custom-hint">
                自定义提供商使用通用 OpenAI Chat Completions 协议。请填写 HTTPS
                Base URL 和模型 ID；地址可以是 API 根路径，也可以直接以
                /chat/completions 结尾。
              </p>
            ) : null}
            <div className="form-grid">
              <label>
                <span>名称</span>
                <input
                  placeholder={
                    draft.kind === "custom" ? "例如：公司模型网关" : undefined
                  }
                  required
                  value={draft.displayName}
                  onChange={(event) =>
                    updateDraft({ displayName: event.target.value })
                  }
                />
              </label>
              <label>
                <span>Provider</span>
                <select
                  value={draft.kind}
                  onChange={(event) =>
                    updateKind(event.target.value as ProviderKind)
                  }
                >
                  {SELECTABLE_PROVIDER_KINDS.map((kind) => (
                    <option key={kind} value={kind}>
                      {formatProviderKind(kind)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>模型 ID</span>
                <input
                  placeholder={
                    draft.kind === "custom" ? "例如：my-chat-model" : undefined
                  }
                  required
                  value={draft.modelId}
                  onChange={(event) =>
                    updateDraft({ modelId: event.target.value })
                  }
                />
              </label>
              <label>
                <span>Base URL</span>
                <input
                  placeholder={
                    draft.kind === "custom"
                      ? "https://api.example.com/v1"
                      : undefined
                  }
                  required
                  value={draft.baseUrl}
                  onChange={(event) =>
                    updateDraft({ baseUrl: event.target.value })
                  }
                />
              </label>
              <label>
                <span>凭据账户</span>
                <input
                  required
                  value={draft.credentialAccountId}
                  onChange={(event) =>
                    updateDraft({ credentialAccountId: event.target.value })
                  }
                />
              </label>
              {draft.kind === "volcengine_ark" ? (
                <label>
                  <span>Endpoint ID（可覆盖模型 ID）</span>
                  <input
                    value={draft.options.endpointId ?? ""}
                    onChange={(event) =>
                      updateOptions({ endpointId: event.target.value })
                    }
                  />
                </label>
              ) : null}
              {draft.kind === "qwen" ? (
                <label>
                  <span>Workspace ID（用于 Base URL 占位符）</span>
                  <input
                    value={draft.options.workspaceId ?? ""}
                    onChange={(event) =>
                      updateOptions({ workspaceId: event.target.value })
                    }
                  />
                </label>
              ) : null}
              {draft.kind === "deep_seek" ||
              draft.kind === "volcengine_ark" ? (
                <label>
                  <span>Reasoning effort</span>
                  <select
                    value={
                      draft.kind === "deep_seek" &&
                      (draft.options.reasoningEffort === "low" ||
                        draft.options.reasoningEffort === "medium")
                        ? "high"
                        : (draft.options.reasoningEffort ?? "")
                    }
                    onChange={(event) =>
                      updateOptions({
                        reasoningEffort:
                          event.target.value === ""
                            ? null
                            : (event.target.value as ReasoningEffort),
                      })
                    }
                  >
                    <option value="">未设置</option>
                    {draft.kind === "volcengine_ark" ? (
                      <>
                        <option value="low">low</option>
                        <option value="medium">medium</option>
                      </>
                    ) : null}
                    <option value="high">high</option>
                    {draft.kind === "deep_seek" ? (
                      <option value="max">max</option>
                    ) : null}
                  </select>
                </label>
              ) : null}
              {draft.kind === "qwen" || draft.kind === "silicon_flow" ? (
                <label>
                  <span>Thinking budget</span>
                  <input
                    min={draft.kind === "silicon_flow" ? 128 : 1}
                    max={draft.kind === "silicon_flow" ? 32768 : undefined}
                    type="number"
                    value={draft.options.thinkingBudget ?? ""}
                    onChange={(event) =>
                      updateOptions({
                        thinkingBudget:
                          event.target.value === ""
                            ? null
                            : Number(event.target.value),
                      })
                    }
                  />
                </label>
              ) : null}
            </div>

            <div className="toggle-row">
              {draft.kind === "custom" ? (
                <label className="provider-private-network-toggle">
                  <input
                    checked={draft.options.allowPrivateNetwork ?? false}
                    type="checkbox"
                    onChange={(event) =>
                      updateOptions({
                        allowPrivateNetwork: event.target.checked,
                      })
                    }
                  />
                  <span>
                    我确认允许访问 localhost、私网或链路本地地址（高风险）
                  </span>
                </label>
              ) : null}
              {draft.kind === "qwen" || draft.kind === "silicon_flow" ? (
                <label>
                  <input
                    checked={draft.options.enableThinking ?? false}
                    type="checkbox"
                    onChange={(event) =>
                      updateOptions({ enableThinking: event.target.checked })
                    }
                  />
                  <span>enable_thinking</span>
                </label>
              ) : null}
              {draft.kind === "deep_seek" ||
              draft.kind === "volcengine_ark" ? (
                <label>
                  <input
                    checked={draft.options.thinking ?? false}
                    type="checkbox"
                    onChange={(event) =>
                      updateOptions({ thinking: event.target.checked })
                    }
                  />
                  <span>thinking</span>
                </label>
              ) : null}
            </div>
            {draft.kind === "custom" &&
            draft.options.allowPrivateNetwork ? (
              <p className="provider-risk-warning" role="alert">
                高风险：该 Provider
                可访问本机及内网服务。仅在你信任目标地址并确认不会形成服务端请求伪造通道时启用。
              </p>
            ) : null}
          </fieldset>

          <div className="command-row">
            <button disabled={busy} type="submit">
              保存 Profile
            </button>
            <button
              disabled={busy || !isSaved}
              type="button"
              onClick={() => void removeProvider()}
            >
              删除 Profile
            </button>
            <button
              disabled={busy || !hasUnsavedChanges}
              type="button"
              onClick={discardDraftChanges}
            >
              放弃未保存修改
            </button>
          </div>
        </form>
      </section>

      <aside
        className="panel provider-status-panel"
        aria-labelledby="provider-status-title"
      >
        <div className="panel-heading">
          <h2 id="provider-status-title">凭据与连接</h2>
          <span>{formatKeyStatus(currentKeyStatus)}</span>
        </div>
        <section className="provider-subsection">
          <h3>API Key</h3>
          <label>
            <span>Key</span>
            <input
              autoComplete="off"
              disabled={busy}
              type="password"
              value={apiKeyInput}
              onChange={(event) => setApiKeyInput(event.target.value)}
              placeholder="API Key"
            />
          </label>
          <div className="command-row">
            <button
              disabled={
                busy ||
                !isSaved ||
                draftIsDirty ||
                currentKeyStatus === undefined ||
                apiKeyInput.trim().length === 0
              }
              type="button"
              onClick={() => void saveApiKey()}
            >
              保存 Key
            </button>
            <button
              disabled={busy || draftIsDirty || !hasKey}
              type="button"
              onClick={() => void removeApiKey()}
            >
              删除 Key
            </button>
          </div>
        </section>

        <section className="provider-subsection">
          <h3>测试连接</h3>
          <div className="connection-summary">
            <span
              className={`status-dot status-dot--${
                currentConnectionResult?.status ?? "idle"
              }`}
            />
            <strong>{formatConnectionResult(currentConnectionResult)}</strong>
          </div>
          <dl className="meta-grid">
            <div>
              <dt>HTTP</dt>
              <dd>{formatHttpStatus(currentConnectionResult?.httpStatus)}</dd>
            </div>
            <div>
              <dt>模型</dt>
              <dd>{currentConnectionResult?.model ?? "未返回"}</dd>
            </div>
            <div>
              <dt title="从发起请求到首个非空 SSE 内容或 reasoning token 到达；不按响应头、keep-alive 或空 delta 计时">
                首个响应 token
              </dt>
              <dd>
                {formatLatency(currentConnectionResult?.firstTokenLatencyMs)}
              </dd>
            </div>
            <div>
              <dt>总耗时</dt>
              <dd>{formatLatency(currentConnectionResult?.totalLatencyMs)}</dd>
            </div>
            <div>
              <dt>错误类型</dt>
              <dd>{currentConnectionResult?.errorType ?? "无"}</dd>
            </div>
          </dl>
          <button
            disabled={busy || !isSaved || draftIsDirty || !hasKey}
            type="button"
            onClick={() => void runConnectionTest()}
          >
            测试连接
          </button>
        </section>
      </aside>
    </SettingsWorkspace>
  );
}
