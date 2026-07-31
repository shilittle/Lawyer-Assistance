import type { CaseAssistantGeneration } from "../../../ipc/case-assistant/types";

export interface CaseAssistantGenerationPickerProps {
  generations: readonly CaseAssistantGeneration[];
  selectedIds: readonly string[];
  disabled: boolean;
  loading: boolean;
  onReload: () => void;
  onToggle: (generationId: string, checked: boolean) => void;
}
export function CaseAssistantGenerationPicker({
  generations,
  selectedIds,
  disabled,
  loading,
  onReload,
  onToggle,
}: CaseAssistantGenerationPickerProps) {
  return (
    <section
      className="case-assistant-source-picker"
      aria-labelledby="case-assistant-source-picker-title"
    >
      <div className="section-heading">
        <div>
          <h3 id="case-assistant-source-picker-title">本次已批准脱敏来源</h3>
          <p>
            这里只显示后端确认属于当前案件且当前可用的元数据；每次发送都必须重新明确勾选。
          </p>
        </div>
        <button disabled={disabled || loading} type="button" onClick={onReload}>
          {loading ? "正在刷新…" : "刷新可用版本"}
        </button>
      </div>
      <div className="case-assistant-generation-list">
        {generations.map((generation) => (
          <label
            className="case-assistant-generation-option"
            key={generation.redactionGenerationId}
          >
            <input
              checked={selectedIds.includes(
                generation.redactionGenerationId,
              )}
              disabled={disabled}
              type="checkbox"
              onChange={(event) =>
                onToggle(
                  generation.redactionGenerationId,
                  event.target.checked,
                )
              }
            />
            <span>
              <strong>{generation.displayName}</strong>
              <small>
                第 {generation.generationNumber} 代 ·{" "}
                {generation.mediaType || "未知媒体类型"} ·{" "}
                {generation.pageCount} 页 · 批准于 {generation.approvedAt}
              </small>
            </span>
          </label>
        ))}
        {generations.length === 0 && !loading ? (
          <p className="empty-state">
            当前案件没有可用于案件助理的 approved/current 脱敏版本。请先到“材料与脱敏”完成复核与批准。
          </p>
        ) : null}
      </div>
      <p className="privacy-note">
        已恢复的历史勾选仅用于界面提示，不会自动扩大本次 Provider
        请求；发送时只提交当前勾选的 opaque generation IDs。
      </p>
    </section>
  );
}
