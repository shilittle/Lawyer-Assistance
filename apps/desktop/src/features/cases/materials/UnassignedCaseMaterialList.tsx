import type { UnassignedCaseMaterialSummary } from "../../../ipc/privacy/case-material-types";

export interface UnassignedCaseMaterialListProps {
  projectId: string;
  materials: readonly UnassignedCaseMaterialSummary[];
  actor: string;
  busy: boolean;
  onActorChange: (actor: string) => void;
  onAssign: (material: UnassignedCaseMaterialSummary) => void;
}

function historicalIdentityLabel(
  value: UnassignedCaseMaterialSummary["historicalIdentity"],
): string {
  return value === "preserved"
    ? "历史材料身份已保留"
    : "历史材料身份为空";
}

export function UnassignedCaseMaterialList({
  projectId,
  materials,
  actor,
  busy,
  onActorChange,
  onAssign,
}: UnassignedCaseMaterialListProps) {
  return (
    <section
      className="case-unassigned-materials panel"
      aria-labelledby="case-unassigned-materials-title"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">迁移待处理</p>
          <h2 id="case-unassigned-materials-title">
            未归属本地材料
          </h2>
        </div>
        <span>{materials.length}</span>
      </div>
      <p>
        这些历史记录尚未归属任何本地案件。只有用户明确确认后，后端才会将所选记录归入
        <code>{projectId}</code>；前端不会生成或推断任何隐私案件身份。
      </p>
      <label className="case-unassigned-materials__actor">
        <span>归属操作人</span>
        <input
          autoCapitalize="off"
          autoComplete="off"
          autoCorrect="off"
          disabled={busy}
          maxLength={128}
          spellCheck={false}
          value={actor}
          onChange={(event) => onActorChange(event.target.value)}
        />
      </label>
      <div className="case-unassigned-materials__items">
        {materials.map((material) => (
          <article
            className="case-unassigned-material-card"
            key={material.materialId}
          >
            <div>
              <strong>{material.displayName}</strong>
              <span>
                {material.mediaType ?? "类型待确认"} ·{" "}
                {material.generationCount} 个脱敏代次
              </span>
              <span>
                {material.sourceKind} · {material.extractionStatus} ·{" "}
                {material.migrationStatus} · {material.state}
              </span>
              <span>
                {historicalIdentityLabel(material.historicalIdentity)} · 行版本{" "}
                {material.rowVersion}
              </span>
              {material.deletedAt ? (
                <span>已删除：{material.deletedAt}</span>
              ) : null}
            </div>
            <button
              disabled={
                busy ||
                !material.assignable ||
                actor.trim().length === 0
              }
              type="button"
              onClick={() => onAssign(material)}
            >
              {material.assignable
                ? "明确归入当前案件"
                : "后端判定不可归属"}
            </button>
          </article>
        ))}
        {materials.length === 0 ? (
          <p className="empty-state">
            当前没有需要人工归属的历史本地材料。
          </p>
        ) : null}
      </div>
    </section>
  );
}
