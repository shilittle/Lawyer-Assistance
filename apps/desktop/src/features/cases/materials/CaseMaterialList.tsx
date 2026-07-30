import type { CaseMaterialSummary } from "../../../ipc/privacy/case-material-types";
import {
  isCaseMaterialAvailable,
  UNAVAILABLE_CASE_MATERIAL_STATES,
} from "./caseMaterialAvailability";

export interface CaseMaterialListProps {
  materials: readonly CaseMaterialSummary[];
  selectedMaterialId: string | null;
  busy: boolean;
  onSelect: (materialId: string) => void;
}

function materialStatus(material: CaseMaterialSummary): string {
  if (material.deletedAt) return "已删除";
  if (material.migrationStatus !== "ready") {
    return `迁移：${material.migrationStatus}`;
  }
  if (
    material.latestGenerationStatus &&
    material.latestGenerationStatus !== "ready"
  ) {
    return `代次：${material.latestGenerationStatus}`;
  }
  if (
    material.latestRevocationState &&
    material.latestRevocationState !== "active"
  ) {
    return `撤销：${material.latestRevocationState}`;
  }
  if (UNAVAILABLE_CASE_MATERIAL_STATES.has(material.state)) {
    return `材料：${material.state}`;
  }
  return material.latestReviewState
    ? `审阅：${material.latestReviewState}`
    : `提取：${material.extractionStatus}`;
}

export function CaseMaterialList({
  materials,
  selectedMaterialId,
  busy,
  onSelect,
}: CaseMaterialListProps) {
  const availableMaterials = materials.filter(isCaseMaterialAvailable);
  const migrationIssues = materials.filter(
    (material) => !isCaseMaterialAvailable(material),
  );
  const renderMaterial = (
    material: CaseMaterialSummary,
    unavailable: boolean,
  ) => (
    <button
      aria-current={
        selectedMaterialId === material.materialId ? "true" : undefined
      }
      className={
        selectedMaterialId === material.materialId
          ? "case-material-card is-selected"
          : unavailable
            ? "case-material-card is-migration-issue"
            : "case-material-card"
      }
      disabled={busy}
      key={material.materialId}
      type="button"
      onClick={() => onSelect(material.materialId)}
    >
      <span className="item-title">{material.displayName}</span>
      <span className="item-meta">
        {material.mediaType ?? "类型待确认"} ·{" "}
        {material.generationCount} 个脱敏代次
      </span>
      <span className="item-summary">{materialStatus(material)}</span>
    </button>
  );

  return (
    <section
      className="case-material-list"
      aria-labelledby="case-material-list-title"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">当前案件</p>
          <h2 id="case-material-list-title">案件材料</h2>
        </div>
        <span>{materials.length}</span>
      </div>
      <div className="case-material-list__items">
        <div className="case-material-list__group-heading">
          <h3>可用材料</h3>
          <span>{availableMaterials.length}</span>
        </div>
        {availableMaterials.map((material) =>
          renderMaterial(material, false),
        )}
        {availableMaterials.length === 0 ? (
          <p className="empty-state">
            当前案件尚无材料。可在右侧选择本机文件，生成第一版脱敏审阅。
          </p>
        ) : null}
        {migrationIssues.length > 0 ? (
          <>
            <div className="case-material-list__group-heading">
              <h3>只读历史与迁移问题</h3>
              <span>{migrationIssues.length}</span>
            </div>
            <p className="case-material-list__group-help">
              以下记录可选择查看安全摘要与版本历史，但不能读取受保护正文、批准、导出、删除或发起新请求。
            </p>
            {migrationIssues.map((material) =>
              renderMaterial(material, true),
            )}
          </>
        ) : null}
      </div>
    </section>
  );
}
