import type {
  CaseMaterialSummary,
  CaseRedactionGenerationSummary,
} from "../../../ipc/privacy/case-material-types";

export interface CaseMaterialHistorySummaryProps {
  material: CaseMaterialSummary;
  generation: CaseRedactionGenerationSummary | null;
}

export function CaseMaterialHistorySummary({
  material,
  generation,
}: CaseMaterialHistorySummaryProps) {
  return (
    <section
      className="case-material-history-summary panel"
      aria-labelledby="case-material-history-summary-title"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">只读历史</p>
          <h2 id="case-material-history-summary-title">
            材料与代次安全摘要
          </h2>
        </div>
        <span className="privacy-config-state">
          不可执行工作流动作
        </span>
      </div>
      <p className="privacy-boundary-warning" role="note">
        当前记录仅展示目录接口已经返回的摘要元数据。系统不会加载受保护的审阅正文，
        也不会允许批准、导出、删除或发起新请求。
      </p>
      <dl className="case-material-history-summary__metadata">
        <div>
          <dt>材料名称</dt>
          <dd>{material.displayName}</dd>
        </div>
        <div>
          <dt>材料标识</dt>
          <dd><code>{material.materialId}</code></dd>
        </div>
        <div>
          <dt>材料状态</dt>
          <dd>
            {material.state} · {material.migrationStatus} ·{" "}
            {material.extractionStatus}
          </dd>
        </div>
        <div>
          <dt>来源与类型</dt>
          <dd>
            {material.sourceKind} · {material.mediaType ?? "类型待确认"}
          </dd>
        </div>
        <div>
          <dt>代次总数</dt>
          <dd>{material.generationCount}</dd>
        </div>
        <div>
          <dt>更新时间</dt>
          <dd>{material.updatedAt}</dd>
        </div>
        {material.deletedAt ? (
          <div>
            <dt>删除标记时间</dt>
            <dd>{material.deletedAt}</dd>
          </div>
        ) : null}
      </dl>

      {generation ? (
        <>
          <h3>所选脱敏代次</h3>
          <dl className="case-material-history-summary__metadata">
            <div>
              <dt>代次</dt>
              <dd>第 {generation.generationNumber} 代</dd>
            </div>
            <div>
              <dt>审阅状态</dt>
              <dd>
                {generation.reviewState} ·{" "}
                {generation.generationStatus}
              </dd>
            </div>
            <div>
              <dt>撤销状态</dt>
              <dd>
                {generation.revocationState}
                {generation.revokedAt
                  ? ` · ${generation.revokedAt}`
                  : ""}
              </dd>
            </div>
            <div>
              <dt>风险 revision</dt>
              <dd>{generation.riskRevision}</dd>
            </div>
            <div>
              <dt>创建时间</dt>
              <dd>{generation.createdAt}</dd>
            </div>
          </dl>
        </>
      ) : (
        <p className="empty-state">该历史材料没有可显示的脱敏代次摘要。</p>
      )}
    </section>
  );
}
