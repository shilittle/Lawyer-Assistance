import { useMemo, useState } from "react";

import "./risk-review.css";

import type {
  PrivacyDictionaryCategory,
  PrivacyEntityType,
  PrivacyFindingSeverity,
  PrivacyFindingView,
  PrivacyRiskReviewAction,
  PrivacyRiskReviewState,
  PrivacyVisualRiskDecision,
} from "../../ipc/privacy/risk-types";

export type RiskPageSort = "risk" | "page";
export type RiskPageFilter = "all" | "unresolved" | "p0" | "ocr" | "visual";

export interface RiskReviewPanelProps {
  state: PrivacyRiskReviewState;
  busy: boolean;
  onAction: (action: PrivacyRiskReviewAction) => void;
  onUndo: () => void;
  onRedo: () => void;
  onManualApprove: () => void;
}

const ENTITY_LABELS: Record<PrivacyEntityType, string> = {
  person_name: "姓名",
  organization_name: "机构名称",
  case_number: "案号",
  identity_number: "身份证号",
  passport_number: "护照号",
  phone_number: "手机号",
  landline_number: "固定电话",
  bank_account: "银行卡/银行账户",
  email_address: "电子邮箱",
  address: "地址",
  organization_code: "统一社会信用代码",
  business_license_number: "营业执照号",
  vehicle_plate: "车牌号",
  ip_address: "IP 地址",
  social_account: "社交账号",
  payment_account: "支付账号",
  account_name: "账户名",
  contract_number: "合同编号",
  tracking_number: "物流单号",
  property_certificate_number: "不动产权证号",
  custom: "自定义敏感项",
};

const DICTIONARY_LABELS: Record<PrivacyDictionaryCategory, string> = {
  party: "当事人",
  agent: "代理人",
  legal_representative: "法定代表人",
  contact: "联系人",
  witness: "证人",
  company: "公司",
  agency: "机构",
  court: "法院",
  address: "地址",
  contact_information: "联系方式",
  account: "账户",
  custom: "自定义类别",
};

const SEVERITY_ORDER: Record<PrivacyFindingSeverity, number> = {
  p0_blocking: 5,
  p1_high: 4,
  p2_medium: 3,
  p3_resolved: 2,
  informational: 1,
};

const SEVERITY_VIEW: Record<
  PrivacyFindingSeverity,
  { icon: string; label: string; className: string }
> = {
  p0_blocking: { icon: "!", label: "P0 阻断", className: "is-p0" },
  p1_high: { icon: "▲", label: "P1 高风险", className: "is-p1" },
  p2_medium: { icon: "●", label: "P2 中风险", className: "is-p2" },
  p3_resolved: { icon: "✓", label: "P3 已处理", className: "is-p3" },
  informational: { icon: "i", label: "提示", className: "is-info" },
};

const AUTOMATIC_ONLY_GATES = new Set([
  "calibrated_policy",
  "approval_mode_allows_automatic",
  "organization_policy_allows_automatic",
  "publication_target_fixed",
]);

function ppm(value: number | null): string {
  return value === null ? "无证据" : `${(value / 10_000).toFixed(1)}%`;
}

function unresolved(finding: PrivacyFindingView): boolean {
  return finding.resolutionState === "unresolved" || finding.resolutionState === "revoked";
}

function conflict(finding: PrivacyFindingView): boolean {
  return !finding.detectorAgreement || finding.reasonCodes.some((reason) => reason.includes("conflict"));
}

function uncertain(finding: PrivacyFindingView): boolean {
  return finding.reasonCodes.some(
    (reason) => reason.includes("confidence") || reason.includes("confusable"),
  );
}

function pageMatches(
  page: PrivacyRiskReviewState["documentRisk"]["pageRisks"][number],
  filter: RiskPageFilter,
): boolean {
  if (filter === "all") return true;
  if (filter === "unresolved") return page.p0Count + page.p1Count + page.p2Count > 0;
  if (filter === "p0") return page.p0Count > 0;
  if (filter === "ocr") {
    return page.ocrMinPpm === null || page.reasonCodes.some((reason) => reason.includes("ocr"));
  }
  return page.visualReviewRequired || page.visualRisks.length > 0;
}

function findingClassName(finding: PrivacyFindingView, selectedCluster: string | null): string {
  const classes = ["privacy-risk-finding", SEVERITY_VIEW[finding.severity].className];
  if (conflict(finding)) classes.push("has-conflict");
  if (uncertain(finding)) classes.push("is-uncertain");
  if (finding.clusterId && finding.clusterId === selectedCluster) classes.push("is-cluster-selected");
  return classes.join(" ");
}

function visualKey(pageIndex: number, riskCode: string): string {
  return `${pageIndex}:${riskCode}`;
}

export function RiskReviewPanel({
  state,
  busy,
  onAction,
  onUndo,
  onRedo,
  onManualApprove,
}: RiskReviewPanelProps) {
  const [sort, setSort] = useState<RiskPageSort>("risk");
  const [filter, setFilter] = useState<RiskPageFilter>("unresolved");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    state.findings.find(unresolved)?.findingId ?? state.findings[0]?.findingId ?? null,
  );
  const [entityType, setEntityType] = useState<PrivacyEntityType>("custom");
  const [replacement, setReplacement] = useState("");
  const [dictionaryCategory, setDictionaryCategory] =
    useState<PrivacyDictionaryCategory>("custom");
  const [dictionaryRequired, setDictionaryRequired] = useState(false);
  const [mergeTarget, setMergeTarget] = useState("");
  const [visualReasons, setVisualReasons] = useState<Record<string, string>>({});

  const selected = state.findings.find((finding) => finding.findingId === selectedFindingId) ?? null;
  const selectedCluster = selected?.clusterId ?? null;
  const pages = useMemo(() => {
    const values = state.documentRisk.pageRisks.filter((page) => pageMatches(page, filter));
    values.sort((left, right) =>
      sort === "page"
        ? left.pageIndex - right.pageIndex
        : right.p0Count - left.p0Count ||
          right.p1Count - left.p1Count ||
          right.p2Count - left.p2Count ||
          left.readinessScore - right.readinessScore ||
          left.pageIndex - right.pageIndex,
    );
    return values;
  }, [filter, sort, state.documentRisk.pageRisks]);
  const visibleFindings = useMemo(() => {
    const pageIndexes = new Set(pages.map((page) => page.pageIndex));
    return state.findings
      .filter((finding) => pageIndexes.has(finding.pageIndex))
      .sort(
        (left, right) =>
          SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity] ||
          right.reviewPriority - left.reviewPriority ||
          left.pageIndex - right.pageIndex ||
          left.startOffset - right.startOffset,
      );
  }, [pages, state.findings]);
  const clusters = useMemo(
    () => [...new Set(state.findings.flatMap((finding) => finding.clusterId ? [finding.clusterId] : []))],
    [state.findings],
  );
  const manualBlockers = state.hardGates.filter(
    (gate) => gate.blocking && !gate.passed && !AUTOMATIC_ONLY_GATES.has(gate.gateId),
  );
  const manualApprovalDisabled =
    busy || state.rejected || !state.detectorRunCompleted || manualBlockers.length > 0;

  const moveRisk = (delta: number) => {
    if (visibleFindings.length === 0) return;
    const current = visibleFindings.findIndex((finding) => finding.findingId === selectedFindingId);
    const next = (Math.max(current, 0) + delta + visibleFindings.length) % visibleFindings.length;
    setSelectedFindingId(visibleFindings[next].findingId);
  };

  const resolveVisualRisk = (
    pageIndex: number,
    riskCode: string,
    decision: PrivacyVisualRiskDecision,
  ) => {
    const reason = (visualReasons[visualKey(pageIndex, riskCode)] ?? "").trim();
    if (!reason) return;
    onAction({ kind: "resolve_visual_risk", pageIndex, riskCode, decision, reason });
  };

  const risk = state.documentRisk;
  return (
    <section className="privacy-risk-panel" aria-labelledby="privacy-risk-title">
      <header className="privacy-risk-overview">
        <div>
          <p className="eyebrow">后端持久化风险审阅</p>
          <h3 id="privacy-risk-title">按严重度、页码与证据逐项处理</h3>
          <p>
            revision {state.revision} · {risk.route} · 策略 {risk.autoApprovalPolicyMode}
          </p>
          <code>{state.caseId} / {state.materialId} / document v{state.documentVersion}</code>
        </div>
        <div className="privacy-readiness" aria-label={`风险就绪度 ${risk.readinessScore} 分`}>
          <strong>{risk.readinessScore}</strong><span>/100 readiness</span>
        </div>
      </header>

      <dl className="privacy-risk-metrics">
        <div><dt>P0 阻断</dt><dd>{risk.totalP0}</dd></div>
        <div><dt>P1 高风险</dt><dd>{risk.totalP1}</dd></div>
        <div><dt>P2 中风险</dt><dd>{risk.totalP2}</dd></div>
        <div><dt>残留扫描</dt><dd>{state.residualScan.passed ? "通过" : `阻断 ${state.residualScan.blockingHitCount}`}</dd></div>
        <div><dt>真实检测完成</dt><dd>{state.detectorRunCompleted ? "是" : "否（阻断）"}</dd></div>
        <div><dt>自动发布</dt><dd>{risk.automaticPublishAllowed ? "后端允许" : "未允许"}</dd></div>
      </dl>

      <div className="privacy-auto-decision" role="status">
        <strong>{risk.productionAutomaticEnabled ? "生产自动批准开关已启用" : "生产自动批准开关未启用"}</strong>
        <span>{risk.shadowWouldAutoApprove ? "Shadow 评估为可能自动批准；本轮仍需人工批准。" : "当前风险或资格证据不足，保持 fail closed。"}</span>
        {!state.detectorRunCompleted ? <span className="privacy-risk-blocker">尚无真实检测器完成证据，不能批准。</span> : null}
      </div>

      <section className="privacy-hard-gates" aria-labelledby="privacy-hard-gates-title">
        <h4 id="privacy-hard-gates-title">17 项后端硬闸门</h4>
        <ol>
          {state.hardGates.map((gate) => (
            <li key={gate.gateId} className={gate.passed ? "is-pass" : "is-fail"}>
              <span aria-hidden="true">{gate.passed ? "✓" : "✕"}</span>
              <strong>{gate.gateId}</strong>
              <span>{gate.passed ? "通过" : gate.reasonCodes.join("、")}</span>
            </li>
          ))}
        </ol>
      </section>

      <div className="privacy-risk-toolbar" aria-label="风险排序、筛选与历史操作">
        <label>排序
          <select value={sort} onChange={(event) => setSort(event.target.value as RiskPageSort)}>
            <option value="risk">风险优先</option><option value="page">页码顺序</option>
          </select>
        </label>
        <label>筛选
          <select value={filter} onChange={(event) => setFilter(event.target.value as RiskPageFilter)}>
            <option value="all">全部</option><option value="unresolved">未解决风险</option>
            <option value="p0">仅 P0</option><option value="ocr">仅 OCR 风险</option>
            <option value="visual">仅视觉风险</option>
          </select>
        </label>
        <button type="button" disabled={busy || !state.canUndo} onClick={onUndo}>撤销</button>
        <button type="button" disabled={busy || !state.canRedo} onClick={onRedo}>重做</button>
      </div>

      <div className="privacy-risk-layout">
        <nav className="privacy-risk-pages" aria-label="风险页列表">
          {pages.map((page) => (
            <article key={page.pageIndex}>
              <strong>第 {page.pageIndex + 1} 页</strong>
              <span>P0 {page.p0Count} · P1 {page.p1Count} · P2 {page.p2Count}</span>
              <span>readiness {page.readinessScore} · OCR 最低 {ppm(page.ocrMinPpm)}</span>
              {page.visualReviewRequired ? <span>▲ 需要视觉复核</span> : null}
              {!page.completenessPassed ? <span>✕ 页面完整性未通过</span> : null}
            </article>
          ))}
        </nav>

        <div className="privacy-risk-findings" aria-label="风险发现列表">
          {visibleFindings.map((finding) => {
            const severity = SEVERITY_VIEW[finding.severity];
            return (
              <button
                type="button"
                key={finding.findingId}
                className={findingClassName(finding, selectedCluster)}
                aria-label={`${severity.label}，第 ${finding.pageIndex + 1} 页，${ENTITY_LABELS[finding.entityType]}`}
                aria-pressed={finding.findingId === selectedFindingId}
                onClick={() => {
                  setSelectedFindingId(finding.findingId);
                  setEntityType(finding.entityType);
                  setReplacement(finding.proposedReplacement);
                }}
              >
                <span className="risk-icon" aria-hidden="true">{severity.icon}</span>
                <strong>{severity.label}</strong>
                <span>第 {finding.pageIndex + 1} 页 · {ENTITY_LABELS[finding.entityType]}</span>
                <span>{finding.reasonCodes.join("、")}</span>
                {conflict(finding) ? <span>▲ detector 冲突</span> : null}
                {uncertain(finding) ? <span>▲ OCR/字形/置信度不确定</span> : null}
              </button>
            );
          })}
          {visibleFindings.length === 0 ? <p>当前筛选下没有风险发现。</p> : null}
        </div>
      </div>

      {state.documentRisk.pageRisks.some((page) => page.visualRisks.length > 0) ? (
        <section className="privacy-risk-explanation" aria-labelledby="privacy-visual-risk-title">
          <h4 id="privacy-visual-risk-title">视觉风险显式确认</h4>
          <p>每项必须填写原因并选择“已脱敏”或“经查看不敏感”。确认绑定当前 revision、当前脱敏内容哈希和操作人，重新 OCR/检测会使旧确认失效。</p>
          {state.documentRisk.pageRisks.flatMap((page) =>
            page.visualRisks.map((riskCode) => {
              const key = visualKey(page.pageIndex, riskCode);
              return (
                <div className="privacy-risk-edit-grid" key={key}>
                  <strong>第 {page.pageIndex + 1} 页 · <code>{riskCode}</code></strong>
                  <label>确认理由
                    <input
                      autoComplete="off"
                      value={visualReasons[key] ?? ""}
                      onChange={(event) => setVisualReasons((current) => ({ ...current, [key]: event.target.value }))}
                    />
                  </label>
                  <button type="button" disabled={busy || !(visualReasons[key] ?? "").trim()} onClick={() => resolveVisualRisk(page.pageIndex, riskCode, "confirmed_redacted")}>确认已脱敏</button>
                  <button type="button" disabled={busy || !(visualReasons[key] ?? "").trim()} onClick={() => resolveVisualRisk(page.pageIndex, riskCode, "confirmed_reviewed_non_sensitive")}>确认不敏感</button>
                </div>
              );
            }),
          )}
        </section>
      ) : null}

      {selected ? (
        <section className="privacy-risk-explanation" aria-labelledby="privacy-risk-explanation-title">
          <header>
            <h4 id="privacy-risk-explanation-title">发现证据与处理</h4>
            <div><button type="button" onClick={() => moveRisk(-1)}>上一风险</button><button type="button" onClick={() => moveRisk(1)}>下一风险</button></div>
          </header>
          <dl>
            <div><dt>实体类别</dt><dd>{ENTITY_LABELS[selected.entityType]}</dd></div>
            <div><dt>严重度</dt><dd>{SEVERITY_VIEW[selected.severity].label}</dd></div>
            <div><dt>Reason codes</dt><dd>{selected.reasonCodes.join("、")}</dd></div>
            <div><dt>Detector</dt><dd>{selected.detectorSources.join("、")}</dd></div>
            <div><dt>OCR / layout confidence</dt><dd>{ppm(selected.ocrConfidencePpm)} / {ppm(selected.layoutConfidencePpm)}</dd></div>
            <div><dt>案件词典</dt><dd>{selected.caseDictionaryMatch ? "命中" : "未命中"}</dd></div>
            <div><dt>同一 cluster</dt><dd>{selected.clusterId ?? "无"} · {selected.clusterOccurrenceCount} 处</dd></div>
          </dl>
          <div className="privacy-risk-actions">
            <button type="button" disabled={busy} onClick={() => onAction({ kind: "accept_replacement", findingId: selected.findingId, applyCluster: false })}>接受替换</button>
            <button type="button" disabled={busy || !selected.clusterId} onClick={() => onAction({ kind: "accept_replacement", findingId: selected.findingId, applyCluster: true })}>整个 cluster 接受替换</button>
            <button type="button" disabled={busy} onClick={() => onAction({ kind: "mark_not_sensitive", findingId: selected.findingId })}>标记为不敏感</button>
            <button type="button" disabled={busy || !selected.clusterId} onClick={() => onAction({ kind: "split_cluster", findingId: selected.findingId })}>拆分 cluster</button>
          </div>
          <div className="privacy-risk-edit-grid">
            <label>修改实体类别<select value={entityType} onChange={(event) => setEntityType(event.target.value as PrivacyEntityType)}>{Object.entries(ENTITY_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
            <button type="button" disabled={busy} onClick={() => onAction({ kind: "change_entity_type", findingId: selected.findingId, entityType })}>提交类别</button>
            <label>修改占位符<input autoComplete="off" value={replacement} onChange={(event) => setReplacement(event.target.value)} /></label>
            <button type="button" disabled={busy || !replacement.trim()} onClick={() => onAction({ kind: "change_placeholder", findingId: selected.findingId, replacement: replacement.trim(), applyCluster: false })}>提交占位符</button>
            <label>加入案件词典<select value={dictionaryCategory} onChange={(event) => setDictionaryCategory(event.target.value as PrivacyDictionaryCategory)}>{Object.entries(DICTIONARY_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
            <label><input type="checkbox" checked={dictionaryRequired} onChange={(event) => setDictionaryRequired(event.target.checked)} />设为必需实体</label>
            <button type="button" disabled={busy} onClick={() => onAction({ kind: "add_to_dictionary", findingId: selected.findingId, category: dictionaryCategory, required: dictionaryRequired })}>加入词典</button>
            <label>合并到 cluster<select value={mergeTarget} onChange={(event) => setMergeTarget(event.target.value)}><option value="">请选择</option>{clusters.filter((cluster) => cluster !== selected.clusterId).map((cluster) => <option key={cluster} value={cluster}>{cluster}</option>)}</select></label>
            <button type="button" disabled={busy || !selected.clusterId || !mergeTarget} onClick={() => onAction({ kind: "merge_clusters", clusterIds: [selected.clusterId ?? "", mergeTarget] })}>合并 cluster</button>
          </div>
        </section>
      ) : null}

      {state.visualRiskResolutions.length > 0 ? (
        <p className="privacy-help">已保存 {state.visualRiskResolutions.length} 条 revision 绑定的视觉风险确认记录。</p>
      ) : null}
      {manualBlockers.length > 0 ? (
        <p className="privacy-risk-blocker">人工批准仍被阻断：{manualBlockers.map((gate) => gate.gateId).join("、")}</p>
      ) : null}
      <footer className="privacy-risk-footer">
        <button type="button" disabled={busy} onClick={() => onAction({ kind: "confirm_edited_output" })}>保存当前编辑并重跑残留扫描</button>
        <button type="button" disabled={busy} onClick={() => onAction({ kind: "batch_accept_p3" })}>批量接受 P3</button>
        <button type="button" disabled={manualApprovalDisabled} onClick={onManualApprove}>进入人工批准</button>
        <button className="is-danger" type="button" disabled={busy || state.rejected} onClick={() => onAction({ kind: "reject_publication" })}>拒绝发布</button>
      </footer>
    </section>
  );
}
