import type {
  CaseGapKind,
  CaseGapSeverity,
  CitationInvalidReason,
  CitationStatus,
  ConfirmationStatus,
  LegalIssueStatus,
  PartyRole,
} from "./types";

export function formatPartyRole(role: PartyRole): string {
  const labels: Record<PartyRole, string> = {
    plaintiff: "原告",
    defendant: "被告",
    claimant: "申请人",
    respondent: "被申请人",
    third_party: "第三人",
    other: "其他",
  };

  return labels[role];
}

export function formatConfirmationStatus(status: ConfirmationStatus): string {
  return status === "confirmed" ? "已确认事实" : "模型建议";
}

export function formatLegalIssueStatus(status: LegalIssueStatus): string {
  return status === "open" ? "待处理" : "已解决";
}

export function formatGapKind(kind: CaseGapKind): string {
  const labels: Record<CaseGapKind, string> = {
    timeline_conflict: "时间线冲突",
    party_name_inconsistent: "当事人名称不一致",
    evidence_missing_source: "证据缺少来源",
    fact_missing_evidence: "事实缺少证据支撑",
    evidence_missing_formed_on: "证据缺少形成时间",
    invalid_evidence_id: "无效证据编号",
    legal_issue_missing_basis: "争点缺少法律依据",
  };

  return labels[kind];
}

export function formatGapSeverity(severity: CaseGapSeverity): string {
  return severity === "blocking" ? "需处理" : "提醒";
}

export function formatLegalBasisStatus(status: CitationStatus): string {
  return status === "valid" ? "已校验" : "未通过";
}

export function formatLegalBasisInvalidReason(
  reason?: CitationInvalidReason | null,
): string {
  const labels: Record<CitationInvalidReason, string> = {
    invalid_syntax: "引用格式无效",
    duplicate: "重复引用",
    not_found: "本地库不存在",
    not_in_context: "未在候选来源中",
    version_mismatch: "法律版本不匹配",
    date_out_of_range: "不适用于案件日期",
    paragraph_not_found: "条文段落不存在",
  };

  return reason ? labels[reason] : "未知原因";
}
