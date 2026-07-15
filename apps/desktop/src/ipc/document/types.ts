export type DocumentTemplateId =
  | "complaint"
  | "defence"
  | "evidence_schedule"
  | "fact_timeline"
  | "legal_research_report"
  | "lawyer_letter";

export interface DocumentTemplateMetadata {
  templateId: DocumentTemplateId;
  name: string;
  scenario: string;
  requiredFields: string[];
  optionalFields: string[];
  citationPolicy: string;
  version: string;
}

export interface DocumentCitation {
  sourceId: string;
  canonicalLabel: string;
  excerpt: string;
  documentId: string;
  versionId: string;
  articleId: string;
}

export interface DocumentSection {
  heading: string;
  level: number;
  paragraphs: string[];
  sourceIds: string[];
}

export interface DocumentTableRow {
  cells: string[];
  sourceIds: string[];
}

export interface DocumentTable {
  sectionHeading: string;
  headers: string[];
  columnWidthsDxa: number[];
  rows: DocumentTableRow[];
  sourceIds: string[];
}

export interface GeneratedDocument {
  template: DocumentTemplateMetadata;
  title: string;
  fields: Array<{
    key: string;
    value: string;
    sourceKind: string;
    sourceId: string;
  }>;
  sections: DocumentSection[];
  tables: DocumentTable[];
  citations: DocumentCitation[];
  markdown: string;
}

export interface DocumentValidationErrorPayload {
  code: string;
  missingFields: string[];
  invalidCitationIds: string[];
}

export interface DocumentIpcError {
  errorType: string;
  message: string;
}

export interface PreviewDocumentRequest {
  projectId: string;
  templateId: DocumentTemplateId;
  modelDraft?: string | null;
}

export interface ExportDocumentRequest extends PreviewDocumentRequest {
  exportPath: string;
}
