export interface SearchLawsRequest {
  query: string;
  limit?: number;
}

export interface SearchLawsResponse {
  results: LawSearchResult[];
}

export interface LawSearchResult {
  documentId: string;
  title: string;
  documentType: string;
  authorityName: string;
  effectivenessLevel: string;
  status: string;
  currentVersionId?: string | null;
  currentEffectiveFrom?: string | null;
  currentEffectiveTo?: string | null;
  matchedAlias?: string | null;
  summary: string;
  score: number;
}

export interface SearchArticlesRequest {
  query: string;
  documentId?: string | null;
  caseDate?: string | null;
  limit?: number;
}

export interface SearchArticlesResponse {
  results: ArticleSearchResult[];
}

export interface ArticleSearchResult {
  articleId: string;
  documentId: string;
  versionId: string;
  documentTitle: string;
  articleNumber: string;
  articleTitle?: string | null;
  snippet: string;
  citationId: string;
  effectiveFrom: string;
  effectiveTo?: string | null;
  versionStatus: string;
  score: number;
}

export interface GetArticleRequest {
  articleId: string;
}

export interface GetArticleResponse {
  article?: LawArticleDetail | null;
}

export interface LawArticleDetail {
  articleId: string;
  documentId: string;
  versionId: string;
  documentTitle: string;
  versionLabel: string;
  articleNumber: string;
  articleTitle?: string | null;
  content: string;
  citationId: string;
  canonicalLabel: string;
  effectiveFrom: string;
  effectiveTo?: string | null;
  versionStatus: string;
  topics: string[];
}

export interface GetLawVersionsRequest {
  documentId: string;
}

export interface GetLawVersionsResponse {
  versions: LawVersionInfo[];
}

export interface LawVersionInfo {
  versionId: string;
  documentId: string;
  versionLabel: string;
  status: string;
  effectiveFrom: string;
  effectiveTo?: string | null;
  publishedOn?: string | null;
  sourceReference: string;
  articleCount: number;
}

export type RelationDirection = "both" | "outgoing" | "incoming";

export interface GetLawRelationsRequest {
  documentId: string;
  direction?: RelationDirection | null;
}

export interface GetLawRelationsResponse {
  relations: LawRelationInfo[];
}

export interface LawRelationInfo {
  relationId: string;
  fromDocumentId: string;
  fromTitle: string;
  toDocumentId: string;
  toTitle: string;
  relationType: string;
  description: string;
  sourceReference: string;
}

export interface LegalAnswerCandidatesRequest {
  question: string;
  lawName?: string | null;
  articleNumber?: string | null;
  keywords: string[];
  caseDate?: string | null;
  effectivenessLevels: string[];
  includeExpired: boolean;
  limit?: number | null;
}

export interface StructuredLegalQuery {
  lawNames: string[];
  articleNumbers: string[];
  keywords: string[];
  legalIssue: string;
  caseDate?: string | null;
  effectivenessLevels: string[];
  includeExpired: boolean;
}

export interface LegalSource {
  sourceId: string;
  articleId: string;
  documentId: string;
  versionId: string;
  documentTitle: string;
  versionLabel: string;
  articleNumber: string;
  articleTitle?: string | null;
  canonicalLabel: string;
  content: string;
  snippet: string;
  effectiveFrom: string;
  effectiveTo?: string | null;
  versionStatus: string;
}

export interface LegalAnswerContext {
  query: StructuredLegalQuery;
  sources: LegalSource[];
  prompt: string;
  warnings: string[];
}

export interface LegalAnswerCandidatesResponse {
  context: LegalAnswerContext;
}

export type CitationStatus = "valid" | "invalid";

export type CitationInvalidReason =
  | "invalid_syntax"
  | "duplicate"
  | "not_found"
  | "not_in_context"
  | "version_mismatch"
  | "date_out_of_range"
  | "paragraph_not_found";

export interface ValidatedCitation {
  rawMarker: string;
  sourceId: string;
  status: CitationStatus;
  reason?: CitationInvalidReason | null;
  source?: LegalSource | null;
}

export interface CitationValidationReport {
  citations: ValidatedCitation[];
  validCount: number;
  invalidCount: number;
  unsupportedLegalConclusion: boolean;
}

export interface LegalAnswerRequest extends LegalAnswerCandidatesRequest {
  providerId: string;
  temperature?: number | null;
  maxTokens?: number | null;
}

export type LegalAnswerStreamEventType = "delta" | "usage" | "error" | "done";

export interface LegalAnswerStreamEvent {
  eventType: LegalAnswerStreamEventType;
  content?: string | null;
  errorType?: string | null;
  message?: string | null;
}

export interface LegalAnswerResponse {
  providerId: string;
  answer: string;
  context: LegalAnswerContext;
  citationReport: CitationValidationReport;
  streamEvents: LegalAnswerStreamEvent[];
  recordId?: string | null;
}
