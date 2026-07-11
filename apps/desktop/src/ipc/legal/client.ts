import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  CancelLegalAnswerRequest,
  CancelLegalAnswerResponse,
  GetArticleRequest,
  GetArticleResponse,
  GetLawRelationsRequest,
  GetLawRelationsResponse,
  GetLawVersionsRequest,
  GetLawVersionsResponse,
  LegalAnswerCandidatesRequest,
  LegalAnswerCandidatesResponse,
  LegalAnswerRequest,
  LegalAnswerResponse,
  LegalAnswerStreamEvent,
  SearchArticlesRequest,
  SearchArticlesResponse,
  SearchLawsRequest,
  SearchLawsResponse,
} from "./types";

export function searchLaws(
  request: SearchLawsRequest,
): Promise<SearchLawsResponse> {
  return invoke<SearchLawsResponse>("search_laws", { request });
}

export function searchArticles(
  request: SearchArticlesRequest,
): Promise<SearchArticlesResponse> {
  return invoke<SearchArticlesResponse>("search_articles", { request });
}

export function getArticle(
  request: GetArticleRequest,
): Promise<GetArticleResponse> {
  return invoke<GetArticleResponse>("get_article", { request });
}

export function getLawVersions(
  request: GetLawVersionsRequest,
): Promise<GetLawVersionsResponse> {
  return invoke<GetLawVersionsResponse>("get_law_versions", { request });
}

export function getLawRelations(
  request: GetLawRelationsRequest,
): Promise<GetLawRelationsResponse> {
  return invoke<GetLawRelationsResponse>("get_law_relations", { request });
}

export function findLegalAnswerCandidates(
  request: LegalAnswerCandidatesRequest,
): Promise<LegalAnswerCandidatesResponse> {
  return invoke<LegalAnswerCandidatesResponse>("find_legal_answer_candidates", {
    request,
  });
}

export function answerLegalQuestion(
  request: LegalAnswerRequest,
  onEvent: (event: LegalAnswerStreamEvent) => void,
): Promise<LegalAnswerResponse> {
  const eventChannel = new Channel<LegalAnswerStreamEvent>(onEvent);

  return invoke<LegalAnswerResponse>("answer_legal_question", {
    request,
    onEvent: eventChannel,
  });
}

export function cancelLegalAnswer(
  request: CancelLegalAnswerRequest,
): Promise<CancelLegalAnswerResponse> {
  return invoke<CancelLegalAnswerResponse>("cancel_legal_answer", { request });
}
