use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchLawsRequest {
    pub query: String,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchLawsResponse {
    pub results: Vec<LawSearchResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LawSearchResult {
    pub document_id: String,
    pub title: String,
    pub document_type: String,
    pub authority_name: String,
    pub effectiveness_level: String,
    pub status: String,
    pub current_version_id: Option<String>,
    pub current_effective_from: Option<String>,
    pub current_effective_to: Option<String>,
    pub matched_alias: Option<String>,
    pub summary: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchArticlesRequest {
    pub query: String,
    pub document_id: Option<String>,
    pub case_date: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchArticlesResponse {
    pub results: Vec<ArticleSearchResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArticleSearchResult {
    pub article_id: String,
    pub document_id: String,
    pub version_id: String,
    pub document_title: String,
    pub article_number: String,
    pub article_title: Option<String>,
    pub snippet: String,
    pub citation_id: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub version_status: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetArticleRequest {
    pub article_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetArticleResponse {
    pub article: Option<LawArticleDetail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LawArticleDetail {
    pub article_id: String,
    pub document_id: String,
    pub version_id: String,
    pub document_title: String,
    pub version_label: String,
    pub article_number: String,
    pub article_title: Option<String>,
    pub content: String,
    pub citation_id: String,
    pub canonical_label: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub version_status: String,
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLawVersionsRequest {
    pub document_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLawVersionsResponse {
    pub versions: Vec<LawVersionInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LawVersionInfo {
    pub version_id: String,
    pub document_id: String,
    pub version_label: String,
    pub status: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub published_on: Option<String>,
    pub source_reference: String,
    pub article_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationDirection {
    Both,
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLawRelationsRequest {
    pub document_id: String,
    pub direction: Option<RelationDirection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLawRelationsResponse {
    pub relations: Vec<LawRelationInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LawRelationInfo {
    pub relation_id: String,
    pub from_document_id: String,
    pub from_title: String,
    pub to_document_id: String,
    pub to_title: String,
    pub relation_type: String,
    pub description: String,
    pub source_reference: String,
}

pub fn generate_article_citation_id(
    document_id: &str,
    version_id: &str,
    article_number: &str,
) -> String {
    let normalized_article = article_number
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();

    if normalized_article.is_empty() {
        format!("law:{document_id}:{version_id}:art:{article_number}")
    } else {
        format!("law:{document_id}:{version_id}:art:{normalized_article}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_articles_request_serializes_for_ipc() {
        let request = SearchArticlesRequest {
            query: "合同".to_owned(),
            document_id: Some("cn-civil-code".to_owned()),
            case_date: Some("2024-01-01".to_owned()),
            limit: Some(20),
        };

        let serialized = serde_json::to_value(request).expect("request serializes");

        assert_eq!(serialized["query"], "合同");
        assert_eq!(serialized["documentId"], "cn-civil-code");
        assert_eq!(serialized["caseDate"], "2024-01-01");
        assert_eq!(serialized["limit"], 20);
    }

    #[test]
    fn relation_direction_uses_snake_case_contract() {
        let serialized =
            serde_json::to_value(RelationDirection::Outgoing).expect("direction serializes");

        assert_eq!(serialized, "outgoing");
    }
}
