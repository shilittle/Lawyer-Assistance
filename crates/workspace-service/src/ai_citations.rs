//! Durable, mechanical citation evidence for AI answers.
//!
//! Evidence stores identities, hashes, locators and check states only. Source
//! bodies stay in the read-only legal database and exist only in the blocking
//! verification worker while a match is being evaluated.

use crate::{hash, id, now, AdmissionClass, AiRun, Error, Result, Workspace};
use serde::{de::Deserializer, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AiCaseDateUpdate {
    /// The JSON member was omitted, so retain the run's existing date.
    #[default]
    Inherit,
    /// A present JSON member either replaces the date (`Some`) or explicitly
    /// clears it (`None`).
    Set(Option<String>),
}

impl<'de> Deserialize<'de> for AiCaseDateUpdate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(Self::Set)
    }
}

#[cfg(test)]
mod date_update_tests {
    use super::*;

    #[test]
    fn date_edit_distinguishes_omitted_null_and_value() {
        let omitted: AiDocumentEdit =
            serde_json::from_value(json!({"expected_revision": 3, "content": "x"})).unwrap();
        let cleared: AiDocumentEdit = serde_json::from_value(json!({
            "expected_revision": 3,
            "content": "x",
            "case_date": null
        }))
        .unwrap();
        let explicit: AiDocumentEdit = serde_json::from_value(json!({
            "expected_revision": 3,
            "content": "x",
            "case_date": "2026-08-11"
        }))
        .unwrap();
        assert_eq!(omitted.case_date, AiCaseDateUpdate::Inherit);
        assert_eq!(cleared.case_date, AiCaseDateUpdate::Set(None));
        assert_eq!(
            explicit.case_date,
            AiCaseDateUpdate::Set(Some("2026-08-11".into()))
        );
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiDocumentEdit {
    pub expected_revision: u64,
    pub content: String,
    /// Omitted means inherit; JSON null means explicitly clear the legal
    /// query date. This distinction prevents an old edit from silently
    /// changing a version-scoped answer's date.
    #[serde(default)]
    pub case_date: AiCaseDateUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AiCitationMatchRange {
    /// UTF-8 byte positions in the authoritative source body. Both values
    /// come from `str::match_indices`, so no offset can split a code point.
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AiCitationSourceEvidence {
    pub source_kind: String,
    pub source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_full_text_sha256: Option<String>,
    pub citation_locator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_sha256: Option<String>,
    pub matched_ranges: Vec<AiCitationMatchRange>,
    pub source_exists: String,
    pub full_text_read: String,
    pub citation_match: String,
    pub time_check: String,
    pub source_content: String,
    /// A stable, body-free read outcome. This never contains a database or
    /// provider diagnostic and is absent after a successful source read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    /// Mechanical checks never establish legal relevance.
    pub relevance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AiCitationVerification {
    pub state: String,
    pub reasons: Vec<String>,
    pub body_sha256: String,
    pub run_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<u64>,
    pub sources: Vec<AiCitationSourceEvidence>,
}

impl AiCitationVerification {
    pub(crate) fn legacy_pending() -> Self {
        Self {
            state: "legacy_pending".into(),
            reasons: vec!["citation_evidence_missing".into()],
            body_sha256: String::new(),
            run_revision: 0,
            case_date: None,
            verified_at: None,
            sources: Vec::new(),
        }
    }

    pub(crate) fn stale_for_run(run: &AiRun, reason: &str) -> Self {
        Self {
            state: "stale".into(),
            reasons: vec![reason.into()],
            body_sha256: hash(run.content.as_bytes()),
            run_revision: run.revision,
            case_date: run.request.case_date.clone(),
            verified_at: None,
            sources: Vec::new(),
        }
    }

    pub(crate) fn state_for_run(&self, run: &AiRun) -> String {
        // Missing historical evidence is its own conservative state. It is
        // not a proof bound to revision zero, so a legacy row must remain
        // `legacy_pending` rather than being misleadingly relabelled stale.
        if self.state == "legacy_pending" {
            "legacy_pending".into()
        } else if self.run_revision != run.revision
            || self.body_sha256 != hash(run.content.as_bytes())
            || self.case_date != run.request.case_date
        {
            "stale".into()
        } else {
            self.state.clone()
        }
    }

    pub(crate) fn public_view(&self, run: &AiRun) -> Value {
        let mut view = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        view["state"] = json!(self.state_for_run(run));
        view
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct AiDocumentExportRecord {
    id: String,
    run_id: String,
    run_revision: u64,
    format: String,
    citation_state: String,
    citation_body_sha256: String,
    exported_at: u64,
}

#[derive(Clone)]
pub(crate) struct CitationInput {
    kind: String,
    id: String,
    quote: Option<String>,
    reason: String,
}

pub(crate) struct CitationCheckResult {
    pub(crate) citations: Vec<Value>,
    pub(crate) verification: AiCitationVerification,
}

/// All immutable inputs that bind a mechanical citation check to an answer.
/// Keeping this together avoids a call site accidentally passing an old body
/// hash or date beside a new run revision.
pub(crate) struct CitationCheckRequest {
    pub(crate) inputs: Vec<CitationInput>,
    pub(crate) body_sha256: String,
    pub(crate) run_revision: u64,
    pub(crate) case_date: Option<String>,
    pub(crate) previous: Option<AiCitationVerification>,
    pub(crate) allow_missing_sources: bool,
}

struct QuoteMatch {
    state: &'static str,
    quote_sha256: Option<String>,
    ranges: Vec<AiCitationMatchRange>,
}

struct CancelSearchOnDrop(legal_services::SearchCancellation);

impl Drop for CancelSearchOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl Workspace {
    pub(crate) fn final_citation_inputs(
        &self,
        run: &AiRun,
        values: &[Value],
    ) -> Result<Vec<CitationInput>> {
        let mut inputs = Vec::new();
        let mut seen = BTreeSet::new();
        for value in values {
            let (preferred_kind, source_id) = if let Some(id) = value["article_id"].as_str() {
                (Some("article"), id)
            } else if let Some(id) = value["case_id"].as_str() {
                (Some("case"), id)
            } else if let Some(id) = value["id"].as_str() {
                (None, id)
            } else {
                return Err(Error::new("citation_identifier_missing"));
            };
            if source_id.is_empty() || source_id.len() > 200 {
                return Err(Error::new("citation_identifier_missing"));
            }
            let source = resolve_allowed_source(&run.allowed_sources, preferred_kind, source_id)?;
            let kind = source["kind"]
                .as_str()
                .filter(|kind| matches!(*kind, "article" | "case"))
                .ok_or_else(|| Error::new("citation_not_retrieved"))?;
            let key = source_key(kind, source_id);
            if !seen.insert(key) {
                continue;
            }
            let quote = value["quote"]
                .as_str()
                .filter(|quote| !quote.is_empty())
                .map(str::to_owned);
            if quote
                .as_ref()
                .is_some_and(|quote| quote.len() > 64 * 1024 || quote.contains('\0'))
            {
                return Err(Error::new("citation_quote_invalid"));
            }
            let reason = value["reason"]
                .as_str()
                .filter(|reason| !reason.is_empty() && reason.len() <= 8 * 1024)
                .unwrap_or("相关法律依据")
                .to_owned();
            inputs.push(CitationInput {
                kind: kind.into(),
                id: source_id.into(),
                quote,
                reason,
            });
        }
        Ok(inputs)
    }

    pub(crate) fn persisted_citation_inputs(&self, run: &AiRun) -> Result<Vec<CitationInput>> {
        // A public citation omits a mismatched quote so consumers do not
        // mistake it for an authenticated excerpt.  The encrypted final model
        // message is nevertheless part of the run record, and lets a later
        // mechanical recheck retry the exact quoted span without putting the
        // source body into evidence.
        for message in run.messages.iter().rev() {
            let Some(content) = message["content"].as_str() else {
                continue;
            };
            let Ok(answer) = serde_json::from_str::<Value>(super::strip_json_fence(content)) else {
                continue;
            };
            let Some(citations) = answer["citations"].as_array() else {
                continue;
            };
            let inputs = self.final_citation_inputs(run, citations)?;
            if !inputs.is_empty() {
                return Ok(inputs);
            }
        }
        let mut inputs = Vec::new();
        let mut seen = BTreeSet::new();
        for citation in &run.citations {
            let kind = citation["kind"]
                .as_str()
                .filter(|kind| matches!(*kind, "article" | "case"))
                .ok_or_else(|| Error::new("citation_evidence_missing"))?;
            let id = match kind {
                "article" => citation["article_id"].as_str(),
                "case" => citation["case_id"].as_str(),
                _ => None,
            }
            .filter(|id| !id.is_empty() && id.len() <= 200)
            .ok_or_else(|| Error::new("citation_evidence_missing"))?;
            if !seen.insert(source_key(kind, id)) {
                continue;
            }
            let quote = citation["quote"]
                .as_str()
                .filter(|quote| !quote.is_empty())
                .map(str::to_owned);
            inputs.push(CitationInput {
                kind: kind.into(),
                id: id.into(),
                quote,
                reason: citation["reason"]
                    .as_str()
                    .filter(|reason| !reason.is_empty() && reason.len() <= 8 * 1024)
                    .unwrap_or("相关法律依据")
                    .to_owned(),
            });
        }
        Ok(inputs)
    }

    pub(crate) async fn check_ai_citations(
        &self,
        request: CitationCheckRequest,
        cancel: &CancellationToken,
    ) -> Result<CitationCheckResult> {
        let permit = self
            .acquire_admission(AdmissionClass::Search, cancel)
            .await?;
        let legal = self.legal.clone();
        let worker_token = cancel.clone();
        let search_cancel = legal_services::SearchCancellation::new();
        let _cancel_search = CancelSearchOnDrop(search_cancel.clone());
        let worker_search_cancel = search_cancel.clone();
        let prior_hashes = previous_source_hashes(request.previous.as_ref());
        let mut worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if worker_token.is_cancelled() {
                return Err(Error::new("cancelled"));
            }
            resolve_citation_sources(
                &legal,
                &worker_search_cancel,
                request.inputs,
                request.body_sha256,
                request.run_revision,
                request.case_date,
                prior_hashes,
                request.allow_missing_sources,
            )
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                search_cancel.cancel();
                let _ = worker.await;
                Err(Error::new("cancelled"))
            }
            result = &mut worker => result.map_err(|_| Error::new("citation_recheck_failed"))?,
        }
    }

    pub async fn recheck_ai_citations(
        self: &Arc<Self>,
        id: &str,
        expected_revision: u64,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let snapshot = {
            let _gate = self.lock()?;
            let run: AiRun = self.store.get("ai_run", id)?;
            if run.revision != expected_revision {
                return Err(Error::new("revision_conflict"));
            }
            if run.status != "completed" {
                return Err(Error::new("document_not_ready"));
            }
            run
        };
        let inputs = self.persisted_citation_inputs(&snapshot)?;
        let checked = self
            .check_ai_citations(
                CitationCheckRequest {
                    inputs,
                    body_sha256: hash(snapshot.content.as_bytes()),
                    run_revision: snapshot.revision,
                    case_date: snapshot.request.case_date.clone(),
                    previous: snapshot.citation_verification.clone(),
                    allow_missing_sources: true,
                },
                cancel,
            )
            .await?;
        let _gate = self.lock()?;
        let mut current: AiRun = self.store.get("ai_run", id)?;
        if current.revision != snapshot.revision
            || current.content != snapshot.content
            || current.request.case_date != snapshot.request.case_date
        {
            return Err(Error::new("revision_conflict"));
        }
        current.citations = checked.citations;
        current.citation_verification = Some(checked.verification);
        current.updated_at = now();
        self.store.save("ai_run", id, &current)?;
        Ok(Self::public_run(&current))
    }

    pub(crate) fn record_ai_document_export(&self, run: &AiRun, format: &str) -> Result<()> {
        let verification = run
            .citation_verification
            .as_ref()
            .map(|verification| {
                (
                    verification.state_for_run(run),
                    verification.body_sha256.clone(),
                )
            })
            .unwrap_or_else(|| ("legacy_pending".into(), String::new()));
        let record = AiDocumentExportRecord {
            id: id("ai_export"),
            run_id: run.id.clone(),
            run_revision: run.revision,
            format: format.into(),
            citation_state: verification.0,
            citation_body_sha256: verification.1,
            exported_at: now(),
        };
        self.store.save("ai_document_export", &record.id, &record)
    }
}

fn resolve_allowed_source<'a>(
    sources: &'a BTreeMap<String, Value>,
    preferred_kind: Option<&str>,
    id: &str,
) -> Result<&'a Value> {
    if let Some(kind) = preferred_kind {
        return sources
            .get(&source_key(kind, id))
            .or_else(|| {
                sources
                    .get(id)
                    .filter(|source| source["kind"].as_str() == Some(kind))
            })
            .ok_or_else(|| Error::new("citation_not_retrieved"));
    }
    let found = ["article", "case"]
        .iter()
        .filter_map(|kind| sources.get(&source_key(kind, id)))
        .chain(sources.get(id))
        .collect::<Vec<_>>();
    match found.as_slice() {
        [source] => Ok(*source),
        [] => Err(Error::new("citation_not_retrieved")),
        _ => Err(Error::new("citation_identifier_ambiguous")),
    }
}

pub(crate) fn source_key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

fn previous_source_hashes(previous: Option<&AiCitationVerification>) -> BTreeMap<String, String> {
    previous
        .into_iter()
        .flat_map(|verification| verification.sources.iter())
        .filter_map(|source| {
            source.source_full_text_sha256.as_ref().map(|hash| {
                (
                    source_key(&source.source_kind, &source.source_id),
                    hash.clone(),
                )
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_citation_sources(
    legal: &legal_services::LegalServices,
    cancellation: &legal_services::SearchCancellation,
    inputs: Vec<CitationInput>,
    body_sha256: String,
    run_revision: u64,
    case_date: Option<String>,
    previous_hashes: BTreeMap<String, String>,
    allow_missing_sources: bool,
) -> Result<CitationCheckResult> {
    let mut citations = Vec::new();
    let mut sources = Vec::new();
    let mut reasons = BTreeSet::new();
    for input in inputs {
        if cancellation.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        let key = source_key(&input.kind, &input.id);
        let prior_hash = previous_hashes.get(&key).map(String::as_str);
        let resolved = match input.kind.as_str() {
            "article" => resolve_article(
                legal,
                cancellation,
                &input,
                case_date.as_deref(),
                prior_hash,
            ),
            "case" => resolve_case(legal, cancellation, &input, prior_hash),
            _ => Err(Error::new("citation_not_retrieved")),
        };
        match resolved {
            Ok((citation, evidence)) => {
                collect_evidence_reasons(&evidence, &mut reasons);
                citations.push(citation);
                sources.push(evidence);
            }
            Err(error) if error.code == "cancelled" => return Err(error),
            Err(error) if error.code == "citation_not_found" && allow_missing_sources => {
                let evidence = missing_source_evidence(&input);
                collect_evidence_reasons(&evidence, &mut reasons);
                citations.push(fallback_citation(&input));
                sources.push(evidence);
            }
            Err(error) if allow_missing_sources => {
                // A broken or unavailable legal database does not establish
                // that a source disappeared. Persist an explicitly pending,
                // body-free outcome for rechecks; cancellation still returns
                // above and never publishes partial evidence.
                let evidence =
                    unavailable_source_evidence(&input, safe_source_error_category(&error));
                collect_evidence_reasons(&evidence, &mut reasons);
                citations.push(fallback_citation(&input));
                sources.push(evidence);
            }
            Err(error) => return Err(error),
        }
    }
    if sources.is_empty() {
        reasons.insert("no_citations".into());
    }
    let state = if reasons.is_empty() {
        "passed"
    } else {
        "pending"
    };
    Ok(CitationCheckResult {
        citations,
        verification: AiCitationVerification {
            state: state.into(),
            reasons: reasons.into_iter().collect(),
            body_sha256,
            run_revision,
            case_date,
            verified_at: Some(now()),
            sources,
        },
    })
}

fn resolve_article(
    legal: &legal_services::LegalServices,
    cancellation: &legal_services::SearchCancellation,
    input: &CitationInput,
    case_date: Option<&str>,
    prior_hash: Option<&str>,
) -> Result<(Value, AiCitationSourceEvidence)> {
    let article = legal
        .legal_get_article_cancellable(
            legal_services::LegalGetArticleRequest {
                schema_version: 1,
                article_id: input.id.clone(),
            },
            cancellation,
        )
        .map_err(map_legal_error)?
        .article;
    let source_hash = hash(article.content.as_bytes());
    let quote_match = quote_match(input.quote.as_deref(), &article.content);
    let evidence = AiCitationSourceEvidence {
        source_kind: "article".into(),
        source_id: article.article_id.clone(),
        document_id: Some(article.document_id.clone()),
        version_id: Some(article.version_id.clone()),
        source_full_text_sha256: Some(source_hash.clone()),
        citation_locator: format!(
            "law-article:{}:{}:{}",
            article.document_id, article.version_id, article.article_number
        ),
        quote_sha256: quote_match.quote_sha256,
        matched_ranges: quote_match.ranges,
        source_exists: "passed".into(),
        full_text_read: "passed".into(),
        citation_match: quote_match.state.into(),
        time_check: article_time_check(
            case_date,
            &article.effective_from,
            article.effective_to.as_deref(),
            &article.version_status,
        )
        .into(),
        source_content: content_state(prior_hash, &source_hash).into(),
        error_category: None,
        relevance: "manual_review_required".into(),
    };
    let mut citation = json!({
        "kind":"article",
        "article_id":article.article_id,
        "document_id":article.document_id,
        "title":article.document_title,
        "article_number":article.article_number,
        "version_id":article.version_id,
        "version_label":article.version_label,
        "effective_from":article.effective_from,
        "effective_to":article.effective_to,
        "status":article.version_status,
        "reason":input.reason,
    });
    if evidence.citation_match == "matched" {
        citation["quote"] = json!(input.quote.as_deref().unwrap_or_default());
    }
    Ok((citation, evidence))
}

fn resolve_case(
    legal: &legal_services::LegalServices,
    cancellation: &legal_services::SearchCancellation,
    input: &CitationInput,
    prior_hash: Option<&str>,
) -> Result<(Value, AiCitationSourceEvidence)> {
    let case = legal
        .judicial_case_get_cancellable(
            legal_services::JudicialCaseGetRequest {
                schema_version: 1,
                case_id: input.id.clone(),
            },
            cancellation,
        )
        .map_err(map_legal_error)?
        .case;
    let source_hash = hash(case.full_text.as_bytes());
    let quote_match = quote_match(input.quote.as_deref(), &case.full_text);
    let evidence = AiCitationSourceEvidence {
        source_kind: "case".into(),
        source_id: case.summary.case_id.clone(),
        document_id: None,
        version_id: None,
        source_full_text_sha256: Some(source_hash.clone()),
        citation_locator: format!("judicial-case:{}", case.summary.case_id),
        quote_sha256: quote_match.quote_sha256,
        matched_ranges: quote_match.ranges,
        source_exists: "passed".into(),
        full_text_read: "passed".into(),
        citation_match: quote_match.state.into(),
        // A case publication date is retained as a factual record only. It is
        // never compared with case_date as a statutory applicability gate.
        time_check: "not_applicable".into(),
        source_content: content_state(prior_hash, &source_hash).into(),
        error_category: None,
        relevance: "manual_review_required".into(),
    };
    let mut citation = json!({
        "kind":"case",
        "case_id":case.summary.case_id,
        "title":case.summary.title,
        "source_url":case.summary.source_url,
        "publication_date":case.summary.publication_date,
        "status":case.summary.status,
        "reason":input.reason,
    });
    if evidence.citation_match == "matched" {
        citation["quote"] = json!(input.quote.as_deref().unwrap_or_default());
    }
    Ok((citation, evidence))
}

fn map_legal_error(error: legal_services::ServiceError) -> Error {
    match error.code.as_str() {
        "request_cancelled" | "cancelled" => Error::new("cancelled"),
        "not_found" => Error::new("citation_not_found"),
        _ => Error::new("citation_source_unavailable"),
    }
}

fn fallback_citation(input: &CitationInput) -> Value {
    let mut value = json!({"kind":input.kind,"reason":input.reason});
    value[if input.kind == "case" {
        "case_id"
    } else {
        "article_id"
    }] = json!(input.id);
    value
}

fn missing_source_evidence(input: &CitationInput) -> AiCitationSourceEvidence {
    AiCitationSourceEvidence {
        source_kind: input.kind.clone(),
        source_id: input.id.clone(),
        document_id: None,
        version_id: None,
        source_full_text_sha256: None,
        citation_locator: match input.kind.as_str() {
            "article" => format!("law-article:{}", input.id),
            "case" => format!("judicial-case:{}", input.id),
            _ => format!("source:{}", input.id),
        },
        quote_sha256: input.quote.as_ref().map(|quote| hash(quote.as_bytes())),
        matched_ranges: Vec::new(),
        source_exists: "not_found".into(),
        full_text_read: "not_read".into(),
        citation_match: "not_checked".into(),
        time_check: if input.kind == "case" {
            "not_applicable"
        } else {
            "unknown"
        }
        .into(),
        source_content: "unknown".into(),
        error_category: Some("citation_not_found".into()),
        relevance: "manual_review_required".into(),
    }
}

fn unavailable_source_evidence(
    input: &CitationInput,
    error_category: &'static str,
) -> AiCitationSourceEvidence {
    AiCitationSourceEvidence {
        source_kind: input.kind.clone(),
        source_id: input.id.clone(),
        document_id: None,
        version_id: None,
        source_full_text_sha256: None,
        citation_locator: match input.kind.as_str() {
            "article" => format!("law-article:{}", input.id),
            "case" => format!("judicial-case:{}", input.id),
            _ => format!("source:{}", input.id),
        },
        quote_sha256: input.quote.as_ref().map(|quote| hash(quote.as_bytes())),
        matched_ranges: Vec::new(),
        source_exists: "unknown".into(),
        full_text_read: "unavailable".into(),
        citation_match: "not_checked".into(),
        time_check: if input.kind == "case" {
            "not_applicable"
        } else {
            "unknown"
        }
        .into(),
        source_content: "unknown".into(),
        error_category: Some(error_category.into()),
        relevance: "manual_review_required".into(),
    }
}

fn safe_source_error_category(error: &Error) -> &'static str {
    match error.code.as_str() {
        "citation_source_unavailable" => "citation_source_unavailable",
        // Citation resolution deliberately collapses raw storage, SQLite and
        // service errors before this point. Keep an allowlist even if a later
        // implementation supplies a new internal code.
        _ => "citation_source_unavailable",
    }
}

fn quote_match(quote: Option<&str>, source: &str) -> QuoteMatch {
    let Some(quote) = quote else {
        return QuoteMatch {
            state: "not_provided",
            quote_sha256: None,
            ranges: Vec::new(),
        };
    };
    // Source bodies can contain a repeated boilerplate quote. Preserve only a
    // bounded set of byte ranges; the state makes the multiplicity explicit.
    let ranges = source
        .match_indices(quote)
        .take(8)
        .map(|(start_byte, matched)| AiCitationMatchRange {
            start_byte,
            end_byte: start_byte + matched.len(),
        })
        .collect::<Vec<_>>();
    QuoteMatch {
        state: match ranges.len() {
            0 => "mismatch",
            1 => "matched",
            _ => "ambiguous",
        },
        quote_sha256: Some(hash(quote.as_bytes())),
        ranges,
    }
}

fn article_time_check(
    case_date: Option<&str>,
    effective_from: &str,
    effective_to: Option<&str>,
    version_status: &str,
) -> &'static str {
    let Some(case_date) = case_date else {
        return "unknown";
    };
    if !domain::date::is_iso_calendar_date(case_date) {
        return "unknown";
    }
    if effective_from > case_date
        || effective_to.is_some_and(|effective_to| effective_to < case_date)
        || (version_status == "repealed" && effective_to.is_none())
    {
        "outside_case_date"
    } else {
        "passed"
    }
}

fn content_state(previous: Option<&str>, current: &str) -> &'static str {
    match previous {
        Some(previous) if previous != current => "changed",
        Some(_) => "unchanged",
        None => "first_seen",
    }
}

fn collect_evidence_reasons(evidence: &AiCitationSourceEvidence, reasons: &mut BTreeSet<String>) {
    if evidence.source_exists == "not_found" {
        reasons.insert("citation_source_missing".into());
    }
    if evidence.full_text_read != "passed" {
        reasons.insert("citation_full_text_unreadable".into());
    }
    if let Some(category) = &evidence.error_category {
        reasons.insert(category.clone());
    }
    match evidence.citation_match.as_str() {
        "mismatch" => {
            reasons.insert("citation_quote_mismatch".into());
        }
        "ambiguous" => {
            reasons.insert("citation_quote_ambiguous".into());
        }
        "not_provided" => {
            reasons.insert("citation_quote_missing".into());
        }
        "not_checked" => {
            reasons.insert("citation_quote_unchecked".into());
        }
        _ => {}
    }
    match evidence.time_check.as_str() {
        "unknown" => {
            reasons.insert("case_date_unknown".into());
        }
        "outside_case_date" => {
            reasons.insert("citation_outside_case_date".into());
        }
        _ => {}
    }
    if evidence.source_content == "changed" {
        reasons.insert("citation_source_changed".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_locator_preserves_utf8_boundaries_and_marks_repetition_ambiguous() {
        let source = "首段：争议条文。末段：争议条文。";
        let result = quote_match(Some("争议条文"), source);
        assert_eq!(result.state, "ambiguous");
        assert_eq!(result.ranges.len(), 2);
        for range in result.ranges {
            assert!(source.is_char_boundary(range.start_byte));
            assert!(source.is_char_boundary(range.end_byte));
            assert_eq!(&source[range.start_byte..range.end_byte], "争议条文");
        }
        assert!(result.quote_sha256.is_some());

        assert_eq!(quote_match(Some("不存在"), source).state, "mismatch");
        assert_eq!(quote_match(None, source).state, "not_provided");
    }

    #[test]
    fn unavailable_source_is_not_reclassified_as_missing() {
        let input = CitationInput {
            kind: "article".into(),
            id: "law-577".into(),
            quote: Some("条文".into()),
            reason: "依据".into(),
        };
        let evidence = unavailable_source_evidence(&input, "citation_source_unavailable");
        assert_eq!(evidence.source_exists, "unknown");
        assert_eq!(evidence.full_text_read, "unavailable");
        assert_eq!(
            evidence.error_category.as_deref(),
            Some("citation_source_unavailable")
        );
        assert_ne!(evidence.source_exists, "not_found");
    }
}
