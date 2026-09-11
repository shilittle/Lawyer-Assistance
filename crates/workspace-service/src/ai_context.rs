use crate::{hash, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Legacy model settings cannot safely imply a tokenizer or a context window.  These values are
/// deliberately conservative and visible to callers as `verified: false` rather than guessed
/// from a model name.
pub const UNKNOWN_CONTEXT_WINDOW_TOKENS: u32 = 20_480;
pub const UNKNOWN_INPUT_TOKENS: u32 = 16_384;
pub const UNKNOWN_MAX_OUTPUT_TOKENS: u32 = 4_096;

/// The first response reserves room for a final answer and for a bounded tool exchange.  It is
/// not a pricing estimate and never leaves the workspace.
pub const DEFAULT_TOOL_RESERVE_TOKENS: u32 = 2_048;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextCapabilities {
    pub verified: bool,
    pub context_window_tokens: u32,
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub supports_tools: Option<bool>,
    pub supports_structured_output: Option<bool>,
    pub supports_vision: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextEstimate {
    pub input_tokens: u32,
    pub reserved_output_tokens: u32,
    pub system_tokens: u32,
    pub request_tokens: u32,
    pub history_tokens: u32,
    pub material_tokens: u32,
    pub attachment_tokens: u32,
    pub tool_reserve_tokens: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextRange {
    pub source_kind: String,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default)]
    pub locators: Vec<String>,
    pub estimated_tokens: u32,
}

/// A user-visible, structural selection made before the protected source body is opened.
/// Unit numbering is one-based and inclusive.  The server canonicalizes `ranges` before it is
/// persisted or hashed, so callers may submit overlapping or unordered intervals.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextUnitRange {
    pub start: u32,
    pub end: u32,
}

/// The requested source extent.  `source` distinguishes a material's original and redacted
/// variants; attachments leave it absent.  `inspection_hash` is required for explicit page or
/// paragraph ranges and binds their bounds to an inspected local source revision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextRangeSelection {
    pub source_kind: String,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<AiContextUnitRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection_hash: Option<String>,
}

/// Request for local structural inspection.  It never carries a path, text, range, or model
/// configuration; the workspace resolves the opaque source reference itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiContextInspectRequest {
    pub source_kind: String,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Safe result of local structural inspection.  `estimated_input_tokens` is deliberately a
/// budget estimate, not extracted source text.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextInspectResponse {
    pub source_kind: String,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub format: String,
    pub unit_kind: String,
    pub unit_count: u32,
    pub unit_version: String,
    pub inspection_hash: String,
    pub estimated_input_tokens: u32,
    pub estimate_basis: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextScope {
    #[serde(default)]
    pub materials: Vec<AiContextRange>,
    #[serde(default)]
    pub attachments: Vec<AiContextRange>,
    #[serde(default)]
    pub history_run_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextOmission {
    pub source_kind: String,
    pub source_id: String,
    pub reason: String,
    pub estimated_tokens: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<String>,
}

/// An immutable, safe-to-display context decision.  The plan intentionally records only opaque
/// IDs, hashes represented by their existing bindings, and structural locators; it never stores
/// extracted paragraphs, attachment bytes, model messages, names, paths, or provider failures.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiContextPlan {
    pub schema_version: u32,
    /// Immutable hash returned by summary-only preflight and submitted with run creation.
    pub plan_hash: String,
    /// Hash of the actual selected ranges and final budget ledger after protected context work.
    /// It never replaces `plan_hash`, so an accepted preflight remains auditable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_plan_hash: Option<String>,
    pub stage: String,
    pub capabilities: AiContextCapabilities,
    pub estimate: AiContextEstimate,
    /// The normalized user request remains immutable after preflight.  Actual prompt locators
    /// belong in `selected_scope`, so a later budget cut is auditable without rewriting intent.
    #[serde(default)]
    pub requested_scope: Vec<AiContextRangeSelection>,
    pub selected_scope: AiContextScope,
    #[serde(default)]
    pub omitted_scope: Vec<AiContextOmission>,
}

impl AiContextPlan {
    pub(crate) fn new(
        stage: &str,
        capabilities: AiContextCapabilities,
        estimate: AiContextEstimate,
        requested_scope: Vec<AiContextRangeSelection>,
        selected_scope: AiContextScope,
        omitted_scope: Vec<AiContextOmission>,
        binding: &Value,
    ) -> Result<Self> {
        let plan_hash = hash(&serde_json::to_vec(&json!({
            "schema_version": 2,
            "stage": stage,
            "capabilities": capabilities,
            "estimate": estimate,
            "requested_scope": requested_scope,
            "selected_scope": selected_scope,
            "omitted_scope": omitted_scope,
            "binding": binding,
        }))?);
        Ok(Self {
            schema_version: 2,
            plan_hash,
            actual_plan_hash: None,
            stage: stage.to_owned(),
            capabilities,
            estimate,
            requested_scope,
            selected_scope,
            omitted_scope,
        })
    }

    pub fn public_view(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "plan_hash": self.plan_hash,
            "actual_plan_hash": self.actual_plan_hash,
            "stage": self.stage,
            "capabilities": self.capabilities,
            "estimate": self.estimate,
            "requested_scope": self.requested_scope,
            "selected_scope": self.selected_scope,
            "omitted_scope": self.omitted_scope,
        })
    }

    pub(crate) fn input_limit(&self) -> usize {
        usize::try_from(self.capabilities.max_input_tokens).unwrap_or(usize::MAX)
    }

    /// Rebind the persisted execution view after actual context construction.  The preflight
    /// hash stays immutable; this second hash makes the adopted locators, omissions and budget
    /// ledger independently auditable without exposing prompt text.
    pub(crate) fn refresh_actual_plan_hash(&mut self) -> Result<()> {
        // Schema 1 pre-dates requested_scope. Deserializing it supplies an empty default for
        // display only; including that field in its hash would make authentic legacy evidence
        // unverifiable. Every newly created plan is schema 2 and binds requested_scope.
        let actual = if self.schema_version >= 2 {
            json!({
                "schema_version": self.schema_version,
                "preflight_plan_hash": self.plan_hash,
                "stage": self.stage,
                "capabilities": self.capabilities,
                "estimate": self.estimate,
                "requested_scope": self.requested_scope,
                "selected_scope": self.selected_scope,
                "omitted_scope": self.omitted_scope,
            })
        } else {
            json!({
                "schema_version": self.schema_version,
                "preflight_plan_hash": self.plan_hash,
                "stage": self.stage,
                "capabilities": self.capabilities,
                "estimate": self.estimate,
                "selected_scope": self.selected_scope,
                "omitted_scope": self.omitted_scope,
            })
        };
        self.actual_plan_hash = Some(hash(&serde_json::to_vec(&actual)?));
        Ok(())
    }
}

/// A deliberately conservative text estimate.  UTF-8 byte length is an upper bound for normal
/// byte-fallback tokenizers; a fixed envelope is charged independently for message structure.
pub(crate) fn estimate_text_tokens(text: &str) -> usize {
    text.len()
}

/// Image base64 characters are not text context.  This conservative, documented fallback uses
/// source-image bytes with a minimum per visual page.  A model-specific image estimator can only
/// raise this number at a later capability revision.
pub(crate) fn estimate_image_tokens(image_bytes: usize) -> usize {
    const MIN_IMAGE_TOKENS: usize = 1_024;
    const BYTES_PER_TOKEN: usize = 64;
    MIN_IMAGE_TOKENS.max(image_bytes.saturating_add(BYTES_PER_TOKEN - 1) / BYTES_PER_TOKEN)
}

#[derive(Clone)]
pub(crate) struct ContextExtractionPlan {
    state: Arc<Mutex<BudgetState>>,
}

#[derive(Default)]
struct BudgetState {
    input_limit: usize,
    used: usize,
    pending: BTreeMap<String, usize>,
    // The optional material variant is part of the ledger identity: the same material may
    // legally contribute both its original and its redacted representation.
    ranges: BTreeMap<(String, String, Option<String>, String), usize>,
}

pub(crate) struct ContextBudgetReservation {
    state: Arc<Mutex<BudgetState>>,
    key: Option<String>,
    source_kind: String,
    source_id: String,
    source: Option<String>,
    locator: String,
}

impl ContextExtractionPlan {
    pub(crate) fn new(input_limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState {
                input_limit,
                ..BudgetState::default()
            })),
        }
    }

    fn reserve(
        &self,
        source_kind: &str,
        source_id: &str,
        source: Option<&str>,
        locator: &str,
        tokens: usize,
    ) -> Result<ContextBudgetReservation> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))?;
        let pending = state.pending.values().copied().sum::<usize>();
        if state.used.saturating_add(pending).saturating_add(tokens) > state.input_limit {
            return Err(Error::new("context_budget_exceeded"));
        }
        let key = format!(
            "{}:{}:{:?}:{}:{}",
            source_kind,
            source_id,
            source,
            locator,
            state.pending.len()
        );
        state.pending.insert(key.clone(), tokens);
        Ok(ContextBudgetReservation {
            state: Arc::clone(&self.state),
            key: Some(key),
            source_kind: source_kind.to_owned(),
            source_id: source_id.to_owned(),
            source: source.map(str::to_owned),
            locator: locator.to_owned(),
        })
    }

    /// Reserve a visual page before a renderer/OCR request starts.  The caller supplies its
    /// page-text estimate when available; image bytes enforce the explicit visual fallback.
    pub(crate) fn reserve_ocr_page(
        &self,
        source_kind: &str,
        source_id: &str,
        source: Option<&str>,
        locator: &str,
        estimated_tokens: usize,
        image_bytes: usize,
    ) -> Result<ContextBudgetReservation> {
        self.reserve(
            source_kind,
            source_id,
            source,
            locator,
            estimated_tokens.max(estimate_image_tokens(image_bytes)),
        )
    }

    pub(crate) fn reserve_text_segment(
        &self,
        source_kind: &str,
        source_id: &str,
        source: Option<&str>,
        locator: &str,
        text: &str,
    ) -> Result<ContextBudgetReservation> {
        self.reserve(
            source_kind,
            source_id,
            source,
            locator,
            estimate_text_tokens(text),
        )
    }

    pub(crate) fn charge_fixed(&self, tokens: usize) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))?;
        let pending = state.pending.values().copied().sum::<usize>();
        if state.used.saturating_add(pending).saturating_add(tokens) > state.input_limit {
            return Err(Error::new("context_budget_exceeded"));
        }
        state.used = state.used.saturating_add(tokens);
        Ok(())
    }

    pub(crate) fn used_tokens(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.used)
            .unwrap_or(usize::MAX)
    }

    pub(crate) fn remaining_tokens(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.input_limit.saturating_sub(state.used))
            .unwrap_or(0)
    }

    pub(crate) fn selected_ranges(&self) -> Vec<AiContextRange> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let mut values = state
            .ranges
            .iter()
            .map(
                |((source_kind, source_id, source, locator), tokens)| AiContextRange {
                    source_kind: source_kind.clone(),
                    source_id: source_id.clone(),
                    source: source.clone(),
                    format: None,
                    locators: vec![locator.clone()],
                    estimated_tokens: u32::try_from(*tokens).unwrap_or(u32::MAX),
                },
            )
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            (
                &left.source_kind,
                &left.source_id,
                &left.source,
                &left.locators,
            )
                .cmp(&(
                    &right.source_kind,
                    &right.source_id,
                    &right.source,
                    &right.locators,
                ))
        });
        values
    }
}

impl ContextBudgetReservation {
    /// Finalize an OCR reservation with the locally observed text size.  If OCR produced more
    /// than the remaining prompt budget, the error is returned before its text can be appended.
    pub(crate) fn record_ocr_result(mut self, actual_tokens: usize) -> Result<()> {
        self.commit(actual_tokens)
    }

    pub(crate) fn record_text_result(mut self, actual_tokens: usize) -> Result<()> {
        self.commit(actual_tokens)
    }

    fn commit(&mut self, actual_tokens: usize) -> Result<()> {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::new("context_budget_reservation_invalid"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))?;
        let reserved = state
            .pending
            .remove(&key)
            .ok_or_else(|| Error::new("context_budget_reservation_invalid"))?;
        let actual_tokens = actual_tokens.max(reserved);
        if state.used.saturating_add(actual_tokens) > state.input_limit {
            return Err(Error::new("context_budget_exceeded"));
        }
        state.used = state.used.saturating_add(actual_tokens);
        state
            .ranges
            .entry((
                self.source_kind.clone(),
                self.source_id.clone(),
                self.source.clone(),
                self.locator.clone(),
            ))
            .and_modify(|total| *total = total.saturating_add(actual_tokens))
            .or_insert(actual_tokens);
        Ok(())
    }
}

impl Drop for ContextBudgetReservation {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_budget_is_explicit_and_is_not_based_on_base64_text_length() {
        assert_eq!(estimate_image_tokens(1), 1_024);
        assert_eq!(estimate_image_tokens(65), 1_024);
        assert_eq!(estimate_image_tokens(65_536), 1_024);
        assert_eq!(estimate_image_tokens(65_537), 1_025);
    }

    #[test]
    fn actual_context_hash_rebinds_scope_without_replacing_preflight_hash() {
        let capabilities = AiContextCapabilities {
            verified: false,
            context_window_tokens: 20_480,
            max_input_tokens: 16_384,
            max_output_tokens: 4_096,
            supports_tools: None,
            supports_structured_output: None,
            supports_vision: None,
        };
        let mut plan = AiContextPlan::new(
            "conservative",
            capabilities,
            AiContextEstimate::default(),
            Vec::new(),
            AiContextScope::default(),
            Vec::new(),
            &json!({"provider_revision": 1}),
        )
        .expect("preflight plan");
        let preflight = plan.plan_hash.clone();
        plan.selected_scope.history_run_ids.push("run_prior".into());
        plan.estimate.history_tokens = 128;
        plan.refresh_actual_plan_hash().expect("execution hash");
        let first = plan.actual_plan_hash.clone().expect("actual hash");
        plan.estimate.history_tokens = 129;
        plan.refresh_actual_plan_hash()
            .expect("changed execution hash");
        assert_eq!(plan.plan_hash, preflight);
        assert_ne!(plan.actual_plan_hash.as_deref(), Some(first.as_str()));
    }

    #[test]
    fn legacy_schema_one_actual_hash_excludes_defaulted_requested_scope() {
        let legacy = json!({
            "schema_version": 1,
            "plan_hash": "legacy-preflight-hash",
            "actual_plan_hash": null,
            "stage": "conservative",
            "capabilities": {
                "verified": false,
                "context_window_tokens": 20480,
                "max_input_tokens": 16384,
                "max_output_tokens": 4096,
                "supports_tools": null,
                "supports_structured_output": null,
                "supports_vision": null
            },
            "estimate": {
                "input_tokens": 42,
                "reserved_output_tokens": 4096,
                "system_tokens": 10,
                "request_tokens": 12,
                "history_tokens": 0,
                "material_tokens": 20,
                "attachment_tokens": 0,
                "tool_reserve_tokens": 0
            },
            "selected_scope": {"materials":[],"attachments":[],"history_run_ids":[]},
            "omitted_scope": []
        });
        let mut plan: AiContextPlan = serde_json::from_value(legacy).expect("legacy plan reads");
        assert_eq!(plan.schema_version, 1);
        assert!(plan.requested_scope.is_empty());
        assert_eq!(plan.public_view()["schema_version"], 1);
        assert_eq!(plan.public_view()["requested_scope"], json!([]));

        let expected = hash(
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "preflight_plan_hash": "legacy-preflight-hash",
                "stage": "conservative",
                "capabilities": plan.capabilities,
                "estimate": plan.estimate,
                "selected_scope": plan.selected_scope,
                "omitted_scope": plan.omitted_scope,
            }))
            .expect("legacy hash serialization"),
        );
        plan.refresh_actual_plan_hash()
            .expect("legacy actual hash refreshes");
        assert_eq!(plan.actual_plan_hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn cancelled_or_failed_ocr_reservation_releases_pending_budget() {
        let plan = ContextExtractionPlan::new(2_000);
        let reservation = plan
            .reserve_ocr_page("attachment", "attachment_a", None, "page:1", 1_024, 1)
            .expect("page reserves before OCR");
        drop(reservation);
        assert_eq!(plan.remaining_tokens(), 2_000);
        let reservation = plan
            .reserve_ocr_page("attachment", "attachment_a", None, "page:1", 1_024, 1)
            .expect("released reservation can be reacquired");
        reservation
            .record_ocr_result(1_100)
            .expect("actual page remains within budget");
        assert_eq!(plan.used_tokens(), 1_100);
    }
}
