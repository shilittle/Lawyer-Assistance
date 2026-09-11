use crate::ai_context::{
    UNKNOWN_CONTEXT_WINDOW_TOKENS, UNKNOWN_INPUT_TOKENS, UNKNOWN_MAX_OUTPUT_TOKENS,
};
use crate::*;
use providers::{ApiSecret, ProviderKind, ProviderProfile, ReqwestStreamingTransport};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiModelSelection {
    pub provider_id: String,
    pub model: String,
}

/// Explicit capability declarations are provider configuration, never model-name heuristics.
/// Omitted values remain compatible with existing providers and resolve to the visible,
/// conservative legacy budget in `resolved_model_capabilities`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiModelCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// `None` is intentionally serialized as JSON `null`: the wire contract has three
    /// capability states (unknown, supported and unsupported).  The request decoder below
    /// records whether a null was explicit so a capacity-only update cannot erase a prior
    /// declaration.
    #[serde(default)]
    pub supports_tools: Option<bool>,
    #[serde(default)]
    pub supports_structured_output: Option<bool>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
}

/// Provenance for a capability declaration.  This is stored separately from the legacy
/// `AiProviderMetadata` object so old workspace rows and source-level struct literals remain
/// readable.  A declaration is never presented as a provider probe result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiCapabilityDeclaration {
    pub declaration_source: String,
    pub declared_at: u64,
    pub config_binding: String,
    pub declaration_hash: String,
    #[serde(default)]
    pub verification_state: String,
    #[serde(default)]
    pub needs_review: bool,
    /// Capability fields inherited from an unverified/legacy binding.  Keeping this list makes
    /// a single explicit correction sufficient for that field without pretending that unrelated
    /// inherited fields were reviewed too.
    #[serde(default)]
    pub fields_needing_review: Vec<String>,
    #[serde(default)]
    pub provider_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_config_binding: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiProviderCapabilityMetadata {
    #[serde(default)]
    pub model_capabilities: BTreeMap<String, AiCapabilityDeclaration>,
}

const AI_PROVIDER_CAPABILITY_METADATA_KIND: &str = "ai_provider_capability_metadata";

/// Presence is intentionally separate from `Option<T>`.  Serde maps both a missing JSON field
/// and an explicit `null` to `None`; without this record, a capacity-only update would silently
/// clear an existing `supports_*: false` declaration, while a user could not intentionally reset
/// one field to unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiModelCapabilityPresence {
    pub context_window_tokens: bool,
    pub max_output_tokens: bool,
    pub supports_tools: bool,
    pub supports_structured_output: bool,
    pub supports_vision: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AiProviderMetadata {
    pub preset: String,
    pub enabled_models: Vec<String>,
    pub trust_raw: bool,
    pub base_url: String,
    #[serde(default)]
    pub model_capabilities: BTreeMap<String, AiModelCapabilities>,
}
pub struct AiCompletion {
    pub message: Value,
    pub usage: Value,
    pub model: String,
}
#[derive(Clone, Default)]
pub struct AiProviderRequest {
    pub id: Option<String>,
    pub provider_id: Option<String>,
    pub name: String,
    pub preset: String,
    pub base_url: String,
    pub model: String,
    pub enabled_models: Vec<String>,
    pub model_capabilities: BTreeMap<String, AiModelCapabilities>,
    /// Server-only field populated by the custom decoder.  It is skipped on the wire and is
    /// empty for source-level callers that construct the request directly; in that case `None`
    /// means "field not supplied", which preserves the existing declaration.
    #[doc(hidden)]
    pub model_capability_presence: BTreeMap<String, AiModelCapabilityPresence>,
    pub api_key: Option<String>,
    pub trust_raw: Option<bool>,
    pub allow_private_network: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AiProviderRequestWire {
    pub id: Option<String>,
    pub provider_id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub enabled_models: Vec<String>,
    #[serde(default)]
    pub model_capabilities: Option<BTreeMap<String, Value>>,
    pub api_key: Option<String>,
    pub trust_raw: Option<bool>,
    #[serde(default)]
    pub allow_private_network: bool,
}

impl<'de> Deserialize<'de> for AiProviderRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AiProviderRequestWire::deserialize(deserializer)?;
        let mut model_capabilities = BTreeMap::new();
        let mut model_capability_presence = BTreeMap::new();
        if let Some(entries) = wire.model_capabilities {
            for (model, raw) in entries {
                let object = raw
                    .as_object()
                    .ok_or_else(|| D::Error::custom("model_capabilities_entry_invalid"))?;
                let capability = serde_json::from_value::<AiModelCapabilities>(raw.clone())
                    .map_err(|_| D::Error::custom("invalid_model_capabilities"))?;
                model_capability_presence.insert(
                    model.clone(),
                    AiModelCapabilityPresence {
                        context_window_tokens: object.contains_key("context_window_tokens")
                            || object.contains_key("contextWindowTokens"),
                        max_output_tokens: object.contains_key("max_output_tokens")
                            || object.contains_key("maxOutputTokens"),
                        supports_tools: object.contains_key("supports_tools")
                            || object.contains_key("supportsTools"),
                        supports_structured_output: object
                            .contains_key("supports_structured_output")
                            || object.contains_key("supportsStructuredOutput"),
                        supports_vision: object.contains_key("supports_vision")
                            || object.contains_key("supportsVision"),
                    },
                );
                model_capabilities.insert(model, capability);
            }
        }
        Ok(Self {
            id: wire.id,
            provider_id: wire.provider_id,
            name: wire.name,
            preset: wire.preset,
            base_url: wire.base_url,
            model: wire.model,
            enabled_models: wire.enabled_models,
            model_capabilities,
            model_capability_presence,
            api_key: wire.api_key,
            trust_raw: wire.trust_raw,
            allow_private_network: wire.allow_private_network,
        })
    }
}

/// A per-dispatch output ceiling supplied by the context planner.  It deliberately excludes
/// prices and provider-specific tokenizers; its only purpose is to prevent one request from
/// consuming output reserved for later tool rounds or the final answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AiDispatchBudget {
    pub(crate) max_output_tokens: u32,
}

pub fn ai_presets() -> Value {
    json!([
        {"id":"glm","name":"智谱 GLM","base_url":"https://open.bigmodel.cn/api/paas/v4","domestic":true},
        {"id":"deepseek","name":"DeepSeek","base_url":"https://api.deepseek.com","domestic":true},
        {"id":"qwen","name":"通义千问","base_url":"https://dashscope.aliyuncs.com/compatible-mode/v1","domestic":true},
        {"id":"siliconflow","name":"硅基流动","base_url":"https://api.siliconflow.cn/v1","domestic":true},
        {"id":"volcengine","name":"火山方舟","base_url":"https://ark.cn-beijing.volces.com/api/v3","domestic":true},
        {"id":"kimi","name":"Kimi","base_url":"https://api.moonshot.cn/v1","domestic":true},
        {"id":"custom","name":"自定义兼容服务","base_url":"","domestic":false}
    ])
}

fn normalized_base(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('/')
        .trim_end_matches("/chat/completions")
        .trim_end_matches("/responses")
        .to_owned()
}
fn recognized_preset(base: &str) -> Option<String> {
    ai_presets()
        .as_array()?
        .iter()
        .find(|p| {
            !p["base_url"].as_str().unwrap_or_default().is_empty()
                && normalized_base(p["base_url"].as_str().unwrap_or_default())
                    == normalized_base(base)
        })
        .and_then(|p| p["id"].as_str().map(str::to_owned))
}

fn capability_config_binding(config: &ProviderConfig, model: &str) -> String {
    // The binding deliberately excludes credentials and display names.  It changes when the
    // provider identity, endpoint or selected model changes, while a repeated save of the same
    // endpoint/model does not make an otherwise unchanged declaration stale merely because the
    // provider revision counter advanced.
    hash(
        format!(
            "provider_id={}\nbase_url={}\nmodel={}",
            config.id,
            normalized_base(&config.base_url),
            model
        )
        .as_bytes(),
    )
}

fn capability_declaration_hash(
    model: &str,
    capability: &AiModelCapabilities,
    config_binding: &str,
) -> String {
    let value = json!({
        "model": model,
        "capability": capability,
        "config_binding": config_binding,
    });
    serde_json::to_vec(&value)
        .map(|bytes| hash(&bytes))
        .unwrap_or_else(|_| hash(b"invalid_capability_declaration"))
}

fn unknown_capability_declaration(config: &ProviderConfig, model: &str) -> AiCapabilityDeclaration {
    let binding = capability_config_binding(config, model);
    let capability = AiModelCapabilities::default();
    AiCapabilityDeclaration {
        declaration_source: "unknown".into(),
        declared_at: 0,
        config_binding: binding.clone(),
        declaration_hash: capability_declaration_hash(model, &capability, &binding),
        verification_state: "unknown".into(),
        needs_review: true,
        fields_needing_review: Vec::new(),
        provider_revision: config.revision,
        current_config_binding: None,
    }
}

fn legacy_capability_declaration(
    config: &ProviderConfig,
    model: &str,
    capability: &AiModelCapabilities,
) -> AiCapabilityDeclaration {
    let binding = capability_config_binding(config, model);
    let mut fields_needing_review = Vec::new();
    if capability.context_window_tokens.is_some() {
        fields_needing_review.push("context_window_tokens".into());
    }
    if capability.max_output_tokens.is_some() {
        fields_needing_review.push("max_output_tokens".into());
    }
    if capability.supports_tools.is_some() {
        fields_needing_review.push("supports_tools".into());
    }
    if capability.supports_structured_output.is_some() {
        fields_needing_review.push("supports_structured_output".into());
    }
    if capability.supports_vision.is_some() {
        fields_needing_review.push("supports_vision".into());
    }
    AiCapabilityDeclaration {
        declaration_source: "legacy_migrated".into(),
        declared_at: 0,
        config_binding: binding.clone(),
        declaration_hash: capability_declaration_hash(model, capability, &binding),
        verification_state: "legacy".into(),
        needs_review: true,
        fields_needing_review,
        provider_revision: config.revision,
        current_config_binding: None,
    }
}

fn declared_capability_metadata(
    config: &ProviderConfig,
    model: &str,
    capability: &AiModelCapabilities,
    previous: Option<&AiCapabilityDeclaration>,
    fields: Option<&AiModelCapabilityPresence>,
) -> AiCapabilityDeclaration {
    let binding = capability_config_binding(config, model);
    let all_fields_explicit = all_capability_fields_explicit(capability, fields);
    let stale_binding = previous.is_some_and(|old| old.config_binding != binding);
    let mut fields_needing_review = previous
        .map(|old| old.fields_needing_review.clone())
        .unwrap_or_default();
    let remove_reviewed = |field: &str, fields_needing_review: &mut Vec<String>| {
        fields_needing_review.retain(|value| value != field);
    };
    let explicit_field = |field: &str| {
        fields.is_some_and(|value| match field {
            "context_window_tokens" => value.context_window_tokens,
            "max_output_tokens" => value.max_output_tokens,
            "supports_tools" => value.supports_tools,
            "supports_structured_output" => value.supports_structured_output,
            "supports_vision" => value.supports_vision,
            _ => false,
        }) || match field {
            "context_window_tokens" => capability.context_window_tokens.is_some(),
            "max_output_tokens" => capability.max_output_tokens.is_some(),
            "supports_tools" => capability.supports_tools.is_some(),
            "supports_structured_output" => capability.supports_structured_output.is_some(),
            "supports_vision" => capability.supports_vision.is_some(),
            _ => false,
        }
    };
    for (field, value_is_some) in [
        (
            "context_window_tokens",
            capability.context_window_tokens.is_some(),
        ),
        ("max_output_tokens", capability.max_output_tokens.is_some()),
        ("supports_tools", capability.supports_tools.is_some()),
        (
            "supports_structured_output",
            capability.supports_structured_output.is_some(),
        ),
        ("supports_vision", capability.supports_vision.is_some()),
    ] {
        if value_is_some || explicit_field(field) {
            remove_reviewed(field, &mut fields_needing_review);
        }
    }
    if stale_binding && !all_fields_explicit {
        for (field, value_is_some) in [
            (
                "context_window_tokens",
                capability.context_window_tokens.is_some(),
            ),
            ("max_output_tokens", capability.max_output_tokens.is_some()),
            ("supports_tools", capability.supports_tools.is_some()),
            (
                "supports_structured_output",
                capability.supports_structured_output.is_some(),
            ),
            ("supports_vision", capability.supports_vision.is_some()),
        ] {
            if value_is_some
                && !explicit_field(field)
                && !fields_needing_review.iter().any(|v| v == field)
            {
                fields_needing_review.push(field.into());
            }
        }
    }
    fields_needing_review.sort();
    fields_needing_review.dedup();
    AiCapabilityDeclaration {
        declaration_source: "user_configuration".into(),
        declared_at: now(),
        config_binding: binding.clone(),
        declaration_hash: capability_declaration_hash(model, capability, &binding),
        verification_state: "declared".into(),
        // A partial update on a changed/legacy binding still carries old values.  Keep the
        // review marker for each inherited field until that field is explicitly supplied,
        // including an explicit null to return it to unknown.
        needs_review: stale_binding || !fields_needing_review.is_empty(),
        fields_needing_review,
        provider_revision: config.revision,
        current_config_binding: None,
    }
}

fn reconcile_legacy_declaration(
    config: &ProviderConfig,
    model: &str,
    mut declaration: AiCapabilityDeclaration,
) -> AiCapabilityDeclaration {
    let current = capability_config_binding(config, model);
    if declaration.config_binding != current {
        declaration.current_config_binding = Some(current);
        declaration.needs_review = true;
    }
    declaration
}

fn merge_capability_fields(
    previous: Option<&AiModelCapabilities>,
    incoming: &AiModelCapabilities,
    presence: Option<&AiModelCapabilityPresence>,
) -> AiModelCapabilities {
    let previous = previous.cloned().unwrap_or_default();
    // Source-level callers have no presence map.  Their Some values are still explicit and
    // their None values retain the prior declaration.  JSON callers additionally distinguish
    // an explicit null from a missing key via `presence`.
    let explicit = |present: bool, value_is_some: bool| present || value_is_some;
    let context_present = explicit(
        presence.is_some_and(|value| value.context_window_tokens),
        incoming.context_window_tokens.is_some(),
    );
    let output_present = explicit(
        presence.is_some_and(|value| value.max_output_tokens),
        incoming.max_output_tokens.is_some(),
    );
    let tools_present = explicit(
        presence.is_some_and(|value| value.supports_tools),
        incoming.supports_tools.is_some(),
    );
    let structured_present = explicit(
        presence.is_some_and(|value| value.supports_structured_output),
        incoming.supports_structured_output.is_some(),
    );
    let vision_present = explicit(
        presence.is_some_and(|value| value.supports_vision),
        incoming.supports_vision.is_some(),
    );
    AiModelCapabilities {
        context_window_tokens: if context_present {
            incoming.context_window_tokens
        } else {
            previous.context_window_tokens
        },
        max_output_tokens: if output_present {
            incoming.max_output_tokens
        } else {
            previous.max_output_tokens
        },
        supports_tools: if tools_present {
            incoming.supports_tools
        } else {
            previous.supports_tools
        },
        supports_structured_output: if structured_present {
            incoming.supports_structured_output
        } else {
            previous.supports_structured_output
        },
        supports_vision: if vision_present {
            incoming.supports_vision
        } else {
            previous.supports_vision
        },
    }
}

fn capability_field_is_explicit(
    value_is_some: bool,
    presence: Option<&AiModelCapabilityPresence>,
    field: impl FnOnce(&AiModelCapabilityPresence) -> bool,
) -> bool {
    value_is_some || presence.is_some_and(field)
}

fn capability_update_has_explicit_fields(
    capability: &AiModelCapabilities,
    presence: Option<&AiModelCapabilityPresence>,
) -> bool {
    capability.context_window_tokens.is_some()
        || capability.max_output_tokens.is_some()
        || capability.supports_tools.is_some()
        || capability.supports_structured_output.is_some()
        || capability.supports_vision.is_some()
        || presence.is_some_and(|value| {
            value.context_window_tokens
                || value.max_output_tokens
                || value.supports_tools
                || value.supports_structured_output
                || value.supports_vision
        })
}

fn all_capability_fields_explicit(
    capability: &AiModelCapabilities,
    presence: Option<&AiModelCapabilityPresence>,
) -> bool {
    capability_field_is_explicit(
        capability.context_window_tokens.is_some(),
        presence,
        |value| value.context_window_tokens,
    ) && capability_field_is_explicit(capability.max_output_tokens.is_some(), presence, |value| {
        value.max_output_tokens
    }) && capability_field_is_explicit(capability.supports_tools.is_some(), presence, |value| {
        value.supports_tools
    }) && capability_field_is_explicit(
        capability.supports_structured_output.is_some(),
        presence,
        |value| value.supports_structured_output,
    ) && capability_field_is_explicit(capability.supports_vision.is_some(), presence, |value| {
        value.supports_vision
    })
}

fn capability_declarations_for(
    config: &ProviderConfig,
    metadata: &AiProviderMetadata,
    existing: Option<&AiProviderCapabilityMetadata>,
) -> AiProviderCapabilityMetadata {
    let mut declarations = existing
        .map(|value| value.model_capabilities.clone())
        .unwrap_or_default();
    for model in &metadata.enabled_models {
        let declaration = declarations
            .remove(model)
            .map(|value| reconcile_legacy_declaration(config, model, value))
            .unwrap_or_else(|| {
                if let Some(capability) = metadata.model_capabilities.get(model) {
                    let mut legacy_config = config.clone();
                    legacy_config.base_url = metadata.base_url.clone();
                    reconcile_legacy_declaration(
                        config,
                        model,
                        legacy_capability_declaration(&legacy_config, model, capability),
                    )
                } else {
                    unknown_capability_declaration(config, model)
                }
            });
        declarations.insert(model.clone(), declaration);
    }
    // Keep declarations for disabled models as historical evidence.  They are not active in
    // `resolved_model_capabilities`, but retaining them lets a later re-enable still surface an
    // old false value for explicit review instead of silently resetting to unknown.
    AiProviderCapabilityMetadata {
        model_capabilities: declarations,
    }
}
fn profile_for(config: &ProviderConfig, model: &str) -> ProviderProfile {
    let mut p = ProviderProfile::new_default(&config.id, ProviderKind::Custom);
    p.base_url = config.base_url.clone();
    p.model_id = model.into();
    p.options.allow_private_network = Some(config.allow_private_network);
    p
}
fn provider_error(e: providers::ProviderError) -> Error {
    match e.http_status {
        Some(401 | 403) => Error::new("provider_auth_failed"),
        Some(429) => Error::retry("provider_rate_limited"),
        Some(400 | 404) => Error::new("provider_model_or_request_invalid"),
        _ => match e.kind {
            providers::ProviderErrorKind::Network => Error::retry("provider_network_failed"),
            providers::ProviderErrorKind::Timeout => Error::retry("provider_timeout"),
            providers::ProviderErrorKind::Parse => Error::new("provider_response_invalid"),
            providers::ProviderErrorKind::InvalidRequest => {
                Error::new("provider_authorization_invalid")
            }
            providers::ProviderErrorKind::ResponseTooLarge => {
                Error::new("provider_response_too_large")
            }
            _ => Error::retry("provider_request_failed"),
        },
    }
}

fn validate_capabilities(
    enabled_models: &[String],
    capabilities: &BTreeMap<String, AiModelCapabilities>,
) -> Result<()> {
    if capabilities
        .keys()
        .any(|model| !enabled_models.contains(model))
    {
        return Err(Error::new("model_capability_not_enabled"));
    }
    for capability in capabilities.values() {
        if capability
            .context_window_tokens
            .is_some_and(|value| !(1_024..=10_000_000).contains(&value))
            || capability
                .max_output_tokens
                .is_some_and(|value| !(1..=1_000_000).contains(&value))
        {
            return Err(Error::new("invalid_model_capabilities"));
        }
        if let (Some(context), Some(output)) = (
            capability.context_window_tokens,
            capability.max_output_tokens,
        ) {
            if output >= context {
                return Err(Error::new("invalid_model_capabilities"));
            }
        }
    }
    Ok(())
}

fn resolved_model_capabilities(
    metadata: &AiProviderMetadata,
    model: &str,
) -> Result<AiContextCapabilities> {
    let configured = metadata
        .model_capabilities
        .get(model)
        .cloned()
        .unwrap_or_default();
    let context_window_tokens = configured
        .context_window_tokens
        .unwrap_or(UNKNOWN_CONTEXT_WINDOW_TOKENS);
    let max_output_tokens = configured
        .max_output_tokens
        .unwrap_or(UNKNOWN_MAX_OUTPUT_TOKENS);
    if max_output_tokens >= context_window_tokens {
        return Err(Error::new("invalid_model_capabilities"));
    }
    let max_input_tokens =
        if configured.context_window_tokens.is_none() && configured.max_output_tokens.is_none() {
            UNKNOWN_INPUT_TOKENS
        } else {
            context_window_tokens.saturating_sub(max_output_tokens)
        };
    // The legacy fallback is a deliberate 16k input/4k output contract.  A partially declared
    // record remains unverified so the UI can avoid overstating provider support.
    Ok(AiContextCapabilities {
        verified: configured.context_window_tokens.is_some()
            && configured.max_output_tokens.is_some(),
        context_window_tokens,
        max_input_tokens,
        max_output_tokens,
        supports_tools: configured.supports_tools,
        supports_structured_output: configured.supports_structured_output,
        supports_vision: configured.supports_vision,
    })
}

fn validate_requested_features(
    capabilities: &AiContextCapabilities,
    tools: bool,
    structured_output: bool,
    vision: bool,
) -> Result<()> {
    if tools && capabilities.supports_tools == Some(false) {
        return Err(Error::new("model_tools_unsupported"));
    }
    if structured_output && capabilities.supports_structured_output == Some(false) {
        return Err(Error::new("model_structured_output_unsupported"));
    }
    if vision && capabilities.supports_vision == Some(false) {
        return Err(Error::new("model_vision_unsupported"));
    }
    Ok(())
}

fn contains_image_input(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "image_url")
                || object.values().any(contains_image_input)
        }
        Value::Array(values) => values.iter().any(contains_image_input),
        _ => false,
    }
}
impl Workspace {
    pub fn ai_usage(&self) -> Result<Value> {
        let mut groups = BTreeMap::<String, Value>::new();
        for record in self.store.list::<Value>("ai_dispatch")? {
            let key = format!(
                "{}/{}",
                record["model"].as_str().unwrap_or_default(),
                record["purpose"].as_str().unwrap_or_default()
            );
            let entry=groups.entry(key).or_insert_with(||json!({"model":record["model"],"purpose":record["purpose"],"requests":0,"completed":0,"failed":0,"prompt_tokens":0,"completion_tokens":0,"total_tokens":0,"elapsed_seconds":0}));
            entry["requests"] = json!(entry["requests"].as_u64().unwrap_or(0) + 1);
            for key in ["completed", "failed"] {
                if record["status"] == key {
                    entry[key] = json!(entry[key].as_u64().unwrap_or(0) + 1);
                }
            }
            for key in ["prompt_tokens", "completion_tokens", "total_tokens"] {
                entry[key] = json!(
                    entry[key].as_u64().unwrap_or(0) + record["usage"][key].as_u64().unwrap_or(0)
                );
            }
            entry["elapsed_seconds"] = json!(
                entry["elapsed_seconds"].as_u64().unwrap_or(0)
                    + record["finished_at"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(record["created_at"].as_u64().unwrap_or(0))
            );
        }
        Ok(json!({"groups":groups.into_values().collect::<Vec<_>>()}))
    }
    pub(crate) fn migrate_ai_settings(&self) -> Result<()> {
        let providers = self.store.list::<ProviderConfig>("provider")?;
        for provider in &providers {
            let stored_metadata = self
                .store
                .maybe::<AiProviderMetadata>("ai_provider", &provider.id)?;
            let metadata = stored_metadata.clone().unwrap_or_else(|| {
                let preset =
                    recognized_preset(&provider.base_url).unwrap_or_else(|| "custom".into());
                AiProviderMetadata {
                    preset,
                    enabled_models: vec![provider.model.clone()],
                    trust_raw: recognized_preset(&provider.base_url).is_some(),
                    base_url: provider.base_url.clone(),
                    model_capabilities: BTreeMap::new(),
                }
            });
            if stored_metadata.is_none() {
                self.store.save("ai_provider", &provider.id, &metadata)?;
            }
            let existing_declarations = self.store.maybe::<AiProviderCapabilityMetadata>(
                AI_PROVIDER_CAPABILITY_METADATA_KIND,
                &provider.id,
            )?;
            let declarations =
                capability_declarations_for(provider, &metadata, existing_declarations.as_ref());
            if existing_declarations.as_ref() != Some(&declarations) {
                self.store.save(
                    AI_PROVIDER_CAPABILITY_METADATA_KIND,
                    &provider.id,
                    &declarations,
                )?;
            }
        }
        if self
            .store
            .maybe::<BTreeMap<String, AiModelSelection>>("ai_defaults", "default")?
            .is_none()
        {
            if let Some(provider) = providers.first() {
                let selection = AiModelSelection {
                    provider_id: provider.id.clone(),
                    model: provider.model.clone(),
                };
                let defaults = ["chat", "writing", "redaction", "ocr"]
                    .into_iter()
                    .map(|purpose| (purpose.to_owned(), selection.clone()))
                    .collect::<BTreeMap<_, _>>();
                self.store.save("ai_defaults", "default", &defaults)?;
            }
        }
        Ok(())
    }
    pub fn ai_defaults(&self) -> Result<BTreeMap<String, AiModelSelection>> {
        Ok(self
            .store
            .maybe("ai_defaults", "default")?
            .unwrap_or_default())
    }
    pub fn save_ai_defaults(&self, defaults: BTreeMap<String, AiModelSelection>) -> Result<Value> {
        // AI-provider saves read and rewrite this record as part of their
        // SQLite snapshot.  Share their gate so a defaults update cannot be
        // lost between that read and the multi-row commit.
        let _gate = self.lock()?;
        for (purpose, model) in &defaults {
            if !["chat", "redaction", "writing", "ocr"].contains(&purpose.as_str()) {
                return Err(Error::new("invalid_model_purpose"));
            }
            self.ai_config(model)?;
        }
        self.store.save("ai_defaults", "default", &defaults)?;
        Ok(json!({"defaults":defaults}))
    }
    pub fn selected_ai_model(&self, purpose: &str) -> Result<AiModelSelection> {
        let defaults = self.ai_defaults()?;
        let selection = defaults
            .get(purpose)
            .or_else(|| defaults.get("chat"))
            .cloned()
            .ok_or_else(|| Error::new("ai_model_required"))?;
        self.ai_config(&selection)?;
        Ok(selection)
    }
    pub(crate) fn ai_metadata(&self, config: &ProviderConfig) -> Result<AiProviderMetadata> {
        let mut metadata = self
            .store
            .maybe::<AiProviderMetadata>("ai_provider", &config.id)?
            .unwrap_or_else(|| AiProviderMetadata {
                preset: recognized_preset(&config.base_url).unwrap_or_else(|| "custom".into()),
                enabled_models: vec![config.model.clone()],
                trust_raw: recognized_preset(&config.base_url).is_some(),
                base_url: config.base_url.clone(),
                model_capabilities: BTreeMap::new(),
            });
        // Keep legacy declarations even when an endpoint changes.  The sidecar records the
        // binding mismatch and marks the entry for review; dropping the map here would silently
        // turn an old explicit false into unknown and could permit an unsupported request.
        metadata.base_url = config.base_url.clone();
        Ok(metadata)
    }
    pub(crate) fn ai_config(
        &self,
        model: &AiModelSelection,
    ) -> Result<(ProviderConfig, AiProviderMetadata)> {
        let config: ProviderConfig = self.store.get("provider", &model.provider_id)?;
        let metadata = self.ai_metadata(&config)?;
        if !metadata.enabled_models.contains(&model.model) {
            return Err(Error::new("model_not_enabled"));
        }
        Ok((config, metadata))
    }
    pub fn ai_model_capabilities(&self, model: &AiModelSelection) -> Result<AiContextCapabilities> {
        let (_, metadata) = self.ai_config(model)?;
        resolved_model_capabilities(&metadata, &model.model)
    }
    pub fn ai_provider_is_trusted(&self, model: &AiModelSelection) -> Result<bool> {
        Ok(self.ai_config(model)?.1.trust_raw)
    }
    pub fn ai_providers(&self) -> Result<Value> {
        // A provider, its encrypted metadata, declaration sidecar, defaults,
        // and credential status are a single UI snapshot.  SQLite commits its
        // rows atomically, but this response issues multiple reads.
        let _gate = self.lock()?;
        let mut out = Vec::new();
        for config in self.store.list::<ProviderConfig>("provider")? {
            let m = self.ai_metadata(&config)?;
            let declaration_metadata = capability_declarations_for(
                &config,
                &m,
                self.store
                    .maybe::<AiProviderCapabilityMetadata>(
                        AI_PROVIDER_CAPABILITY_METADATA_KIND,
                        &config.id,
                    )?
                    .as_ref(),
            );
            let capabilities = m
                .enabled_models
                .iter()
                .filter_map(|model| {
                    resolved_model_capabilities(&m, model)
                        .ok()
                        .map(|value| (model.clone(), value))
                })
                .collect::<BTreeMap<_, _>>();
            out.push(json!({"id":config.id,"name":config.name,"base_url":config.base_url,"model":config.model,"preset":m.preset,"enabled_models":m.enabled_models,"model_capabilities":m.model_capabilities,"resolved_model_capabilities":capabilities,"capability_metadata":declaration_metadata.model_capabilities,"trust_raw":m.trust_raw,"allow_private_network":config.allow_private_network,"key_configured":self.api_key(&config.id).is_ok()}));
        }
        Ok(json!({"providers":out,"presets":ai_presets(),"defaults":self.ai_defaults()?}))
    }
    pub fn save_ai_provider(&self, mut r: AiProviderRequest) -> Result<Value> {
        // Keep the reads, capability merge, provider revision, credential
        // boundary and all SQLite rows in one workspace-critical section.
        // `save_provider` deliberately cannot be called here because its
        // shorter lock would allow another save to interleave config and the
        // capability declaration sidecar.
        let _gate = self.lock()?;
        let requested_provider_id = r.id.clone().or_else(|| r.provider_id.clone());
        let previous_metadata = requested_provider_id
            .as_deref()
            .map(|provider_id| {
                self.store
                    .maybe::<AiProviderMetadata>("ai_provider", provider_id)
            })
            .transpose()?
            .flatten();
        let previous_declarations = requested_provider_id
            .as_deref()
            .map(|provider_id| {
                self.store.maybe::<AiProviderCapabilityMetadata>(
                    AI_PROVIDER_CAPABILITY_METADATA_KIND,
                    provider_id,
                )
            })
            .transpose()?
            .flatten();
        if r.base_url.trim().is_empty() {
            r.base_url = ai_presets()
                .as_array()
                .and_then(|a| a.iter().find(|p| p["id"] == r.preset))
                .and_then(|p| p["base_url"].as_str())
                .unwrap_or_default()
                .into();
        }
        r.base_url = normalized_base(&r.base_url);
        if r.enabled_models.is_empty() && !r.model.is_empty() {
            r.enabled_models.push(r.model.clone());
        }
        r.enabled_models.sort();
        r.enabled_models.dedup();
        if r.enabled_models.is_empty()
            || r.enabled_models.len() > 200
            || r.enabled_models
                .iter()
                .any(|m| m.is_empty() || m.len() > 200 || m.chars().any(char::is_control))
        {
            return Err(Error::new("enabled_models_required"));
        }
        validate_capabilities(&r.enabled_models, &r.model_capabilities)?;
        let mut merged_capabilities = previous_metadata
            .as_ref()
            .map(|value| value.model_capabilities.clone())
            .unwrap_or_default();
        for (model_id, incoming) in &r.model_capabilities {
            let merged = merge_capability_fields(
                merged_capabilities.get(model_id),
                incoming,
                r.model_capability_presence.get(model_id),
            );
            merged_capabilities.insert(model_id.clone(), merged);
        }
        let active_capabilities = merged_capabilities
            .iter()
            .filter(|(model_id, _)| r.enabled_models.contains(model_id))
            .map(|(model_id, capability)| (model_id.clone(), capability.clone()))
            .collect::<BTreeMap<_, _>>();
        validate_capabilities(&r.enabled_models, &active_capabilities)?;
        let model = if r.enabled_models.contains(&r.model) {
            r.model.clone()
        } else {
            r.enabled_models[0].clone()
        };
        let preset = recognized_preset(&r.base_url).unwrap_or_else(|| "custom".into());
        let trust_raw = if preset != "custom" {
            r.trust_raw.unwrap_or(true)
        } else {
            r.trust_raw.unwrap_or(false)
        };
        let prepared = self.prepare_provider_save(SaveProviderRequest {
            id: requested_provider_id,
            name: if r.name.is_empty() {
                preset.clone()
            } else {
                r.name
            },
            base_url: r.base_url.clone(),
            model: model.clone(),
            api_key: r.api_key.filter(|s| !s.is_empty()),
            allow_private_network: r.allow_private_network,
        })?;
        let provider_id = prepared.config.id.clone();
        let saved_config = prepared.config.clone();
        let mut declarations = previous_declarations
            .as_ref()
            .map(|value| value.model_capabilities.clone())
            .unwrap_or_default();
        let declaration_models = merged_capabilities
            .keys()
            .cloned()
            .chain(r.enabled_models.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        for model_id in declaration_models {
            let incoming = r.model_capabilities.get(&model_id);
            let presence = r.model_capability_presence.get(&model_id);
            let merged = merged_capabilities
                .get(&model_id)
                .cloned()
                .unwrap_or_default();
            let old_declaration = declarations.get(&model_id);
            let declaration = if incoming
                .is_some_and(|value| capability_update_has_explicit_fields(value, presence))
            {
                declared_capability_metadata(
                    &saved_config,
                    &model_id,
                    &merged,
                    old_declaration,
                    presence,
                )
            } else if let Some(old) = old_declaration {
                reconcile_legacy_declaration(&saved_config, &model_id, old.clone())
            } else if let Some(old_capability) = previous_metadata
                .as_ref()
                .and_then(|value| value.model_capabilities.get(&model_id))
            {
                let mut legacy_config = saved_config.clone();
                if let Some(old_metadata) = previous_metadata.as_ref() {
                    legacy_config.base_url = old_metadata.base_url.clone();
                }
                reconcile_legacy_declaration(
                    &saved_config,
                    &model_id,
                    legacy_capability_declaration(&legacy_config, &model_id, old_capability),
                )
            } else {
                unknown_capability_declaration(&saved_config, &model_id)
            };
            declarations.insert(model_id, declaration);
        }
        let metadata = AiProviderMetadata {
            preset,
            enabled_models: r.enabled_models,
            trust_raw,
            base_url: r.base_url,
            model_capabilities: merged_capabilities,
        };
        let declaration_metadata = AiProviderCapabilityMetadata {
            model_capabilities: declarations,
        };
        let mut defaults = self.ai_defaults()?;
        for purpose in ["chat", "redaction", "writing", "ocr"] {
            defaults
                .entry(purpose.into())
                .or_insert_with(|| AiModelSelection {
                    provider_id: provider_id.clone(),
                    model: model.clone(),
                });
        }
        let rows = vec![
            crate::store::Store::encoded("ai_provider", &provider_id, &metadata)?,
            crate::store::Store::encoded(
                AI_PROVIDER_CAPABILITY_METADATA_KIND,
                &provider_id,
                &declaration_metadata,
            )?,
            crate::store::Store::encoded("ai_defaults", "default", &defaults)?,
        ];
        self.commit_prepared_provider_save(&prepared, rows)?;
        Ok(json!({"id":provider_id,"saved":true,"defaults":defaults}))
    }
    pub async fn discover_ai_models(&self, mut r: AiProviderRequest) -> Result<Value> {
        let (existing, secret) = {
            // When discovery reuses a stored key, it must read that key with
            // the provider snapshot rather than during another save's
            // credential-manager phase.  The gate is released before the
            // network request below.
            let _gate = self.lock()?;
            let existing = r
                .provider_id
                .as_ref()
                .or(r.id.as_ref())
                .map(|id| self.store.get::<ProviderConfig>("provider", id))
                .transpose()?;
            if r.base_url.is_empty() {
                r.base_url = existing
                    .as_ref()
                    .map(|p| p.base_url.clone())
                    .unwrap_or_else(|| {
                        ai_presets()
                            .as_array()
                            .and_then(|a| a.iter().find(|p| p["id"] == r.preset))
                            .and_then(|p| p["base_url"].as_str())
                            .unwrap_or_default()
                            .into()
                    });
            }
            r.base_url = normalized_base(&r.base_url);
            let secret = match r.api_key.take().filter(|s| !s.is_empty()) {
                Some(key) => ApiSecret::new(key),
                None => {
                    let p = existing
                        .as_ref()
                        .ok_or_else(|| Error::new("api_key_required"))?;
                    if normalized_base(&p.base_url) != r.base_url {
                        return Err(Error::new("api_key_required_for_new_endpoint"));
                    }
                    self.api_key(&p.id)?
                }
            };
            (existing, secret)
        };
        let config = ProviderConfig {
            id: "discovery".into(),
            name: String::new(),
            base_url: r.base_url,
            model: "discovery".into(),
            allow_private_network: r.allow_private_network
                || existing.as_ref().is_some_and(|p| p.allow_private_network),
            revision: 1,
        };
        let transport = ReqwestStreamingTransport::new_with_limits(
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .map_err(provider_error)?;
        let data = transport
            .workspace_models(&profile_for(&config, "discovery"), &secret)
            .await
            .map_err(provider_error)?;
        let models = data["data"]
            .as_array()
            .ok_or_else(|| Error::new("model_list_invalid"))?
            .iter()
            .filter_map(|m| m["id"].as_str())
            .filter(|s| !s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control))
            .map(|id| json!({"id":id}))
            .collect::<Vec<_>>();
        Ok(json!({"models":models}))
    }
    pub async fn test_ai_model(&self, selection: AiModelSelection) -> Result<Value> {
        let result = self
            .ai_complete(
                &selection,
                json!([{"role":"user","content":"Reply exactly OK."}]),
                None,
                None,
                "connection_test",
                &hash(b"connection_test"),
                &CancellationToken::new(),
            )
            .await?;
        Ok(json!({"ok":true,"model":result.model,"usage":result.usage}))
    }
    // Keep purpose, source binding and cancellation explicit at every dispatch call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn ai_complete(
        &self,
        selection: &AiModelSelection,
        messages: Value,
        tools: Option<Value>,
        response_format: Option<Value>,
        purpose: &str,
        binding: &str,
        cancel: &CancellationToken,
    ) -> Result<AiCompletion> {
        self.ai_complete_budgeted(
            selection,
            messages,
            tools,
            response_format,
            purpose,
            binding,
            AiDispatchBudget {
                max_output_tokens: u32::MAX,
            },
            cancel,
        )
        .await
    }

    /// Dispatch with an output ceiling calculated by the run-level context budget.  Older
    /// callers retain `ai_complete` and receive the resolved model ceiling; new AI runs use this
    /// method for every model/tool round.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn ai_complete_budgeted(
        &self,
        selection: &AiModelSelection,
        messages: Value,
        tools: Option<Value>,
        response_format: Option<Value>,
        purpose: &str,
        binding: &str,
        budget: AiDispatchBudget,
        cancel: &CancellationToken,
    ) -> Result<AiCompletion> {
        let _slot = tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::new("cancelled")),slot=self.ai_slots.acquire()=>slot.map_err(|_|Error::new("workspace_unavailable"))?};
        let (provider, metadata) = {
            let _gate = self.lock()?;
            let (config, metadata) = self.ai_config(selection)?;
            let provider = self.provider_dispatch_snapshot_locked(&config)?;
            (provider, metadata)
        };
        let config = provider.config;
        let mut profile = provider.profile;
        profile.model_id = selection.model.clone();
        let secret = provider.secret;
        let capabilities = resolved_model_capabilities(&metadata, &selection.model)?;
        validate_requested_features(
            &capabilities,
            tools.is_some(),
            response_format.is_some(),
            contains_image_input(&messages),
        )?;
        let max_output_tokens = budget.max_output_tokens.min(capabilities.max_output_tokens);
        if max_output_tokens == 0 {
            return Err(Error::new("context_budget_exceeded"));
        }
        let mut body = json!({"model":selection.model,"messages":messages,"stream":false,"max_tokens":max_output_tokens});
        if metadata.preset == "glm" || selection.model.to_lowercase().contains("glm-5.3") {
            body["reasoning_effort"] = json!("low");
        } else if ["deepseek", "volcengine"].contains(&metadata.preset.as_str()) {
            body["thinking"] = json!({"type":"disabled"});
        } else if ["qwen", "siliconflow"].contains(&metadata.preset.as_str()) {
            body["enable_thinking"] = json!(false);
        }
        if let Some(t) = tools {
            body["tools"] = t;
            body["tool_choice"] = json!("auto");
        }
        if let Some(f) = response_format {
            body["response_format"] = f;
        }
        let request = providers::adapter::authorize_workspace_json(
            &profile,
            body,
            purpose,
            binding,
            now() + 900,
        )
        .map_err(provider_error)?;
        let dispatch_id = id("dispatch");
        let mut dispatch = json!({"id":dispatch_id,"purpose":purpose,"binding":binding,"provider_id":selection.provider_id,"model":selection.model,"provider_revision":config.revision,"status":"started","created_at":now()});
        {
            let _gate = self.lock()?;
            if cancel.is_cancelled() {
                return Err(Error::new("cancelled"));
            }
            if self.ai_config(selection)?.0.revision != config.revision {
                return Err(Error::new("provider_changed"));
            }
            self.store.save("ai_dispatch", &dispatch_id, &dispatch)?;
        }
        let transport = ReqwestStreamingTransport::new_with_limits(
            Duration::from_secs(10),
            Duration::from_secs(180),
            Duration::from_secs(600),
        )
        .map_err(provider_error)?;
        let response = tokio::select! {biased;_=cancel.cancelled()=>Err(Error::new("cancelled")),v=transport.send_workspace_json(&profile,&secret,&request)=>v.map_err(provider_error)};
        // A truncated or otherwise unusable completion can still consume billed tokens.
        // Retain the provider's usage even when the payload fails the checks below.
        if let Ok(value) = &response {
            if value["usage"].is_object() {
                dispatch["usage"] = value["usage"].clone();
            }
        }
        let result = response.and_then(|mut value| {
            if self.ai_config(selection)?.0.revision != config.revision {
                return Err(Error::new("provider_changed"));
            }
            let choice = &value["choices"][0];
            if !matches!(
                choice["finish_reason"].as_str(),
                Some("stop" | "tool_calls")
            ) {
                return Err(Error::new("provider_response_incomplete"));
            }
            let mut message = choice["message"].clone();
            if let Some(o) = message.as_object_mut() {
                o.remove("reasoning_content");
                o.remove("reasoning");
            }
            if !message["content"].is_string() && !message["tool_calls"].is_array() {
                return Err(Error::new("provider_response_invalid"));
            }
            Ok(AiCompletion {
                message,
                usage: value["usage"].take(),
                model: selection.model.clone(),
            })
        });
        dispatch["finished_at"] = json!(now());
        match &result {
            Ok(value) => {
                dispatch["status"] = json!("completed");
                dispatch["usage"] = value.usage.clone();
            }
            Err(e) => {
                dispatch["status"] = json!("failed");
                dispatch["error_code"] = json!(e.code);
            }
        }
        self.store.save("ai_dispatch", &dispatch_id, &dispatch)?;
        result
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::provider::{
        set_provider_save_credential_hook_for_tests, ProviderSaveCredentialHookForTests,
    };

    fn credential_hook_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("credential hook test guard")
    }

    fn metadata(capabilities: BTreeMap<String, AiModelCapabilities>) -> AiProviderMetadata {
        AiProviderMetadata {
            preset: "custom".into(),
            enabled_models: vec!["local".into()],
            trust_raw: false,
            base_url: "http://127.0.0.1".into(),
            model_capabilities: capabilities,
        }
    }

    #[test]
    fn unknown_model_capability_is_visible_conservative_16k_input_4k_output() {
        let resolved = resolved_model_capabilities(&metadata(BTreeMap::new()), "local")
            .expect("legacy settings resolve without guessing model family");
        assert!(!resolved.verified);
        assert_eq!(resolved.context_window_tokens, 20_480);
        assert_eq!(resolved.max_input_tokens, 16_384);
        assert_eq!(resolved.max_output_tokens, 4_096);
    }

    #[test]
    fn explicit_unsupported_features_reject_before_transport() {
        let capabilities = AiContextCapabilities {
            verified: true,
            context_window_tokens: 32_768,
            max_input_tokens: 28_672,
            max_output_tokens: 4_096,
            supports_tools: Some(false),
            supports_structured_output: Some(false),
            supports_vision: Some(false),
        };
        assert_eq!(
            validate_requested_features(&capabilities, true, false, false)
                .expect_err("tools must be rejected")
                .code,
            "model_tools_unsupported"
        );
        assert_eq!(
            validate_requested_features(&capabilities, false, true, false)
                .expect_err("json must be rejected")
                .code,
            "model_structured_output_unsupported"
        );
        assert_eq!(
            validate_requested_features(&capabilities, false, false, true)
                .expect_err("vision must be rejected")
                .code,
            "model_vision_unsupported"
        );
    }

    #[test]
    fn capability_wire_keeps_unknown_distinct_from_false() {
        let value = serde_json::to_value(AiModelCapabilities {
            context_window_tokens: Some(131_072),
            max_output_tokens: Some(8_192),
            supports_tools: None,
            supports_structured_output: Some(false),
            supports_vision: Some(true),
        })
        .expect("capability declaration serializes");
        assert_eq!(value["supports_tools"], Value::Null);
        assert_eq!(value["supports_structured_output"], false);
        assert_eq!(value["supports_vision"], true);
    }

    #[test]
    fn json_presence_distinguishes_omitted_and_explicit_null() {
        let request: AiProviderRequest = serde_json::from_value(json!({
            "name": "synthetic",
            "base_url": "http://127.0.0.1:1234/v1",
            "model": "m",
            "enabled_models": ["m"],
            "model_capabilities": {
                "m": {
                    "context_window_tokens": 131072,
                    "max_output_tokens": 8192,
                    "supports_tools": null,
                    "supports_vision": false
                }
            }
        }))
        .expect("request decodes");
        let presence = request
            .model_capability_presence
            .get("m")
            .expect("presence is retained");
        assert!(presence.context_window_tokens);
        assert!(presence.max_output_tokens);
        assert!(presence.supports_tools);
        assert!(!presence.supports_structured_output);
        assert!(presence.supports_vision);
        assert_eq!(request.model_capabilities["m"].supports_tools, None);
    }

    #[test]
    fn capacity_only_update_preserves_old_false_but_explicit_null_resets_it() {
        let old = AiModelCapabilities {
            context_window_tokens: Some(20_480),
            max_output_tokens: Some(4_096),
            supports_tools: Some(false),
            supports_structured_output: Some(true),
            supports_vision: None,
        };
        let capacity_only = AiModelCapabilities {
            context_window_tokens: Some(131_072),
            max_output_tokens: Some(8_192),
            ..Default::default()
        };
        let merged = merge_capability_fields(None, &old, None);
        let merged = merge_capability_fields(Some(&merged), &capacity_only, None);
        assert_eq!(merged.context_window_tokens, Some(131_072));
        assert_eq!(merged.max_output_tokens, Some(8_192));
        assert_eq!(merged.supports_tools, Some(false));
        assert_eq!(merged.supports_structured_output, Some(true));

        let reset = AiModelCapabilities {
            supports_tools: None,
            ..Default::default()
        };
        let presence = AiModelCapabilityPresence {
            supports_tools: true,
            ..Default::default()
        };
        let reset = merge_capability_fields(Some(&merged), &reset, Some(&presence));
        assert_eq!(reset.supports_tools, None);
        assert_eq!(reset.supports_structured_output, Some(true));
    }

    #[test]
    fn capability_binding_and_legacy_review_are_explicit() {
        let first = ProviderConfig {
            id: "provider-a".into(),
            name: "synthetic".into(),
            base_url: "http://127.0.0.1:1234/v1".into(),
            model: "m".into(),
            allow_private_network: true,
            revision: 1,
        };
        let second = ProviderConfig {
            base_url: "http://127.0.0.1:5678/v1".into(),
            ..first.clone()
        };
        let first_binding = capability_config_binding(&first, "m");
        assert_ne!(first_binding, capability_config_binding(&second, "m"));
        assert_eq!(
            first_binding,
            capability_config_binding(
                &ProviderConfig {
                    revision: 99,
                    ..first.clone()
                },
                "m"
            )
        );
        let declaration = legacy_capability_declaration(
            &first,
            "m",
            &AiModelCapabilities {
                supports_tools: Some(false),
                ..Default::default()
            },
        );
        assert!(declaration.needs_review);
        assert_eq!(declaration.fields_needing_review, vec!["supports_tools"]);
        assert_eq!(
            reconcile_legacy_declaration(&second, "m", declaration)
                .current_config_binding
                .as_deref(),
            Some(capability_config_binding(&second, "m").as_str())
        );
    }

    fn atomic_provider_request(
        provider_id: &str,
        base_url: &str,
        context_window_tokens: u32,
        max_output_tokens: u32,
        supports_tools: bool,
    ) -> AiProviderRequest {
        AiProviderRequest {
            id: Some(provider_id.into()),
            name: format!("provider-{supports_tools}"),
            preset: "custom".into(),
            base_url: base_url.into(),
            model: "atomic-model".into(),
            enabled_models: vec!["atomic-model".into()],
            model_capabilities: BTreeMap::from([(
                "atomic-model".into(),
                AiModelCapabilities {
                    context_window_tokens: Some(context_window_tokens),
                    max_output_tokens: Some(max_output_tokens),
                    supports_tools: Some(supports_tools),
                    supports_structured_output: None,
                    supports_vision: None,
                },
            )]),
            allow_private_network: false,
            ..Default::default()
        }
    }

    fn atomic_test_workspace() -> (tempfile::TempDir, std::sync::Arc<Workspace>) {
        let directory = tempfile::tempdir().expect("temporary workspace root");
        let workspace = Workspace::open(
            directory.path().join("workspace"),
            directory.path().join("public-legal.sqlite"),
        )
        .expect("workspace opens without a configured public corpus");
        (directory, workspace)
    }

    #[test]
    fn concurrent_provider_saves_commit_one_coherent_config_capability_snapshot() {
        let (_directory, workspace) = atomic_test_workspace();
        let provider_id = "provider_atomic_concurrent";
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let first_workspace = workspace.clone();
        let first_start = start.clone();
        let first = std::thread::spawn(move || {
            first_start.wait();
            first_workspace.save_ai_provider(atomic_provider_request(
                provider_id,
                "https://atomic-a.invalid/v1",
                32_768,
                4_096,
                false,
            ))
        });
        let second_workspace = workspace.clone();
        let second_start = start.clone();
        let second = std::thread::spawn(move || {
            second_start.wait();
            second_workspace.save_ai_provider(atomic_provider_request(
                provider_id,
                "https://atomic-b.invalid/v1",
                65_536,
                8_192,
                true,
            ))
        });
        start.wait();
        first
            .join()
            .expect("first save thread")
            .expect("first save");
        second
            .join()
            .expect("second save thread")
            .expect("second save");

        let config: ProviderConfig = workspace
            .store
            .get("provider", provider_id)
            .expect("saved provider config");
        let metadata: AiProviderMetadata = workspace
            .store
            .get("ai_provider", provider_id)
            .expect("saved provider metadata");
        let declarations: AiProviderCapabilityMetadata = workspace
            .store
            .get(AI_PROVIDER_CAPABILITY_METADATA_KIND, provider_id)
            .expect("saved declaration sidecar");
        let capability = metadata
            .model_capabilities
            .get("atomic-model")
            .expect("saved model capability");
        let declaration = declarations
            .model_capabilities
            .get("atomic-model")
            .expect("saved model declaration");
        let expected = match config.base_url.as_str() {
            "https://atomic-a.invalid/v1" => (32_768, 4_096, false),
            "https://atomic-b.invalid/v1" => (65_536, 8_192, true),
            other => panic!("unexpected committed endpoint: {other}"),
        };
        assert_eq!(metadata.base_url, config.base_url);
        assert_eq!(capability.context_window_tokens, Some(expected.0));
        assert_eq!(capability.max_output_tokens, Some(expected.1));
        assert_eq!(capability.supports_tools, Some(expected.2));
        assert_eq!(
            declaration.config_binding,
            capability_config_binding(&config, "atomic-model")
        );
        assert_eq!(
            declaration.declaration_hash,
            capability_declaration_hash("atomic-model", capability, &declaration.config_binding)
        );
        assert_eq!(declaration.provider_revision, config.revision);
    }

    #[test]
    fn sidecar_sqlite_failure_rolls_back_provider_config_metadata_and_defaults() {
        let (_directory, workspace) = atomic_test_workspace();
        let provider_id = "provider_atomic_rollback";
        workspace
            .save_ai_provider(atomic_provider_request(
                provider_id,
                "https://atomic-before.invalid/v1",
                32_768,
                4_096,
                false,
            ))
            .expect("initial provider state");
        let before_config: ProviderConfig = workspace.store.get("provider", provider_id).unwrap();
        let before_metadata: AiProviderMetadata =
            workspace.store.get("ai_provider", provider_id).unwrap();
        let before_declarations: AiProviderCapabilityMetadata = workspace
            .store
            .get(AI_PROVIDER_CAPABILITY_METADATA_KIND, provider_id)
            .unwrap();
        let before_defaults: BTreeMap<String, AiModelSelection> =
            workspace.store.get("ai_defaults", "default").unwrap();
        workspace
            .store
            .fail_object_writes_for_kind_for_tests(AI_PROVIDER_CAPABILITY_METADATA_KIND)
            .expect("install deterministic sidecar failure");

        assert!(workspace
            .save_ai_provider(atomic_provider_request(
                provider_id,
                "https://atomic-after.invalid/v1",
                65_536,
                8_192,
                true,
            ))
            .is_err());

        let after_config: ProviderConfig = workspace.store.get("provider", provider_id).unwrap();
        let after_metadata: AiProviderMetadata =
            workspace.store.get("ai_provider", provider_id).unwrap();
        let after_declarations: AiProviderCapabilityMetadata = workspace
            .store
            .get(AI_PROVIDER_CAPABILITY_METADATA_KIND, provider_id)
            .unwrap();
        let after_defaults: BTreeMap<String, AiModelSelection> =
            workspace.store.get("ai_defaults", "default").unwrap();
        assert_eq!(
            serde_json::to_value(after_config).unwrap(),
            serde_json::to_value(before_config).unwrap()
        );
        assert_eq!(
            serde_json::to_value(after_metadata).unwrap(),
            serde_json::to_value(before_metadata).unwrap()
        );
        assert_eq!(after_declarations, before_declarations);
        assert_eq!(
            serde_json::to_value(after_defaults).unwrap(),
            serde_json::to_value(before_defaults).unwrap()
        );
    }

    #[test]
    fn failed_credential_save_never_exposes_its_temporary_key_to_a_dispatch_snapshot() {
        let _hook_guard = credential_hook_test_guard();
        let (_directory, workspace) = atomic_test_workspace();
        let provider_id = "provider_atomic_credential_rollback";
        let mut initial = atomic_provider_request(
            provider_id,
            "https://atomic-before.invalid/v1",
            32_768,
            4_096,
            false,
        );
        initial.api_key = Some("atomic-old-test-key".into());
        workspace
            .save_ai_provider(initial)
            .expect("initial provider and credential save");
        let before: ProviderConfig = workspace.store.get("provider", provider_id).unwrap();
        workspace
            .store
            .fail_object_writes_for_kind_for_tests(AI_PROVIDER_CAPABILITY_METADATA_KIND)
            .expect("install deterministic SQLite failure");

        let hook = ProviderSaveCredentialHookForTests {
            provider_id: provider_id.into(),
            credential_written: std::sync::Arc::new(std::sync::Barrier::new(2)),
            release: std::sync::Arc::new(std::sync::Barrier::new(2)),
            force_restore_failure: false,
        };
        set_provider_save_credential_hook_for_tests(Some(hook.clone()));
        struct ResetCredentialHook;
        impl Drop for ResetCredentialHook {
            fn drop(&mut self) {
                set_provider_save_credential_hook_for_tests(None);
            }
        }
        let _reset = ResetCredentialHook;

        let saving_workspace = workspace.clone();
        let saving = std::thread::spawn(move || {
            let mut changed = atomic_provider_request(
                provider_id,
                "https://atomic-after.invalid/v1",
                65_536,
                8_192,
                true,
            );
            changed.api_key = Some("atomic-new-temporary-key".into());
            saving_workspace.save_ai_provider(changed)
        });
        hook.credential_written.wait();

        let reading_workspace = workspace.clone();
        let expected = before.clone();
        let (ready, result) = std::sync::mpsc::sync_channel(1);
        let reading = std::thread::spawn(move || {
            ready
                .send(reading_workspace.provider_dispatch_snapshot(&expected))
                .expect("snapshot receiver remains available");
        });
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        hook.release.wait();
        assert!(saving.join().expect("failed save thread joins").is_err());
        let snapshot = result
            .recv_timeout(Duration::from_secs(2))
            .expect("snapshot unblocks after credential rollback")
            .expect("snapshot reads restored provider state");
        reading.join().expect("snapshot thread joins");
        assert_eq!(
            serde_json::to_value(&snapshot.config).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(snapshot.secret.expose_secret(), "atomic-old-test-key");

        set_provider_save_credential_hook_for_tests(None);
        workspace
            .save_provider(SaveProviderRequest {
                id: Some(provider_id.into()),
                name: "credential test cleanup".into(),
                base_url: "https://cleanup.invalid/v1".into(),
                model: "cleanup-model".into(),
                api_key: Some(String::new()),
                allow_private_network: false,
            })
            .expect("test credential cleanup");
    }

    #[tokio::test]
    async fn unverified_credential_compensation_persistently_blocks_dispatch_until_reconfigured() {
        let _hook_guard = credential_hook_test_guard();
        let (directory, workspace) = atomic_test_workspace();
        let workspace_root = directory.path().join("workspace");
        let legal_database = directory.path().join("public-legal.sqlite");
        let provider_id = "provider_atomic_credential_fault";
        let mut initial = atomic_provider_request(
            provider_id,
            "https://atomic-before.invalid/v1",
            32_768,
            4_096,
            false,
        );
        initial.api_key = Some("atomic-old-fault-test-key".into());
        workspace
            .save_ai_provider(initial)
            .expect("initial provider and credential save");
        let before: ProviderConfig = workspace.store.get("provider", provider_id).unwrap();
        workspace
            .store
            .fail_object_writes_for_kind_for_tests(AI_PROVIDER_CAPABILITY_METADATA_KIND)
            .expect("install deterministic SQLite failure");

        let hook = ProviderSaveCredentialHookForTests {
            provider_id: provider_id.into(),
            credential_written: std::sync::Arc::new(std::sync::Barrier::new(1)),
            release: std::sync::Arc::new(std::sync::Barrier::new(1)),
            force_restore_failure: true,
        };
        set_provider_save_credential_hook_for_tests(Some(hook));
        struct ResetCredentialHook;
        impl Drop for ResetCredentialHook {
            fn drop(&mut self) {
                set_provider_save_credential_hook_for_tests(None);
            }
        }
        let _reset = ResetCredentialHook;

        let mut changed = atomic_provider_request(
            provider_id,
            "https://atomic-after.invalid/v1",
            65_536,
            8_192,
            true,
        );
        changed.api_key = Some("atomic-new-fault-test-key".into());
        assert_eq!(
            workspace.save_ai_provider(changed).unwrap_err().code,
            "credential_write_failed"
        );
        let blocked = match workspace.provider_dispatch_snapshot(&before) {
            Ok(_) => panic!("a provider with an unverified vault compensation must not dispatch"),
            Err(error) => error,
        };
        assert_eq!(
            blocked.code, "credential_write_failed",
            "the old SQLite config cannot dispatch with a possibly new vault key"
        );
        drop(_reset);
        drop(_hook_guard);
        let discovery_error = workspace
            .discover_ai_models(atomic_provider_request(
                provider_id,
                "https://atomic-before.invalid/v1",
                32_768,
                4_096,
                false,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            discovery_error.code, "credential_write_failed",
            "stored-key model discovery must stop before constructing a transport request"
        );

        workspace
            .store
            .clear_object_write_failure_for_tests()
            .expect("remove injected sidecar failure");
        // A capacity-only save still has no authoritative credential value,
        // so it may update its own configuration but must retain the block.
        workspace
            .save_ai_provider(atomic_provider_request(
                provider_id,
                "https://atomic-capacity-only.invalid/v1",
                98_304,
                12_288,
                false,
            ))
            .expect("capacity-only save persists without clearing credential fault");
        let capacity_only: ProviderConfig = workspace.store.get("provider", provider_id).unwrap();
        let blocked = match workspace.provider_dispatch_snapshot(&capacity_only) {
            Ok(_) => panic!("a capacity-only update must retain the credential dispatch block"),
            Err(error) => error,
        };
        assert_eq!(blocked.code, "credential_write_failed");

        drop(workspace);
        let reopened = Workspace::open(workspace_root, legal_database)
            .expect("credential fault state survives workspace reopen");
        let persisted: ProviderConfig = reopened.store.get("provider", provider_id).unwrap();
        let blocked = match reopened.provider_dispatch_snapshot(&persisted) {
            Ok(_) => panic!("the persisted credential fault must block after reopen"),
            Err(error) => error,
        };
        assert_eq!(blocked.code, "credential_write_failed");

        reopened
            .save_provider(SaveProviderRequest {
                id: Some(provider_id.into()),
                name: "credential fault test reconfigured".into(),
                base_url: "https://reconfigured.invalid/v1".into(),
                model: "reconfigured-model".into(),
                api_key: Some("atomic-reconfigured-fault-test-key".into()),
                allow_private_network: false,
            })
            .expect("explicit credential reconfiguration clears the dispatch block");
        let reconfigured: ProviderConfig = reopened.store.get("provider", provider_id).unwrap();
        let snapshot = reopened
            .provider_dispatch_snapshot(&reconfigured)
            .expect("only a successful explicit credential update clears the block");
        assert_eq!(
            snapshot.secret.expose_secret(),
            "atomic-reconfigured-fault-test-key"
        );
        reopened
            .save_provider(SaveProviderRequest {
                id: Some(provider_id.into()),
                name: "credential fault test cleanup".into(),
                base_url: "https://cleanup.invalid/v1".into(),
                model: "cleanup-model".into(),
                api_key: Some(String::new()),
                allow_private_network: false,
            })
            .expect("test credential cleanup");
    }
}
