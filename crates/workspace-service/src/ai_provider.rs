use crate::ai_context::{
    UNKNOWN_CONTEXT_WINDOW_TOKENS, UNKNOWN_INPUT_TOKENS, UNKNOWN_MAX_OUTPUT_TOKENS,
};
use crate::*;
use providers::{ApiSecret, ProviderKind, ProviderProfile, ReqwestStreamingTransport};
use serde::{Deserialize, Serialize};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_tools: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_structured_output: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_vision: Option<bool>,
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
#[derive(Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AiProviderRequest {
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
    pub model_capabilities: BTreeMap<String, AiModelCapabilities>,
    pub api_key: Option<String>,
    pub trust_raw: Option<bool>,
    #[serde(default)]
    pub allow_private_network: bool,
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
            if self
                .store
                .maybe::<AiProviderMetadata>("ai_provider", &provider.id)?
                .is_none()
            {
                self.store
                    .save("ai_provider", &provider.id, &self.ai_metadata(provider)?)?;
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
        Ok(self
            .store
            .maybe::<AiProviderMetadata>("ai_provider", &config.id)?
            .filter(|p| p.base_url == config.base_url)
            .unwrap_or_else(|| AiProviderMetadata {
                preset: recognized_preset(&config.base_url).unwrap_or_else(|| "custom".into()),
                enabled_models: vec![config.model.clone()],
                trust_raw: recognized_preset(&config.base_url).is_some(),
                base_url: config.base_url.clone(),
                model_capabilities: BTreeMap::new(),
            }))
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
        let mut out = Vec::new();
        for config in self.store.list::<ProviderConfig>("provider")? {
            let m = self.ai_metadata(&config)?;
            let capabilities = m
                .enabled_models
                .iter()
                .filter_map(|model| {
                    resolved_model_capabilities(&m, model)
                        .ok()
                        .map(|value| (model.clone(), value))
                })
                .collect::<BTreeMap<_, _>>();
            out.push(json!({"id":config.id,"name":config.name,"base_url":config.base_url,"model":config.model,"preset":m.preset,"enabled_models":m.enabled_models,"model_capabilities":m.model_capabilities,"resolved_model_capabilities":capabilities,"trust_raw":m.trust_raw,"allow_private_network":config.allow_private_network,"key_configured":self.api_key(&config.id).is_ok()}));
        }
        Ok(json!({"providers":out,"presets":ai_presets(),"defaults":self.ai_defaults()?}))
    }
    pub fn save_ai_provider(&self, mut r: AiProviderRequest) -> Result<Value> {
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
        let result = self.save_provider(SaveProviderRequest {
            id: r.id.or(r.provider_id),
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
        let provider_id = result["id"]
            .as_str()
            .ok_or_else(|| Error::new("provider_save_failed"))?
            .to_owned();
        self.store.save(
            "ai_provider",
            &provider_id,
            &AiProviderMetadata {
                preset,
                enabled_models: r.enabled_models,
                trust_raw,
                base_url: r.base_url,
                model_capabilities: r.model_capabilities,
            },
        )?;
        let mut defaults = self.ai_defaults()?;
        for purpose in ["chat", "redaction", "writing", "ocr"] {
            defaults
                .entry(purpose.into())
                .or_insert_with(|| AiModelSelection {
                    provider_id: provider_id.clone(),
                    model: model.clone(),
                });
        }
        self.store.save("ai_defaults", "default", &defaults)?;
        Ok(json!({"id":provider_id,"saved":true,"defaults":defaults}))
    }
    pub async fn discover_ai_models(&self, mut r: AiProviderRequest) -> Result<Value> {
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
        let secret = match r.api_key.filter(|s| !s.is_empty()) {
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
        let capabilities = self.ai_model_capabilities(selection)?;
        self.ai_complete_budgeted(
            selection,
            messages,
            tools,
            response_format,
            purpose,
            binding,
            AiDispatchBudget {
                max_output_tokens: capabilities.max_output_tokens,
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
        let (config, metadata) = self.ai_config(selection)?;
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
        let profile = profile_for(&config, &selection.model);
        let secret = self.api_key(&selection.provider_id)?;
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
}
