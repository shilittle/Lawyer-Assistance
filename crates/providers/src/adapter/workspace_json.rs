use super::*;

/// Opaque, one-use authorization for multimodal and tool-enabled workspace calls.
/// The workspace owns material/trust checks; the complete body and profile are bound here.
pub struct AuthorizedWorkspaceJson {
    body: Vec<u8>,
    profile_hash: String,
    body_hash: String,
    expires: u64,
    used: AtomicBool,
}

pub fn authorize_workspace_json(
    profile: &ProviderProfile,
    body: serde_json::Value,
    purpose: &str,
    source_binding: &str,
    expires: u64,
) -> Result<AuthorizedWorkspaceJson, ProviderError> {
    validate_provider_binding_text("purpose", purpose)?;
    if !valid_lower_sha256(source_binding) || expires <= system_unix_time()? {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace binding invalid",
        ));
    }
    provider_endpoint_origin(profile)?;
    let messages = body
        .get("messages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ProviderError::new(ProviderErrorKind::InvalidRequest, "messages required")
        })?;
    if messages.is_empty()
        || messages.len() > 256
        || body["model"].as_str() != Some(effective_model_id(profile))
        || body["stream"] != false
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace request shape invalid",
        ));
    }
    for message in messages {
        if !matches!(
            message["role"].as_str(),
            Some("system" | "user" | "assistant" | "tool")
        ) {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "message role invalid",
            ));
        }
    }
    let bytes = serde_json::to_vec(&body).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "request serialization failed",
        )
    })?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace request too large",
        ));
    }
    Ok(AuthorizedWorkspaceJson {
        body_hash: privacy::sha256_hex(&bytes),
        body: bytes,
        profile_hash: workspace_profile_sha256(profile)?,
        expires,
        used: AtomicBool::new(false),
    })
}

impl ReqwestStreamingTransport {
    pub async fn send_workspace_json(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &AuthorizedWorkspaceJson,
    ) -> Result<serde_json::Value, ProviderError> {
        if request.expires <= system_unix_time()?
            || request.profile_hash != workspace_profile_sha256(profile)?
            || request.body_hash != privacy::sha256_hex(&request.body)
            || request.used.swap(true, Ordering::AcqRel)
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "workspace request expired, changed, or consumed",
            ));
        }
        let url = chat_completions_url(profile)?;
        let client = if private_network_is_explicitly_allowed(profile) {
            &self.private_network_client
        } else {
            &self.safe_client
        };
        let response = client
            .post(url)
            .bearer_auth(secret.expose_secret())
            .header("content-type", "application/json")
            .body(request.body.clone())
            .send()
            .await
            .map_err(|e| redact_known_secret(map_reqwest_error(e), secret))?;
        bounded_json(response, secret).await
    }

    /// Model discovery is read-only and uses exactly the configured endpoint origin.
    pub async fn workspace_models(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
    ) -> Result<serde_json::Value, ProviderError> {
        let (base, _) = parsed_provider_base_url(profile)?;
        let base = base
            .trim_end_matches("/chat/completions")
            .trim_end_matches("/responses");
        let client = if private_network_is_explicitly_allowed(profile) {
            &self.private_network_client
        } else {
            &self.safe_client
        };
        let response = client
            .get(format!("{base}/models"))
            .bearer_auth(secret.expose_secret())
            .send()
            .await
            .map_err(|e| redact_known_secret(map_reqwest_error(e), secret))?;
        bounded_json(response, secret).await
    }
}

async fn bounded_json(
    mut response: reqwest::Response,
    secret: &ApiSecret,
) -> Result<serde_json::Value, ProviderError> {
    let status = response.status().as_u16();
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| redact_known_secret(map_reqwest_error(e), secret))?
    {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(ProviderError::new(
                ProviderErrorKind::ResponseTooLarge,
                "provider response too large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !(200..300).contains(&status) {
        return Err(ProviderError::with_status(
            ProviderErrorKind::Http,
            status,
            "provider request failed",
        ));
    }
    if !secret.expose_secret().is_empty()
        && bytes
            .windows(secret.expose_secret().len())
            .any(|v| v == secret.expose_secret().as_bytes())
    {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "provider credential echo rejected",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| ProviderError::new(ProviderErrorKind::Parse, "provider JSON invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_json_shape_and_expiry() {
        let mut profile = ProviderProfile::new_default("test", ProviderKind::Custom);
        profile.base_url = "https://example.com/v1".into();
        profile.model_id = "test-model".into();
        let good = serde_json::json!({"model":"test-model","stream":false,"messages":[{"role":"user","content":[{"type":"text","text":"synthetic"}]}]});
        assert!(authorize_workspace_json(
            &profile,
            good.clone(),
            "ocr",
            &"a".repeat(64),
            system_unix_time().unwrap() + 60
        )
        .is_ok());
        assert!(authorize_workspace_json(&profile, good, "ocr", &"a".repeat(64), 1).is_err());
        assert!(authorize_workspace_json(
            &profile,
            serde_json::json!({"model":"different","stream":false,"messages":[]}),
            "ocr",
            &"a".repeat(64),
            system_unix_time().unwrap() + 60
        )
        .is_err());
    }
}
