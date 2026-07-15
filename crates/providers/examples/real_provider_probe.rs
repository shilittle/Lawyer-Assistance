//! Manual, billable interoperability probe for the supported BYOK providers.
//!
//! The provider kind is the only command-line argument. The API key must be
//! supplied on standard input so it does not appear in the process command
//! line, shell history, SQLite, or the JSON result.

use providers::{
    ApiSecret, ConnectionTestStatus, OpenAiCompatibleAdapter, ProviderKind, ProviderProfile,
    ReasoningEffort, ReqwestTransport,
};
use serde_json::json;
use std::{
    env,
    io::{self, Read},
    process::ExitCode,
    time::Duration,
};

const WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES: usize = 5 * 512;

#[derive(Clone, Copy)]
struct ProbeTarget {
    kind: ProviderKind,
    name: &'static str,
    base_url_override: Option<&'static str>,
    thinking: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(status) => status,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(64)
        }
    }
}

fn run() -> Result<ExitCode, &'static str> {
    let mut arguments = env::args().skip(1);
    let provider_argument = arguments
        .next()
        .ok_or("usage: real_provider_probe <target>; pass the API key on stdin")?;
    if arguments.next().is_some() {
        return Err("the probe accepts exactly one non-secret provider argument");
    }

    let target = parse_target(&provider_argument)?;
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|_| "could not read the API key from stdin")?;
    let input = normalize_stdin_secret(input)?;

    // Move the only owned copy straight into the redacting secret wrapper.
    // The short-lived process exits immediately after this single probe.
    let secret = ApiSecret::new(input);

    let mut profile =
        ProviderProfile::new_default(format!("acceptance-{}", target.name), target.kind);
    if let Some(base_url) = target.base_url_override {
        profile.base_url = base_url.to_owned();
    }
    if target.thinking {
        profile.options.thinking = Some(true);
        profile.options.reasoning_effort = Some(ReasoningEffort::Max);
    }
    let transport = ReqwestTransport::new(Duration::from_secs(60))
        .map_err(|_| "could not initialize the HTTPS transport")?;
    let result = OpenAiCompatibleAdapter::new(transport).test_connection(&profile, &secret);
    let succeeded = result.status == ConnectionTestStatus::Succeeded;
    let provider_error_code = allowlisted_provider_error_code(&result.message);

    let output = json!({
        "provider": target.name,
        "status": result.status,
        "httpStatus": result.http_status,
        "model": result.model,
        "firstContentTokenLatencyMs": result.first_token_latency_ms,
        "totalLatencyMs": result.total_latency_ms,
        "usage": result.usage,
        "providerErrorCode": provider_error_code,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("probe output is serializable")
    );

    Ok(if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn allowlisted_provider_error_code(message: &str) -> Option<&'static str> {
    match message.split_once(':')?.0 {
        // This is a public Alibaba Cloud Model Studio error identifier. Return
        // our own literal instead of any borrowed upstream text so account or
        // credential fragments can never cross this output boundary.
        "AccessDenied.Unpurchased" => Some("AccessDenied.Unpurchased"),
        _ => None,
    }
}

fn normalize_stdin_secret(mut input: String) -> Result<String, &'static str> {
    while matches!(input.as_bytes().last(), Some(b'\r' | b'\n')) {
        input.pop();
    }

    // Windows PowerShell 5.1 prefixes text piped to a native process with a
    // UTF-8 BOM. It is transport framing, not part of the credential.
    if input.starts_with('\u{feff}') {
        input.drain(..'\u{feff}'.len_utf8());
    }

    if input.is_empty() {
        return Err("stdin did not contain an API key");
    }
    if input.len() > WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES {
        return Err("the API key exceeds the Windows credential blob limit");
    }
    if !input.chars().all(|character| character.is_ascii_graphic()) {
        return Err("the API key must contain printable ASCII without whitespace");
    }

    Ok(input)
}

fn parse_target(value: &str) -> Result<ProbeTarget, &'static str> {
    match value {
        "deep_seek" | "deepseek" => Ok(ProbeTarget {
            kind: ProviderKind::DeepSeek,
            name: "deep_seek",
            base_url_override: None,
            thinking: false,
        }),
        "deepseek_thinking" => Ok(ProbeTarget {
            kind: ProviderKind::DeepSeek,
            name: "deep_seek_thinking",
            base_url_override: None,
            thinking: true,
        }),
        "qwen" => Ok(ProbeTarget {
            kind: ProviderKind::Qwen,
            name: "qwen_china_beijing",
            base_url_override: None,
            thinking: false,
        }),
        "qwen_singapore" => Ok(ProbeTarget {
            kind: ProviderKind::Qwen,
            name: "qwen_singapore",
            base_url_override: Some("https://dashscope-intl.aliyuncs.com/compatible-mode/v1"),
            thinking: false,
        }),
        "qwen_us" => Ok(ProbeTarget {
            kind: ProviderKind::Qwen,
            name: "qwen_us_virginia",
            base_url_override: Some("https://dashscope-us.aliyuncs.com/compatible-mode/v1"),
            thinking: false,
        }),
        "silicon_flow" | "siliconflow" => Ok(ProbeTarget {
            kind: ProviderKind::SiliconFlow,
            name: "silicon_flow_china",
            base_url_override: None,
            thinking: false,
        }),
        "silicon_flow_global" => Ok(ProbeTarget {
            kind: ProviderKind::SiliconFlow,
            name: "silicon_flow_global",
            base_url_override: Some("https://api.siliconflow.com/v1"),
            thinking: false,
        }),
        "volcengine_ark" | "volcengine" => Ok(ProbeTarget {
            kind: ProviderKind::VolcengineArk,
            name: "volcengine_ark",
            base_url_override: None,
            thinking: false,
        }),
        _ => Err("unsupported provider probe target"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        allowlisted_provider_error_code, normalize_stdin_secret, parse_target, ProviderKind,
    };

    #[test]
    fn normalizes_powershell_bom_and_line_ending_without_changing_the_key() {
        assert_eq!(
            normalize_stdin_secret("\u{feff}sk-test-1234\r\n".to_owned()).unwrap(),
            "sk-test-1234"
        );
    }

    #[test]
    fn rejects_blank_non_ascii_and_whitespace_bearing_input() {
        for input in ["\r\n", "密钥", "sk-test 1234"] {
            assert!(normalize_stdin_secret(input.to_owned()).is_err());
        }
    }

    #[test]
    fn exposes_only_an_explicitly_allowlisted_machine_error_code() {
        assert_eq!(
            allowlisted_provider_error_code("AccessDenied.Unpurchased: upstream detail"),
            Some("AccessDenied.Unpurchased")
        );
        assert_eq!(
            allowlisted_provider_error_code("InvalidParameter: upstream detail"),
            None
        );
        assert_eq!(
            allowlisted_provider_error_code("free form upstream detail"),
            None
        );
    }

    #[test]
    fn maps_every_supported_probe_target_to_the_expected_provider_and_region() {
        let cases = [
            (
                "deep_seek",
                "deep_seek",
                ProviderKind::DeepSeek,
                None,
                false,
            ),
            ("deepseek", "deep_seek", ProviderKind::DeepSeek, None, false),
            (
                "deepseek_thinking",
                "deep_seek_thinking",
                ProviderKind::DeepSeek,
                None,
                true,
            ),
            (
                "qwen",
                "qwen_china_beijing",
                ProviderKind::Qwen,
                None,
                false,
            ),
            (
                "qwen_singapore",
                "qwen_singapore",
                ProviderKind::Qwen,
                Some("https://dashscope-intl.aliyuncs.com/compatible-mode/v1"),
                false,
            ),
            (
                "qwen_us",
                "qwen_us_virginia",
                ProviderKind::Qwen,
                Some("https://dashscope-us.aliyuncs.com/compatible-mode/v1"),
                false,
            ),
            (
                "silicon_flow",
                "silicon_flow_china",
                ProviderKind::SiliconFlow,
                None,
                false,
            ),
            (
                "siliconflow",
                "silicon_flow_china",
                ProviderKind::SiliconFlow,
                None,
                false,
            ),
            (
                "silicon_flow_global",
                "silicon_flow_global",
                ProviderKind::SiliconFlow,
                Some("https://api.siliconflow.com/v1"),
                false,
            ),
            (
                "volcengine_ark",
                "volcengine_ark",
                ProviderKind::VolcengineArk,
                None,
                false,
            ),
            (
                "volcengine",
                "volcengine_ark",
                ProviderKind::VolcengineArk,
                None,
                false,
            ),
        ];

        for (argument, expected_name, expected_kind, expected_base_url, expected_thinking) in cases
        {
            let target = parse_target(argument).unwrap();
            assert_eq!(target.name, expected_name);
            assert_eq!(target.kind, expected_kind);
            assert_eq!(target.base_url_override, expected_base_url);
            assert_eq!(target.thinking, expected_thinking);
        }
        assert!(parse_target("unsupported").is_err());
    }
}
