use crate::{
    redaction::truncate_for_log,
    types::{ChatUsage, ProviderError, ProviderErrorKind},
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Delta {
        content: String,
        model: Option<String>,
    },
    Usage(ChatUsage),
    Error {
        error_type: String,
        message: String,
    },
    Done,
}

#[derive(Debug, Default)]
pub struct StreamParser {
    buffer: Vec<u8>,
}

impl StreamParser {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<Result<StreamEvent, ProviderError>> {
        if chunk.is_empty() {
            return Vec::new();
        }

        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();

        while let Some(index) = find_event_separator(&self.buffer) {
            let event_bytes: Vec<u8> = self.buffer.drain(..index).collect();
            let separator_len = separator_len(&self.buffer);
            self.buffer.drain(..separator_len);

            if event_bytes.iter().all(u8::is_ascii_whitespace) || is_comment_only(&event_bytes) {
                continue;
            }

            events.push(parse_event_bytes(&event_bytes));
        }

        events
    }
}

fn is_comment_only(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).ok().is_some_and(|text| {
        text.lines().all(|line| {
            let line = line.trim();
            line.is_empty() || line.starts_with(':')
        })
    })
}

fn find_event_separator(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .or_else(|| buffer.windows(4).position(|window| window == b"\r\n\r\n"))
}

fn separator_len(buffer: &[u8]) -> usize {
    if buffer.starts_with(b"\r\n\r\n") {
        4
    } else {
        2
    }
}

fn parse_event_bytes(bytes: &[u8]) -> Result<StreamEvent, ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("stream chunk was not valid UTF-8: {error}"),
        )
    })?;

    let mut event_name = None;
    let mut data_lines = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');

        if let Some(value) = line.strip_prefix("event:") {
            event_name = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start().to_owned());
        }
    }

    let data = data_lines.join("\n");

    if data.trim() == "[DONE]" {
        return Ok(StreamEvent::Done);
    }

    if event_name.as_deref() == Some("error") {
        return parse_error_event(&data);
    }

    parse_data_event(&data)
}

fn parse_data_event(data: &str) -> Result<StreamEvent, ProviderError> {
    if data.trim().is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "stream event did not include data",
        ));
    }

    let value: Value = serde_json::from_str(data).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("stream event data was not valid JSON: {error}"),
        )
    })?;

    if let Some(error) = value.get("error") {
        return parse_error_value(error);
    }

    if let Some(usage) = value.get("usage").filter(|usage| usage.is_object()) {
        return Ok(StreamEvent::Usage(ChatUsage {
            prompt_tokens: usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            completion_tokens: usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            total_tokens: usage
                .get("total_tokens")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
        }));
    }

    let content = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("delta"))
        .and_then(|delta| delta.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);

    Ok(StreamEvent::Delta { content, model })
}

fn parse_error_event(data: &str) -> Result<StreamEvent, ProviderError> {
    if data.trim().is_empty() {
        return Ok(StreamEvent::Error {
            error_type: "provider_error".to_owned(),
            message: "provider stream returned an error event".to_owned(),
        });
    }

    let value: Value = serde_json::from_str(data).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("stream error event was not valid JSON: {error}"),
        )
    })?;

    parse_error_value(value.get("error").unwrap_or(&value))
}

fn parse_error_value(value: &Value) -> Result<StreamEvent, ProviderError> {
    let error_type = value
        .get("type")
        .and_then(Value::as_str)
        .or_else(|| value.get("code").and_then(Value::as_str))
        .unwrap_or("provider_error")
        .to_owned();
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("provider stream returned an error")
        .to_owned();

    Ok(StreamEvent::Error {
        error_type,
        message: truncate_for_log(&message, 240),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normal_delta_chunk() {
        let mut parser = StreamParser::new();
        let events = parser.push(br#"data: {"choices":[{"delta":{"content":"hello"}}]}"#);
        assert!(events.is_empty(), "event is incomplete without separator");

        let events = parser.push(b"\n\n");
        assert_eq!(
            events,
            vec![Ok(StreamEvent::Delta {
                content: "hello".to_owned(),
                model: None,
            })]
        );
    }

    #[test]
    fn empty_chunk_returns_no_events() {
        let mut parser = StreamParser::new();

        assert!(parser.push(b"").is_empty());
    }

    #[test]
    fn parses_done_event() {
        let mut parser = StreamParser::new();

        assert_eq!(
            parser.push(b"data: [DONE]\n\n"),
            vec![Ok(StreamEvent::Done)]
        );
    }

    #[test]
    fn parses_error_event() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            br#"event: error
data: {"error":{"type":"rate_limit","message":"too many requests"}}

"#,
        );

        assert_eq!(
            events,
            vec![Ok(StreamEvent::Error {
                error_type: "rate_limit".to_owned(),
                message: "too many requests".to_owned()
            })]
        );
    }

    #[test]
    fn supports_utf8_half_package() {
        let mut parser = StreamParser::new();

        assert!(parser
            .push("data: {\"choices\":[{\"delta\":{\"content\":\"你".as_bytes())
            .is_empty());
        let events = parser.push("好\"}}]}\n\n".as_bytes());

        assert_eq!(
            events,
            vec![Ok(StreamEvent::Delta {
                content: "你好".to_owned(),
                model: None,
            })]
        );
    }

    #[test]
    fn ignores_sse_keepalive_comments() {
        let mut parser = StreamParser::new();

        assert!(parser.push(b": keep-alive\n\n").is_empty());
    }

    #[test]
    fn captures_model_from_content_delta() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            br#"data: {"model":"qwen-plus","choices":[{"delta":{"content":"pong"}}]}

"#,
        );

        assert_eq!(
            events,
            vec![Ok(StreamEvent::Delta {
                content: "pong".to_owned(),
                model: Some("qwen-plus".to_owned()),
            })]
        );
    }

    #[test]
    fn usage_null_does_not_hide_content_delta() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            br#"data: {"model":"qwen-plus","choices":[{"delta":{"content":"pong"}}],"usage":null}

"#,
        );

        assert_eq!(
            events,
            vec![Ok(StreamEvent::Delta {
                content: "pong".to_owned(),
                model: Some("qwen-plus".to_owned()),
            })]
        );
    }

    #[test]
    fn reports_non_utf8_event() {
        let mut parser = StreamParser::new();
        let events = parser.push(&[b'd', b'a', b't', b'a', b':', b' ', 0xff, b'\n', b'\n']);

        assert_eq!(events.len(), 1);
        let error = events[0]
            .as_ref()
            .expect_err("invalid UTF-8 returns an error");
        assert_eq!(error.kind, ProviderErrorKind::Parse);
    }

    #[test]
    fn reports_non_json_event_data() {
        let mut parser = StreamParser::new();
        let events = parser.push(b"data: not-json\n\n");

        assert_eq!(events.len(), 1);
        let error = events[0]
            .as_ref()
            .expect_err("invalid JSON returns an error");
        assert_eq!(error.kind, ProviderErrorKind::Parse);
    }
}
