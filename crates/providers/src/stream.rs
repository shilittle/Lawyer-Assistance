use crate::{
    redaction::truncate_for_log,
    types::{ChatUsage, ProviderError, ProviderErrorKind},
};
use serde_json::Value;

const MAX_PENDING_SSE_EVENT_BYTES: usize = 1024 * 1024;

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

        while let Some((index, separator_len)) = find_event_separator(&self.buffer) {
            let event_bytes: Vec<u8> = self.buffer.drain(..index).collect();
            self.buffer.drain(..separator_len);

            if event_bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            append_parsed_event(&mut events, &event_bytes);
        }

        if self.buffer.len() > MAX_PENDING_SSE_EVENT_BYTES {
            self.buffer.clear();
            events.push(Err(ProviderError::new(
                ProviderErrorKind::ResponseTooLarge,
                "provider SSE event exceeded the 1 MiB pending-event limit",
            )));
        }

        events
    }
    /// Flushes the final SSE event at EOF. A provider is allowed to close the
    /// stream without an extra blank line, but an incomplete UTF-8 or JSON
    /// payload is still reported as a parse error.
    pub fn finish(&mut self) -> Vec<Result<StreamEvent, ProviderError>> {
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            self.buffer.clear();
            return Vec::new();
        }

        let event_bytes = std::mem::take(&mut self.buffer);
        let mut events = Vec::new();
        append_parsed_event(&mut events, &event_bytes);
        events
    }
}

fn append_parsed_event(events: &mut Vec<Result<StreamEvent, ProviderError>>, event_bytes: &[u8]) {
    match parse_event_bytes(event_bytes) {
        Ok(parsed_events) => events.extend(parsed_events.into_iter().map(Ok)),
        Err(error) => events.push(Err(error)),
    }
}

/// Finds the first SSE blank line and returns its byte position and length.
/// SSE permits CRLF, LF, or CR line endings, including mixed line endings.
fn find_event_separator(buffer: &[u8]) -> Option<(usize, usize)> {
    let mut index = 0;

    while index < buffer.len() {
        let Some(first_len) = line_ending_len(buffer, index) else {
            index += 1;
            continue;
        };
        let second_index = index + first_len;
        if let Some(second_len) = line_ending_len(buffer, second_index) {
            return Some((index, first_len + second_len));
        }
        index = second_index;
    }

    None
}

fn line_ending_len(buffer: &[u8], index: usize) -> Option<usize> {
    match buffer.get(index) {
        Some(b'\n') => Some(1),
        Some(b'\r') if buffer.get(index + 1) == Some(&b'\n') => Some(2),
        Some(b'\r') => Some(1),
        _ => None,
    }
}

fn parse_event_bytes(bytes: &[u8]) -> Result<Vec<StreamEvent>, ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("stream chunk was not valid UTF-8: {error}"),
        )
    })?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let mut event_name = None;
    let mut data_lines = Vec::new();

    for line in text.split(['\r', '\n']) {
        if let Some(value) = line.strip_prefix("event:") {
            event_name = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.strip_prefix(' ').unwrap_or(value).to_owned());
        } else if line == "data" {
            data_lines.push(String::new());
        }
    }

    // Per the SSE dispatch algorithm, comment/heartbeat events and events
    // without a data field are ignored rather than treated as malformed JSON.
    if data_lines.is_empty() {
        return Ok(Vec::new());
    }

    let data = data_lines.join("\n");

    if data.trim() == "[DONE]" {
        return Ok(vec![StreamEvent::Done]);
    }

    if event_name.as_deref() == Some("error") {
        return parse_error_event(&data).map(|event| vec![event]);
    }

    if data.is_empty() {
        return Ok(Vec::new());
    }

    parse_data_events(&data)
}

fn parse_data_events(data: &str) -> Result<Vec<StreamEvent>, ProviderError> {
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
        return parse_error_value(error).map(|event| vec![event]);
    }

    let usage = value
        .get("usage")
        .filter(|usage| usage.is_object())
        .map(|usage| ChatUsage {
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
        });

    let delta = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("delta"));
    let content = delta
        .and_then(|delta| delta.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let mut events = Vec::with_capacity(2);
    if delta.is_some() || model.is_some() {
        events.push(StreamEvent::Delta { content, model });
    }
    if let Some(usage) = usage {
        events.push(StreamEvent::Usage(usage));
    }

    // Keep the historical parser contract for syntactically valid data that
    // contains neither a delta nor usage; consumers can ignore the empty delta.
    if events.is_empty() {
        events.push(StreamEvent::Delta {
            content: String::new(),
            model: None,
        });
    }

    Ok(events)
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
    fn finish_dispatches_final_event_without_empty_line() {
        let mut parser = StreamParser::new();
        assert!(parser
            .push(
                br#"data: {"model":"deepseek-v4-flash","choices":[{"delta":{"content":"pong"}}]}"#
            )
            .is_empty());

        assert_eq!(
            parser.finish(),
            vec![Ok(StreamEvent::Delta {
                content: "pong".to_owned(),
                model: Some("deepseek-v4-flash".to_owned()),
            })]
        );
        assert!(parser.finish().is_empty(), "finish is idempotent after EOF");
    }

    #[test]
    fn finish_ignores_trailing_keepalive_comment() {
        let mut parser = StreamParser::new();
        assert!(parser.push(b": keep-alive").is_empty());

        assert!(parser.finish().is_empty());
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

    #[test]
    fn flushes_final_event_without_separator() {
        let mut parser = StreamParser::new();
        assert!(parser
            .push(br#"data: {"choices":[{"delta":{"content":"tail"}}]}"#)
            .is_empty());

        assert_eq!(
            parser.finish(),
            vec![Ok(StreamEvent::Delta {
                content: "tail".to_owned(),
                model: None,
            })]
        );
    }

    #[test]
    fn parses_the_earliest_separator_when_line_endings_are_mixed() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\r\n\r\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"second\"}}]}\n\n"
            )
            .as_bytes(),
        );

        assert_eq!(
            events,
            vec![
                Ok(StreamEvent::Delta {
                    content: "first".to_owned(),
                    model: None,
                }),
                Ok(StreamEvent::Delta {
                    content: "second".to_owned(),
                    model: None,
                }),
            ]
        );
    }

    #[test]
    fn accepts_cr_only_and_mixed_blank_lines() {
        let mut parser = StreamParser::new();
        let events = parser
            .push(b"data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\r\rdata: [DONE]\n\r\n");

        assert_eq!(
            events,
            vec![
                Ok(StreamEvent::Delta {
                    content: "one".to_owned(),
                    model: None,
                }),
                Ok(StreamEvent::Done),
            ]
        );
    }

    #[test]
    fn joins_multi_line_data_with_cr_only_line_endings() {
        let mut parser = StreamParser::new();
        let events =
            parser.push(b"data: {\"choices\":[{\"delta\":\rdata: {\"content\":\"joined\"}}]}\r\r");

        assert_eq!(
            events,
            vec![Ok(StreamEvent::Delta {
                content: "joined".to_owned(),
                model: None,
            })]
        );
    }

    #[test]
    fn ignores_keepalive_comments_and_empty_data_events() {
        let mut parser = StreamParser::new();

        assert!(parser
            .push(b": keep-alive\nretry: 1000\n\ndata:\n\n")
            .is_empty());
    }

    #[test]
    fn keeps_content_when_usage_is_present_in_the_same_event() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            br#"data: {"model":"qwen-plus","choices":[{"delta":{"content":"pong"}}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}

"#,
        );

        assert_eq!(
            events,
            vec![
                Ok(StreamEvent::Delta {
                    content: "pong".to_owned(),
                    model: Some("qwen-plus".to_owned()),
                }),
                Ok(StreamEvent::Usage(ChatUsage {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(2),
                    total_tokens: Some(3),
                })),
            ]
        );
    }

    #[test]
    fn accepts_a_utf8_bom_on_the_first_event() {
        let mut parser = StreamParser::new();

        assert_eq!(
            parser.push(
                "\u{feff}data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n".as_bytes(),
            ),
            vec![Ok(StreamEvent::Delta {
                content: "ok".to_owned(),
                model: None,
            })]
        );
    }

    #[test]
    fn rejects_an_unbounded_pending_sse_event_with_a_typed_error() {
        let mut parser = StreamParser::new();
        let oversized = vec![b'x'; MAX_PENDING_SSE_EVENT_BYTES + 1];
        let events = parser.push(&oversized);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .as_ref()
                .expect_err("oversized pending event is rejected")
                .kind,
            ProviderErrorKind::ResponseTooLarge
        );
        assert!(parser.finish().is_empty(), "oversized buffer is released");
    }

    #[test]
    fn finish_reports_incomplete_utf8_half_package() {
        let mut parser = StreamParser::new();
        parser.push(&[b'd', b'a', b't', b'a', b':', b' ', 0xe4, 0xbd]);

        let events = parser.finish();
        let error = events[0]
            .as_ref()
            .expect_err("incomplete UTF-8 is rejected at EOF");
        assert_eq!(error.kind, ProviderErrorKind::Parse);
    }
}
