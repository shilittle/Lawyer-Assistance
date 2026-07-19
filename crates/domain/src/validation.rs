use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputValidationError {
    message: String,
}

impl InputValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for InputValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for InputValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextMode {
    SingleLine,
    MultiLine,
}

pub fn required_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    mode: TextMode,
) -> Result<(), InputValidationError> {
    validate_text(field, value, max_bytes, mode)?;
    if value.trim().is_empty() {
        return Err(InputValidationError::new(format!(
            "{field} must not be blank"
        )));
    }
    Ok(())
}

pub fn optional_text(
    field: &str,
    value: Option<&str>,
    max_bytes: usize,
    mode: TextMode,
) -> Result<(), InputValidationError> {
    if let Some(value) = value {
        required_text(field, value, max_bytes, mode)?;
    }
    Ok(())
}

pub fn bounded_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    mode: TextMode,
) -> Result<(), InputValidationError> {
    validate_text(field, value, max_bytes, mode)
}

/// Rejects machine-only or engineering text before it can enter a
/// lawyer-facing business field. Identifiers used for provenance and
/// persistence must travel in their dedicated typed fields instead.
pub fn public_business_text(field: &str, value: &str) -> Result<(), InputValidationError> {
    if business_text_contains_internal_detail(value) {
        return Err(InputValidationError::new(format!(
            "{field} contains content that is not permitted in a business field"
        )));
    }
    Ok(())
}

pub fn business_text_contains_internal_detail(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();

    if matches!(
        serde_json::from_str::<serde_json::Value>(trimmed),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    ) || contains_json_member(trimmed)
        || contains_internal_field_token(&lower)
        || contains_path_or_uri(trimmed, &lower)
        || contains_uuid(trimmed)
        || contains_hash(trimmed)
        || contains_opaque_internal_identifier(&lower)
        || contains_namespaced_identifier(trimmed)
        || [
            "[src:",
            "[cit:",
            "internal field",
            "internal id",
            "raw json",
            "model output",
            "model extraction",
            "system field",
            "内部字段",
            "内部标识",
            "内部编号",
            "内部路径",
            "本地路径",
            "系统字段",
            "工程字段",
            "技术字段",
            "原始json",
            "原始 json",
            "模型输出",
            "模型抽取",
            "模型建议",
            "服务端字段",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }

    false
}

fn contains_json_member(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut escaped = false;
        while index < bytes.len() {
            match (bytes[index], escaped) {
                (_, true) => escaped = false,
                (b'\\', false) => escaped = true,
                (b'"', false) => break,
                _ => {}
            }
            index += 1;
        }
        if index >= bytes.len() {
            return false;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b':') {
            return true;
        }
    }
    false
}

fn contains_internal_field_token(lower: &str) -> bool {
    lower
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "id" | "fileid"
                    | "file_id"
                    | "sourceid"
                    | "source_id"
                    | "sourceref"
                    | "source_ref"
                    | "sourcerefs"
                    | "source_refs"
                    | "proposalhash"
                    | "proposal_hash"
                    | "providerid"
                    | "provider_id"
                    | "providersnapshot"
                    | "provider_snapshot"
                    | "reviewid"
                    | "review_id"
                    | "requestid"
                    | "request_id"
                    | "runid"
                    | "run_id"
                    | "articleid"
                    | "article_id"
                    | "attachmentid"
                    | "attachment_id"
                    | "artifactid"
                    | "artifact_id"
                    | "documentid"
                    | "document_id"
                    | "versionid"
                    | "version_id"
                    | "schema"
                    | "schemaversion"
                    | "schema_version"
                    | "rawoutput"
                    | "raw_output"
                    | "repairoutput"
                    | "repair_output"
                    | "payload"
                    | "metadata"
                    | "endpoint"
                    | "localpath"
                    | "uuid"
                    | "hash"
                    | "sha256"
            )
        })
}

fn contains_path_or_uri(value: &str, lower: &str) -> bool {
    if value.contains('\\')
        || value.contains("](")
        || lower.contains("://")
        || lower.contains("file:/")
        || [
            "/users/",
            "/home/",
            "/tmp/",
            "/var/",
            "/etc/",
            "/workspace/",
            "/mnt/",
            "/programdata/",
        ]
        .iter()
        .any(|prefix| lower.contains(prefix))
    {
        return true;
    }
    value.as_bytes().windows(3).any(|part| {
        part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
    })
}

fn contains_uuid(value: &str) -> bool {
    value.as_bytes().windows(36).any(|candidate| {
        [8, 13, 18, 23]
            .iter()
            .all(|index| candidate[*index] == b'-')
            && candidate
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
    })
}

fn contains_hash(value: &str) -> bool {
    let mut length = 0usize;
    let mut has_digit = false;
    let mut has_hex_letter = false;
    for byte in value.bytes().chain(std::iter::once(b' ')) {
        if byte.is_ascii_hexdigit() {
            length += 1;
            has_digit |= byte.is_ascii_digit();
            has_hex_letter |= matches!(byte.to_ascii_lowercase(), b'a'..=b'f');
        } else {
            if length >= 16 && has_digit && has_hex_letter {
                return true;
            }
            length = 0;
            has_digit = false;
            has_hex_letter = false;
        }
    }
    false
}

fn contains_opaque_internal_identifier(lower: &str) -> bool {
    lower
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
        })
        .filter_map(|token| token.split_once('-'))
        .any(|(prefix, suffix)| {
            matches!(
                prefix,
                "art"
                    | "att"
                    | "attachment"
                    | "artifact"
                    | "case"
                    | "citation"
                    | "conversation"
                    | "doc"
                    | "document"
                    | "evidence"
                    | "fact"
                    | "file"
                    | "issue"
                    | "message"
                    | "msg"
                    | "project"
                    | "proj"
                    | "proposal"
                    | "prop"
                    | "provider"
                    | "record"
                    | "request"
                    | "req"
                    | "review"
                    | "run"
                    | "service"
                    | "source"
                    | "src"
                    | "tool"
                    | "version"
            ) && !suffix.is_empty()
                && suffix.bytes().any(|byte| byte.is_ascii_digit())
        })
}

fn contains_namespaced_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b':' || bytes.get(index + 1) == Some(&b'/') {
            continue;
        }
        let left_start = bytes[..index]
            .iter()
            .rposition(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
            .map_or(0, |position| position + 1);
        let right_end = bytes[index + 1..]
            .iter()
            .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
            .map_or(bytes.len(), |position| index + 1 + position);
        let left = &bytes[left_start..index];
        let right = &bytes[index + 1..right_end];
        if left.len() >= 2
            && left[0].is_ascii_alphabetic()
            && !right.is_empty()
            && right.iter().any(|byte| byte.is_ascii_alphanumeric())
        {
            return true;
        }
    }
    false
}

pub fn identifier(field: &str, value: &str, max_bytes: usize) -> Result<(), InputValidationError> {
    required_text(field, value, max_bytes, TextMode::SingleLine)?;
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(InputValidationError::new(format!(
            "{field} must not contain whitespace"
        )));
    }
    Ok(())
}

pub fn item_count(field: &str, count: usize, max_items: usize) -> Result<(), InputValidationError> {
    if count > max_items {
        return Err(InputValidationError::new(format!(
            "{field} exceeds the {max_items}-item limit"
        )));
    }
    Ok(())
}

pub fn required_string_list(
    field: &str,
    values: &[String],
    max_items: usize,
    max_item_bytes: usize,
) -> Result<(), InputValidationError> {
    item_count(field, values.len(), max_items)?;
    for value in values {
        required_text(field, value, max_item_bytes, TextMode::SingleLine)?;
    }
    Ok(())
}

pub fn identifier_list(
    field: &str,
    values: &[String],
    max_items: usize,
    max_item_bytes: usize,
) -> Result<(), InputValidationError> {
    item_count(field, values.len(), max_items)?;
    for value in values {
        identifier(field, value, max_item_bytes)?;
    }
    Ok(())
}

pub fn optional_positive_u32(
    field: &str,
    value: Option<u32>,
    max: u32,
) -> Result<(), InputValidationError> {
    if value.is_some_and(|value| value == 0 || value > max) {
        return Err(InputValidationError::new(format!(
            "{field} must be between 1 and {max}"
        )));
    }
    Ok(())
}

pub fn optional_finite_f32(
    field: &str,
    value: Option<f32>,
    min: f32,
    max: f32,
) -> Result<(), InputValidationError> {
    if value.is_some_and(|value| !value.is_finite() || value < min || value > max) {
        return Err(InputValidationError::new(format!(
            "{field} must be a finite number between {min} and {max}"
        )));
    }
    Ok(())
}

fn validate_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    mode: TextMode,
) -> Result<(), InputValidationError> {
    if value.len() > max_bytes {
        return Err(InputValidationError::new(format!(
            "{field} exceeds the {max_bytes}-byte limit"
        )));
    }
    let contains_unsupported_control = value.chars().any(|character| match mode {
        TextMode::SingleLine => {
            character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
        }
        TextMode::MultiLine => character.is_control() && !matches!(character, '\n' | '\r' | '\t'),
    });
    if contains_unsupported_control {
        return Err(InputValidationError::new(format!(
            "{field} contains unsupported control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_chinese_and_counts_utf8_bytes_without_ascii_restrictions() {
        required_text("title", "中华人民共和国民法典", 30, TextMode::SingleLine)
            .expect("valid Chinese title is accepted");
        assert!(required_text("title", "中华人民共和国民法典", 29, TextMode::SingleLine).is_err());
    }

    #[test]
    fn rejects_controls_but_allows_normal_multiline_text() {
        bounded_text("summary", "第一行\n第二行\t说明", 128, TextMode::MultiLine)
            .expect("normal multiline text is accepted");
        assert!(bounded_text("summary", "text\0hidden", 128, TextMode::MultiLine).is_err());
        assert!(bounded_text("title", "first\nsecond", 128, TextMode::SingleLine).is_err());
    }

    #[test]
    fn numeric_helpers_reject_zero_overflow_and_non_finite_values() {
        assert!(optional_positive_u32("limit", Some(0), 50).is_err());
        assert!(optional_positive_u32("limit", Some(51), 50).is_err());
        optional_positive_u32("limit", Some(50), 50).expect("upper bound is accepted");

        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 2.1] {
            assert!(optional_finite_f32("temperature", Some(invalid), 0.0, 2.0).is_err());
        }
        optional_finite_f32("temperature", Some(2.0), 0.0, 2.0)
            .expect("finite upper bound is accepted");
    }
}
