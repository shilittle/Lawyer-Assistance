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
