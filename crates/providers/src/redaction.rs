const REDACTION: &str = "<redacted>";

pub fn redact_sensitive(input: &str) -> String {
    let mut output = Vec::new();

    for line in input.lines() {
        let lower = line.to_ascii_lowercase();

        if lower.contains("authorization:")
            || lower.contains("api-key")
            || lower.contains("api_key")
            || lower.contains("apikey")
            || lower.contains("x-api-key")
        {
            output.push(redact_key_value_line(line));
        } else {
            output.push(redact_bearer_tokens(line));
        }
    }

    output.join("\n")
}

fn redact_key_value_line(line: &str) -> String {
    if let Some((name, _)) = line.split_once(':') {
        format!("{name}: {REDACTION}")
    } else if let Some((name, _)) = line.split_once('=') {
        format!("{name}={REDACTION}")
    } else {
        REDACTION.to_owned()
    }
}

fn redact_bearer_tokens(line: &str) -> String {
    let mut redacted = String::with_capacity(line.len());
    let mut remaining = line;

    while let Some(index) = remaining.to_ascii_lowercase().find("bearer ") {
        let (prefix, suffix) = remaining.split_at(index);
        redacted.push_str(prefix);
        redacted.push_str("Bearer ");

        let token_start = "Bearer ".len();
        let token_and_tail = &suffix[token_start..];
        let token_len = token_and_tail
            .find(char::is_whitespace)
            .unwrap_or(token_and_tail.len());
        redacted.push_str(REDACTION);
        remaining = &token_and_tail[token_len..];
    }

    redacted.push_str(remaining);
    redacted
}

pub fn truncate_for_log(input: &str, limit: usize) -> String {
    let sanitized = redact_sensitive(input);

    if sanitized.chars().count() <= limit {
        sanitized
    } else {
        let prefix: String = sanitized.chars().take(limit).collect();
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_authorization_api_key_and_bearer_tokens() {
        let raw = "Authorization: Bearer lawyer-secret-1234\nx-api-key: plain-secret\nmessage Bearer inline-secret";
        let redacted = redact_sensitive(raw);

        assert!(!redacted.contains("lawyer-secret-1234"));
        assert!(!redacted.contains("plain-secret"));
        assert!(!redacted.contains("inline-secret"));
        assert!(redacted.contains("Authorization: <redacted>"));
    }
}
