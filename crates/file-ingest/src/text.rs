use crate::{ExtractedSegment, Extraction, IngestError, Limits};

pub(super) fn extract(bytes: &[u8], limits: Limits) -> Result<Extraction, IngestError> {
    let decoded = std::str::from_utf8(bytes).map_err(|_| IngestError::InvalidUtf8)?;
    let decoded = decoded.strip_prefix('\u{feff}').unwrap_or(decoded);
    let normalized = normalize_line_endings(decoded, limits.max_text_bytes)?;
    let segments = segment_lines(
        &normalized,
        limits.text_lines_per_segment,
        limits.max_segments,
    )?;

    Ok(Extraction {
        page_count: None,
        text: normalized,
        segments,
    })
}

fn normalize_line_endings(input: &str, max_bytes: usize) -> Result<String, IngestError> {
    let mut normalized = String::with_capacity(input.len().min(max_bytes));
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\0' {
            return Err(IngestError::NulByteNotAllowed);
        }
        let normalized_character = if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            '\n'
        } else {
            character
        };
        let next_size = normalized
            .len()
            .checked_add(normalized_character.len_utf8())
            .ok_or(IngestError::TextLimitExceeded)?;
        if next_size > max_bytes {
            return Err(IngestError::TextLimitExceeded);
        }
        normalized.push(normalized_character);
    }
    Ok(normalized)
}

fn segment_lines(
    text: &str,
    lines_per_segment: usize,
    max_segments: usize,
) -> Result<Vec<ExtractedSegment>, IngestError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if lines_per_segment == 0 {
        return Err(IngestError::SegmentLimitExceeded);
    }

    let mut segments = Vec::new();
    let mut block_start_byte = 0;
    let mut block_start_line = 1usize;
    let mut current_line = 1usize;
    let mut lines_in_block = 0usize;

    for (byte_index, character) in text.char_indices() {
        if character != '\n' {
            continue;
        }
        lines_in_block += 1;
        if lines_in_block == lines_per_segment {
            push_line_segment(
                &mut segments,
                max_segments,
                block_start_line,
                current_line,
                &text[block_start_byte..byte_index + 1],
            )?;
            block_start_byte = byte_index + 1;
            block_start_line = current_line + 1;
            lines_in_block = 0;
        }
        current_line += 1;
    }

    if block_start_byte < text.len() {
        let end_line = if text.ends_with('\n') {
            current_line.saturating_sub(1)
        } else {
            current_line
        };
        push_line_segment(
            &mut segments,
            max_segments,
            block_start_line,
            end_line,
            &text[block_start_byte..],
        )?;
    }
    Ok(segments)
}

fn push_line_segment(
    segments: &mut Vec<ExtractedSegment>,
    max_segments: usize,
    start_line: usize,
    end_line: usize,
    text: &str,
) -> Result<(), IngestError> {
    if segments.len() >= max_segments {
        return Err(IngestError::SegmentLimitExceeded);
    }
    segments.push(ExtractedSegment {
        locator: format!("line:{start_line}-{end_line}"),
        text: text.to_owned(),
    });
    Ok(())
}
