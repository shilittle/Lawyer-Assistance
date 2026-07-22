//! Reconstructed TXT, Markdown, and DOCX exports for approved redacted pages.
//!
//! These formats are generated exclusively from approved page text. They never
//! accept an original document package, metadata, relationships, media, or
//! embedded objects. Every artifact is reopened and compared with a normalized,
//! domain-separated hash before any bytes are returned.

use crate::safe_export::{
    approved_text_sha256, constant_time_eq, hex_digest, scan_forbidden,
    scan_pdf_bytes_for_ascii_canaries, sha256_hex, validate_request, ApprovedTextPage,
    SafePdfExportError, SafePdfExportLimits, SafePdfExportRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt::Write as _, str};

const TXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";
const MARKDOWN_MEDIA_TYPE: &str = "text/markdown; charset=utf-8";
const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const TXT_PAGE_SEPARATOR: char = '\u{000c}';
const MARKDOWN_HEADER: &str = "# 脱敏文书（经人工批准）\n\n";

const CONTENT_TYPES_PATH: &str = "[Content_Types].xml";
const ROOT_RELS_PATH: &str = "_rels/.rels";
const DOCUMENT_PATH: &str = "word/document.xml";
const DOCX_ENTRY_NAMES: [&str; 3] = [CONTENT_TYPES_PATH, ROOT_RELS_PATH, DOCUMENT_PATH];
const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
const ROOT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
const DOCUMENT_PREFIX: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#;
const FIRST_PAGE_PREFIX: &str = r#"<w:p><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/><w:sz w:val="22"/></w:rPr>"#;
const NEXT_PAGE_PREFIX: &str = r#"<w:p><w:pPr><w:pageBreakBefore/><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/><w:sz w:val="22"/></w:rPr>"#;
const PAGE_SUFFIX: &str = "</w:r></w:p>";
const DOCUMENT_SUFFIX: &str = r#"<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>"#;
const TEXT_START: &str = r#"<w:t xml:space="preserve">"#;
const TEXT_END: &str = "</w:t>";
const LINE_BREAK: &str = "<w:br/>";
const TAB: &str = "<w:tab/>";
const ZIP_LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const ZIP_CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_VERSION: u16 = 20;
const ZIP_DOS_DATE_1980_01_01: u16 = 0x0021;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeDerivedFormat {
    Txt,
    Markdown,
    Docx,
}

impl SafeDerivedFormat {
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Txt => TXT_MEDIA_TYPE,
            Self::Markdown => MARKDOWN_MEDIA_TYPE,
            Self::Docx => DOCX_MEDIA_TYPE,
        }
    }

    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Markdown => "md",
            Self::Docx => "docx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafeDerivedExportEvidence {
    pub format: SafeDerivedFormat,
    pub media_type: String,
    pub file_extension: String,
    pub artifact_sha256: String,
    pub approved_text_sha256: String,
    pub normalized_text_sha256: String,
    pub reopened_text_sha256: String,
    pub source_page_count: u32,
    pub package_entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafeDerivedArtifact {
    pub bytes: Vec<u8>,
    pub evidence: SafeDerivedExportEvidence,
}

/// Hash normalized page text after canonical CRLF/CR to LF conversion.
/// Page numbers and UTF-8 byte lengths remain part of the hash domain.
pub fn normalized_approved_text_sha256(
    pages: &[ApprovedTextPage],
) -> Result<String, SafePdfExportError> {
    approved_text_sha256(pages)?;
    hash_normalized_pages(&normalize_pages(pages))
}

pub fn reconstruct_approved_text_txt(
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafeDerivedArtifact, SafePdfExportError> {
    let (_, pages, _) = prepare_request(request, &limits)?;
    let text_bytes = pages
        .iter()
        .try_fold(0usize, |total, page| total.checked_add(page.text.len()))
        .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
    let output_size = text_bytes
        .checked_add(pages.len().saturating_sub(1))
        .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
    ensure_output_size(output_size, limits.max_output_bytes)?;
    let mut output = String::with_capacity(output_size);
    for (index, page) in pages.iter().enumerate() {
        if index > 0 {
            output.push(TXT_PAGE_SEPARATOR);
        }
        output.push_str(&page.text);
    }
    finish_artifact(SafeDerivedFormat::Txt, output.into_bytes(), request, limits)
}

pub fn reconstruct_approved_text_markdown(
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafeDerivedArtifact, SafePdfExportError> {
    let (_, pages, _) = prepare_request(request, &limits)?;
    let bytes = build_markdown(&pages, limits.max_output_bytes)?.into_bytes();
    finish_artifact(SafeDerivedFormat::Markdown, bytes, request, limits)
}

pub fn reconstruct_approved_text_docx(
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafeDerivedArtifact, SafePdfExportError> {
    let (_, pages, _) = prepare_request(request, &limits)?;
    let document_xml = build_document_xml(&pages, limits.max_output_bytes)?;
    let entries = [
        (CONTENT_TYPES_PATH, CONTENT_TYPES_XML.as_bytes()),
        (ROOT_RELS_PATH, ROOT_RELS_XML.as_bytes()),
        (DOCUMENT_PATH, document_xml.as_bytes()),
    ];
    ensure_output_size(stored_zip_size(&entries)?, limits.max_output_bytes)?;
    let bytes = write_stored_zip(&entries)?;
    finish_artifact(SafeDerivedFormat::Docx, bytes, request, limits)
}

pub fn verify_approved_text_derived_bytes(
    format: SafeDerivedFormat,
    bytes: &[u8],
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafeDerivedExportEvidence, SafePdfExportError> {
    let (approval_hash, expected_pages, normalized_hash) = prepare_request(request, &limits)?;
    if bytes.len() > limits.max_output_bytes {
        return Err(SafePdfExportError::LimitExceeded("max_output_bytes"));
    }

    let (reopened_pages, package_entries) = match format {
        SafeDerivedFormat::Txt => (parse_txt(bytes)?, Vec::new()),
        SafeDerivedFormat::Markdown => (parse_markdown(bytes)?, Vec::new()),
        SafeDerivedFormat::Docx => parse_docx(bytes, &limits)?,
    };
    verify_pages(&expected_pages, &reopened_pages)?;
    scan_forbidden(
        reopened_pages.iter().map(|page| page.text.as_str()),
        &request.forbidden_canaries,
    )?;
    scan_pdf_bytes_for_ascii_canaries(bytes, &request.forbidden_canaries)?;
    let reopened_hash = hash_normalized_pages(&reopened_pages)?;
    if !constant_time_eq(normalized_hash.as_bytes(), reopened_hash.as_bytes()) {
        return Err(SafePdfExportError::DerivedTextReopenFailed);
    }
    let source_page_count = u32::try_from(reopened_pages.len())
        .map_err(|_| SafePdfExportError::LimitExceeded("source_page_count"))?;

    Ok(SafeDerivedExportEvidence {
        format,
        media_type: format.media_type().to_owned(),
        file_extension: format.file_extension().to_owned(),
        artifact_sha256: sha256_hex(bytes),
        approved_text_sha256: approval_hash,
        normalized_text_sha256: normalized_hash,
        reopened_text_sha256: reopened_hash,
        source_page_count,
        package_entries,
    })
}

fn finish_artifact(
    format: SafeDerivedFormat,
    bytes: Vec<u8>,
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafeDerivedArtifact, SafePdfExportError> {
    let evidence = verify_approved_text_derived_bytes(format, &bytes, request, limits)?;
    Ok(SafeDerivedArtifact { bytes, evidence })
}

fn prepare_request(
    request: &SafePdfExportRequest,
    limits: &SafePdfExportLimits,
) -> Result<(String, Vec<ApprovedTextPage>, String), SafePdfExportError> {
    validate_request(request, limits)?;
    let approval_hash = approved_text_sha256(&request.pages)?;
    if !constant_time_eq(
        approval_hash.as_bytes(),
        request.approved_text_sha256.as_bytes(),
    ) {
        return Err(SafePdfExportError::ApprovalHashMismatch);
    }
    scan_forbidden(
        request.pages.iter().map(|page| page.text.as_str()),
        &request.forbidden_canaries,
    )?;
    let pages = normalize_pages(&request.pages);
    scan_forbidden(
        pages.iter().map(|page| page.text.as_str()),
        &request.forbidden_canaries,
    )?;
    let normalized_hash = hash_normalized_pages(&pages)?;
    Ok((approval_hash, pages, normalized_hash))
}

fn normalize_pages(pages: &[ApprovedTextPage]) -> Vec<ApprovedTextPage> {
    pages
        .iter()
        .map(|page| ApprovedTextPage {
            page_number: page.page_number,
            text: page.text.replace("\r\n", "\n").replace('\r', "\n"),
        })
        .collect()
}

fn hash_normalized_pages(pages: &[ApprovedTextPage]) -> Result<String, SafePdfExportError> {
    let mut hasher = Sha256::new();
    hasher.update(b"lawyer-assistance-normalized-approved-pages-v1\0");
    for (index, page) in pages.iter().enumerate() {
        let expected = u32::try_from(index + 1)
            .map_err(|_| SafePdfExportError::LimitExceeded("page_number"))?;
        if page.page_number != expected {
            return Err(SafePdfExportError::InvalidPageOrder {
                expected,
                actual: page.page_number,
            });
        }
        hasher.update(page.page_number.to_be_bytes());
        let length = u64::try_from(page.text.len())
            .map_err(|_| SafePdfExportError::LimitExceeded("text"))?;
        hasher.update(length.to_be_bytes());
        hasher.update(page.text.as_bytes());
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn verify_pages(
    expected: &[ApprovedTextPage],
    actual: &[ApprovedTextPage],
) -> Result<(), SafePdfExportError> {
    if expected.len() != actual.len() {
        return Err(SafePdfExportError::DerivedTextReopenFailed);
    }
    for (expected_page, actual_page) in expected.iter().zip(actual) {
        if expected_page.page_number != actual_page.page_number
            || !constant_time_eq(expected_page.text.as_bytes(), actual_page.text.as_bytes())
        {
            return Err(SafePdfExportError::DerivedTextMismatch {
                page_number: expected_page.page_number,
            });
        }
    }
    Ok(())
}

fn parse_txt(bytes: &[u8]) -> Result<Vec<ApprovedTextPage>, SafePdfExportError> {
    let text = str::from_utf8(bytes).map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?;
    text.split(TXT_PAGE_SEPARATOR)
        .enumerate()
        .map(|(index, text)| {
            Ok(ApprovedTextPage {
                page_number: u32::try_from(index + 1)
                    .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?,
                text: text.to_owned(),
            })
        })
        .collect()
}

fn build_markdown(
    pages: &[ApprovedTextPage],
    max_output_bytes: usize,
) -> Result<String, SafePdfExportError> {
    let maximum_run = pages
        .iter()
        .map(|page| longest_backtick_run(&page.text))
        .max()
        .unwrap_or(0);
    let fence_length = maximum_run
        .checked_add(1)
        .ok_or(SafePdfExportError::LimitExceeded("markdown_fence"))?
        .max(3);
    let mut projected_size = MARKDOWN_HEADER.len();
    for (index, page) in pages.iter().enumerate() {
        let heading_length =
            "## 第 ".len() + decimal_length_u32(page.page_number) + " 页\n\n".len();
        let opening_length = fence_length
            .checked_add("text page=".len())
            .and_then(|value| value.checked_add(decimal_length_u32(page.page_number)))
            .and_then(|value| value.checked_add(" bytes=".len()))
            .and_then(|value| value.checked_add(decimal_length_usize(page.text.len())))
            .and_then(|value| value.checked_add(1))
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
        let page_length = heading_length
            .checked_add(opening_length)
            .and_then(|value| value.checked_add(page.text.len()))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(fence_length))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(usize::from(index + 1 != pages.len())))
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
        projected_size = projected_size
            .checked_add(page_length)
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
        ensure_output_size(projected_size, max_output_bytes)?;
    }

    let fence = "`".repeat(fence_length);
    let mut output = String::with_capacity(projected_size);
    output.push_str(MARKDOWN_HEADER);
    for (index, page) in pages.iter().enumerate() {
        writeln!(output, "## 第 {} 页\n", page.page_number)
            .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?;
        writeln!(
            output,
            "{fence}text page={} bytes={}",
            page.page_number,
            page.text.len()
        )
        .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?;
        output.push_str(&page.text);
        output.push('\n');
        writeln!(output, "{fence}").map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?;
        if index + 1 != pages.len() {
            output.push('\n');
        }
    }
    if output.len() != projected_size {
        return Err(SafePdfExportError::DerivedTextReopenFailed);
    }
    Ok(output)
}

fn decimal_length_u32(value: u32) -> usize {
    value.to_string().len()
}

fn decimal_length_usize(value: usize) -> usize {
    value.to_string().len()
}

fn ensure_output_size(actual: usize, maximum: usize) -> Result<(), SafePdfExportError> {
    if actual > maximum {
        Err(SafePdfExportError::LimitExceeded("max_output_bytes"))
    } else {
        Ok(())
    }
}

fn parse_markdown(bytes: &[u8]) -> Result<Vec<ApprovedTextPage>, SafePdfExportError> {
    let mut remaining = str::from_utf8(bytes)
        .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?
        .strip_prefix(MARKDOWN_HEADER)
        .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
    let mut pages = Vec::new();
    while !remaining.is_empty() {
        let page_number = u32::try_from(pages.len() + 1)
            .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?;
        let heading = format!("## 第 {page_number} 页\n\n");
        remaining = remaining
            .strip_prefix(&heading)
            .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        let line_end = remaining
            .find('\n')
            .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        let opening = &remaining[..line_end];
        let fence_length = opening.bytes().take_while(|byte| *byte == b'`').count();
        if fence_length < 3 {
            return Err(SafePdfExportError::DerivedTextReopenFailed);
        }
        let fence = &opening[..fence_length];
        let info_prefix = format!("text page={page_number} bytes=");
        let byte_length = parse_canonical_usize(
            opening[fence_length..]
                .strip_prefix(&info_prefix)
                .ok_or(SafePdfExportError::DerivedTextReopenFailed)?,
        )?;
        remaining = &remaining[line_end + 1..];
        let body_bytes = remaining
            .as_bytes()
            .get(..byte_length)
            .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        let body = str::from_utf8(body_bytes)
            .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)?
            .to_owned();
        if longest_backtick_run(&body) >= fence_length {
            return Err(SafePdfExportError::DerivedTextReopenFailed);
        }
        remaining = remaining
            .get(byte_length..)
            .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        let closing = format!("\n{fence}\n");
        remaining = remaining
            .strip_prefix(&closing)
            .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        pages.push(ApprovedTextPage {
            page_number,
            text: body,
        });
        if !remaining.is_empty() {
            remaining = remaining
                .strip_prefix('\n')
                .ok_or(SafePdfExportError::DerivedTextReopenFailed)?;
        }
    }
    if pages.is_empty() {
        return Err(SafePdfExportError::DerivedTextReopenFailed);
    }
    Ok(pages)
}

fn longest_backtick_run(text: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for byte in text.bytes() {
        if byte == b'`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn parse_canonical_usize(value: &str) -> Result<usize, SafePdfExportError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(SafePdfExportError::DerivedTextReopenFailed);
    }
    value
        .parse()
        .map_err(|_| SafePdfExportError::DerivedTextReopenFailed)
}

fn build_document_xml(
    pages: &[ApprovedTextPage],
    max_output_bytes: usize,
) -> Result<String, SafePdfExportError> {
    let mut projected_size = DOCUMENT_PREFIX
        .len()
        .checked_add(DOCUMENT_SUFFIX.len())
        .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
    for (index, page) in pages.iter().enumerate() {
        let prefix_length = if index == 0 {
            FIRST_PAGE_PREFIX.len()
        } else {
            NEXT_PAGE_PREFIX.len()
        };
        let encoded_text_length = word_text_encoded_len(&page.text, page.page_number)?;
        projected_size = projected_size
            .checked_add(prefix_length)
            .and_then(|value| value.checked_add(encoded_text_length))
            .and_then(|value| value.checked_add(PAGE_SUFFIX.len()))
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
        ensure_output_size(projected_size, max_output_bytes)?;
    }

    let mut xml = String::with_capacity(projected_size);
    xml.push_str(DOCUMENT_PREFIX);
    for (index, page) in pages.iter().enumerate() {
        xml.push_str(if index == 0 {
            FIRST_PAGE_PREFIX
        } else {
            NEXT_PAGE_PREFIX
        });
        append_word_text(&mut xml, &page.text, page.page_number)?;
        xml.push_str(PAGE_SUFFIX);
    }
    xml.push_str(DOCUMENT_SUFFIX);
    if xml.len() != projected_size {
        return Err(SafePdfExportError::DocxBuildFailed);
    }
    Ok(xml)
}

fn word_text_encoded_len(text: &str, page_number: u32) -> Result<usize, SafePdfExportError> {
    let wrapper_length = TEXT_START
        .len()
        .checked_add(TEXT_END.len())
        .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
    let mut total = 0usize;
    let mut segment_length = 0usize;
    let mut wrote_text = false;
    for character in text.chars() {
        if !xml_character_allowed(character) {
            return Err(SafePdfExportError::DisallowedControlCharacter { page_number });
        }
        match character {
            '\n' | '\t' => {
                total = total
                    .checked_add(wrapper_length)
                    .and_then(|value| value.checked_add(segment_length))
                    .and_then(|value| {
                        value.checked_add(if character == '\n' {
                            LINE_BREAK.len()
                        } else {
                            TAB.len()
                        })
                    })
                    .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
                segment_length = 0;
                wrote_text = true;
            }
            _ => {
                segment_length = segment_length
                    .checked_add(escaped_xml_character_len(character))
                    .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
            }
        }
    }
    if segment_length != 0 || !wrote_text {
        total = total
            .checked_add(wrapper_length)
            .and_then(|value| value.checked_add(segment_length))
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
    }
    Ok(total)
}

fn escaped_xml_character_len(character: char) -> usize {
    match character {
        '&' => "&amp;".len(),
        '<' => "&lt;".len(),
        '>' => "&gt;".len(),
        '"' => "&quot;".len(),
        '\'' => "&apos;".len(),
        _ => character.len_utf8(),
    }
}

fn append_word_text(
    xml: &mut String,
    text: &str,
    page_number: u32,
) -> Result<(), SafePdfExportError> {
    let mut segment = String::new();
    let mut wrote_text = false;
    for character in text.chars() {
        if !xml_character_allowed(character) {
            return Err(SafePdfExportError::DisallowedControlCharacter { page_number });
        }
        match character {
            '\n' | '\t' => {
                append_text_element(xml, &segment);
                segment.clear();
                wrote_text = true;
                xml.push_str(if character == '\n' { LINE_BREAK } else { TAB });
            }
            _ => segment.push(character),
        }
    }
    if !segment.is_empty() || !wrote_text {
        append_text_element(xml, &segment);
    }
    Ok(())
}

fn append_text_element(xml: &mut String, text: &str) {
    xml.push_str(TEXT_START);
    for character in text.chars() {
        match character {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '"' => xml.push_str("&quot;"),
            '\'' => xml.push_str("&apos;"),
            _ => xml.push(character),
        }
    }
    xml.push_str(TEXT_END);
}

fn xml_character_allowed(character: char) -> bool {
    matches!(
        u32::from(character),
        0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff
    )
}
fn parse_docx(
    bytes: &[u8],
    limits: &SafePdfExportLimits,
) -> Result<(Vec<ApprovedTextPage>, Vec<String>), SafePdfExportError> {
    let entries = read_stored_zip(bytes, limits.max_output_bytes)?;
    let content_types = find_entry(&entries, CONTENT_TYPES_PATH)?;
    let root_relationships = find_entry(&entries, ROOT_RELS_PATH)?;
    let document_xml = find_entry(&entries, DOCUMENT_PATH)?;
    validate_content_types(content_types)?;
    validate_root_relationships(root_relationships)?;
    let pages = parse_document_xml(document_xml)?;
    Ok((pages, entries.into_iter().map(|entry| entry.name).collect()))
}

fn find_entry<'a>(entries: &'a [ReadZipEntry], name: &str) -> Result<&'a [u8], SafePdfExportError> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.data.as_slice())
        .ok_or(SafePdfExportError::UnsafeDocxPackage)
}

fn validate_content_types(bytes: &[u8]) -> Result<(), SafePdfExportError> {
    if constant_time_eq(bytes, CONTENT_TYPES_XML.as_bytes()) {
        Ok(())
    } else {
        Err(SafePdfExportError::UnsafeDocxContentType)
    }
}

fn validate_root_relationships(bytes: &[u8]) -> Result<(), SafePdfExportError> {
    if constant_time_eq(bytes, ROOT_RELS_XML.as_bytes()) {
        Ok(())
    } else {
        Err(SafePdfExportError::UnsafeDocxRelationship)
    }
}

fn parse_document_xml(bytes: &[u8]) -> Result<Vec<ApprovedTextPage>, SafePdfExportError> {
    let xml = str::from_utf8(bytes).map_err(|_| SafePdfExportError::UnsafeDocxBody)?;
    let mut body = xml
        .strip_prefix(DOCUMENT_PREFIX)
        .and_then(|value| value.strip_suffix(DOCUMENT_SUFFIX))
        .ok_or(SafePdfExportError::UnsafeDocxBody)?;
    let mut pages = Vec::new();
    while !body.is_empty() {
        let prefix = if pages.is_empty() {
            FIRST_PAGE_PREFIX
        } else {
            NEXT_PAGE_PREFIX
        };
        body = body
            .strip_prefix(prefix)
            .ok_or(SafePdfExportError::UnsafeDocxBody)?;
        let end = body
            .find(PAGE_SUFFIX)
            .ok_or(SafePdfExportError::UnsafeDocxBody)?;
        let page_text = decode_word_text(&body[..end])?;
        let page_number =
            u32::try_from(pages.len() + 1).map_err(|_| SafePdfExportError::UnsafeDocxBody)?;
        pages.push(ApprovedTextPage {
            page_number,
            text: page_text,
        });
        body = &body[end + PAGE_SUFFIX.len()..];
    }
    if pages.is_empty() {
        return Err(SafePdfExportError::UnsafeDocxBody);
    }
    Ok(pages)
}

fn decode_word_text(mut payload: &str) -> Result<String, SafePdfExportError> {
    let mut output = String::new();
    let mut saw_text = false;
    while !payload.is_empty() {
        if let Some(rest) = payload.strip_prefix(TEXT_START) {
            let end = rest
                .find(TEXT_END)
                .ok_or(SafePdfExportError::UnsafeDocxBody)?;
            output.push_str(&decode_xml_text(&rest[..end])?);
            payload = &rest[end + TEXT_END.len()..];
            saw_text = true;
        } else if let Some(rest) = payload.strip_prefix(LINE_BREAK) {
            output.push('\n');
            payload = rest;
        } else if let Some(rest) = payload.strip_prefix(TAB) {
            output.push('\t');
            payload = rest;
        } else {
            return Err(SafePdfExportError::UnsafeDocxBody);
        }
    }
    if !saw_text {
        return Err(SafePdfExportError::UnsafeDocxBody);
    }
    Ok(output)
}

fn decode_xml_text(text: &str) -> Result<String, SafePdfExportError> {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '&' => {
                let mut entity = String::new();
                loop {
                    let next = characters
                        .next()
                        .ok_or(SafePdfExportError::UnsafeDocxBody)?;
                    if next == ';' {
                        break;
                    }
                    if entity.len() >= 5 || !next.is_ascii_alphabetic() {
                        return Err(SafePdfExportError::UnsafeDocxBody);
                    }
                    entity.push(next);
                }
                output.push(match entity.as_str() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => return Err(SafePdfExportError::UnsafeDocxBody),
                });
            }
            '<' | '>' | '"' | '\'' => return Err(SafePdfExportError::UnsafeDocxBody),
            _ if !xml_character_allowed(character) => {
                return Err(SafePdfExportError::UnsafeDocxBody);
            }
            _ => output.push(character),
        }
    }
    Ok(output)
}

#[derive(Debug)]
struct BuiltZipEntry {
    name: String,
    crc32: u32,
    size: u32,
    local_offset: u32,
}

#[derive(Debug)]
struct ReadZipEntry {
    name: String,
    data: Vec<u8>,
}

fn stored_zip_size(entries: &[(&str, &[u8])]) -> Result<usize, SafePdfExportError> {
    let mut total = 22usize;
    for (name, data) in entries {
        total = total
            .checked_add(30)
            .and_then(|value| value.checked_add(name.len()))
            .and_then(|value| value.checked_add(data.len()))
            .and_then(|value| value.checked_add(46))
            .and_then(|value| value.checked_add(name.len()))
            .ok_or(SafePdfExportError::DocxBuildFailed)?;
    }
    Ok(total)
}

fn write_stored_zip(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, SafePdfExportError> {
    let expected_size = stored_zip_size(entries)?;
    let mut output = Vec::with_capacity(expected_size);
    let mut built = Vec::with_capacity(entries.len());
    for (name, data) in entries {
        if !name.is_ascii() {
            return Err(SafePdfExportError::DocxBuildFailed);
        }
        let name_length =
            u16::try_from(name.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
        let size = u32::try_from(data.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
        let local_offset =
            u32::try_from(output.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
        let crc32 = crc32(data);
        push_u32(&mut output, ZIP_LOCAL_SIGNATURE);
        push_u16(&mut output, ZIP_VERSION);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, ZIP_DOS_DATE_1980_01_01);
        push_u32(&mut output, crc32);
        push_u32(&mut output, size);
        push_u32(&mut output, size);
        push_u16(&mut output, name_length);
        push_u16(&mut output, 0);
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(data);
        built.push(BuiltZipEntry {
            name: (*name).to_owned(),
            crc32,
            size,
            local_offset,
        });
    }

    let central_offset =
        u32::try_from(output.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
    for entry in &built {
        let name_length =
            u16::try_from(entry.name.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
        push_u32(&mut output, ZIP_CENTRAL_SIGNATURE);
        push_u16(&mut output, ZIP_VERSION);
        push_u16(&mut output, ZIP_VERSION);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, ZIP_DOS_DATE_1980_01_01);
        push_u32(&mut output, entry.crc32);
        push_u32(&mut output, entry.size);
        push_u32(&mut output, entry.size);
        push_u16(&mut output, name_length);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, 0);
        push_u32(&mut output, entry.local_offset);
        output.extend_from_slice(entry.name.as_bytes());
    }
    let central_end =
        u32::try_from(output.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
    let central_size = central_end
        .checked_sub(central_offset)
        .ok_or(SafePdfExportError::DocxBuildFailed)?;
    let entry_count =
        u16::try_from(built.len()).map_err(|_| SafePdfExportError::DocxBuildFailed)?;
    push_u32(&mut output, ZIP_EOCD_SIGNATURE);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entry_count);
    push_u16(&mut output, entry_count);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    if output.len() != expected_size {
        return Err(SafePdfExportError::DocxBuildFailed);
    }
    Ok(output)
}

fn read_stored_zip(
    bytes: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<ReadZipEntry>, SafePdfExportError> {
    const EOCD_SIZE: usize = 22;
    const CENTRAL_SIZE: usize = 46;
    const LOCAL_SIZE: usize = 30;
    if bytes.len() > max_output_bytes {
        return Err(SafePdfExportError::LimitExceeded("max_output_bytes"));
    }
    let eocd_offset = bytes
        .len()
        .checked_sub(EOCD_SIZE)
        .ok_or(SafePdfExportError::DocxReopenFailed)?;
    if read_u32(bytes, eocd_offset) != Some(ZIP_EOCD_SIGNATURE)
        || read_u16(bytes, eocd_offset + 4) != Some(0)
        || read_u16(bytes, eocd_offset + 6) != Some(0)
        || read_u16(bytes, eocd_offset + 20) != Some(0)
    {
        return Err(SafePdfExportError::DocxReopenFailed);
    }
    let entries_on_disk =
        read_u16(bytes, eocd_offset + 8).ok_or(SafePdfExportError::DocxReopenFailed)?;
    let entry_count =
        read_u16(bytes, eocd_offset + 10).ok_or(SafePdfExportError::DocxReopenFailed)?;
    if entries_on_disk != entry_count || usize::from(entry_count) != DOCX_ENTRY_NAMES.len() {
        return Err(SafePdfExportError::UnsafeDocxPackage);
    }
    let central_size = usize::try_from(
        read_u32(bytes, eocd_offset + 12).ok_or(SafePdfExportError::DocxReopenFailed)?,
    )
    .map_err(|_| SafePdfExportError::DocxReopenFailed)?;
    let central_offset = usize::try_from(
        read_u32(bytes, eocd_offset + 16).ok_or(SafePdfExportError::DocxReopenFailed)?,
    )
    .map_err(|_| SafePdfExportError::DocxReopenFailed)?;
    if central_offset.checked_add(central_size) != Some(eocd_offset) {
        return Err(SafePdfExportError::DocxReopenFailed);
    }

    let mut central_position = central_offset;
    let mut expected_local_offset = 0usize;
    let mut total_size = 0usize;
    let mut names = BTreeSet::new();
    let mut result = Vec::with_capacity(DOCX_ENTRY_NAMES.len());
    for expected_name in DOCX_ENTRY_NAMES {
        let fixed_end = central_position
            .checked_add(CENTRAL_SIZE)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        if fixed_end > eocd_offset
            || read_u32(bytes, central_position) != Some(ZIP_CENTRAL_SIGNATURE)
            || read_u16(bytes, central_position + 4) != Some(ZIP_VERSION)
            || read_u16(bytes, central_position + 6) != Some(ZIP_VERSION)
            || read_u16(bytes, central_position + 8) != Some(0)
            || read_u16(bytes, central_position + 10) != Some(0)
            || read_u16(bytes, central_position + 12) != Some(0)
            || read_u16(bytes, central_position + 14) != Some(ZIP_DOS_DATE_1980_01_01)
            || read_u16(bytes, central_position + 30) != Some(0)
            || read_u16(bytes, central_position + 32) != Some(0)
            || read_u16(bytes, central_position + 34) != Some(0)
            || read_u16(bytes, central_position + 36) != Some(0)
            || read_u32(bytes, central_position + 38) != Some(0)
        {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let crc =
            read_u32(bytes, central_position + 16).ok_or(SafePdfExportError::DocxReopenFailed)?;
        let compressed_size =
            read_u32(bytes, central_position + 20).ok_or(SafePdfExportError::DocxReopenFailed)?;
        let uncompressed_size =
            read_u32(bytes, central_position + 24).ok_or(SafePdfExportError::DocxReopenFailed)?;
        if compressed_size != uncompressed_size {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let name_length = usize::from(
            read_u16(bytes, central_position + 28).ok_or(SafePdfExportError::DocxReopenFailed)?,
        );
        let name_end = fixed_end
            .checked_add(name_length)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        let name_bytes = bytes
            .get(fixed_end..name_end)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        let name = str::from_utf8(name_bytes).map_err(|_| SafePdfExportError::UnsafeDocxPackage)?;
        validate_zip_name(name)?;
        if name != expected_name || !names.insert(name.to_ascii_lowercase()) {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let local_offset = usize::try_from(
            read_u32(bytes, central_position + 42).ok_or(SafePdfExportError::DocxReopenFailed)?,
        )
        .map_err(|_| SafePdfExportError::DocxReopenFailed)?;
        if local_offset != expected_local_offset {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let local_fixed_end = local_offset
            .checked_add(LOCAL_SIZE)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        if local_fixed_end > central_offset
            || read_u32(bytes, local_offset) != Some(ZIP_LOCAL_SIGNATURE)
            || read_u16(bytes, local_offset + 4) != Some(ZIP_VERSION)
            || read_u16(bytes, local_offset + 6) != Some(0)
            || read_u16(bytes, local_offset + 8) != Some(0)
            || read_u16(bytes, local_offset + 10) != Some(0)
            || read_u16(bytes, local_offset + 12) != Some(ZIP_DOS_DATE_1980_01_01)
            || read_u32(bytes, local_offset + 14) != Some(crc)
            || read_u32(bytes, local_offset + 18) != Some(compressed_size)
            || read_u32(bytes, local_offset + 22) != Some(uncompressed_size)
            || read_u16(bytes, local_offset + 26) != u16::try_from(name_length).ok()
            || read_u16(bytes, local_offset + 28) != Some(0)
        {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let local_name_end = local_fixed_end
            .checked_add(name_length)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        if bytes.get(local_fixed_end..local_name_end) != Some(name_bytes) {
            return Err(SafePdfExportError::UnsafeDocxPackage);
        }
        let data_size =
            usize::try_from(uncompressed_size).map_err(|_| SafePdfExportError::DocxReopenFailed)?;
        let data_end = local_name_end
            .checked_add(data_size)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        let data = bytes
            .get(local_name_end..data_end)
            .ok_or(SafePdfExportError::DocxReopenFailed)?;
        if data_end > central_offset || crc32(data) != crc {
            return Err(SafePdfExportError::DocxReopenFailed);
        }
        total_size = total_size
            .checked_add(data.len())
            .ok_or(SafePdfExportError::LimitExceeded("max_output_bytes"))?;
        if total_size > max_output_bytes {
            return Err(SafePdfExportError::LimitExceeded("max_output_bytes"));
        }
        result.push(ReadZipEntry {
            name: name.to_owned(),
            data: data.to_vec(),
        });
        expected_local_offset = data_end;
        central_position = name_end;
    }
    if expected_local_offset != central_offset || central_position != eocd_offset {
        return Err(SafePdfExportError::UnsafeDocxPackage);
    }
    Ok(result)
}

fn validate_zip_name(name: &str) -> Result<(), SafePdfExportError> {
    if name.is_empty()
        || !name.is_ascii()
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains(['\\', ':', '\0'])
        || name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(SafePdfExportError::UnsafeDocxPackage);
    }
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINAL_CANARY: &str = "ORIGINAL_SECRET_CANARY_18612345678";

    fn request(pages: Vec<ApprovedTextPage>) -> SafePdfExportRequest {
        SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("approval hash"),
            pages,
            forbidden_canaries: vec![
                ORIGINAL_CANARY.to_owned(),
                "原始姓名张秘密".to_owned(),
                "Original Metadata Author".to_owned(),
            ],
        }
    }

    fn pages() -> Vec<ApprovedTextPage> {
        vec![
            ApprovedTextPage {
                page_number: 1,
                text: "第一页：原告[姓名1]\r\n电话：[手机号1]\rANCHOR_ONE".to_owned(),
            },
            ApprovedTextPage {
                page_number: 2,
                text: "第二页：A&B <C> \"D\" 'E'\n制表\t内容\nANCHOR_TWO".to_owned(),
            },
        ]
    }

    #[test]
    fn txt_normalizes_rereads_hashes_and_scans_exact_pages() {
        let request = request(pages());
        let artifact = reconstruct_approved_text_txt(&request, SafePdfExportLimits::default())
            .expect("safe TXT");
        assert_eq!(artifact.evidence.format, SafeDerivedFormat::Txt);
        assert_eq!(artifact.evidence.media_type, TXT_MEDIA_TYPE);
        assert_eq!(artifact.evidence.file_extension, "txt");
        assert_eq!(artifact.evidence.source_page_count, 2);
        assert_eq!(
            artifact.evidence.normalized_text_sha256,
            artifact.evidence.reopened_text_sha256
        );
        assert_eq!(
            artifact.evidence.artifact_sha256,
            sha256_hex(&artifact.bytes)
        );
        let text = str::from_utf8(&artifact.bytes).expect("UTF-8 TXT");
        assert!(!text.contains('\r'));
        assert_eq!(text.matches(TXT_PAGE_SEPARATOR).count(), 1);
        assert!(text.contains("ANCHOR_ONE"));
        assert!(text.contains("ANCHOR_TWO"));
        let reverified = verify_approved_text_derived_bytes(
            SafeDerivedFormat::Txt,
            &artifact.bytes,
            &request,
            SafePdfExportLimits::default(),
        )
        .expect("reverify TXT");
        assert_eq!(reverified, artifact.evidence);
        assert!(!artifact
            .bytes
            .windows(ORIGINAL_CANARY.len())
            .any(|window| window == ORIGINAL_CANARY.as_bytes()));
    }

    #[test]
    fn markdown_round_trip_keeps_untrusted_markup_inside_length_bound_fences() {
        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text:
                "![remote](https://example.invalid/a.png)\n<script>alert(1)</script>\n`````\n尾行\n"
                    .to_owned(),
        }];
        let request = request(pages);
        let artifact = reconstruct_approved_text_markdown(&request, SafePdfExportLimits::default())
            .expect("safe Markdown");
        let markdown = str::from_utf8(&artifact.bytes).expect("UTF-8 Markdown");
        assert!(markdown.starts_with(MARKDOWN_HEADER));
        assert!(markdown.contains("``````text page=1 bytes="));
        assert!(markdown.contains("![remote](https://example.invalid/a.png)"));
        assert_eq!(
            artifact.evidence.normalized_text_sha256,
            artifact.evidence.reopened_text_sha256
        );
        verify_approved_text_derived_bytes(
            SafeDerivedFormat::Markdown,
            &artifact.bytes,
            &request,
            SafePdfExportLimits::default(),
        )
        .expect("reverify Markdown");
    }

    #[test]
    fn txt_and_markdown_tampering_fail_closed() {
        for format in [SafeDerivedFormat::Txt, SafeDerivedFormat::Markdown] {
            let request = request(pages());
            let mut artifact = match format {
                SafeDerivedFormat::Txt => {
                    reconstruct_approved_text_txt(&request, SafePdfExportLimits::default())
                        .expect("TXT")
                }
                SafeDerivedFormat::Markdown => {
                    reconstruct_approved_text_markdown(&request, SafePdfExportLimits::default())
                        .expect("Markdown")
                }
                SafeDerivedFormat::Docx => unreachable!(),
            };
            let offset = artifact
                .bytes
                .windows(b"ANCHOR_ONE".len())
                .position(|window| window == b"ANCHOR_ONE")
                .expect("body anchor");
            artifact.bytes[offset] = b'B';
            assert!(verify_approved_text_derived_bytes(
                format,
                &artifact.bytes,
                &request,
                SafePdfExportLimits::default(),
            )
            .is_err());
        }
    }

    #[test]
    fn docx_is_deterministic_minimal_reopened_and_body_hash_bound() {
        let request = request(pages());
        let first = reconstruct_approved_text_docx(&request, SafePdfExportLimits::default())
            .expect("safe DOCX");
        let second = reconstruct_approved_text_docx(&request, SafePdfExportLimits::default())
            .expect("deterministic DOCX");
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.evidence.format, SafeDerivedFormat::Docx);
        assert_eq!(first.evidence.media_type, DOCX_MEDIA_TYPE);
        assert_eq!(first.evidence.file_extension, "docx");
        assert_eq!(first.evidence.package_entries, DOCX_ENTRY_NAMES);
        assert_eq!(
            first.evidence.normalized_text_sha256,
            first.evidence.reopened_text_sha256
        );
        let entries = read_stored_zip(&first.bytes, first.bytes.len()).expect("strict ZIP reopen");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            DOCX_ENTRY_NAMES
        );
        let document = str::from_utf8(find_entry(&entries, DOCUMENT_PATH).expect("document.xml"))
            .expect("document XML UTF-8");
        assert!(document.contains("A&amp;B &lt;C&gt; &quot;D&quot; &apos;E&apos;"));
        for forbidden in [
            "comments",
            "customXml",
            "w:ins",
            "w:del",
            "hyperlink",
            "TargetMode",
            "embedding",
            "vbaProject",
            "docProps",
            "Original Metadata Author",
        ] {
            assert!(!document.contains(forbidden), "DOCX leaked {forbidden}");
        }
        verify_approved_text_derived_bytes(
            SafeDerivedFormat::Docx,
            &first.bytes,
            &request,
            SafePdfExportLimits::default(),
        )
        .expect("reverify DOCX");
    }

    #[test]
    fn docx_crc_or_body_tampering_fails_closed() {
        let request = request(pages());
        let mut artifact = reconstruct_approved_text_docx(&request, SafePdfExportLimits::default())
            .expect("safe DOCX");
        let offset = artifact
            .bytes
            .windows(b"ANCHOR_ONE".len())
            .position(|window| window == b"ANCHOR_ONE")
            .expect("stored XML anchor");
        artifact.bytes[offset] = b'B';
        assert_eq!(
            verify_approved_text_derived_bytes(
                SafeDerivedFormat::Docx,
                &artifact.bytes,
                &request,
                SafePdfExportLimits::default(),
            ),
            Err(SafePdfExportError::DocxReopenFailed)
        );
    }

    #[test]
    fn docx_rejects_zip_slip_case_alias_and_unapproved_parts() {
        let request = request(pages());
        let document =
            build_document_xml(&normalize_pages(&request.pages), usize::MAX).expect("document XML");
        let unsafe_names = [
            "../document.xml",
            "WORD/document.xml",
            "customXml/item1.xml",
            "word/comments.xml",
            "word/embeddings/oleObject1.bin",
            "docProps/core.xml",
        ];
        for unsafe_name in unsafe_names {
            let bytes = write_stored_zip(&[
                (CONTENT_TYPES_PATH, CONTENT_TYPES_XML.as_bytes()),
                (ROOT_RELS_PATH, ROOT_RELS_XML.as_bytes()),
                (unsafe_name, document.as_bytes()),
            ])
            .expect("synthetic hostile ZIP");
            assert_eq!(
                verify_approved_text_derived_bytes(
                    SafeDerivedFormat::Docx,
                    &bytes,
                    &request,
                    SafePdfExportLimits::default(),
                ),
                Err(SafePdfExportError::UnsafeDocxPackage),
                "unsafe part {unsafe_name} must fail"
            );
        }
    }

    #[test]
    fn docx_rejects_external_relationships_macro_types_and_revisions() {
        let request = request(pages());
        let document =
            build_document_xml(&normalize_pages(&request.pages), usize::MAX).expect("document XML");
        let external_relationships = ROOT_RELS_XML.replace(
            "Target=\"word/document.xml\"",
            "Target=\"https://example.invalid/leak\" TargetMode=\"External\"",
        );
        let external = write_stored_zip(&[
            (CONTENT_TYPES_PATH, CONTENT_TYPES_XML.as_bytes()),
            (ROOT_RELS_PATH, external_relationships.as_bytes()),
            (DOCUMENT_PATH, document.as_bytes()),
        ])
        .expect("external relationship fixture");
        assert_eq!(
            verify_approved_text_derived_bytes(
                SafeDerivedFormat::Docx,
                &external,
                &request,
                SafePdfExportLimits::default(),
            ),
            Err(SafePdfExportError::UnsafeDocxRelationship)
        );

        let macro_types = CONTENT_TYPES_XML.replace(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "application/vnd.ms-word.document.macroEnabled.main+xml",
        );
        let macro_package = write_stored_zip(&[
            (CONTENT_TYPES_PATH, macro_types.as_bytes()),
            (ROOT_RELS_PATH, ROOT_RELS_XML.as_bytes()),
            (DOCUMENT_PATH, document.as_bytes()),
        ])
        .expect("macro fixture");
        assert_eq!(
            verify_approved_text_derived_bytes(
                SafeDerivedFormat::Docx,
                &macro_package,
                &request,
                SafePdfExportLimits::default(),
            ),
            Err(SafePdfExportError::UnsafeDocxContentType)
        );

        let revision = document.replace(TEXT_START, "<w:ins><w:r>\n<w:t xml:space=\"preserve\">");
        let revision_package = write_stored_zip(&[
            (CONTENT_TYPES_PATH, CONTENT_TYPES_XML.as_bytes()),
            (ROOT_RELS_PATH, ROOT_RELS_XML.as_bytes()),
            (DOCUMENT_PATH, revision.as_bytes()),
        ])
        .expect("revision fixture");
        assert_eq!(
            verify_approved_text_derived_bytes(
                SafeDerivedFormat::Docx,
                &revision_package,
                &request,
                SafePdfExportLimits::default(),
            ),
            Err(SafePdfExportError::UnsafeDocxBody)
        );
    }

    #[test]
    fn extra_comments_and_embedded_objects_are_rejected_even_if_core_parts_are_valid() {
        let request = request(pages());
        let document =
            build_document_xml(&normalize_pages(&request.pages), usize::MAX).expect("document XML");
        for (name, payload) in [
            ("word/comments.xml", b"<comments/>".as_slice()),
            ("word/embeddings/oleObject1.bin", b"MZ".as_slice()),
            ("customXml/item1.xml", b"<secret/>".as_slice()),
        ] {
            let bytes = write_stored_zip(&[
                (CONTENT_TYPES_PATH, CONTENT_TYPES_XML.as_bytes()),
                (ROOT_RELS_PATH, ROOT_RELS_XML.as_bytes()),
                (DOCUMENT_PATH, document.as_bytes()),
                (name, payload),
            ])
            .expect("extra part fixture");
            assert_eq!(
                verify_approved_text_derived_bytes(
                    SafeDerivedFormat::Docx,
                    &bytes,
                    &request,
                    SafePdfExportLimits::default(),
                ),
                Err(SafePdfExportError::UnsafeDocxPackage)
            );
        }
    }

    #[test]
    fn derived_exports_reject_residuals_approval_changes_and_size_overflow() {
        let residual_pages = vec![ApprovedTextPage {
            page_number: 1,
            text: format!("approved-looking text {ORIGINAL_CANARY}"),
        }];
        let residual = request(residual_pages);
        for build in [
            reconstruct_approved_text_txt as fn(_, _) -> _,
            reconstruct_approved_text_markdown as fn(_, _) -> _,
            reconstruct_approved_text_docx as fn(_, _) -> _,
        ] {
            assert_eq!(
                build(&residual, SafePdfExportLimits::default()),
                Err(SafePdfExportError::SensitiveCanaryPresent)
            );
        }

        let mut changed = request(pages());
        changed.pages[0].text.push_str(" changed after approval");
        assert_eq!(
            reconstruct_approved_text_docx(&changed, SafePdfExportLimits::default()),
            Err(SafePdfExportError::ApprovalHashMismatch)
        );

        let valid = request(pages());
        let limits = SafePdfExportLimits {
            max_output_bytes: 8,
            ..SafePdfExportLimits::default()
        };
        assert_eq!(
            reconstruct_approved_text_markdown(&valid, limits),
            Err(SafePdfExportError::LimitExceeded("max_output_bytes"))
        );
        assert_eq!(
            reconstruct_approved_text_docx(&valid, limits),
            Err(SafePdfExportError::LimitExceeded("max_output_bytes"))
        );
    }

    #[test]
    fn docx_rejects_non_xml_characters_and_crc_is_standard() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text: "approved\u{fffe}text".to_owned(),
        }];
        let request = request(pages);
        assert_eq!(
            reconstruct_approved_text_docx(&request, SafePdfExportLimits::default()),
            Err(SafePdfExportError::DisallowedControlCharacter { page_number: 1 })
        );
    }
}
