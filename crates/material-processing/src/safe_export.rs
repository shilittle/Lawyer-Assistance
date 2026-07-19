//! Irreversible reconstruction of an approved redacted text payload.
//!
//! This module creates a new PDF object graph. It never accepts an original
//! PDF, page image, annotation, attachment, metadata dictionary, or arbitrary
//! PDF object. The caller must bind the input to a prior approval hash and
//! supply source-sensitive canaries for post-export checks.

use lopdf::{Dictionary, Document, Object};
use printpdf::{
    FontId, FontParseSeverity, Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage,
    PdfParseErrorSeverity, PdfSaveOptions, Point, Pt, TextItem,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const PDF_MEDIA_TYPE: &str = "application/pdf";
const PAGE_WIDTH_POINTS: usize = 595;
const HORIZONTAL_MARGIN_POINTS: usize = 42;
const FONT_SIZE_POINTS: usize = 9;
// The embedded CJK face uses one-em ideographs. Wrapping by Unicode scalar
// units is conservative for its narrower Latin glyphs and keeps equal margins.
const MAX_CHAR_UNITS_PER_LINE: usize =
    (PAGE_WIDTH_POINTS - 2 * HORIZONTAL_MARGIN_POINTS) / FONT_SIZE_POINTS;
const MAX_LINES_PER_PHYSICAL_PAGE: usize = 62;
const SAFE_EXPORT_FONT_BYTES: &[u8] = include_bytes!("../assets/fonts/NotoSansSC-Regular.ttf");

/// Reviewed SHA-256 of the bundled, static 400-weight PDF font.
pub const BUNDLED_PDF_FONT_SHA256: &str =
    "c7763f454946833081cc90e73186615f8e1189de9c5e5a5a8752871fd79fddbc";

/// Returns the reviewed font bytes shared by safe redaction exports and
/// ordinary local document exports. Keeping one embedded asset prevents the
/// two PDF paths from silently drifting to different glyph coverage.
#[must_use]
pub fn bundled_pdf_font_bytes() -> &'static [u8] {
    SAFE_EXPORT_FONT_BYTES
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedTextPage {
    pub page_number: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafePdfExportRequest {
    /// SHA-256 returned by approved_text_sha256 at approval time.
    pub approved_text_sha256: String,
    /// Pages must be numbered contiguously from one.
    pub pages: Vec<ApprovedTextPage>,
    /// Source-sensitive values absent from both approved input and output.
    /// At least one non-empty canary is required.
    pub forbidden_canaries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafePdfExportLimits {
    pub max_source_pages: usize,
    pub max_total_text_bytes: usize,
    pub max_page_text_bytes: usize,
    pub max_forbidden_canaries: usize,
    pub max_canary_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for SafePdfExportLimits {
    fn default() -> Self {
        Self {
            max_source_pages: 500,
            max_total_text_bytes: 10 * 1024 * 1024,
            max_page_text_bytes: 512 * 1024,
            max_forbidden_canaries: 10_000,
            max_canary_bytes: 16 * 1024,
            max_output_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePagePlacement {
    pub source_page_number: u32,
    pub first_output_page: u32,
    pub last_output_page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafePdfArtifact {
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub approved_text_sha256: String,
    pub extracted_text_sha256: String,
    pub output_page_count: u32,
    pub source_page_placements: Vec<SourcePagePlacement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafePdfExportError {
    EmptyDocument,
    InvalidPageOrder { expected: u32, actual: u32 },
    DisallowedControlCharacter { page_number: u32 },
    LimitExceeded(&'static str),
    MissingForbiddenCanary,
    ApprovalHashMismatch,
    SensitiveCanaryPresent,
    UnsupportedGlyph,
    PdfBuildFailed,
    PdfReopenFailed,
    UnsafePdfObject,
    ReextractedTextMismatch { page_number: u32 },
}

impl fmt::Display for SafePdfExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDocument => formatter.write_str("approved text document is empty"),
            Self::InvalidPageOrder { expected, actual } => {
                write!(formatter, "expected source page {expected}, got {actual}")
            }
            Self::DisallowedControlCharacter { page_number } => {
                write!(
                    formatter,
                    "page {page_number} has a disallowed control character"
                )
            }
            Self::LimitExceeded(name) => write!(formatter, "safe export limit exceeded: {name}"),
            Self::MissingForbiddenCanary => {
                formatter.write_str("at least one non-empty forbidden canary is required")
            }
            Self::ApprovalHashMismatch => {
                formatter.write_str("approved text no longer matches its approval hash")
            }
            Self::SensitiveCanaryPresent => {
                formatter.write_str("a forbidden source-sensitive canary remains")
            }
            Self::UnsupportedGlyph => formatter.write_str(
                "approved text contains a character unsupported by the embedded export font",
            ),
            Self::PdfBuildFailed => formatter.write_str("failed to build reconstructed PDF"),
            Self::PdfReopenFailed => {
                formatter.write_str("reconstructed PDF could not be reopened or text-extracted")
            }
            Self::UnsafePdfObject => {
                formatter.write_str("reconstructed PDF contains a forbidden object or metadata")
            }
            Self::ReextractedTextMismatch { page_number } => {
                write!(
                    formatter,
                    "re-extracted text differs for source page {page_number}"
                )
            }
        }
    }
}

impl Error for SafePdfExportError {}

/// Compute the exact approval hash for ordered, paginated redacted text.
pub fn approved_text_sha256(pages: &[ApprovedTextPage]) -> Result<String, SafePdfExportError> {
    validate_page_order(pages)?;
    let mut hasher = Sha256::new();
    hasher.update(b"lawyer-assistance-approved-redacted-pages-v1\0");
    for page in pages {
        hasher.update(page.page_number.to_be_bytes());
        let length = u64::try_from(page.text.len())
            .map_err(|_| SafePdfExportError::LimitExceeded("text"))?;
        hasher.update(length.to_be_bytes());
        hasher.update(page.text.as_bytes());
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

/// Build a clean text-only PDF, reopen it, extract it, and audit it before
/// returning any bytes to the caller.
pub fn reconstruct_approved_text_pdf(
    request: &SafePdfExportRequest,
    limits: SafePdfExportLimits,
) -> Result<SafePdfArtifact, SafePdfExportError> {
    validate_request(request, &limits)?;
    let actual_approval_hash = approved_text_sha256(&request.pages)?;
    if !constant_time_eq(
        actual_approval_hash.as_bytes(),
        request.approved_text_sha256.as_bytes(),
    ) {
        return Err(SafePdfExportError::ApprovalHashMismatch);
    }
    scan_forbidden(
        request.pages.iter().map(|page| page.text.as_str()),
        &request.forbidden_canaries,
    )?;

    let (mut document, placements) = build_clean_pdf(&request.pages)?;
    let mut bytes = Vec::new();
    document
        .save_to(&mut bytes)
        .map_err(|_| SafePdfExportError::PdfBuildFailed)?;
    if bytes.len() > limits.max_output_bytes {
        return Err(SafePdfExportError::LimitExceeded("max_output_bytes"));
    }

    let reopened = Document::load_mem(&bytes).map_err(|_| SafePdfExportError::PdfReopenFailed)?;
    audit_clean_object_graph(&reopened)?;
    let output_page_count = u32::try_from(reopened.get_pages().len())
        .map_err(|_| SafePdfExportError::LimitExceeded("output_page_count"))?;
    let extracted_pages = verify_reextracted_pages(&reopened, request, &placements, &limits)?;
    scan_forbidden(
        extracted_pages.iter().map(String::as_str),
        &request.forbidden_canaries,
    )?;
    scan_pdf_bytes_for_ascii_canaries(&bytes, &request.forbidden_canaries)?;

    let mut extracted_hasher = Sha256::new();
    extracted_hasher.update(b"lawyer-assistance-reextracted-pages-v1\0");
    for (source, text) in request.pages.iter().zip(&extracted_pages) {
        extracted_hasher.update(source.page_number.to_be_bytes());
        extracted_hasher.update(text.as_bytes());
    }

    Ok(SafePdfArtifact {
        media_type: PDF_MEDIA_TYPE.to_owned(),
        sha256: sha256_hex(&bytes),
        bytes,
        approved_text_sha256: actual_approval_hash,
        extracted_text_sha256: hex_digest(extracted_hasher.finalize().as_slice()),
        output_page_count,
        source_page_placements: placements,
    })
}

fn validate_request(
    request: &SafePdfExportRequest,
    limits: &SafePdfExportLimits,
) -> Result<(), SafePdfExportError> {
    validate_page_order(&request.pages)?;
    if request.pages.len() > limits.max_source_pages {
        return Err(SafePdfExportError::LimitExceeded("max_source_pages"));
    }
    if request.approved_text_sha256.len() != 64
        || !request
            .approved_text_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SafePdfExportError::ApprovalHashMismatch);
    }
    if request.forbidden_canaries.len() > limits.max_forbidden_canaries {
        return Err(SafePdfExportError::LimitExceeded("max_forbidden_canaries"));
    }
    let canaries = request
        .forbidden_canaries
        .iter()
        .map(|canary| privacy::normalize_sensitive_text(canary))
        .map(|canary| canary.trim().to_owned())
        .filter(|canary| !canary.is_empty())
        .collect::<Vec<_>>();
    if canaries.is_empty() {
        return Err(SafePdfExportError::MissingForbiddenCanary);
    }
    if canaries
        .iter()
        .any(|canary| canary.len() > limits.max_canary_bytes)
    {
        return Err(SafePdfExportError::LimitExceeded("max_canary_bytes"));
    }

    let mut total = 0usize;
    let mut has_visible_text = false;
    for page in &request.pages {
        if page.text.len() > limits.max_page_text_bytes {
            return Err(SafePdfExportError::LimitExceeded("max_page_text_bytes"));
        }
        total = total
            .checked_add(page.text.len())
            .ok_or(SafePdfExportError::LimitExceeded("max_total_text_bytes"))?;
        if total > limits.max_total_text_bytes {
            return Err(SafePdfExportError::LimitExceeded("max_total_text_bytes"));
        }
        has_visible_text |= page
            .text
            .chars()
            .any(|character| !character.is_whitespace());
        if page
            .text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(SafePdfExportError::DisallowedControlCharacter {
                page_number: page.page_number,
            });
        }
    }
    if !has_visible_text {
        return Err(SafePdfExportError::EmptyDocument);
    }
    Ok(())
}

fn validate_page_order(pages: &[ApprovedTextPage]) -> Result<(), SafePdfExportError> {
    if pages.is_empty() {
        return Err(SafePdfExportError::EmptyDocument);
    }
    for (index, page) in pages.iter().enumerate() {
        let expected = u32::try_from(index + 1)
            .map_err(|_| SafePdfExportError::LimitExceeded("page_number"))?;
        if page.page_number != expected {
            return Err(SafePdfExportError::InvalidPageOrder {
                expected,
                actual: page.page_number,
            });
        }
    }
    Ok(())
}

fn build_clean_pdf(
    pages: &[ApprovedTextPage],
) -> Result<(Document, Vec<SourcePagePlacement>), SafePdfExportError> {
    let mut parse_warnings = Vec::new();
    let font = ParsedFont::from_bytes(SAFE_EXPORT_FONT_BYTES, 0, &mut parse_warnings)
        .ok_or(SafePdfExportError::PdfBuildFailed)?;
    if parse_warnings
        .iter()
        .any(|warning| warning.severity == FontParseSeverity::Error)
    {
        return Err(SafePdfExportError::PdfBuildFailed);
    }
    validate_glyph_coverage(pages, &font)?;

    let mut pdf = PdfDocument::new("");
    let font_id = pdf.add_font(&font);
    let mut output_pages = Vec::new();
    let mut placements = Vec::with_capacity(pages.len());
    for source_page in pages {
        let lines = reflow_text(&source_page.text);
        let chunks = if lines.is_empty() {
            vec![Vec::new()]
        } else {
            lines
                .chunks(MAX_LINES_PER_PHYSICAL_PAGE)
                .map(<[String]>::to_vec)
                .collect::<Vec<_>>()
        };
        let first_output_page = u32::try_from(output_pages.len() + 1)
            .map_err(|_| SafePdfExportError::LimitExceeded("output_page_count"))?;
        for chunk in chunks {
            output_pages.push(PdfPage::new(
                Mm(210.0),
                Mm(297.0),
                encode_text_page(&chunk, &font_id),
            ));
        }
        let last_output_page = u32::try_from(output_pages.len())
            .map_err(|_| SafePdfExportError::LimitExceeded("output_page_count"))?;
        placements.push(SourcePagePlacement {
            source_page_number: source_page.page_number,
            first_output_page,
            last_output_page,
        });
    }

    pdf.with_pages(output_pages);
    let save_options = PdfSaveOptions {
        optimize: false,
        subset_fonts: false,
        secure: true,
        image_optimization: None,
    };
    let mut save_warnings = Vec::new();
    let serialized = pdf.save(&save_options, &mut save_warnings);
    if serialized.is_empty()
        || save_warnings
            .iter()
            .any(|warning| warning.severity == PdfParseErrorSeverity::Error)
    {
        return Err(SafePdfExportError::PdfBuildFailed);
    }
    let mut document =
        Document::load_mem(&serialized).map_err(|_| SafePdfExportError::PdfBuildFailed)?;
    sanitize_printpdf_object_graph(&mut document)?;
    Ok((document, placements))
}

fn validate_glyph_coverage(
    pages: &[ApprovedTextPage],
    font: &ParsedFont,
) -> Result<(), SafePdfExportError> {
    for character in pages.iter().flat_map(|page| page.text.chars()) {
        if matches!(character, '\n' | '\r' | '\t') {
            continue;
        }
        if font.lookup_glyph_index(u32::from(character)).is_none() {
            return Err(SafePdfExportError::UnsupportedGlyph);
        }
    }
    Ok(())
}

fn sanitize_printpdf_object_graph(document: &mut Document) -> Result<(), SafePdfExportError> {
    document.trailer.remove(b"Info");
    document.trailer.remove(b"ID");

    let root_id = document
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| SafePdfExportError::PdfBuildFailed)?;
    document
        .get_object_mut(root_id)
        .and_then(Object::as_dict_mut)
        .map_err(|_| SafePdfExportError::PdfBuildFailed)?
        .remove(b"Metadata");

    let mut resource_ids = Vec::new();
    for object in document.objects.values_mut() {
        let Object::Dictionary(dictionary) = object else {
            continue;
        };
        if dictionary
            .get(b"Type")
            .and_then(Object::as_name)
            .is_ok_and(|object_type| object_type == b"Page")
        {
            dictionary.remove(b"Annots");
            match dictionary.get_mut(b"Resources") {
                Ok(Object::Reference(resource_id)) => resource_ids.push(*resource_id),
                Ok(Object::Dictionary(resources)) => strip_unused_page_resources(resources),
                _ => return Err(SafePdfExportError::PdfBuildFailed),
            }
        }
    }
    for resource_id in resource_ids {
        let resources = document
            .get_object_mut(resource_id)
            .and_then(Object::as_dict_mut)
            .map_err(|_| SafePdfExportError::PdfBuildFailed)?;
        strip_unused_page_resources(resources);
    }
    let _ = document.prune_objects();
    document.renumber_objects();
    Ok(())
}

fn strip_unused_page_resources(resources: &mut Dictionary) {
    resources.remove(b"XObject");
    resources.remove(b"ExtGState");
    resources.remove(b"Shading");
}

fn encode_text_page(lines: &[String], font_id: &FontId) -> Vec<Op> {
    let mut operations = vec![
        Op::StartTextSection,
        Op::SetFont {
            font: PdfFontHandle::External(font_id.clone()),
            size: Pt(FONT_SIZE_POINTS as f32),
        },
        Op::SetLineHeight { lh: Pt(12.0) },
        Op::SetTextCursor {
            pos: Point {
                x: Pt(HORIZONTAL_MARGIN_POINTS as f32),
                y: Pt(800.0),
            },
        },
    ];
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            operations.push(Op::AddLineBreak);
        }
        operations.push(Op::ShowText {
            items: vec![TextItem::Text(line.clone())],
        });
    }
    operations.push(Op::EndTextSection);
    operations
}

fn reflow_text(text: &str) -> Vec<String> {
    let normalized = text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\t', "    ");
    let mut output = Vec::new();
    for source_line in normalized.split('\n') {
        if source_line.is_empty() {
            output.push(String::new());
            continue;
        }
        let mut line = String::new();
        let mut char_units = 0usize;
        for character in source_line.chars() {
            let width = character.len_utf16();
            if char_units > 0 && char_units + width > MAX_CHAR_UNITS_PER_LINE {
                output.push(std::mem::take(&mut line));
                char_units = 0;
            }
            line.push(character);
            char_units += width;
        }
        output.push(line);
    }
    output
}

fn canonicalize_reextracted_text(text: &str) -> String {
    // PDF text extractors do not preserve empty ShowText operations. Empty rows are
    // layout-only, so compare every non-empty reflowed line byte-for-byte while
    // allowing those rows to disappear from the extracted representation.
    text.trim_end_matches(char::is_whitespace)
        .split('\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn verify_reextracted_pages(
    document: &Document,
    request: &SafePdfExportRequest,
    placements: &[SourcePagePlacement],
    limits: &SafePdfExportLimits,
) -> Result<Vec<String>, SafePdfExportError> {
    let page_numbers = document.get_pages();
    let mut result = Vec::with_capacity(request.pages.len());
    for (source, placement) in request.pages.iter().zip(placements) {
        let mut extracted = String::new();
        for output_page in placement.first_output_page..=placement.last_output_page {
            let chunk = document
                .extract_text_with_limit(
                    &[output_page],
                    limits.max_page_text_bytes.saturating_mul(4),
                )
                .map_err(|_| SafePdfExportError::PdfReopenFailed)?;
            extracted.push_str(&chunk);
        }
        let expected = reflow_text(&source.text).join("\n");
        if canonicalize_reextracted_text(&extracted) != canonicalize_reextracted_text(&expected) {
            return Err(SafePdfExportError::ReextractedTextMismatch {
                page_number: source.page_number,
            });
        }
        result.push(extracted);
    }
    if page_numbers.len()
        != placements
            .last()
            .map_or(0, |placement| placement.last_output_page as usize)
    {
        return Err(SafePdfExportError::PdfReopenFailed);
    }
    Ok(result)
}

fn audit_clean_object_graph(document: &Document) -> Result<(), SafePdfExportError> {
    const FORBIDDEN_KEYS: &[&[u8]] = &[
        b"AA",
        b"AcroForm",
        b"AF",
        b"Collection",
        b"EmbeddedFiles",
        b"Encrypt",
        b"FileAttachment",
        b"Info",
        b"JavaScript",
        b"JS",
        b"Metadata",
        b"Names",
        b"OpenAction",
        b"PieceInfo",
        b"RichMedia",
        b"XFA",
        b"XObject",
    ];
    for key in FORBIDDEN_KEYS {
        if document.trailer.has(key) {
            return Err(SafePdfExportError::UnsafePdfObject);
        }
    }
    for object in document.objects.values() {
        let dictionary = match object {
            Object::Dictionary(dictionary) => dictionary,
            Object::Stream(stream) => &stream.dict,
            _ => continue,
        };
        audit_dictionary(dictionary, FORBIDDEN_KEYS)?;
    }
    Ok(())
}

fn audit_dictionary(
    dictionary: &Dictionary,
    forbidden_keys: &[&[u8]],
) -> Result<(), SafePdfExportError> {
    if forbidden_keys.iter().any(|key| dictionary.has(key)) {
        return Err(SafePdfExportError::UnsafePdfObject);
    }
    if let Ok(object_type) = dictionary.get(b"Type").and_then(Object::as_name) {
        if matches!(
            object_type,
            b"EmbeddedFile" | b"Filespec" | b"Metadata" | b"Annot" | b"XObject" | b"ObjStm"
        ) {
            return Err(SafePdfExportError::UnsafePdfObject);
        }
    }
    if let Ok(subtype) = dictionary.get(b"Subtype").and_then(Object::as_name) {
        if matches!(
            subtype,
            b"Image" | b"FileAttachment" | b"RichMedia" | b"Movie" | b"Sound"
        ) {
            return Err(SafePdfExportError::UnsafePdfObject);
        }
    }
    Ok(())
}

fn scan_forbidden<'a>(
    texts: impl Iterator<Item = &'a str>,
    forbidden_canaries: &[String],
) -> Result<(), SafePdfExportError> {
    let normalized_text = texts
        .map(compact_for_verification)
        .collect::<Vec<_>>()
        .join("");
    for canary in forbidden_canaries {
        let compact_canary = compact_for_verification(canary.trim());
        if !compact_canary.is_empty() && normalized_text.contains(&compact_canary) {
            return Err(SafePdfExportError::SensitiveCanaryPresent);
        }
    }
    Ok(())
}

fn scan_pdf_bytes_for_ascii_canaries(
    bytes: &[u8],
    forbidden_canaries: &[String],
) -> Result<(), SafePdfExportError> {
    let haystack = String::from_utf8_lossy(bytes).to_lowercase();
    for canary in forbidden_canaries {
        if canary.is_ascii() && haystack.contains(&canary.to_lowercase()) {
            return Err(SafePdfExportError::SensitiveCanaryPresent);
        }
    }
    Ok(())
}

fn compact_for_verification(text: &str) -> String {
    privacy::normalize_sensitive_text(text)
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
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

    #[test]
    fn reflow_bounds_long_ascii_and_surrogate_pairs() {
        assert_eq!(MAX_CHAR_UNITS_PER_LINE, 56);
        let ascii = "A".repeat(82);
        let ascii_lines = reflow_text(&ascii);
        assert_eq!(
            ascii_lines.iter().map(String::len).collect::<Vec<_>>(),
            vec![56, 26]
        );

        let mixed = format!("{}😀{}", "中".repeat(54), "B".repeat(4));
        let mixed_lines = reflow_text(&mixed);
        assert_eq!(mixed_lines.len(), 2);
        assert!(mixed_lines
            .iter()
            .all(|line| line.encode_utf16().count() <= MAX_CHAR_UNITS_PER_LINE));

        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text: ascii,
        }];
        let request = SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("approval hash"),
            pages,
            forbidden_canaries: vec!["source-secret-not-present".to_owned()],
        };
        let artifact = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect("bounded-width PDF");
        let reopened = Document::load_mem(&artifact.bytes).expect("open output PDF");
        let text = reopened.extract_text(&[1]).expect("extract wrapped text");
        assert_eq!(text.lines().map(str::len).collect::<Vec<_>>(), vec![56, 26]);
    }

    #[test]
    fn reconstructs_text_only_pdf_and_reopens_unicode_text() {
        let request = request(vec![
            ApprovedTextPage {
                page_number: 1,
                text: "第一页：原告[姓名1]，联系电话[手机号1]。\nPAGE_ONE_ANCHOR".to_owned(),
            },
            ApprovedTextPage {
                page_number: 2,
                text: "第二页：被告[姓名2]。\nPAGE_TWO_ANCHOR".to_owned(),
            },
        ]);
        let artifact = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect("safe reconstruction");

        assert_eq!(artifact.media_type, PDF_MEDIA_TYPE);
        assert_eq!(artifact.source_page_placements.len(), 2);
        assert!(
            artifact.source_page_placements[0].last_output_page
                < artifact.source_page_placements[1].first_output_page
        );
        let reopened = Document::load_mem(&artifact.bytes).expect("open output PDF");
        let first = reopened.extract_text(&[1]).expect("extract page one");
        let second = reopened.extract_text(&[2]).expect("extract page two");
        assert!(first.contains("PAGE_ONE_ANCHOR"));
        assert!(second.contains("PAGE_TWO_ANCHOR"));
        assert!(first.contains("[姓名1]"));
        assert!(!artifact
            .bytes
            .windows(ORIGINAL_CANARY.len())
            .any(|window| window == ORIGINAL_CANARY.as_bytes()));
    }

    #[test]
    fn embeds_verified_cjk_font_program_without_stsong_fallback() {
        assert_eq!(sha256_hex(SAFE_EXPORT_FONT_BYTES), BUNDLED_PDF_FONT_SHA256);
        assert_eq!(
            BUNDLED_PDF_FONT_SHA256,
            "c7763f454946833081cc90e73186615f8e1189de9c5e5a5a8752871fd79fddbc"
        );
        let request = request(vec![ApprovedTextPage {
            page_number: 1,
            text: "普通中文与脱敏占位符：[姓名1]、[手机号1]、[案号1]。".to_owned(),
        }]);
        let artifact = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect("embedded-font safe reconstruction");
        let reopened = Document::load_mem(&artifact.bytes).expect("open embedded-font PDF");

        let has_embedded_font_program = reopened
            .objects
            .values()
            .filter_map(|object| match object {
                Object::Dictionary(dictionary) => Some(dictionary),
                Object::Stream(stream) => Some(&stream.dict),
                _ => None,
            })
            .any(|dictionary| {
                dictionary
                    .get(b"Type")
                    .and_then(Object::as_name)
                    .is_ok_and(|object_type| object_type == b"FontDescriptor")
                    && (dictionary.has(b"FontFile2") || dictionary.has(b"FontFile3"))
            });
        assert!(has_embedded_font_program);
        assert!(!artifact
            .bytes
            .windows(b"STSong-Light".len())
            .any(|window| window == b"STSong-Light"));
        assert!(!reopened.trailer.has(b"Info"));
        assert!(!reopened.trailer.has(b"ID"));
        audit_clean_object_graph(&reopened).expect("embedded-font graph remains clean");
        let extracted = reopened
            .extract_text(&[1])
            .expect("extract embedded CJK text");
        assert!(extracted.contains("普通中文与脱敏占位符"));
        assert!(extracted.contains("[姓名1]"));
    }

    #[test]
    fn blank_layout_lines_preserve_all_nonempty_approved_text() {
        let approved = "脱敏审阅副本\n\n原告：[姓名1]\n\n发送前逐页复核。";
        let request = request(vec![ApprovedTextPage {
            page_number: 1,
            text: approved.to_owned(),
        }]);
        let artifact = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect("blank layout rows must not defeat safe reconstruction");
        let reopened = Document::load_mem(&artifact.bytes).expect("open blank-line PDF");
        let extracted = reopened
            .extract_text(&[1])
            .expect("extract approved non-empty lines");

        assert_eq!(
            canonicalize_reextracted_text(&extracted),
            canonicalize_reextracted_text(approved)
        );
        assert!(extracted.contains("[姓名1]"));
    }

    #[test]
    fn unsupported_font_glyph_fails_closed_without_echoing_input() {
        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text: "经批准正文包含罕见字符：\u{20000}".to_owned(),
        }];
        let request = SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("approval hash"),
            pages,
            forbidden_canaries: vec!["source-secret-not-present".to_owned()],
        };
        let error = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect_err("unsupported glyph must fail closed");
        assert_eq!(error, SafePdfExportError::UnsupportedGlyph);
        assert!(!error.to_string().contains('\u{20000}'));
    }

    #[test]
    fn embedded_font_output_still_obeys_output_size_limit() {
        let request = request(vec![ApprovedTextPage {
            page_number: 1,
            text: "已脱敏正文。[姓名1]".to_owned(),
        }]);
        let limits = SafePdfExportLimits {
            max_output_bytes: 1,
            ..SafePdfExportLimits::default()
        };
        assert_eq!(
            reconstruct_approved_text_pdf(&request, limits),
            Err(SafePdfExportError::LimitExceeded("max_output_bytes"))
        );
    }
    #[test]
    fn unicode_obfuscation_cannot_reintroduce_forbidden_canaries() {
        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text: "原告张\u{200b}三，电话13800138000。".to_owned(),
        }];
        let request = SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("approval hash"),
            pages,
            forbidden_canaries: vec!["张三".to_owned(), "１３８００１３８０００".to_owned()],
        };
        assert_eq!(
            reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default()),
            Err(SafePdfExportError::SensitiveCanaryPresent)
        );
    }
    #[test]
    fn emits_no_original_metadata_or_active_embedded_objects() {
        let request = request(vec![ApprovedTextPage {
            page_number: 1,
            text: "仅包含经批准的脱敏正文。[案号1]".to_owned(),
        }]);
        let artifact = reconstruct_approved_text_pdf(&request, SafePdfExportLimits::default())
            .expect("safe reconstruction");
        let reopened = Document::load_mem(&artifact.bytes).expect("open output PDF");
        assert!(!reopened.trailer.has(b"Info"));
        assert!(!reopened.trailer.has(b"Encrypt"));
        audit_clean_object_graph(&reopened).expect("clean graph");
        let raw = String::from_utf8_lossy(&artifact.bytes);
        assert!(!raw.contains("Original Metadata Author"));
        assert!(!raw.contains("ORIGINAL_SECRET_CANARY"));
    }

    #[test]
    fn rejects_empty_input_and_size_limit() {
        let empty = SafePdfExportRequest {
            approved_text_sha256: "0".repeat(64),
            pages: Vec::new(),
            forbidden_canaries: vec!["source-secret".to_owned()],
        };
        assert_eq!(
            reconstruct_approved_text_pdf(&empty, SafePdfExportLimits::default()),
            Err(SafePdfExportError::EmptyDocument)
        );

        let oversized = request(vec![ApprovedTextPage {
            page_number: 1,
            text: "approved redacted text".to_owned(),
        }]);
        let limits = SafePdfExportLimits {
            max_page_text_bytes: 4,
            ..SafePdfExportLimits::default()
        };
        assert_eq!(
            reconstruct_approved_text_pdf(&oversized, limits),
            Err(SafePdfExportError::LimitExceeded("max_page_text_bytes"))
        );
    }

    #[test]
    fn approval_and_residual_checks_fail_closed() {
        let residual = request(vec![ApprovedTextPage {
            page_number: 1,
            text: format!("redacted body accidentally includes {ORIGINAL_CANARY}"),
        }]);
        assert_eq!(
            reconstruct_approved_text_pdf(&residual, SafePdfExportLimits::default()),
            Err(SafePdfExportError::SensitiveCanaryPresent)
        );

        let mut changed = request(vec![ApprovedTextPage {
            page_number: 1,
            text: "approved text".to_owned(),
        }]);
        changed.pages[0].text.push_str(" changed after approval");
        assert_eq!(
            reconstruct_approved_text_pdf(&changed, SafePdfExportLimits::default()),
            Err(SafePdfExportError::ApprovalHashMismatch)
        );
    }

    #[test]
    fn rejects_page_reordering_and_missing_canary() {
        let reordered_pages = vec![ApprovedTextPage {
            page_number: 2,
            text: "page two".to_owned(),
        }];
        assert_eq!(
            approved_text_sha256(&reordered_pages),
            Err(SafePdfExportError::InvalidPageOrder {
                expected: 1,
                actual: 2
            })
        );

        let pages = vec![ApprovedTextPage {
            page_number: 1,
            text: "approved text".to_owned(),
        }];
        let missing = SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("hash"),
            pages,
            forbidden_canaries: vec!["   ".to_owned()],
        };
        assert_eq!(
            reconstruct_approved_text_pdf(&missing, SafePdfExportLimits::default()),
            Err(SafePdfExportError::MissingForbiddenCanary)
        );
    }
}
