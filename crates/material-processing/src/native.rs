use crate::types::{
    PageExtractionDecision, ProcessingError, ProcessingLimits, QualityReasonCode,
    TextLayerAssessment,
};
use lopdf::{
    content::Content, DecompressError, Dictionary, Document, Error as PdfError, LoadOptions,
    Object, ObjectId,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub(crate) struct NativePage {
    pub page_number: u32,
    pub text: String,
    pub assessment: TextLayerAssessment,
}

#[derive(Debug, Clone)]
pub(crate) struct NativePdf {
    pub source_sha256: String,
    pub page_count: u32,
    pub pages: Vec<NativePage>,
}

pub fn assess_pdf_text_layer(
    bytes: &[u8],
    limits: &ProcessingLimits,
) -> Result<Vec<TextLayerAssessment>, ProcessingError> {
    Ok(extract_native_pdf(bytes, limits)?
        .pages
        .into_iter()
        .map(|page| page.assessment)
        .collect())
}

pub(crate) fn extract_native_pdf(
    bytes: &[u8],
    limits: &ProcessingLimits,
) -> Result<NativePdf, ProcessingError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(ProcessingError::InputTooLarge);
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(ProcessingError::InvalidInput);
    }
    let options = LoadOptions::with_max_decompressed_size(limits.max_page_stream_bytes);
    let document = Document::load_mem_with_options(bytes, options).map_err(map_pdf_error)?;
    if document.is_encrypted() || document.was_encrypted() {
        return Err(ProcessingError::EncryptedPdf);
    }
    let page_map = document.get_pages();
    if page_map.len() > limits.max_pages {
        return Err(ProcessingError::PageLimitExceeded);
    }
    let page_count =
        u32::try_from(page_map.len()).map_err(|_| ProcessingError::PageLimitExceeded)?;
    let has_interactive_form = document.catalog().map_err(map_pdf_error)?.has(b"AcroForm");
    let mut pages = Vec::with_capacity(page_map.len());
    for (page_number, page_id) in page_map.iter().map(|(number, id)| (*number, *id)) {
        let page_content = document
            .get_page_content_with_limit(page_id, limits.max_page_stream_bytes)
            .map_err(map_pdf_error)?;
        let decoded_content = Content::decode(&page_content).map_err(map_pdf_error)?;
        let has_inline_image = decoded_content
            .operations
            .iter()
            .any(|operation| operation.operator == "BI");
        let has_non_text_graphics = content_has_non_text_graphics(&decoded_content);
        let has_visual_xobject = page_has_xobjects(&document, page_id)?;
        let has_annotations = page_has_annotations(&document, page_id)?;
        let extracted = document
            .extract_text_with_limit(&[page_number], limits.max_page_stream_bytes)
            .map_err(map_pdf_error)?;
        let text = normalize_text(&extracted)?;
        let mut assessment = assess_text(page_number, &text, limits);
        if has_inline_image || has_visual_xobject || has_non_text_graphics {
            require_local_ocr(&mut assessment, QualityReasonCode::VisualContentPresent);
        }
        if has_annotations {
            require_local_ocr(&mut assessment, QualityReasonCode::PageAnnotationsPresent);
        }
        if has_interactive_form {
            require_local_ocr(&mut assessment, QualityReasonCode::InteractiveFormPresent);
        }
        pages.push(NativePage {
            page_number,
            text: text.trim().to_owned(),
            assessment,
        });
    }
    Ok(NativePdf {
        source_sha256: sha256_hex(bytes),
        page_count,
        pages,
    })
}

fn content_has_non_text_graphics(content: &Content) -> bool {
    content.operations.iter().any(|operation| {
        matches!(
            operation.operator.as_str(),
            // Path construction and painting can carry signatures, stamps,
            // vector masks or table content that is absent from the text layer.
            "m" | "l"
                | "c"
                | "v"
                | "y"
                | "h"
                | "re"
                | "S"
                | "s"
                | "f"
                | "F"
                | "f*"
                | "B"
                | "B*"
                | "b"
                | "b*"
                | "W"
                | "W*"
                | "sh"
                // Extended graphics state may introduce transparency or a
                // soft mask even when no XObject is directly visible here.
                | "gs"
        )
    })
}

fn page_has_xobjects(document: &Document, page_id: ObjectId) -> Result<bool, ProcessingError> {
    let (direct_resources, resource_ids) = document
        .get_page_resources(page_id)
        .map_err(map_pdf_error)?;
    if direct_resources.is_some_and(|resources| resources_have_xobjects(document, resources)) {
        return Ok(true);
    }
    for resource_id in resource_ids {
        let resources = document
            .get_dictionary(resource_id)
            .map_err(map_pdf_error)?;
        if resources_have_xobjects(document, resources) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resources_have_xobjects(document: &Document, resources: &Dictionary) -> bool {
    let Ok(xobjects) = resources.get(b"XObject") else {
        return false;
    };
    match xobjects {
        Object::Dictionary(dictionary) => !dictionary.is_empty(),
        Object::Reference(object_id) => document
            .get_dictionary(*object_id)
            .map(|dictionary| !dictionary.is_empty())
            .unwrap_or(true),
        _ => true,
    }
}

fn page_has_annotations(document: &Document, page_id: ObjectId) -> Result<bool, ProcessingError> {
    let page = document.get_dictionary(page_id).map_err(map_pdf_error)?;
    let Ok(annotations) = page.get(b"Annots") else {
        return Ok(false);
    };
    let annotations = match annotations {
        Object::Array(values) => values,
        Object::Reference(object_id) => document
            .get_object(*object_id)
            .and_then(Object::as_array)
            .map_err(map_pdf_error)?,
        _ => return Err(ProcessingError::CorruptPdf),
    };
    Ok(!annotations.is_empty())
}

fn require_local_ocr(assessment: &mut TextLayerAssessment, reason: QualityReasonCode) {
    assessment
        .reason_codes
        .retain(|existing| *existing != QualityReasonCode::NativeTextHealthy);
    if !assessment.reason_codes.contains(&reason) {
        assessment.reason_codes.push(reason);
    }
    assessment.decision = PageExtractionDecision::LocalOcrRequired;
}
pub(crate) fn assess_text(
    page_number: u32,
    text: &str,
    limits: &ProcessingLimits,
) -> TextLayerAssessment {
    let characters = text.chars().collect::<Vec<_>>();
    let total = characters.len().max(1);
    let non_whitespace = characters
        .iter()
        .filter(|character| !character.is_whitespace())
        .count();
    let printable = characters
        .iter()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .count();
    let replacement = characters
        .iter()
        .filter(|character| matches!(character, '\u{fffd}' | '\u{25a1}'))
        .count();
    let cjk = characters
        .iter()
        .filter(|character| is_cjk(**character))
        .count();
    let non_empty_lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let single_character_lines = non_empty_lines
        .iter()
        .filter(|line| line.chars().count() <= 1)
        .count();
    let reading_order_score = if non_empty_lines.is_empty() {
        0.0
    } else {
        1.0 - single_character_lines as f32 / non_empty_lines.len() as f32
    };
    let printable_ratio = printable as f32 / total as f32;
    let replacement_char_ratio = replacement as f32 / total as f32;
    let cjk_ratio = if non_whitespace == 0 {
        0.0
    } else {
        cjk as f32 / non_whitespace as f32
    };

    let mut reasons = Vec::new();
    if non_whitespace < limits.min_native_chars {
        reasons.push(QualityReasonCode::TooLittleText);
    }
    if printable_ratio < limits.min_printable_ratio {
        reasons.push(QualityReasonCode::LowPrintableRatio);
    }
    if replacement_char_ratio > limits.max_replacement_ratio {
        reasons.push(QualityReasonCode::ExcessReplacementCharacters);
    }
    if reading_order_score < limits.min_reading_order_score {
        reasons.push(QualityReasonCode::SuspiciousReadingOrder);
    }
    let decision = if reasons.is_empty() {
        reasons.push(QualityReasonCode::NativeTextHealthy);
        PageExtractionDecision::NativeAccepted
    } else {
        PageExtractionDecision::LocalOcrRequired
    };

    TextLayerAssessment {
        page_number,
        non_whitespace_chars: u32::try_from(non_whitespace).unwrap_or(u32::MAX),
        printable_ratio,
        replacement_char_ratio,
        cjk_ratio,
        reading_order_score,
        decision,
        reason_codes: reasons,
    }
}

fn normalize_text(input: &str) -> Result<String, ProcessingError> {
    let mut normalized = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\0' {
            return Err(ProcessingError::CorruptPdf);
        }
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                let _ = characters.next();
            }
            normalized.push('\n');
        } else {
            normalized.push(character);
        }
    }
    Ok(normalized)
}

fn map_pdf_error(error: PdfError) -> ProcessingError {
    match error {
        PdfError::Decompress(DecompressError::MemoryLimitExceeded { .. }) => {
            ProcessingError::PageContentLimitExceeded
        }
        PdfError::AlreadyEncrypted
        | PdfError::InvalidPassword
        | PdfError::Decryption(_)
        | PdfError::UnsupportedSecurityHandler(_) => ProcessingError::EncryptedPdf,
        _ => ProcessingError::CorruptPdf,
    }
}

fn is_cjk(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_paths_and_extended_graphics_state_require_visual_completeness() {
        for bytes in [
            b"0 0 m 100 100 l S".as_slice(),
            b"10 10 30 30 re f".as_slice(),
            b"/GS1 gs".as_slice(),
        ] {
            let content = Content::decode(bytes).expect("decode content");
            assert!(content_has_non_text_graphics(&content));
        }
        let text_only = Content::decode(b"BT /F1 12 Tf (safe) Tj ET").expect("text content");
        assert!(!content_has_non_text_graphics(&text_only));
    }

    #[test]
    fn healthy_native_text_is_accepted() {
        let assessment = assess_text(
            1,
            "中华人民共和国民法典第五百七十七条规定违约责任。\n本页具有连续可读文本。",
            &ProcessingLimits::default(),
        );
        assert_eq!(assessment.decision, PageExtractionDecision::NativeAccepted);
        assert!(assessment
            .reason_codes
            .contains(&QualityReasonCode::NativeTextHealthy));
    }

    #[test]
    fn empty_garbled_and_one_character_per_line_require_ocr() {
        for text in [
            "",
            "\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□\u{FFFD}□",
            "一\n二\n三\n四\n五\n六\n七\n八\n九\n十\n甲\n乙\n丙\n丁\n戊\n己\n庚\n辛\n壬\n癸",
        ] {
            let assessment = assess_text(1, text, &ProcessingLimits::default());
            assert_eq!(
                assessment.decision,
                PageExtractionDecision::LocalOcrRequired
            );
        }
    }
}
