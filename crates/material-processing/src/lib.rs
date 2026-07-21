//! Local-only legal material extraction and MinerU orchestration.
//!
//! Searchable PDF pages use the bounded native text layer. Pages whose text
//! layer is empty or suspicious require a version-pinned local MinerU worker.
//! No URL, SSH host, cloud OCR, or silent remote fallback exists in this crate.

mod mineru;
mod mineru_config;
mod native;
mod safe_export;
mod types;
mod worker_protocol;
mod worker_protocol_validation;

pub use mineru_config::validate_local_mineru_config;
pub use native::assess_pdf_text_layer;
pub use safe_export::*;
pub use types::*;
pub use worker_protocol::*;
pub use worker_protocol_validation::*;

use mineru::run_local_mineru;
use native::extract_native_pdf;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Arc},
};

pub fn process_pdf(
    bytes: &[u8],
    ocr_mode: OcrMode,
    mineru: Option<&LocalMineruConfig>,
    limits: ProcessingLimits,
) -> Result<ProcessedDocument, ProcessingError> {
    process_pdf_with_cancel(bytes, ocr_mode, mineru, limits, None)
}

pub fn process_pdf_with_cancel(
    bytes: &[u8],
    ocr_mode: OcrMode,
    mineru: Option<&LocalMineruConfig>,
    limits: ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
) -> Result<ProcessedDocument, ProcessingError> {
    let mut native = extract_native_pdf(bytes, &limits)?;
    let required_pages = match ocr_mode {
        OcrMode::ForceLocal => {
            for page in &mut native.pages {
                page.assessment.decision = PageExtractionDecision::LocalOcrRequired;
                page.assessment.reason_codes = vec![QualityReasonCode::ForcedLocalOcr];
            }
            native
                .pages
                .iter()
                .map(|page| page.page_number)
                .collect::<Vec<_>>()
        }
        OcrMode::AutoLocal | OcrMode::Off => native
            .pages
            .iter()
            .filter(|page| page.assessment.decision == PageExtractionDecision::LocalOcrRequired)
            .map(|page| page.page_number)
            .collect::<Vec<_>>(),
    };

    if !required_pages.is_empty() && ocr_mode == OcrMode::Off {
        return Err(ProcessingError::OcrDisabled);
    }

    let ocr_run = if required_pages.is_empty() {
        None
    } else {
        let config = mineru.ok_or(ProcessingError::OcrBackendUnavailable)?;
        Some(run_local_mineru(
            bytes,
            native.page_count,
            &required_pages,
            config,
            &limits,
            cancelled,
        )?)
    };
    let required = required_pages.iter().copied().collect::<BTreeSet<_>>();
    let mut pages = Vec::with_capacity(native.pages.len());
    let mut native_pages = Vec::new();
    for page in native.pages {
        let spans = if required.contains(&page.page_number) {
            let spans = ocr_run
                .as_ref()
                .and_then(|run| run.spans_by_page.get(&page.page_number))
                .cloned()
                .ok_or(ProcessingError::OcrOutputIncomplete)?;
            if spans.is_empty() {
                return Err(ProcessingError::OcrOutputIncomplete);
            }
            spans
        } else {
            native_pages.push(page.page_number);
            if page.text.trim().is_empty() {
                Vec::new()
            } else {
                vec![ProcessedSpan {
                    span_id: format!(
                        "native-{}-{}",
                        page.page_number,
                        short_hash(page.text.as_bytes())
                    ),
                    text: page.text,
                    bbox: None,
                    confidence: None,
                    kind: SpanKind::Text,
                    backend: ExtractionBackend::NativeText,
                }]
            }
        };
        pages.push(ProcessedPage {
            page_number: page.page_number,
            assessment: page.assessment,
            spans,
        });
    }

    let mut backend_trace = Vec::new();
    if !native_pages.is_empty() {
        backend_trace.push(BackendTrace {
            backend: ExtractionBackend::NativeText,
            worker_sha256: None,
            model_manifest_sha256: None,
            config_sha256: None,
            device: "cpu".to_owned(),
            page_numbers: native_pages,
            isolation_verified: true,
            isolation_mechanism: Some("in_process_no_network_code_path".to_owned()),
        });
    }
    if let Some(run) = ocr_run {
        backend_trace.push(run.trace);
    }

    Ok(ProcessedDocument {
        processing_version: MATERIAL_PROCESSING_VERSION.to_owned(),
        source_sha256: native.source_sha256,
        media_type: "application/pdf".to_owned(),
        page_count: native.page_count,
        backend_trace,
        pages,
    })
}

fn short_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(12);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.iter().take(6) {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{
        content::{Content, Operation},
        dictionary, Document, Object, Stream,
    };

    fn pdf_with_text(text: Option<&str>) -> Vec<u8> {
        pdf_with_text_and_image(text, false)
    }

    fn pdf_with_text_and_image(text: Option<&str>, include_image: bool) -> Vec<u8> {
        pdf_with_text_and_visual(text, include_image, false)
    }

    fn pdf_with_text_and_vector(text: Option<&str>) -> Vec<u8> {
        pdf_with_text_and_visual(text, false, true)
    }

    fn pdf_with_text_and_visual(
        text: Option<&str>,
        include_image: bool,
        include_vector: bool,
    ) -> Vec<u8> {
        let mut document = Document::with_version("1.5");
        let pages_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let mut resources = dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        };
        let mut operations = text.map_or_else(Vec::new, |value| {
            vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
                Operation::new("Td", vec![20.into(), 100.into()]),
                Operation::new("Tj", vec![Object::string_literal(value)]),
                Operation::new("ET", vec![]),
            ]
        });
        if include_vector {
            operations.extend([
                Operation::new("re", vec![40.into(), 40.into(), 120.into(), 80.into()]),
                Operation::new("f", vec![]),
            ]);
        }
        if include_image {
            let image_id = document.add_object(Stream::new(
                dictionary! {
                    "Type" => "XObject",
                    "Subtype" => "Image",
                    "Width" => 1,
                    "Height" => 1,
                    "ColorSpace" => "DeviceGray",
                    "BitsPerComponent" => 8,
                },
                vec![0],
            ));
            resources.set("XObject", dictionary! { "Im1" => image_id });
            operations.extend([
                Operation::new("q", vec![]),
                Operation::new(
                    "cm",
                    vec![
                        200.into(),
                        0.into(),
                        0.into(),
                        200.into(),
                        0.into(),
                        0.into(),
                    ],
                ),
                Operation::new("Do", vec![Object::Name(b"Im1".to_vec())]),
                Operation::new("Q", vec![]),
            ]);
        }
        let resources_id = document.add_object(resources);
        let content = Content { operations }.encode().expect("encode PDF content");
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 300.into(), 300.into()],
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).expect("save PDF");
        bytes
    }
    #[test]
    fn healthy_searchable_pdf_stays_on_native_local_path() {
        let bytes = pdf_with_text(Some(
            "This searchable legal document contains enough continuous text for native extraction.",
        ));
        let processed = process_pdf(
            &bytes,
            OcrMode::AutoLocal,
            None,
            ProcessingLimits::default(),
        )
        .expect("native processing");
        assert_eq!(processed.page_count, 1);
        assert_eq!(processed.backend_trace.len(), 1);
        assert_eq!(
            processed.backend_trace[0].backend,
            ExtractionBackend::NativeText
        );
    }

    #[test]
    fn searchable_text_plus_page_image_requires_local_ocr() {
        let bytes = pdf_with_text_and_image(
            Some("This hidden searchable layer looks healthy but the visible scan may contain secrets."),
            true,
        );
        let assessments =
            assess_pdf_text_layer(&bytes, &ProcessingLimits::default()).expect("assessment");
        assert_eq!(
            assessments[0].decision,
            PageExtractionDecision::LocalOcrRequired
        );
        assert!(assessments[0]
            .reason_codes
            .contains(&QualityReasonCode::VisualContentPresent));
        assert_eq!(
            process_pdf(&bytes, OcrMode::Off, None, ProcessingLimits::default()),
            Err(ProcessingError::OcrDisabled)
        );
        assert_eq!(
            process_pdf(
                &bytes,
                OcrMode::AutoLocal,
                None,
                ProcessingLimits::default()
            ),
            Err(ProcessingError::OcrBackendUnavailable)
        );
    }
    #[test]
    fn healthy_text_with_vector_signature_requires_local_ocr() {
        let bytes = pdf_with_text_and_vector(Some(
            "This page has a complete text layer, but the vector stamp is not represented in it.",
        ));
        let assessments =
            assess_pdf_text_layer(&bytes, &ProcessingLimits::default()).expect("assessment");
        assert_eq!(
            assessments[0].decision,
            PageExtractionDecision::LocalOcrRequired
        );
        assert!(assessments[0]
            .reason_codes
            .contains(&QualityReasonCode::VisualContentPresent));
        assert_eq!(
            process_pdf(&bytes, OcrMode::Off, None, ProcessingLimits::default()),
            Err(ProcessingError::OcrDisabled)
        );
    }

    #[test]
    fn scanned_or_empty_pdf_fails_closed_when_ocr_is_off() {
        let bytes = pdf_with_text(None);
        assert_eq!(
            process_pdf(&bytes, OcrMode::Off, None, ProcessingLimits::default()),
            Err(ProcessingError::OcrDisabled)
        );
        assert_eq!(
            process_pdf(
                &bytes,
                OcrMode::AutoLocal,
                None,
                ProcessingLimits::default()
            ),
            Err(ProcessingError::OcrBackendUnavailable)
        );
    }
}
