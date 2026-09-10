use crate::{IngestError, Limits, PdfPage, TextBuilder};
use lopdf::{
    content::Content, DecompressError, Dictionary, Document, Error as PdfError, LoadOptions, Object,
};
use std::collections::HashSet;

pub(super) fn extract(bytes: &[u8], limits: Limits) -> Result<crate::Extraction, IngestError> {
    let options = LoadOptions::with_max_decompressed_size(limits.max_pdf_page_content_bytes);
    let document = Document::load_mem_with_options(bytes, options).map_err(map_pdf_error)?;
    if document.is_encrypted() || document.was_encrypted() {
        return Err(IngestError::EncryptedPdf);
    }

    let pages = document.get_pages();
    if pages.len() > limits.max_pdf_pages {
        return Err(IngestError::PdfPageLimitExceeded);
    }
    let page_count = u32::try_from(pages.len()).map_err(|_| IngestError::PdfPageLimitExceeded)?;
    let mut builder = TextBuilder::new(limits);

    for page_number in pages.keys().copied() {
        let extracted = document
            .extract_text_with_limit(&[page_number], limits.max_pdf_page_content_bytes)
            .map_err(map_pdf_error)?;
        let normalized = normalize_pdf_text(&extracted)?;
        let normalized = normalized.trim().to_owned();
        if !normalized.is_empty() {
            builder.push(format!("page:{page_number}"), normalized, "\n")?;
        }
    }

    let result = builder.finish(Some(page_count));
    if result.text.trim().is_empty() {
        return Err(IngestError::NonTextPdf);
    }
    Ok(result)
}

pub(super) fn inspect_pages(bytes: &[u8], limits: Limits) -> Result<Vec<PdfPage>, IngestError> {
    let options = LoadOptions::with_max_decompressed_size(limits.max_pdf_page_content_bytes);
    let document = Document::load_mem_with_options(bytes, options).map_err(map_pdf_error)?;
    if document.is_encrypted() || document.was_encrypted() {
        return Err(IngestError::EncryptedPdf);
    }
    let pages = document.get_pages();
    if pages.len() > limits.max_pdf_pages {
        return Err(IngestError::PdfPageLimitExceeded);
    }
    let mut total_text = 0usize;
    let mut result = Vec::with_capacity(pages.len());
    for (page_number, page_id) in pages {
        let extracted = document
            .extract_text_with_limit(&[page_number], limits.max_pdf_page_content_bytes)
            .map_err(map_pdf_error)?;
        let text = normalize_pdf_text(&extracted)?.trim().to_owned();
        let separator = usize::from(!text.is_empty() && total_text > 0);
        total_text = total_text
            .checked_add(separator)
            .and_then(|size| size.checked_add(text.len()))
            .ok_or(IngestError::TextLimitExceeded)?;
        if total_text > limits.max_text_bytes {
            return Err(IngestError::TextLimitExceeded);
        }
        let mut seen = HashSet::new();
        let has_images = page_has_images(
            &document,
            page_id,
            limits.max_pdf_page_content_bytes,
            &mut seen,
        )
        .map_err(map_pdf_error)?;
        result.push(PdfPage {
            number: page_number,
            locator: format!("page:{page_number}"),
            needs_ocr: text.is_empty() || has_images,
            text,
        });
    }
    Ok(result)
}

fn page_has_images(
    document: &Document,
    page_id: lopdf::ObjectId,
    max_page_content_bytes: usize,
    seen: &mut HashSet<lopdf::ObjectId>,
) -> Result<bool, PdfError> {
    let content = document.get_page_content_with_limit(page_id, max_page_content_bytes)?;
    if Content::decode(&content)?
        .operations
        .iter()
        .any(|operation| operation.operator == "BI")
    {
        return Ok(true);
    }
    let (direct, inherited) = document.get_page_resources(page_id)?;
    if let Some(resources) = direct {
        if resources_have_images(document, resources, seen)? {
            return Ok(true);
        }
    }
    for resource_id in inherited {
        if resources_have_images(document, document.get_dictionary(resource_id)?, seen)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resources_have_images(
    document: &Document,
    resources: &Dictionary,
    seen: &mut HashSet<lopdf::ObjectId>,
) -> Result<bool, PdfError> {
    let xobjects = match resources.get(b"XObject") {
        Ok(Object::Reference(id)) => document.get_dictionary(*id)?,
        Ok(Object::Dictionary(dictionary)) => dictionary,
        Ok(_) => {
            return Err(PdfError::ObjectType {
                expected: "Dictionary",
                found: "other",
            })
        }
        Err(_) => return Ok(false),
    };
    for (_, object) in xobjects.iter() {
        if xobject_has_image(document, object, seen)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn xobject_has_image(
    document: &Document,
    object: &Object,
    seen: &mut HashSet<lopdf::ObjectId>,
) -> Result<bool, PdfError> {
    let object = match object {
        Object::Reference(id) => {
            if !seen.insert(*id) {
                return Ok(false);
            }
            document.get_object(*id)?
        }
        object => object,
    };
    let dictionary = match object {
        Object::Stream(stream) => &stream.dict,
        Object::Dictionary(dictionary) => dictionary,
        _ => return Ok(false),
    };
    if matches!(
        dictionary.get(b"Subtype").and_then(Object::as_name),
        Ok(b"Image")
    ) {
        return Ok(true);
    }
    if matches!(
        dictionary.get(b"Subtype").and_then(Object::as_name),
        Ok(b"Form")
    ) {
        if let Ok(resources) = dictionary.get(b"Resources") {
            return match resources {
                Object::Reference(id) => {
                    resources_have_images(document, document.get_dictionary(*id)?, seen)
                }
                Object::Dictionary(resources) => resources_have_images(document, resources, seen),
                _ => Err(PdfError::ObjectType {
                    expected: "Dictionary",
                    found: "other",
                }),
            };
        }
    }
    Ok(false)
}

fn normalize_pdf_text(input: &str) -> Result<String, IngestError> {
    let mut normalized = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\0' {
            return Err(IngestError::CorruptPdf);
        }
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            normalized.push('\n');
        } else {
            normalized.push(character);
        }
    }
    Ok(normalized)
}

fn map_pdf_error(error: PdfError) -> IngestError {
    match error {
        PdfError::Decompress(DecompressError::MemoryLimitExceeded { .. }) => {
            IngestError::PdfContentLimitExceeded
        }
        PdfError::AlreadyEncrypted
        | PdfError::InvalidPassword
        | PdfError::Decryption(_)
        | PdfError::UnsupportedSecurityHandler(_) => IngestError::EncryptedPdf,
        _ => IngestError::CorruptPdf,
    }
}
