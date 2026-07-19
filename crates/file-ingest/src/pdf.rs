use crate::{IngestError, Limits, TextBuilder};
use lopdf::{DecompressError, Document, Error as PdfError, LoadOptions};

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
