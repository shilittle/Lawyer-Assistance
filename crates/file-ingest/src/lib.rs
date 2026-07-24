//! Bounded, deterministic extraction for the attachment formats accepted by Stage 8.
//!
//! This crate deliberately accepts bytes plus a basename, rather than a path. The desktop
//! boundary is responsible for choosing and reading a file. This keeps absolute paths out of
//! extraction errors and makes the parser independent from Tauri, persistence, networking and
//! logging.

mod docx;
mod pdf;
mod text;

use sha2::{Digest, Sha256};
use std::fmt::{self, Write as _};

/// Maximum accepted size of one source file (20 MiB).
pub const MAX_FILE_BYTES: usize = 20 * 1024 * 1024;
/// Maximum number of pages in a PDF.
pub const MAX_PDF_PAGES: usize = 200;
/// Maximum decompressed bytes for an individual PDF stream/page extraction operation.
pub const MAX_PDF_PAGE_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of entries in a DOCX ZIP container.
pub const MAX_DOCX_ENTRIES: usize = 2_000;
/// Maximum uncompressed size of one DOCX ZIP entry (16 MiB).
pub const MAX_DOCX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum declared and actually-read uncompressed total for a DOCX (64 MiB).
pub const MAX_DOCX_EXPANDED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum uncompressed-to-compressed ratio for a DOCX entry and the aggregate archive.
pub const MAX_DOCX_COMPRESSION_RATIO: u64 = 100;
/// Maximum extracted UTF-8 text size (2 MiB).
pub const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of extracted locator segments.
pub const MAX_SEGMENTS: usize = 5_000;
/// Number of normalized lines grouped into one TXT/Markdown segment.
pub const TEXT_LINES_PER_SEGMENT: usize = 40;
/// Maximum accepted basename length in UTF-8 bytes.
pub const MAX_FILE_NAME_BYTES: usize = 255;

const PDF_MIME: &str = "application/pdf";
const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const TXT_MIME: &str = "text/plain; charset=utf-8";
const MARKDOWN_MIME: &str = "text/markdown; charset=utf-8";
const PNG_MIME: &str = "image/png";
const JPEG_MIME: &str = "image/jpeg";

/// A format accepted by the Stage 8 attachment importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Pdf,
    Docx,
    Txt,
    Markdown,
    Png,
    Jpeg,
}

impl FileFormat {
    /// Stable storage/API value for the format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Docx => "docx",
            Self::Txt => "txt",
            Self::Markdown => "md",
            Self::Png => "png",
            Self::Jpeg => "jpeg",
        }
    }

    /// MIME value emitted after extension, magic and container validation succeed.
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Pdf => PDF_MIME,
            Self::Docx => DOCX_MIME,
            Self::Txt => TXT_MIME,
            Self::Markdown => MARKDOWN_MIME,
            Self::Png => PNG_MIME,
            Self::Jpeg => JPEG_MIME,
        }
    }
}

impl fmt::Display for FileFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One deterministic, bounded section of extracted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSegment {
    /// `page:n`, `paragraph:n`, or `line:start-end`.
    pub locator: String,
    /// Text belonging to this locator. It never contains source paths.
    pub text: String,
}

/// Fully validated extraction result ready for conversion into desktop/database types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedDocument {
    /// Validated basename supplied by the desktop boundary.
    pub file_name: String,
    pub format: FileFormat,
    pub mime_type: String,
    /// Lowercase hexadecimal SHA-256 of the original bytes.
    pub sha256_hex: String,
    pub size_bytes: u64,
    /// Present for PDF, absent for formats without a page model.
    pub page_count: Option<u32>,
    /// Normalized extracted text, bounded by [`MAX_TEXT_BYTES`].
    pub text: String,
    /// Deterministically ordered, bounded locator segments.
    pub segments: Vec<ExtractedSegment>,
}

/// Stable, payload-free failures suitable for conversion into sanitized IPC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IngestError {
    InvalidFileName,
    UnsupportedExtension,
    ImageRequiresLocalOcr,
    FormatMismatch,
    FileTooLarge,
    CorruptPdf,
    EncryptedPdf,
    PdfPageLimitExceeded,
    PdfContentLimitExceeded,
    NonTextPdf,
    CorruptDocx,
    EncryptedDocx,
    UnsafeArchiveEntry,
    UnsupportedDocxCompression,
    IncompleteDocxExtraction,
    DocxEntryLimitExceeded,
    DocxEntryTooLarge,
    DocxExpandedSizeExceeded,
    DocxCompressionRatioExceeded,
    ActiveContentNotAllowed,
    XmlDoctypeNotAllowed,
    InvalidUtf8,
    NulByteNotAllowed,
    TextLimitExceeded,
    SegmentLimitExceeded,
}

impl IngestError {
    /// Stable machine-readable discriminator. It intentionally contains no dynamic data.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFileName => "invalid_file_name",
            Self::UnsupportedExtension => "unsupported_extension",
            Self::ImageRequiresLocalOcr => "image_requires_local_ocr",
            Self::FormatMismatch => "format_mismatch",
            Self::FileTooLarge => "file_too_large",
            Self::CorruptPdf => "corrupt_pdf",
            Self::EncryptedPdf => "encrypted_pdf",
            Self::PdfPageLimitExceeded => "pdf_page_limit_exceeded",
            Self::PdfContentLimitExceeded => "pdf_content_limit_exceeded",
            Self::NonTextPdf => "non_text_pdf",
            Self::CorruptDocx => "corrupt_docx",
            Self::EncryptedDocx => "encrypted_docx",
            Self::UnsafeArchiveEntry => "unsafe_archive_entry",
            Self::UnsupportedDocxCompression => "unsupported_docx_compression",
            Self::IncompleteDocxExtraction => "incomplete_docx_extraction",
            Self::DocxEntryLimitExceeded => "docx_entry_limit_exceeded",
            Self::DocxEntryTooLarge => "docx_entry_too_large",
            Self::DocxExpandedSizeExceeded => "docx_expanded_size_exceeded",
            Self::DocxCompressionRatioExceeded => "docx_compression_ratio_exceeded",
            Self::ActiveContentNotAllowed => "active_content_not_allowed",
            Self::XmlDoctypeNotAllowed => "xml_doctype_not_allowed",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::NulByteNotAllowed => "nul_byte_not_allowed",
            Self::TextLimitExceeded => "text_limit_exceeded",
            Self::SegmentLimitExceeded => "segment_limit_exceeded",
        }
    }

    /// Sanitized user-facing summary. It intentionally omits source/library error text.
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidFileName => "The file name must be a safe basename.",
            Self::UnsupportedExtension => "This file extension is not supported.",
            Self::ImageRequiresLocalOcr => {
                "PNG and JPEG images require the isolated local OCR worker."
            }
            Self::FormatMismatch => "The file extension does not match its content.",
            Self::FileTooLarge => "The file exceeds the attachment size limit.",
            Self::CorruptPdf => "The PDF is malformed or unsupported.",
            Self::EncryptedPdf => "Encrypted PDF files are not supported.",
            Self::PdfPageLimitExceeded => "The PDF exceeds the page limit.",
            Self::PdfContentLimitExceeded => "The PDF exceeds a safe content limit.",
            Self::NonTextPdf => "The PDF has no extractable text layer.",
            Self::CorruptDocx => "The DOCX container is malformed or incomplete.",
            Self::EncryptedDocx => "Encrypted DOCX files are not supported.",
            Self::UnsafeArchiveEntry => "The DOCX contains an unsafe archive entry.",
            Self::UnsupportedDocxCompression => "The DOCX uses an unsupported compression method.",
            Self::IncompleteDocxExtraction => {
                "The DOCX contains text or images that this local extractor cannot fully inspect."
            }
            Self::DocxEntryLimitExceeded => "The DOCX contains too many archive entries.",
            Self::DocxEntryTooLarge => "A DOCX archive entry exceeds the size limit.",
            Self::DocxExpandedSizeExceeded => "The DOCX expands beyond the size limit.",
            Self::DocxCompressionRatioExceeded => "The DOCX exceeds the safe compression ratio.",
            Self::ActiveContentNotAllowed => "Active or embedded DOCX content is not allowed.",
            Self::XmlDoctypeNotAllowed => "DOCX XML document type declarations are not allowed.",
            Self::InvalidUtf8 => "The text file is not valid UTF-8.",
            Self::NulByteNotAllowed => "NUL bytes are not allowed in text attachments.",
            Self::TextLimitExceeded => "The extracted text exceeds the size limit.",
            Self::SegmentLimitExceeded => "The extracted text exceeds the segment limit.",
        }
    }
}

impl fmt::Display for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for IngestError {}

/// Validate a basename and return the format selected by its extension.
pub fn detect_format(file_name: &str) -> Result<FileFormat, IngestError> {
    validate_basename(file_name)?;
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .filter(|extension| !extension.is_empty())
        .ok_or(IngestError::UnsupportedExtension)?;

    if extension.eq_ignore_ascii_case("pdf") {
        Ok(FileFormat::Pdf)
    } else if extension.eq_ignore_ascii_case("docx") {
        Ok(FileFormat::Docx)
    } else if extension.eq_ignore_ascii_case("txt") {
        Ok(FileFormat::Txt)
    } else if extension.eq_ignore_ascii_case("md") || extension.eq_ignore_ascii_case("markdown") {
        Ok(FileFormat::Markdown)
    } else if extension.eq_ignore_ascii_case("png") {
        Ok(FileFormat::Png)
    } else if extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg") {
        Ok(FileFormat::Jpeg)
    } else {
        Err(IngestError::UnsupportedExtension)
    }
}

/// Validate, hash and extract an attachment from original bytes.
pub fn ingest_bytes(file_name: &str, bytes: &[u8]) -> Result<ExtractedDocument, IngestError> {
    ingest_bytes_with_limits(file_name, bytes, Limits::default())
}

fn ingest_bytes_with_limits(
    file_name: &str,
    bytes: &[u8],
    limits: Limits,
) -> Result<ExtractedDocument, IngestError> {
    let format = detect_format(file_name)?;
    if bytes.len() > limits.max_file_bytes {
        return Err(IngestError::FileTooLarge);
    }
    verify_magic(format, bytes)?;

    let extraction = match format {
        FileFormat::Pdf => pdf::extract(bytes, limits)?,
        FileFormat::Docx => docx::extract(bytes, limits)?,
        FileFormat::Txt | FileFormat::Markdown => text::extract(bytes, limits)?,
        FileFormat::Png | FileFormat::Jpeg => return Err(IngestError::ImageRequiresLocalOcr),
    };

    let size_bytes = u64::try_from(bytes.len()).map_err(|_| IngestError::FileTooLarge)?;
    Ok(ExtractedDocument {
        file_name: file_name.to_owned(),
        format,
        mime_type: format.mime_type().to_owned(),
        sha256_hex: sha256_hex(bytes),
        size_bytes,
        page_count: extraction.page_count,
        text: extraction.text,
        segments: extraction.segments,
    })
}

fn validate_basename(file_name: &str) -> Result<(), IngestError> {
    if file_name.is_empty()
        || file_name.len() > MAX_FILE_NAME_BYTES
        || matches!(file_name, "." | "..")
        || file_name.ends_with('.')
        || file_name.chars().any(|character| {
            character == '\0'
                || character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
                )
        })
    {
        return Err(IngestError::InvalidFileName);
    }
    Ok(())
}

fn verify_magic(format: FileFormat, bytes: &[u8]) -> Result<(), IngestError> {
    let inferred = infer::get(bytes);
    match format {
        FileFormat::Pdf => {
            let inferred_pdf = inferred.is_some_and(|kind| kind.mime_type() == PDF_MIME);
            if !bytes.starts_with(b"%PDF-") || !inferred_pdf {
                return Err(IngestError::FormatMismatch);
            }
        }
        FileFormat::Docx => {
            // Password-protected OOXML is commonly wrapped in an OLE/CFB compound file
            // (`EncryptedPackage` + `EncryptionInfo`) instead of remaining a ZIP container.
            // We do not attempt password handling or parse the compound payload.
            if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
                return Err(IngestError::EncryptedDocx);
            }
            let inferred_ooxml_or_zip = inferred
                .is_some_and(|kind| matches!(kind.mime_type(), DOCX_MIME | "application/zip"));
            if !bytes.starts_with(b"PK\x03\x04") || !inferred_ooxml_or_zip {
                return Err(IngestError::FormatMismatch);
            }
        }
        FileFormat::Png => {
            let inferred_png = inferred.is_some_and(|kind| kind.mime_type() == PNG_MIME);
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") || !inferred_png {
                return Err(IngestError::FormatMismatch);
            }
        }
        FileFormat::Jpeg => {
            let inferred_jpeg = inferred.is_some_and(|kind| kind.mime_type() == JPEG_MIME);
            if !bytes.starts_with(b"\xff\xd8\xff")
                || !bytes.ends_with(b"\xff\xd9")
                || !inferred_jpeg
            {
                return Err(IngestError::FormatMismatch);
            }
        }
        FileFormat::Txt | FileFormat::Markdown => {
            // Text formats have no authoritative magic. A known binary signature is a mismatch;
            // strict UTF-8 and NUL validation below provide the positive content check.
            if inferred.is_some() {
                return Err(IngestError::FormatMismatch);
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing into a String is infallible.
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_file_bytes: usize,
    max_pdf_pages: usize,
    max_pdf_page_content_bytes: usize,
    max_docx_entries: usize,
    max_docx_entry_bytes: u64,
    max_docx_expanded_bytes: u64,
    max_docx_compression_ratio: u64,
    max_text_bytes: usize,
    max_segments: usize,
    text_lines_per_segment: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_FILE_BYTES,
            max_pdf_pages: MAX_PDF_PAGES,
            max_pdf_page_content_bytes: MAX_PDF_PAGE_CONTENT_BYTES,
            max_docx_entries: MAX_DOCX_ENTRIES,
            max_docx_entry_bytes: MAX_DOCX_ENTRY_BYTES,
            max_docx_expanded_bytes: MAX_DOCX_EXPANDED_BYTES,
            max_docx_compression_ratio: MAX_DOCX_COMPRESSION_RATIO,
            max_text_bytes: MAX_TEXT_BYTES,
            max_segments: MAX_SEGMENTS,
            text_lines_per_segment: TEXT_LINES_PER_SEGMENT,
        }
    }
}

struct Extraction {
    page_count: Option<u32>,
    text: String,
    segments: Vec<ExtractedSegment>,
}

struct TextBuilder {
    text: String,
    segments: Vec<ExtractedSegment>,
    max_text_bytes: usize,
    max_segments: usize,
}

impl TextBuilder {
    fn new(limits: Limits) -> Self {
        Self {
            text: String::new(),
            segments: Vec::new(),
            max_text_bytes: limits.max_text_bytes,
            max_segments: limits.max_segments,
        }
    }

    fn push(
        &mut self,
        locator: String,
        segment_text: String,
        separator: &str,
    ) -> Result<(), IngestError> {
        if segment_text.is_empty() {
            return Ok(());
        }
        if self.segments.len() >= self.max_segments {
            return Err(IngestError::SegmentLimitExceeded);
        }
        let separator_bytes = if self.text.is_empty() {
            0
        } else {
            separator.len()
        };
        let next_size = self
            .text
            .len()
            .checked_add(separator_bytes)
            .and_then(|size| size.checked_add(segment_text.len()))
            .ok_or(IngestError::TextLimitExceeded)?;
        if next_size > self.max_text_bytes {
            return Err(IngestError::TextLimitExceeded);
        }
        if !self.text.is_empty() {
            self.text.push_str(separator);
        }
        self.text.push_str(&segment_text);
        self.segments.push(ExtractedSegment {
            locator,
            text: segment_text,
        });
        Ok(())
    }

    fn finish(self, page_count: Option<u32>) -> Extraction {
        Extraction {
            page_count,
            text: self.text,
            segments: self.segments,
        }
    }
}

#[cfg(test)]
mod tests;
