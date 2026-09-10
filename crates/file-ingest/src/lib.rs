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
use std::{
    fmt::{self, Write as _},
    io::Cursor,
    path::Path,
    sync::{Mutex, OnceLock},
};

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
/// Maximum rendered OCR image width or height.
pub const MAX_OCR_IMAGE_DIMENSION: u32 = 12_000;
/// Maximum rendered OCR image pixels.
pub const MAX_OCR_IMAGE_PIXELS: u64 = 80_000_000;
/// Maximum encoded page image sent to a vision provider.
pub const MAX_OCR_IMAGE_BYTES: usize = 12 * 1024 * 1024;
/// Maximum aggregate rendered image bytes retained for one PDF OCR job.
pub const MAX_OCR_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;

const PDF_MIME: &str = "application/pdf";
const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const TXT_MIME: &str = "text/plain; charset=utf-8";
const MARKDOWN_MIME: &str = "text/markdown; charset=utf-8";
const PNG_MIME: &str = "image/png";
const JPEG_MIME: &str = "image/jpeg";
const WEBP_MIME: &str = "image/webp";

/// A format accepted by the Stage 8 attachment importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Pdf,
    Docx,
    Txt,
    Markdown,
    Png,
    Jpeg,
    Webp,
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
            Self::Webp => "webp",
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
            Self::Webp => WEBP_MIME,
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

/// An image extracted from an attachment for a separately authorized vision request.
///
/// The bytes are sensitive and deliberately do not implement `Debug`. `locator` is a stable
/// page/media position and never contains a source path.
#[derive(Clone, PartialEq, Eq)]
pub struct OcrAsset {
    pub locator: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// Internal marker inserted into DOCX body text at the position of a validated embedded image.
///
/// The marker is never derived from a document relationship ID or source path.  The OCR pipeline
/// replaces it only after it has obtained the separately authorized visual transcription, so a
/// drawing stays at its original reading position instead of being appended to the document.
pub fn docx_ocr_placeholder(locator: &str) -> Option<String> {
    let index = locator.strip_prefix("docx-image:")?;
    if index.is_empty()
        || index.starts_with('0')
        || !index.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let index = index.parse::<usize>().ok()?;
    if index == 0 {
        return None;
    }
    Some(format!("\u{e000}LA_DOCX_OCR_IMAGE_{index}\u{e001}"))
}

/// Stable, payload-free failures suitable for conversion into sanitized IPC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IngestError {
    InvalidFileName,
    UnsupportedExtension,
    ImageRequiresLocalOcr,
    CorruptImage,
    ImageDimensionLimitExceeded,
    PdfiumUnavailable,
    PdfRenderFailed,
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
    UnsupportedTextEncoding,
    InvalidTextEncoding,
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
            Self::CorruptImage => "corrupt_image",
            Self::ImageDimensionLimitExceeded => "image_dimension_limit_exceeded",
            Self::PdfiumUnavailable => "pdfium_unavailable",
            Self::PdfRenderFailed => "pdf_render_failed",
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
            Self::UnsupportedTextEncoding => "unsupported_text_encoding",
            Self::InvalidTextEncoding => "invalid_text_encoding",
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
                "PNG, JPEG and WebP images require the isolated local OCR worker."
            }
            Self::CorruptImage => "The image is malformed or unsupported.",
            Self::ImageDimensionLimitExceeded => "The image exceeds the safe OCR dimensions.",
            Self::PdfiumUnavailable => "The bundled PDF renderer is unavailable.",
            Self::PdfRenderFailed => "The PDF page could not be rendered for OCR.",
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
            Self::UnsupportedTextEncoding => "The requested text encoding is not supported.",
            Self::InvalidTextEncoding => "The text file is not valid in the requested encoding.",
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
    } else if extension.eq_ignore_ascii_case("webp") {
        Ok(FileFormat::Webp)
    } else {
        Err(IngestError::UnsupportedExtension)
    }
}

/// Validate, hash and extract an attachment from original bytes.
pub fn ingest_bytes(file_name: &str, bytes: &[u8]) -> Result<ExtractedDocument, IngestError> {
    ingest_bytes_with_limits(file_name, bytes, Limits::default())
}

/// Extract plaintext accepted by the new privacy workspace.
///
/// TXT requires strict decoding: without an explicit encoding it is UTF-8 only. The accepted
/// explicit labels are UTF-8, GB18030, UTF-16, UTF-16LE and UTF-16BE. DOCX has no external text
/// encoding and is parsed through the guarded OOXML extractor; passing an encoding for DOCX is
/// rejected to avoid giving callers a false sense that container bytes were decoded as text.
pub fn extract_plain_text(
    file_name: &str,
    bytes: &[u8],
    encoding: Option<&str>,
) -> Result<String, IngestError> {
    let format = detect_format(file_name)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    match format {
        FileFormat::Txt => {
            if infer::get(bytes).is_some() {
                return Err(IngestError::FormatMismatch);
            }
            let decoded = decode_text(bytes, encoding)?;
            Ok(text::extract_decoded(&decoded, Limits::default())?.text)
        }
        FileFormat::Docx => {
            if encoding.is_some() {
                return Err(IngestError::UnsupportedTextEncoding);
            }
            Ok(ingest_bytes_with_limits(file_name, bytes, Limits::default())?.text)
        }
        _ => Err(IngestError::UnsupportedExtension),
    }
}

/// Extract the textual body of a DOCX while returning validated embedded PNG/JPEG assets for a
/// separately authorized vision request. The normal extractor continues to reject uninspected
/// media; callers must opt into this API explicitly when the AI OCR pipeline is enabled.
pub fn extract_plain_text_with_media(
    file_name: &str,
    bytes: &[u8],
) -> Result<(String, Vec<OcrAsset>), IngestError> {
    if detect_format(file_name)? != FileFormat::Docx {
        return Err(IngestError::UnsupportedExtension);
    }
    if bytes.len() > MAX_FILE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    verify_magic(FileFormat::Docx, bytes)?;
    let (extraction, media) = docx::extract_with_media(bytes, Limits::default())?;
    Ok((extraction.text, media))
}

/// Validate an image and return its dimensions without decoding the full pixel buffer. This is
/// used immediately before any remote OCR request; the legacy importer intentionally keeps its
/// `ImageRequiresLocalOcr` error for compatibility.
pub fn inspect_ocr_image(file_name: &str, bytes: &[u8]) -> Result<OcrAsset, IngestError> {
    let format = detect_format(file_name)?;
    if bytes.len() > MAX_OCR_IMAGE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    let (mime_type, width, height, ocr_bytes) = match format {
        FileFormat::Png => {
            verify_magic(format, bytes)?;
            let (width, height) = png_dimensions(bytes)?;
            (PNG_MIME, width, height, bytes.to_vec())
        }
        FileFormat::Jpeg => {
            verify_magic(format, bytes)?;
            let (width, height) = jpeg_dimensions(bytes)?;
            (JPEG_MIME, width, height, bytes.to_vec())
        }
        FileFormat::Webp => {
            verify_magic(format, bytes)?;
            let (png, width, height) = decode_webp_for_ocr(bytes)?;
            (PNG_MIME, width, height, png)
        }
        _ => return Err(IngestError::UnsupportedExtension),
    };
    validate_image_dimensions(width, height)?;
    Ok(OcrAsset {
        locator: "page:1".to_owned(),
        mime_type: mime_type.to_owned(),
        bytes: ocr_bytes,
        width,
        height,
    })
}

/// Decode WebP only after its extension and RIFF signature have been checked, then send a PNG
/// to the vision provider. This avoids relying on a provider-specific WebP implementation while
/// preserving the same locally enforced source-size and dimension limits as other OCR images.
fn decode_webp_for_ocr(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32), IngestError> {
    let dimensions = image::ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::WebP)
        .into_dimensions()
        .map_err(|_| IngestError::CorruptImage)?;
    validate_image_dimensions(dimensions.0, dimensions.1)?;

    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::WebP);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_OCR_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_OCR_IMAGE_DIMENSION);
    limits.max_alloc = Some(
        MAX_OCR_IMAGE_PIXELS
            .checked_mul(4)
            .ok_or(IngestError::ImageDimensionLimitExceeded)?,
    );
    reader.limits(limits);
    let image = reader.decode().map_err(|_| IngestError::CorruptImage)?;
    if (image.width(), image.height()) != dimensions {
        return Err(IngestError::CorruptImage);
    }
    let mut encoded = Cursor::new(Vec::new());
    image
        .write_to(&mut encoded, image::ImageFormat::Png)
        .map_err(|_| IngestError::CorruptImage)?;
    let encoded = encoded.into_inner();
    if encoded.len() > MAX_OCR_IMAGE_BYTES {
        return Err(IngestError::ImageDimensionLimitExceeded);
    }
    Ok((encoded, dimensions.0, dimensions.1))
}

/// Render every PDF page to a bounded PNG for cloud vision OCR. The caller supplies the path to
/// the packaged Pdfium DLL; no system installation is searched implicitly. Rendering is kept in
/// this crate so the workspace service can authorize and persist the resulting text without
/// exposing a parser or filesystem path to the browser.
pub fn render_pdf_pages(bytes: &[u8], pdfium_library: &Path) -> Result<Vec<OcrAsset>, IngestError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    verify_magic(FileFormat::Pdf, bytes)?;
    if !pdfium_library.is_absolute() || !pdfium_library.is_file() {
        return Err(IngestError::PdfiumUnavailable);
    }
    let pdfium = bind_pdfium(pdfium_library)?;
    let document = pdfium
        .load_pdf_from_byte_slice(bytes, None)
        .map_err(|_| IngestError::PdfRenderFailed)?;
    let page_count = document.pages().len();
    let page_count = usize::try_from(page_count).map_err(|_| IngestError::PdfPageLimitExceeded)?;
    if page_count > MAX_PDF_PAGES {
        return Err(IngestError::PdfPageLimitExceeded);
    }
    let mut assets = Vec::with_capacity(page_count);
    let mut total_encoded = 0usize;
    for (index, page) in document.pages().iter().enumerate() {
        let bitmap = page
            .render_with_config(
                &pdfium_render::prelude::PdfRenderConfig::new()
                    .set_target_width(1_600)
                    .set_maximum_width(2_400)
                    .set_maximum_height(3_200),
            )
            .map_err(|_| IngestError::PdfRenderFailed)?;
        let image = bitmap
            .as_image()
            .map_err(|_| IngestError::PdfRenderFailed)?;
        let (width, height) = (image.width(), image.height());
        validate_image_dimensions(width, height)?;
        let mut encoded = Cursor::new(Vec::new());
        image
            .write_to(&mut encoded, image::ImageFormat::Png)
            .map_err(|_| IngestError::PdfRenderFailed)?;
        let encoded = encoded.into_inner();
        if encoded.len() > MAX_OCR_IMAGE_BYTES {
            return Err(IngestError::ImageDimensionLimitExceeded);
        }
        total_encoded = total_encoded
            .checked_add(encoded.len())
            .ok_or(IngestError::FileTooLarge)?;
        if total_encoded > MAX_OCR_DOCUMENT_BYTES {
            return Err(IngestError::FileTooLarge);
        }
        assets.push(OcrAsset {
            locator: format!("page:{}", index + 1),
            mime_type: PNG_MIME.to_owned(),
            bytes: encoded,
            width,
            height,
        });
    }
    Ok(assets)
}

fn bind_pdfium(pdfium_library: &Path) -> Result<pdfium_render::prelude::Pdfium, IngestError> {
    static BOUND_PATH: OnceLock<Mutex<Option<std::path::PathBuf>>> = OnceLock::new();
    let state = BOUND_PATH.get_or_init(|| Mutex::new(None));
    let mut bound_path = state.lock().map_err(|_| IngestError::PdfiumUnavailable)?;
    if let Some(existing) = bound_path.as_ref() {
        return if existing == pdfium_library {
            Ok(pdfium_render::prelude::Pdfium::default())
        } else {
            Err(IngestError::PdfiumUnavailable)
        };
    }
    let bindings = pdfium_render::prelude::Pdfium::bind_to_library(pdfium_library)
        .map_err(|_| IngestError::PdfiumUnavailable)?;
    let pdfium = pdfium_render::prelude::Pdfium::new(bindings);
    *bound_path = Some(pdfium_library.to_owned());
    Ok(pdfium)
}

fn validate_image_dimensions(width: u32, height: u32) -> Result<(), IngestError> {
    if width == 0
        || height == 0
        || width > MAX_OCR_IMAGE_DIMENSION
        || height > MAX_OCR_IMAGE_DIMENSION
        || u64::from(width)
            .checked_mul(u64::from(height))
            .is_none_or(|pixels| pixels > MAX_OCR_IMAGE_PIXELS)
    {
        return Err(IngestError::ImageDimensionLimitExceeded);
    }
    Ok(())
}

pub(crate) fn inspect_image_payload(
    _name: &str,
    bytes: &[u8],
) -> Result<(String, u32, u32), IngestError> {
    if bytes.len() > MAX_OCR_IMAGE_BYTES {
        return Err(IngestError::FileTooLarge);
    }
    let Some(kind) = infer::get(bytes) else {
        return Err(IngestError::CorruptImage);
    };
    let mime = kind.mime_type();
    let (width, height) = match mime {
        PNG_MIME => png_dimensions(bytes)?,
        JPEG_MIME => jpeg_dimensions(bytes)?,
        _ => return Err(IngestError::CorruptImage),
    };
    validate_image_dimensions(width, height)?;
    Ok((mime.to_owned(), width, height))
}

fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), IngestError> {
    if bytes.len() < 24 || &bytes[12..16] != b"IHDR" {
        return Err(IngestError::CorruptImage);
    }
    let width = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| IngestError::CorruptImage)?,
    );
    let height = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| IngestError::CorruptImage)?,
    );
    Ok((width, height))
}

fn jpeg_dimensions(bytes: &[u8]) -> Result<(u32, u32), IngestError> {
    if bytes.len() < 4 || !bytes.starts_with(b"\xff\xd8\xff") || !bytes.ends_with(b"\xff\xd9") {
        return Err(IngestError::CorruptImage);
    }
    let mut cursor = 2usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor] != 0xff {
            cursor += 1;
        }
        while cursor < bytes.len() && bytes[cursor] == 0xff {
            cursor += 1;
        }
        let marker = *bytes.get(cursor).ok_or(IngestError::CorruptImage)?;
        cursor += 1;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if marker == 0x00 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(cursor).ok_or(IngestError::CorruptImage)?,
            *bytes.get(cursor + 1).ok_or(IngestError::CorruptImage)?,
        ]));
        if length < 2
            || cursor
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(IngestError::CorruptImage);
        }
        let is_sof = matches!(
            marker,
            0xc0..=0xc3
                | 0xc5..=0xc7
                | 0xc9..=0xcb
                | 0xcd..=0xcf
        );
        if is_sof {
            if length < 7 {
                return Err(IngestError::CorruptImage);
            }
            let height = u32::from(u16::from_be_bytes([bytes[cursor + 3], bytes[cursor + 4]]));
            let width = u32::from(u16::from_be_bytes([bytes[cursor + 5], bytes[cursor + 6]]));
            return Ok((width, height));
        }
        cursor += length;
    }
    Err(IngestError::CorruptImage)
}

fn decode_text(bytes: &[u8], encoding: Option<&str>) -> Result<String, IngestError> {
    let label = encoding.unwrap_or("utf-8").trim().to_ascii_lowercase();
    match label.as_str() {
        "utf-8" | "utf8" => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| IngestError::InvalidUtf8),
        "gb18030" => encoding_rs::GB18030
            .decode_without_bom_handling_and_without_replacement(bytes)
            .map(|value| value.into_owned())
            .ok_or(IngestError::InvalidTextEncoding),
        "utf-16" | "utf16" => decode_utf16_with_bom(bytes),
        "utf-16le" | "utf16le" => decode_with_encoding(encoding_rs::UTF_16LE, bytes),
        "utf-16be" | "utf16be" => decode_with_encoding(encoding_rs::UTF_16BE, bytes),
        _ => Err(IngestError::UnsupportedTextEncoding),
    }
}

fn decode_utf16_with_bom(bytes: &[u8]) -> Result<String, IngestError> {
    let Some((first, second)) = bytes.first().zip(bytes.get(1)) else {
        return Err(IngestError::InvalidTextEncoding);
    };
    match (*first, *second) {
        (0xff, 0xfe) => decode_with_encoding(encoding_rs::UTF_16LE, &bytes[2..]),
        (0xfe, 0xff) => decode_with_encoding(encoding_rs::UTF_16BE, &bytes[2..]),
        _ => Err(IngestError::InvalidTextEncoding),
    }
}

fn decode_with_encoding(
    encoding: &'static encoding_rs::Encoding,
    bytes: &[u8],
) -> Result<String, IngestError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(IngestError::InvalidTextEncoding);
    }
    encoding
        .decode_without_bom_handling_and_without_replacement(bytes)
        .map(|value| value.into_owned())
        .ok_or(IngestError::InvalidTextEncoding)
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
        FileFormat::Png | FileFormat::Jpeg | FileFormat::Webp => {
            return Err(IngestError::ImageRequiresLocalOcr);
        }
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
        FileFormat::Webp => {
            let inferred_webp = inferred.is_some_and(|kind| kind.mime_type() == WEBP_MIME);
            if bytes.len() < 12
                || !bytes.starts_with(b"RIFF")
                || bytes.get(8..12) != Some(b"WEBP".as_slice())
                || !inferred_webp
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
