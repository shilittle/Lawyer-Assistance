use crate::{Extraction, IngestError, Limits, TextBuilder};
use quick_xml::encoding::Decoder;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

pub(super) const CONTENT_TYPES_PATH: &str = "[Content_Types].xml";
pub(super) const ROOT_RELS_PATH: &str = "_rels/.rels";
pub(super) const DOCUMENT_PATH: &str = "word/document.xml";
const DOCUMENT_RELATIONSHIPS_PATH: &str = "word/_rels/document.xml.rels";
pub(super) const DOCX_MAIN_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
const OFFICE_DOCUMENT_REL_SUFFIX: &str = "/officeDocument";
const CONTENT_TYPES_NAMESPACE: &[u8] =
    b"http://schemas.openxmlformats.org/package/2006/content-types";
const PACKAGE_RELATIONSHIPS_NAMESPACE: &[u8] =
    b"http://schemas.openxmlformats.org/package/2006/relationships";
const WORD_NAMESPACE_TRANSITIONAL: &[u8] =
    b"http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const WORD_NAMESPACE_STRICT: &[u8] = b"http://purl.oclc.org/ooxml/wordprocessingml/main";
const DRAWING_NAMESPACE_TRANSITIONAL: &[u8] =
    b"http://schemas.openxmlformats.org/drawingml/2006/main";
const DRAWING_NAMESPACE_STRICT: &[u8] = b"http://purl.oclc.org/ooxml/drawingml/main";

#[derive(Debug)]
struct EntryMetadata {
    index: usize,
    name: String,
    size: u64,
    is_directory: bool,
}

pub(super) fn extract(bytes: &[u8], limits: Limits) -> Result<Extraction, IngestError> {
    extract_internal(bytes, limits, false).map(|(extraction, _)| extraction)
}

pub(super) fn extract_with_media(
    bytes: &[u8],
    limits: Limits,
) -> Result<(Extraction, Vec<crate::OcrAsset>), IngestError> {
    extract_internal(bytes, limits, true)
}

fn extract_internal(
    bytes: &[u8],
    limits: Limits,
    allow_media: bool,
) -> Result<(Extraction, Vec<crate::OcrAsset>), IngestError> {
    validate_declared_entry_count(bytes, limits.max_docx_entries)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| IngestError::CorruptDocx)?;
    let entries = scan_container(&mut archive, limits, allow_media)?;

    let mut content_types = None;
    let mut root_relationships = None;
    let mut document_xml = None;
    let mut actual_total = 0u64;
    let mut media_by_path = BTreeMap::new();
    let mut document_relationships = None;

    for metadata in entries {
        if metadata.is_directory {
            continue;
        }
        let mut entry = archive
            .by_index(metadata.index)
            .map_err(|_| IngestError::CorruptDocx)?;
        let read_cap = limits
            .max_docx_entry_bytes
            .checked_add(1)
            .ok_or(IngestError::DocxEntryTooLarge)?;
        let mut data = Vec::with_capacity(
            usize::try_from(metadata.size.min(64 * 1024))
                .map_err(|_| IngestError::DocxEntryTooLarge)?,
        );
        entry
            .by_ref()
            .take(read_cap)
            .read_to_end(&mut data)
            .map_err(|_| IngestError::CorruptDocx)?;
        let actual_size = u64::try_from(data.len()).map_err(|_| IngestError::DocxEntryTooLarge)?;
        if actual_size > limits.max_docx_entry_bytes {
            return Err(IngestError::DocxEntryTooLarge);
        }
        if actual_size != metadata.size {
            return Err(IngestError::CorruptDocx);
        }
        actual_total = actual_total
            .checked_add(actual_size)
            .ok_or(IngestError::DocxExpandedSizeExceeded)?;
        if actual_total > limits.max_docx_expanded_bytes {
            return Err(IngestError::DocxExpandedSizeExceeded);
        }

        let lowercase_name = metadata.name.to_ascii_lowercase();
        if lowercase_name.ends_with(".xml") || lowercase_name.ends_with(".rels") {
            validate_xml(&data)?;
        }
        if metadata.name == CONTENT_TYPES_PATH {
            content_types = Some(data);
        } else if metadata.name == ROOT_RELS_PATH {
            root_relationships = Some(data);
        } else if metadata.name == DOCUMENT_PATH {
            document_xml = Some(data);
        } else if metadata.name == DOCUMENT_RELATIONSHIPS_PATH {
            inspect_relationships(&data, false)?;
            document_relationships = Some(data);
        } else if allow_media && lowercase_name.starts_with("word/media/") {
            let (mime_type, width, height) = crate::inspect_image_payload(&metadata.name, &data)?;
            if media_by_path
                .insert(
                    metadata.name.clone(),
                    crate::OcrAsset {
                        locator: String::new(),
                        mime_type,
                        bytes: data,
                        width,
                        height,
                    },
                )
                .is_some()
            {
                return Err(IngestError::CorruptDocx);
            }
        } else if allow_media && lowercase_name.starts_with("customxml/") {
            // Custom XML is not rendered document text. Accept the empty metadata parts emitted
            // by common DOCX producers, but reject any non-whitespace payload rather than
            // silently omitting a possible sensitive field from the redaction source.
            inspect_xml_without_text(&data)?;
        } else if lowercase_name.ends_with(".rels") {
            inspect_relationships(&data, false)?;
        }
    }

    let content_types = content_types.ok_or(IngestError::CorruptDocx)?;
    let root_relationships = root_relationships.ok_or(IngestError::CorruptDocx)?;
    let document_xml = document_xml.ok_or(IngestError::CorruptDocx)?;
    inspect_content_types(&content_types)?;
    inspect_relationships(&root_relationships, true)?;
    let (media, drawing_markers) = if allow_media && !media_by_path.is_empty() {
        let document_relationships = document_relationships
            .as_deref()
            .ok_or(IngestError::IncompleteDocxExtraction)?;
        let image_relationships =
            document_image_relationships(document_relationships, &media_by_path)?;
        let mut media = Vec::with_capacity(image_relationships.len());
        let mut drawing_markers = BTreeMap::new();
        for (index, (relationship_id, target)) in image_relationships.into_iter().enumerate() {
            let locator = format!("docx-image:{}", index + 1);
            let marker = crate::docx_ocr_placeholder(&locator)
                .ok_or(IngestError::IncompleteDocxExtraction)?;
            let mut asset = media_by_path
                .get(&target)
                .cloned()
                .ok_or(IngestError::IncompleteDocxExtraction)?;
            asset.locator = locator;
            if drawing_markers.insert(relationship_id, marker).is_some() {
                return Err(IngestError::CorruptDocx);
            }
            media.push(asset);
        }
        (media, drawing_markers)
    } else {
        (Vec::new(), BTreeMap::new())
    };
    let extraction = extract_document_xml(
        &document_xml,
        limits,
        (!drawing_markers.is_empty()).then_some(&drawing_markers),
    )?;
    Ok((extraction, media))
}

fn validate_declared_entry_count(bytes: &[u8], maximum_entries: usize) -> Result<(), IngestError> {
    // The non-ZIP64 End of Central Directory record is at least 22 bytes and its comment is
    // bounded to u16::MAX. Stage 8's 20 MiB/2,000-entry DOCX profile never needs ZIP64, so a
    // ZIP64 sentinel is rejected instead of widening an attacker-controlled allocation.
    const EOCD_MIN_BYTES: usize = 22;
    const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
    if bytes.len() < EOCD_MIN_BYTES {
        return Err(IngestError::CorruptDocx);
    }
    let earliest = bytes
        .len()
        .saturating_sub(EOCD_MIN_BYTES + usize::from(u16::MAX));
    let latest = bytes.len() - EOCD_MIN_BYTES;
    let position = (earliest..=latest)
        .rev()
        .find(|position| {
            bytes[*position..].starts_with(EOCD_SIGNATURE)
                && read_u16_le(bytes, *position + 20).is_some_and(|comment_length| {
                    position.checked_add(EOCD_MIN_BYTES + usize::from(comment_length))
                        == Some(bytes.len())
                })
        })
        .ok_or(IngestError::CorruptDocx)?;

    let disk_number = read_u16_le(bytes, position + 4).ok_or(IngestError::CorruptDocx)?;
    let directory_disk = read_u16_le(bytes, position + 6).ok_or(IngestError::CorruptDocx)?;
    let entries_on_disk = read_u16_le(bytes, position + 8).ok_or(IngestError::CorruptDocx)?;
    let total_entries = read_u16_le(bytes, position + 10).ok_or(IngestError::CorruptDocx)?;
    if disk_number != 0 || directory_disk != 0 || entries_on_disk != total_entries {
        return Err(IngestError::CorruptDocx);
    }
    let entry_count = usize::from(total_entries);
    if total_entries == u16::MAX || entry_count > maximum_entries {
        return Err(IngestError::DocxEntryLimitExceeded);
    }

    let directory_size =
        usize::try_from(read_u32_le(bytes, position + 12).ok_or(IngestError::CorruptDocx)?)
            .map_err(|_| IngestError::CorruptDocx)?;
    let directory_start =
        usize::try_from(read_u32_le(bytes, position + 16).ok_or(IngestError::CorruptDocx)?)
            .map_err(|_| IngestError::CorruptDocx)?;
    let directory_end = directory_start
        .checked_add(directory_size)
        .ok_or(IngestError::CorruptDocx)?;
    if directory_end > position {
        return Err(IngestError::CorruptDocx);
    }
    Ok(())
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn scan_container(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    limits: Limits,
    allow_media: bool,
) -> Result<Vec<EntryMetadata>, IngestError> {
    if archive.len() > limits.max_docx_entries {
        return Err(IngestError::DocxEntryLimitExceeded);
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut names = HashSet::with_capacity(archive.len());
    let mut declared_total = 0u64;
    let mut compressed_total = 0u64;
    let mut has_content_types = false;
    let mut has_root_relationships = false;
    let mut has_document = false;

    for index in 0..archive.len() {
        let entry = archive
            .by_index_raw(index)
            .map_err(|_| IngestError::CorruptDocx)?;
        if entry.encrypted() {
            return Err(IngestError::EncryptedDocx);
        }
        if entry.enclosed_name().is_none() || entry.is_symlink() {
            return Err(IngestError::UnsafeArchiveEntry);
        }
        if !entry.is_file() && !entry.is_dir() {
            return Err(IngestError::UnsafeArchiveEntry);
        }
        validate_entry_name(entry.name(), entry.is_dir())?;
        let lowercase_name = entry.name().to_ascii_lowercase();
        if !names.insert(lowercase_name.clone()) {
            return Err(IngestError::UnsafeArchiveEntry);
        }
        if is_active_entry_name(&lowercase_name) {
            return Err(IngestError::ActiveContentNotAllowed);
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(IngestError::UnsupportedDocxCompression);
        }

        let size = entry.size();
        let compressed_size = entry.compressed_size();
        if size > limits.max_docx_entry_bytes {
            return Err(IngestError::DocxEntryTooLarge);
        }
        declared_total = declared_total
            .checked_add(size)
            .ok_or(IngestError::DocxExpandedSizeExceeded)?;
        compressed_total = compressed_total
            .checked_add(compressed_size)
            .ok_or(IngestError::DocxCompressionRatioExceeded)?;
        if declared_total > limits.max_docx_expanded_bytes {
            return Err(IngestError::DocxExpandedSizeExceeded);
        }
        if exceeds_ratio(size, compressed_size, limits.max_docx_compression_ratio) {
            return Err(IngestError::DocxCompressionRatioExceeded);
        }
        if entry.is_file()
            && is_uninspected_content_entry(&lowercase_name)
            && !(allow_media
                && (lowercase_name.starts_with("word/media/")
                    || lowercase_name.starts_with("customxml/")))
        {
            return Err(IngestError::IncompleteDocxExtraction);
        }

        has_content_types |= entry.name() == CONTENT_TYPES_PATH;
        has_root_relationships |= entry.name() == ROOT_RELS_PATH;
        has_document |= entry.name() == DOCUMENT_PATH;
        entries.push(EntryMetadata {
            index,
            name: entry.name().to_owned(),
            size,
            is_directory: entry.is_dir(),
        });
    }

    if !has_content_types || !has_root_relationships || !has_document {
        return Err(IngestError::CorruptDocx);
    }
    if exceeds_ratio(
        declared_total,
        compressed_total,
        limits.max_docx_compression_ratio,
    ) {
        return Err(IngestError::DocxCompressionRatioExceeded);
    }
    Ok(entries)
}

fn exceeds_ratio(uncompressed: u64, compressed: u64, maximum_ratio: u64) -> bool {
    if uncompressed == 0 {
        return false;
    }
    if compressed == 0 {
        return true;
    }
    compressed
        .checked_mul(maximum_ratio)
        .is_some_and(|maximum| uncompressed > maximum)
}

fn validate_entry_name(name: &str, is_directory: bool) -> Result<(), IngestError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains(['\0', '\\', ':'])
        || is_directory != name.ends_with('/')
    {
        return Err(IngestError::UnsafeArchiveEntry);
    }

    let without_directory_suffix = name.strip_suffix('/').unwrap_or(name);
    if without_directory_suffix.is_empty()
        || without_directory_suffix
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(IngestError::UnsafeArchiveEntry);
    }
    Ok(())
}

fn is_uninspected_content_entry(lowercase_name: &str) -> bool {
    lowercase_name.starts_with("word/header")
        || lowercase_name.starts_with("word/footer")
        || lowercase_name.starts_with("word/comments")
        || lowercase_name.starts_with("word/threadedcomments")
        || lowercase_name.starts_with("word/media/")
        || lowercase_name.starts_with("word/charts/")
        || lowercase_name.starts_with("word/diagrams/")
        || lowercase_name.starts_with("word/drawings/")
        || lowercase_name.starts_with("word/ink/")
        || lowercase_name.starts_with("word/glossary/")
        || lowercase_name.starts_with("customxml/")
        || matches!(
            lowercase_name,
            "word/footnotes.xml" | "word/endnotes.xml" | "word/people.xml"
        )
}
fn is_active_entry_name(lowercase_name: &str) -> bool {
    let path_markers = [
        "/activex/",
        "/embeddings/",
        "/scripts/",
        "/oleobject",
        "/vbaproject",
        "/afchunk",
    ];
    let active_extensions = [
        ".bin", ".exe", ".dll", ".com", ".bat", ".cmd", ".msi", ".js", ".vbs", ".ps1", ".hta",
        ".jar", ".html", ".xhtml", ".svg", ".svgz", ".mjs", ".cjs", ".wsf", ".wsh", ".sct", ".scr",
        ".pif", ".lnk", ".url", ".chm", ".xsl", ".xslt",
    ];
    path_markers
        .iter()
        .any(|marker| lowercase_name.contains(marker))
        || lowercase_name.starts_with("activex/")
        || lowercase_name.starts_with("embeddings/")
        || lowercase_name.starts_with("scripts/")
        || active_extensions
            .iter()
            .any(|extension| lowercase_name.ends_with(extension))
}

fn validate_xml(bytes: &[u8]) -> Result<(), IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().check_comments = true;
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut closed_root = false;

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        if matches!(resolution, ResolveResult::Unknown(_))
            && matches!(event, Event::Start(_) | Event::Empty(_) | Event::End(_))
        {
            return Err(IngestError::CorruptDocx);
        }
        match event {
            Event::Start(_) => {
                if depth == 0 {
                    if saw_root || closed_root {
                        return Err(IngestError::CorruptDocx);
                    }
                    saw_root = true;
                }
                depth = depth.checked_add(1).ok_or(IngestError::CorruptDocx)?;
            }
            Event::Empty(_) if depth == 0 => {
                if saw_root || closed_root {
                    return Err(IngestError::CorruptDocx);
                }
                saw_root = true;
                closed_root = true;
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(IngestError::CorruptDocx)?;
                if depth == 0 {
                    closed_root = true;
                }
            }
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Text(text) if depth == 0 => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::CData(text) if depth == 0 => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::GeneralRef(reference) => {
                resolve_reference(&reference)?;
                if depth == 0 {
                    return Err(IngestError::CorruptDocx);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_root || !closed_root || depth != 0 {
        return Err(IngestError::CorruptDocx);
    }
    Ok(())
}

fn ensure_outer_xml_whitespace(content: &str) -> Result<(), IngestError> {
    if content.trim().is_empty() {
        Ok(())
    } else {
        Err(IngestError::CorruptDocx)
    }
}

fn inspect_xml_without_text(bytes: &[u8]) -> Result<(), IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    loop {
        let (_, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        match event {
            Event::Text(text) => {
                let decoded = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                let unescaped =
                    quick_xml::escape::unescape(&decoded).map_err(|_| IngestError::CorruptDocx)?;
                if !unescaped.trim().is_empty() {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
            }
            Event::CData(text) => {
                let decoded = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                if !decoded.trim().is_empty() {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
            }
            Event::GeneralRef(_) => return Err(IngestError::IncompleteDocxExtraction),
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(())
}

fn inspect_content_types(bytes: &[u8]) -> Result<(), IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    let decoder = reader.decoder();
    let mut main_document_count = 0usize;
    let mut saw_root = false;

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        let in_content_types_namespace = is_bound_to(&resolution, CONTENT_TYPES_NAMESPACE);
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let local_name = element.local_name();
                if !saw_root {
                    if local_name.as_ref() != b"Types" || !in_content_types_namespace {
                        return Err(IngestError::CorruptDocx);
                    }
                    saw_root = true;
                } else if local_name.as_ref() == b"Override" {
                    if !in_content_types_namespace {
                        return Err(IngestError::CorruptDocx);
                    }
                    let part_name = attribute_value(&element, b"PartName", decoder)?
                        .ok_or(IngestError::CorruptDocx)?;
                    let content_type = attribute_value(&element, b"ContentType", decoder)?
                        .ok_or(IngestError::CorruptDocx)?;
                    if is_active_marker(&content_type.to_ascii_lowercase()) {
                        return Err(IngestError::ActiveContentNotAllowed);
                    }
                    if part_name == "/word/document.xml" {
                        if !content_type.eq_ignore_ascii_case(DOCX_MAIN_CONTENT_TYPE) {
                            return Err(IngestError::ActiveContentNotAllowed);
                        }
                        main_document_count = main_document_count
                            .checked_add(1)
                            .ok_or(IngestError::CorruptDocx)?;
                    }
                } else if local_name.as_ref() == b"Default" {
                    if !in_content_types_namespace {
                        return Err(IngestError::CorruptDocx);
                    }
                    if let Some(content_type) = attribute_value(&element, b"ContentType", decoder)?
                    {
                        if is_active_marker(&content_type.to_ascii_lowercase()) {
                            return Err(IngestError::ActiveContentNotAllowed);
                        }
                    }
                } else {
                    return Err(IngestError::CorruptDocx);
                }
            }
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Text(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::CData(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::GeneralRef(_) => return Err(IngestError::CorruptDocx),
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_root || main_document_count != 1 {
        return Err(IngestError::CorruptDocx);
    }
    Ok(())
}

fn inspect_relationships(bytes: &[u8], require_office_document: bool) -> Result<(), IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    let decoder = reader.decoder();
    let mut office_document_count = 0usize;
    let mut saw_root = false;

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        let in_relationships_namespace = is_bound_to(&resolution, PACKAGE_RELATIONSHIPS_NAMESPACE);
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let local_name = element.local_name();
                if !saw_root {
                    if local_name.as_ref() != b"Relationships" || !in_relationships_namespace {
                        return Err(IngestError::CorruptDocx);
                    }
                    saw_root = true;
                } else if local_name.as_ref() == b"Relationship" {
                    if !in_relationships_namespace {
                        return Err(IngestError::CorruptDocx);
                    }
                    let relationship_type = attribute_value(&element, b"Type", decoder)?
                        .ok_or(IngestError::CorruptDocx)?;
                    let target = attribute_value(&element, b"Target", decoder)?
                        .ok_or(IngestError::CorruptDocx)?;
                    let target_mode = attribute_value(&element, b"TargetMode", decoder)?;
                    let lowercase_type = relationship_type.to_ascii_lowercase();
                    let lowercase_target = target.to_ascii_lowercase();
                    if is_active_marker(&lowercase_type) || is_active_target(&lowercase_target) {
                        return Err(IngestError::ActiveContentNotAllowed);
                    }
                    if relationship_type.ends_with(OFFICE_DOCUMENT_REL_SUFFIX) {
                        let normalized_target = target.strip_prefix('/').unwrap_or(&target);
                        if target_mode
                            .as_deref()
                            .is_some_and(|mode| mode.eq_ignore_ascii_case("External"))
                            || normalized_target != DOCUMENT_PATH
                        {
                            return Err(IngestError::CorruptDocx);
                        }
                        office_document_count = office_document_count
                            .checked_add(1)
                            .ok_or(IngestError::CorruptDocx)?;
                    }
                } else {
                    return Err(IngestError::CorruptDocx);
                }
            }
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Text(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::CData(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::GeneralRef(_) => return Err(IngestError::CorruptDocx),
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_root || (require_office_document && office_document_count != 1) {
        return Err(IngestError::CorruptDocx);
    }
    Ok(())
}

/// Resolve the document's embedded-image relationships before accepting their payloads for OCR.
/// A ZIP entry order is not a document reading order, so callers must use this map together with
/// the `a:blip r:embed` encountered in `word/document.xml`.
fn document_image_relationships(
    bytes: &[u8],
    media_by_path: &BTreeMap<String, crate::OcrAsset>,
) -> Result<BTreeMap<String, String>, IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    let decoder = reader.decoder();
    let mut saw_root = false;
    let mut relationships = BTreeMap::new();

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        let is_relationships = is_bound_to(&resolution, PACKAGE_RELATIONSHIPS_NAMESPACE);
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let local_name = element.local_name();
                if !saw_root {
                    if local_name.as_ref() != b"Relationships" || !is_relationships {
                        return Err(IngestError::CorruptDocx);
                    }
                    saw_root = true;
                } else if local_name.as_ref() == b"Relationship" && is_relationships {
                    let relationship_type = attribute_value(&element, b"Type", decoder)?
                        .ok_or(IngestError::CorruptDocx)?;
                    if relationship_type.to_ascii_lowercase().ends_with("/image") {
                        let relationship_id = attribute_value(&element, b"Id", decoder)?
                            .ok_or(IngestError::CorruptDocx)?;
                        let target = attribute_value(&element, b"Target", decoder)?
                            .ok_or(IngestError::CorruptDocx)?;
                        let target_mode = attribute_value(&element, b"TargetMode", decoder)?;
                        if target_mode
                            .as_deref()
                            .is_some_and(|mode| mode.eq_ignore_ascii_case("External"))
                        {
                            return Err(IngestError::IncompleteDocxExtraction);
                        }
                        let target = document_media_target(&target)?;
                        if !media_by_path.contains_key(&target)
                            || relationships.insert(relationship_id, target).is_some()
                        {
                            return Err(IngestError::IncompleteDocxExtraction);
                        }
                    }
                } else {
                    return Err(IngestError::CorruptDocx);
                }
            }
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Text(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::CData(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                ensure_outer_xml_whitespace(&content)?;
            }
            Event::GeneralRef(_) => return Err(IngestError::CorruptDocx),
            Event::Eof => break,
            _ => {}
        }
    }

    let referenced_media = relationships.values().collect::<HashSet<_>>();
    if !saw_root
        || relationships.is_empty()
        || referenced_media.len() != media_by_path.len()
        || !media_by_path
            .keys()
            .all(|path| referenced_media.contains(path))
    {
        return Err(IngestError::IncompleteDocxExtraction);
    }
    Ok(relationships)
}

fn document_media_target(target: &str) -> Result<String, IngestError> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains(['\\', ':', '\0'])
        || target
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(IngestError::IncompleteDocxExtraction);
    }
    Ok(format!("word/{target}"))
}

fn is_bound_to(resolution: &ResolveResult<'_>, expected: &[u8]) -> bool {
    matches!(
        resolution,
        ResolveResult::Bound(namespace)
            if namespace.as_ref() == expected
    )
}

fn is_active_marker(lowercase_value: &str) -> bool {
    [
        "macroenabled",
        "vbaproject",
        "activex",
        "oleobject",
        "attachedtemplate",
        "altchunk",
        "afchunk",
        "script",
        "relationships/package",
        "application/x-msdownload",
    ]
    .iter()
    .any(|marker| lowercase_value.contains(marker))
}

fn is_active_target(lowercase_target: &str) -> bool {
    is_active_entry_name(lowercase_target)
        || lowercase_target.contains("vbaproject")
        || lowercase_target.contains("oleobject")
        || lowercase_target.contains("activex")
        || lowercase_target.contains("embeddings")
}

fn attribute_value(
    element: &BytesStart<'_>,
    expected_local_name: &[u8],
    decoder: Decoder,
) -> Result<Option<String>, IngestError> {
    let mut value = None;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| IngestError::CorruptDocx)?;
        if attribute.key.as_ref() == expected_local_name {
            if value.is_some() {
                return Err(IngestError::CorruptDocx);
            }
            value = Some(
                attribute
                    .decode_and_unescape_value(decoder)
                    .map_err(|_| IngestError::CorruptDocx)?
                    .into_owned(),
            );
        }
    }
    Ok(value)
}

fn extract_document_xml(
    bytes: &[u8],
    limits: Limits,
    drawing_markers: Option<&BTreeMap<String, String>>,
) -> Result<Extraction, IngestError> {
    let mut reader = NsReader::from_reader(bytes);
    let mut builder = TextBuilder::new(limits);
    let mut saw_document_root = false;
    let mut saw_body = false;
    let mut paragraph_number = 0usize;
    let mut paragraph = None::<String>;
    let mut in_text = false;
    let mut drawing_marker_counts = BTreeMap::<String, usize>::new();

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        let is_word = is_word_namespace(&resolution);
        if matches!(resolution, ResolveResult::Unknown(_))
            && matches!(event, Event::Start(_) | Event::Empty(_) | Event::End(_))
        {
            return Err(IngestError::CorruptDocx);
        }

        match event {
            Event::Start(element) => {
                let local_name = element.local_name();
                if is_word && is_revision_element(local_name.as_ref()) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                if is_word && local_name.as_ref() == b"drawing" {
                    let drawing_markers =
                        drawing_markers.ok_or(IngestError::IncompleteDocxExtraction)?;
                    if paragraph.is_none() || in_text {
                        return Err(IngestError::CorruptDocx);
                    }
                    let relationship_id = consume_drawing(&mut reader)?;
                    let marker = drawing_markers
                        .get(&relationship_id)
                        .ok_or(IngestError::IncompleteDocxExtraction)?;
                    append_paragraph_text(
                        paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                        marker,
                        limits.max_text_bytes,
                    )?;
                    let count = drawing_marker_counts.entry(marker.clone()).or_default();
                    *count = count.checked_add(1).ok_or(IngestError::TextLimitExceeded)?;
                    continue;
                }
                if is_word && is_unhandled_document_content(local_name.as_ref()) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                if !saw_document_root {
                    if !is_word || local_name.as_ref() != b"document" {
                        return Err(IngestError::CorruptDocx);
                    }
                    saw_document_root = true;
                }
                if is_word && local_name.as_ref() == b"body" {
                    saw_body = true;
                } else if is_word && local_name.as_ref() == b"p" {
                    if paragraph.is_some() {
                        return Err(IngestError::CorruptDocx);
                    }
                    paragraph_number = paragraph_number
                        .checked_add(1)
                        .ok_or(IngestError::SegmentLimitExceeded)?;
                    paragraph = Some(String::new());
                } else if is_word && local_name.as_ref() == b"t" {
                    if paragraph.is_none() || in_text {
                        return Err(IngestError::CorruptDocx);
                    }
                    in_text = true;
                }
            }
            Event::Empty(element) if is_word => {
                if is_revision_element(element.local_name().as_ref()) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                if is_unhandled_document_content(element.local_name().as_ref()) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                match element.local_name().as_ref() {
                    b"p" => {
                        paragraph_number = paragraph_number
                            .checked_add(1)
                            .ok_or(IngestError::SegmentLimitExceeded)?;
                    }
                    b"tab" if paragraph.is_some() => {
                        append_paragraph_text(
                            paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                            "\t",
                            limits.max_text_bytes,
                        )?;
                    }
                    b"br" | b"cr" if paragraph.is_some() => {
                        append_paragraph_text(
                            paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                            "\n",
                            limits.max_text_bytes,
                        )?;
                    }
                    _ => {}
                }
            }
            Event::End(element) if is_word && element.local_name().as_ref() == b"t" => {
                if !in_text {
                    return Err(IngestError::CorruptDocx);
                }
                in_text = false;
            }
            Event::End(element) if is_word && element.local_name().as_ref() == b"p" => {
                if in_text {
                    return Err(IngestError::CorruptDocx);
                }
                // Text extraction is the redaction source of truth. Do not trim runs here:
                // leading/trailing whitespace and explicit line breaks can be material in legal
                // text and the minimal exporter verifies an exact extraction round-trip.
                let paragraph_text = paragraph.take().ok_or(IngestError::CorruptDocx)?;
                if !paragraph_text.is_empty() {
                    builder.push(
                        format!("paragraph:{paragraph_number}"),
                        paragraph_text,
                        "\n",
                    )?;
                }
            }
            Event::Text(text) if in_text => {
                let decoded = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                let unescaped =
                    quick_xml::escape::unescape(&decoded).map_err(|_| IngestError::CorruptDocx)?;
                append_paragraph_text(
                    paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                    &unescaped,
                    limits.max_text_bytes,
                )?;
            }
            Event::CData(text) if in_text => {
                let decoded = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                append_paragraph_text(
                    paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                    &decoded,
                    limits.max_text_bytes,
                )?;
            }
            Event::GeneralRef(reference) if in_text => {
                let resolved = resolve_reference(&reference)?;
                let mut buffer = [0u8; 4];
                append_paragraph_text(
                    paragraph.as_mut().ok_or(IngestError::CorruptDocx)?,
                    resolved.encode_utf8(&mut buffer),
                    limits.max_text_bytes,
                )?;
            }
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_document_root || !saw_body || paragraph.is_some() || in_text {
        return Err(IngestError::CorruptDocx);
    }
    let extraction = builder.finish(None);
    if drawing_marker_counts
        .iter()
        .any(|(marker, expected_count)| {
            extraction.text.match_indices(marker).count() != *expected_count
        })
    {
        // A source run cannot be allowed to impersonate an internal image marker.  The count
        // also makes sure a malformed drawing was not silently dropped while parsing.
        return Err(IngestError::IncompleteDocxExtraction);
    }
    Ok(extraction)
}

fn consume_drawing(reader: &mut NsReader<&[u8]>) -> Result<String, IngestError> {
    let decoder = reader.decoder();
    let mut depth = 1usize;
    let mut embedded_relationship = None;

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| IngestError::CorruptDocx)?;
        if matches!(resolution, ResolveResult::Unknown(_))
            && matches!(event, Event::Start(_) | Event::Empty(_) | Event::End(_))
        {
            return Err(IngestError::CorruptDocx);
        }
        let is_drawing = is_drawing_namespace(&resolution);
        match event {
            Event::Start(element) => {
                if is_drawing && is_visual_text_element(&element) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                if is_drawing && element.local_name().as_ref() == b"blip" {
                    set_embedded_relationship(
                        &mut embedded_relationship,
                        drawing_embed_relationship(&element, decoder)?,
                    )?;
                }
                depth = depth.checked_add(1).ok_or(IngestError::CorruptDocx)?;
            }
            Event::Empty(element) => {
                if is_drawing && is_visual_text_element(&element) {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
                if is_drawing && element.local_name().as_ref() == b"blip" {
                    set_embedded_relationship(
                        &mut embedded_relationship,
                        drawing_embed_relationship(&element, decoder)?,
                    )?;
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(IngestError::CorruptDocx)?;
                if depth == 0 {
                    return embedded_relationship.ok_or(IngestError::IncompleteDocxExtraction);
                }
            }
            Event::Text(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                if !content.trim().is_empty() {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
            }
            Event::CData(text) => {
                let content = text.xml_content().map_err(|_| IngestError::CorruptDocx)?;
                if !content.trim().is_empty() {
                    return Err(IngestError::IncompleteDocxExtraction);
                }
            }
            Event::GeneralRef(_) => return Err(IngestError::IncompleteDocxExtraction),
            Event::DocType(_) => return Err(IngestError::XmlDoctypeNotAllowed),
            Event::Eof => return Err(IngestError::CorruptDocx),
            _ => {}
        }
    }
}

fn is_visual_text_element(element: &BytesStart<'_>) -> bool {
    matches!(element.local_name().as_ref(), b"t" | b"txbxContent")
}

fn drawing_embed_relationship(
    element: &BytesStart<'_>,
    decoder: Decoder,
) -> Result<Option<String>, IngestError> {
    let mut relationship = None;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| IngestError::CorruptDocx)?;
        // DOCX DrawingML uses the relationships namespace through the conventional `r` prefix.
        // An unqualified `embed` is intentionally not treated as a relationship.
        if attribute.key.as_ref() == b"r:embed" {
            if relationship.is_some() {
                return Err(IngestError::CorruptDocx);
            }
            relationship = Some(
                attribute
                    .decode_and_unescape_value(decoder)
                    .map_err(|_| IngestError::CorruptDocx)?
                    .into_owned(),
            );
        }
    }
    Ok(relationship)
}

fn set_embedded_relationship(
    destination: &mut Option<String>,
    relationship: Option<String>,
) -> Result<(), IngestError> {
    let relationship = relationship.ok_or(IngestError::IncompleteDocxExtraction)?;
    if relationship.is_empty() || destination.replace(relationship).is_some() {
        return Err(IngestError::IncompleteDocxExtraction);
    }
    Ok(())
}

fn is_revision_element(local_name: &[u8]) -> bool {
    matches!(
        local_name,
        b"del"
            | b"ins"
            | b"moveFrom"
            | b"moveTo"
            | b"moveFromRangeStart"
            | b"moveFromRangeEnd"
            | b"moveToRangeStart"
            | b"moveToRangeEnd"
            | b"rPrChange"
            | b"pPrChange"
            | b"tblPrChange"
            | b"tblGridChange"
            | b"trPrChange"
            | b"tcPrChange"
            | b"sectPrChange"
            | b"numberingChange"
    )
}

/// These WordprocessingML constructs either contain text outside the literal paragraph/run
/// stream or draw/compute visible content. The workspace deliberately rebuilds a minimal DOCX,
/// so accepting any of them would silently lose potentially sensitive material.
fn is_unhandled_document_content(local_name: &[u8]) -> bool {
    matches!(
        local_name,
        b"drawing"
            | b"pict"
            | b"object"
            | b"altChunk"
            | b"txbxContent"
            | b"fldSimple"
            | b"instrText"
            | b"fldChar"
            | b"ruby"
            | b"annotationRef"
    )
}
fn is_word_namespace(resolution: &ResolveResult<'_>) -> bool {
    matches!(
        resolution,
        ResolveResult::Bound(namespace)
            if namespace.as_ref() == WORD_NAMESPACE_TRANSITIONAL
                || namespace.as_ref() == WORD_NAMESPACE_STRICT
    )
}

fn is_drawing_namespace(resolution: &ResolveResult<'_>) -> bool {
    matches!(
        resolution,
        ResolveResult::Bound(namespace)
            if namespace.as_ref() == DRAWING_NAMESPACE_TRANSITIONAL
                || namespace.as_ref() == DRAWING_NAMESPACE_STRICT
    )
}

fn append_paragraph_text(
    paragraph: &mut String,
    value: &str,
    max_text_bytes: usize,
) -> Result<(), IngestError> {
    if value.contains('\0') {
        return Err(IngestError::CorruptDocx);
    }
    let next_size = paragraph
        .len()
        .checked_add(value.len())
        .ok_or(IngestError::TextLimitExceeded)?;
    if next_size > max_text_bytes {
        return Err(IngestError::TextLimitExceeded);
    }
    paragraph.push_str(value);
    Ok(())
}

fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, IngestError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|_| IngestError::CorruptDocx)?
    {
        if character == '\0' {
            return Err(IngestError::CorruptDocx);
        }
        return Ok(character);
    }
    match reference
        .decode()
        .map_err(|_| IngestError::CorruptDocx)?
        .as_ref()
    {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(IngestError::CorruptDocx),
    }
}
