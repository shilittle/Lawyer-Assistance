use super::*;
use crate::docx::{CONTENT_TYPES_PATH, DOCUMENT_PATH, DOCX_MAIN_CONTENT_TYPE, ROOT_RELS_PATH};
use lopdf::{
    dictionary, Document, EncryptionState, EncryptionVersion, Object, Permissions, Stream,
};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const CONTENT_TYPES_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="{main_content_type}"/>
</Types>"#;

const ROOT_RELATIONSHIPS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

fn word_document(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{body}<w:sectPr/></w:body>
</w:document>"#
    )
}

fn make_docx(document_xml: &str) -> Vec<u8> {
    make_docx_with(
        document_xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[],
        CompressionMethod::Deflated,
    )
}

fn make_docx_with(
    document_xml: &str,
    main_content_type: &str,
    extra_entries: &[(&str, &[u8])],
    compression: CompressionMethod,
) -> Vec<u8> {
    let content_types = CONTENT_TYPES_TEMPLATE.replace("{main_content_type}", main_content_type);
    make_docx_parts(
        &content_types,
        ROOT_RELATIONSHIPS,
        document_xml,
        extra_entries,
        compression,
    )
}

fn make_docx_parts(
    content_types: &str,
    root_relationships: &str,
    document_xml: &str,
    extra_entries: &[(&str, &[u8])],
    compression: CompressionMethod,
) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(compression);

    writer.start_file(CONTENT_TYPES_PATH, options).unwrap();
    writer.write_all(content_types.as_bytes()).unwrap();
    writer.start_file(ROOT_RELS_PATH, options).unwrap();
    writer.write_all(root_relationships.as_bytes()).unwrap();
    writer.start_file(DOCUMENT_PATH, options).unwrap();
    writer.write_all(document_xml.as_bytes()).unwrap();
    for (name, data) in extra_entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn make_pdf(page_texts: &[Option<&str>]) -> Vec<u8> {
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let resources_id = document.add_object(dictionary! {
        "Font" => dictionary! { "F1" => Object::Reference(font_id) },
    });
    let mut page_ids = Vec::new();

    for page_text in page_texts {
        let content = match page_text {
            Some(text) => format!("BT\n/F1 12 Tf\n72 720 Td\n({text}) Tj\nET\n").into_bytes(),
            None => b"q\n1 0 0 1 0 0 cm\nQ\n".to_vec(),
        };
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let page_id = document.new_object_id();
        document.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page",
                "Parent" => Object::Reference(pages_id),
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Resources" => Object::Reference(resources_id),
                "Contents" => Object::Reference(content_id),
            }),
        );
        page_ids.push(page_id);
    }

    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(page_ids.len()).unwrap(),
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
    });
    document.trailer.set("Root", Object::Reference(catalog_id));
    document.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal("fixture-primary"),
            Object::string_literal("fixture-secondary"),
        ]),
    );
    save_pdf(document)
}

fn save_pdf(mut document: Document) -> Vec<u8> {
    let mut bytes = Vec::new();
    document.save_to(&mut bytes).unwrap();
    bytes
}

fn make_encrypted_pdf() -> Vec<u8> {
    let bytes = make_pdf(&[Some("secret")]);
    let mut document = Document::load_mem(&bytes).unwrap();
    let encryption = EncryptionVersion::V2 {
        document: &document,
        owner_password: "owner-secret",
        user_password: "user-secret",
        key_length: 128,
        permissions: Permissions::all(),
    };
    let state = EncryptionState::try_from(encryption).unwrap();
    document.encrypt(&state).unwrap();
    save_pdf(document)
}

fn mark_zip_encrypted(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut index = 0usize;
    while index + 10 <= bytes.len() {
        if bytes[index..].starts_with(b"PK\x03\x04") {
            bytes[index + 6] |= 1;
        } else if bytes[index..].starts_with(b"PK\x01\x02") {
            bytes[index + 8] |= 1;
        }
        index += 1;
    }
    bytes
}

fn replace_all_equal_length(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut offset = 0usize;
    while offset + from.len() <= bytes.len() {
        if bytes[offset..].starts_with(from) {
            bytes[offset..offset + from.len()].copy_from_slice(to);
            offset += from.len();
        } else {
            offset += 1;
        }
    }
}

#[test]
fn extracts_pdf_with_page_locators() {
    let bytes = make_pdf(&[Some("First page"), Some("Second page")]);
    let document = ingest_bytes("evidence.PDF", &bytes).unwrap();
    assert_eq!(document.format, FileFormat::Pdf);
    assert_eq!(document.mime_type, PDF_MIME);
    assert_eq!(document.page_count, Some(2));
    assert!(document.text.contains("First page"));
    assert!(document.text.contains("Second page"));
    assert_eq!(document.segments.len(), 2);
    assert_eq!(document.segments[0].locator, "page:1");
    assert_eq!(document.segments[1].locator, "page:2");
}

#[test]
fn extracts_deflated_docx_with_physical_paragraph_locators() {
    let xml = word_document(
        "<w:p><w:r><w:t>Alpha &amp; beta</w:t></w:r></w:p>\
         <w:p/>\
         <w:p><w:r><w:t>Gamma</w:t><w:tab/><w:t>delta</w:t></w:r></w:p>",
    );
    let bytes = make_docx(&xml);
    let document = ingest_bytes("brief.docx", &bytes).unwrap();
    assert_eq!(document.format, FileFormat::Docx);
    assert_eq!(document.mime_type, DOCX_MIME);
    assert_eq!(document.page_count, None);
    assert_eq!(document.text, "Alpha & beta\nGamma\tdelta");
    assert_eq!(
        document
            .segments
            .iter()
            .map(|segment| segment.locator.as_str())
            .collect::<Vec<_>>(),
        ["paragraph:1", "paragraph:3"]
    );
}

#[test]
fn extracts_utf8_txt_and_normalizes_line_endings() {
    let input = (1..=41)
        .map(|line| format!("line {line}"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let document = ingest_bytes("notes.txt", input.as_bytes()).unwrap();
    assert_eq!(document.format, FileFormat::Txt);
    assert!(!document.text.contains('\r'));
    assert_eq!(document.segments.len(), 2);
    assert_eq!(document.segments[0].locator, "line:1-40");
    assert_eq!(document.segments[1].locator, "line:41-41");
    assert_eq!(
        document
            .segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<String>(),
        document.text
    );
}

#[test]
fn extracts_utf8_markdown_and_strips_bom() {
    let document = ingest_bytes("argument.markdown", b"\xef\xbb\xbf# Heading\r\n\r\nBody").unwrap();
    assert_eq!(document.format, FileFormat::Markdown);
    assert_eq!(document.mime_type, MARKDOWN_MIME);
    assert_eq!(document.text, "# Heading\n\nBody");
    assert_eq!(document.segments[0].locator, "line:1-3");
}

#[test]
fn sha256_is_deterministic_for_duplicate_bytes() {
    let first = ingest_bytes("one.txt", b"abc").unwrap();
    let second = ingest_bytes("two.md", b"abc").unwrap();
    assert_eq!(first.sha256_hex, second.sha256_hex);
    assert_eq!(
        first.sha256_hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rejects_non_basename_and_unsupported_extension() {
    assert_eq!(
        ingest_bytes("folder/file.txt", b"safe").unwrap_err(),
        IngestError::InvalidFileName
    );
    assert_eq!(
        ingest_bytes("folder\\file.txt", b"safe").unwrap_err(),
        IngestError::InvalidFileName
    );
    assert_eq!(
        ingest_bytes("bad\0name.txt", b"safe").unwrap_err(),
        IngestError::InvalidFileName
    );
    assert_eq!(
        ingest_bytes("legacy.doc", b"safe").unwrap_err(),
        IngestError::UnsupportedExtension
    );
}

#[test]
fn rejects_extension_magic_mismatch_and_known_binary_as_text() {
    let pdf = make_pdf(&[Some("text")]);
    assert_eq!(
        ingest_bytes("renamed.docx", &pdf).unwrap_err(),
        IngestError::FormatMismatch
    );
    assert_eq!(
        ingest_bytes("renamed.txt", &pdf).unwrap_err(),
        IngestError::FormatMismatch
    );
}

#[test]
fn rejects_corrupt_pdf_and_docx() {
    assert_eq!(
        ingest_bytes("bad.pdf", b"%PDF-1.7\nbroken").unwrap_err(),
        IngestError::CorruptPdf
    );
    assert_eq!(
        ingest_bytes("bad.docx", b"PK\x03\x04broken").unwrap_err(),
        IngestError::CorruptDocx
    );
}

#[test]
fn rejects_encrypted_and_non_text_pdf() {
    assert_eq!(
        ingest_bytes("secret.pdf", &make_encrypted_pdf()).unwrap_err(),
        IngestError::EncryptedPdf
    );
    assert_eq!(
        ingest_bytes("scan.pdf", &make_pdf(&[None])).unwrap_err(),
        IngestError::NonTextPdf
    );
}

#[test]
fn rejects_invalid_utf8_and_nul_text() {
    assert_eq!(
        ingest_bytes("bad.txt", &[0xff, 0xfe]).unwrap_err(),
        IngestError::InvalidUtf8
    );
    assert_eq!(
        ingest_bytes("bad.md", b"before\0after").unwrap_err(),
        IngestError::NulByteNotAllowed
    );
}

#[test]
fn rejects_docx_macro_embedding_doctype_and_zip_bomb() {
    let normal_xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let macro_docx = make_docx_with(
        &normal_xml,
        "application/vnd.ms-word.document.macroEnabled.main+xml",
        &[],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("macro.docx", &macro_docx).unwrap_err(),
        IngestError::ActiveContentNotAllowed
    );

    let embedded_docx = make_docx_with(
        &normal_xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[("word/embeddings/oleObject1.bin", b"payload")],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("embedded.docx", &embedded_docx).unwrap_err(),
        IngestError::ActiveContentNotAllowed
    );

    let doctype_xml = format!(
        "<?xml version=\"1.0\"?><!DOCTYPE w:document [<!ENTITY x \"hidden\">]>{}",
        word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>")
            .split_once("?>")
            .unwrap()
            .1
    );
    let doctype_docx = make_docx(&doctype_xml);
    assert_eq!(
        ingest_bytes("doctype.docx", &doctype_docx).unwrap_err(),
        IngestError::XmlDoctypeNotAllowed
    );

    let bomb = vec![b'A'; 100_000];
    let bomb_docx = make_docx_with(
        &normal_xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[("word/media/padding.txt", &bomb)],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("bomb.docx", &bomb_docx).unwrap_err(),
        IngestError::DocxCompressionRatioExceeded
    );
}

#[test]
fn rejects_docx_parts_and_revisions_that_are_not_fully_extracted() {
    let xml = word_document("<w:p><w:r><w:t>visible</w:t></w:r></w:p>");
    for (name, data) in [
        ("word/header1.xml", b"<w:hdr>secret</w:hdr>".as_slice()),
        (
            "word/comments.xml",
            b"<w:comments>secret</w:comments>".as_slice(),
        ),
        ("word/media/image1.png", b"not-a-real-image".as_slice()),
        (
            "word/footnotes.xml",
            b"<w:footnotes>secret</w:footnotes>".as_slice(),
        ),
    ] {
        let bytes = make_docx_with(
            &xml,
            DOCX_MAIN_CONTENT_TYPE,
            &[(name, data)],
            CompressionMethod::Deflated,
        );
        assert_eq!(
            ingest_bytes("incomplete.docx", &bytes).unwrap_err(),
            IngestError::IncompleteDocxExtraction,
            "entry {name} must fail closed"
        );
    }

    let tracked = word_document("<w:p><w:ins><w:r><w:t>inserted secret</w:t></w:r></w:ins></w:p>");
    assert_eq!(
        ingest_bytes("tracked.docx", &make_docx(&tracked)).unwrap_err(),
        IngestError::IncompleteDocxExtraction
    );
}
#[test]
fn rejects_encrypted_and_unsafe_docx_entries() {
    let xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let encrypted = mark_zip_encrypted(make_docx(&xml));
    assert_eq!(
        ingest_bytes("encrypted.docx", &encrypted).unwrap_err(),
        IngestError::EncryptedDocx
    );

    let unsafe_docx = make_docx_with(
        &xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[("../outside.xml", b"<outside/>")],
        CompressionMethod::Stored,
    );
    assert_eq!(
        ingest_bytes("unsafe.docx", &unsafe_docx).unwrap_err(),
        IngestError::UnsafeArchiveEntry
    );
}

#[test]
fn rejects_cfb_encrypted_wrapper_and_active_svg() {
    let mut encrypted_wrapper = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
    encrypted_wrapper.extend_from_slice(b"EncryptedPackage");
    assert_eq!(
        ingest_bytes("protected.docx", &encrypted_wrapper).unwrap_err(),
        IngestError::EncryptedDocx
    );

    let xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>bad()</script></svg>"#;
    let svg_docx = make_docx_with(
        &xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[("word/media/active.svg", svg)],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("active-svg.docx", &svg_docx).unwrap_err(),
        IngestError::ActiveContentNotAllowed
    );
}

#[test]
fn rejects_spoofed_opc_root_namespaces() {
    let xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let spoofed_content_types = CONTENT_TYPES_TEMPLATE
        .replace("{main_content_type}", DOCX_MAIN_CONTENT_TYPE)
        .replace(
            "http://schemas.openxmlformats.org/package/2006/content-types",
            "https://attacker.invalid/content-types",
        );
    let content_types_docx = make_docx_parts(
        &spoofed_content_types,
        ROOT_RELATIONSHIPS,
        &xml,
        &[],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("spoofed-content-types.docx", &content_types_docx).unwrap_err(),
        IngestError::CorruptDocx
    );

    let spoofed_relationships = ROOT_RELATIONSHIPS.replace(
        "http://schemas.openxmlformats.org/package/2006/relationships",
        "https://attacker.invalid/relationships",
    );
    let relationships_docx = make_docx_parts(
        &CONTENT_TYPES_TEMPLATE.replace("{main_content_type}", DOCX_MAIN_CONTENT_TYPE),
        &spoofed_relationships,
        &xml,
        &[],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("spoofed-relationships.docx", &relationships_docx).unwrap_err(),
        IngestError::CorruptDocx
    );

    let namespaced_attributes = format!(
        r#"<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"
       xmlns:evil="https://attacker.invalid/attributes">
  <Override evil:PartName="/word/document.xml" evil:ContentType="{DOCX_MAIN_CONTENT_TYPE}"/>
</Types>"#
    );
    let attributes_docx = make_docx_parts(
        &namespaced_attributes,
        ROOT_RELATIONSHIPS,
        &xml,
        &[],
        CompressionMethod::Deflated,
    );
    assert_eq!(
        ingest_bytes("spoofed-attributes.docx", &attributes_docx).unwrap_err(),
        IngestError::CorruptDocx
    );
}

#[test]
fn enforces_raw_eocd_count_when_duplicate_names_collapse() {
    let xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let mut docx = make_docx_with(
        &xml,
        DOCX_MAIN_CONTENT_TYPE,
        &[("word/duplicat.xml", xml.as_bytes())],
        CompressionMethod::Stored,
    );
    // zip 2.x stores entries in an IndexMap and duplicate names collapse after central-directory
    // parsing. The raw EOCD count must still enforce the four declared records.
    replace_all_equal_length(&mut docx, b"word/duplicat.xml", b"word/document.xml");
    let limits = Limits {
        max_docx_entries: 3,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("duplicates.docx", &docx, limits).unwrap_err(),
        IngestError::DocxEntryLimitExceeded
    );
}

#[test]
fn enforces_pdf_page_text_and_segment_limits() {
    let two_pages = make_pdf(&[Some("one"), Some("two")]);
    let mut limits = Limits {
        max_pdf_pages: 1,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("pages.pdf", &two_pages, limits).unwrap_err(),
        IngestError::PdfPageLimitExceeded
    );

    limits = Limits {
        max_text_bytes: 3,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("text.pdf", &make_pdf(&[Some("four")]), limits).unwrap_err(),
        IngestError::TextLimitExceeded
    );

    limits = Limits {
        max_segments: 1,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("segments.pdf", &two_pages, limits).unwrap_err(),
        IngestError::SegmentLimitExceeded
    );
}

#[test]
fn enforces_file_text_and_line_segment_limits() {
    let limits = Limits {
        max_file_bytes: 2,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("large.txt", b"abc", limits).unwrap_err(),
        IngestError::FileTooLarge
    );

    let limits = Limits {
        max_text_bytes: 2,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("text.txt", b"abc", limits).unwrap_err(),
        IngestError::TextLimitExceeded
    );

    let limits = Limits {
        max_segments: 1,
        text_lines_per_segment: 1,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("segments.md", b"one\ntwo", limits).unwrap_err(),
        IngestError::SegmentLimitExceeded
    );
}

#[test]
fn enforces_production_file_text_and_segment_limits() {
    let oversized_file = vec![b'a'; MAX_FILE_BYTES + 1];
    assert_eq!(
        ingest_bytes("oversized.txt", &oversized_file).unwrap_err(),
        IngestError::FileTooLarge
    );

    let oversized_text = vec![b'a'; MAX_TEXT_BYTES + 1];
    assert_eq!(
        ingest_bytes("too-much-text.txt", &oversized_text).unwrap_err(),
        IngestError::TextLimitExceeded
    );

    let too_many_line_blocks = "\n".repeat(MAX_SEGMENTS * TEXT_LINES_PER_SEGMENT + 1);
    assert!(too_many_line_blocks.len() < MAX_TEXT_BYTES);
    assert_eq!(
        ingest_bytes("too-many-segments.md", too_many_line_blocks.as_bytes()).unwrap_err(),
        IngestError::SegmentLimitExceeded
    );
}

#[test]
fn enforces_production_docx_entry_count() {
    let xml = word_document("<w:p><w:r><w:t>safe</w:t></w:r></w:p>");
    let names = (0..(MAX_DOCX_ENTRIES - 2))
        .map(|index| format!("word/media/padding-{index}.txt"))
        .collect::<Vec<_>>();
    let extra_entries = names
        .iter()
        .map(|name| (name.as_str(), b"x".as_slice()))
        .collect::<Vec<_>>();
    let docx = make_docx_with(
        &xml,
        DOCX_MAIN_CONTENT_TYPE,
        &extra_entries,
        CompressionMethod::Stored,
    );
    assert_eq!(
        ingest_bytes("too-many-entries.docx", &docx).unwrap_err(),
        IngestError::DocxEntryLimitExceeded
    );
}

#[test]
fn enforces_docx_entry_expansion_text_and_segment_limits() {
    let xml = word_document(
        "<w:p><w:r><w:t>first</w:t></w:r></w:p><w:p><w:r><w:t>second</w:t></w:r></w:p>",
    );
    let docx = make_docx(&xml);

    let limits = Limits {
        max_docx_entries: 2,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("entries.docx", &docx, limits).unwrap_err(),
        IngestError::DocxEntryLimitExceeded
    );

    let limits = Limits {
        max_docx_entry_bytes: 32,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("entry.docx", &docx, limits).unwrap_err(),
        IngestError::DocxEntryTooLarge
    );

    let limits = Limits {
        max_docx_expanded_bytes: 64,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("expanded.docx", &docx, limits).unwrap_err(),
        IngestError::DocxExpandedSizeExceeded
    );

    let limits = Limits {
        max_text_bytes: 4,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("text.docx", &docx, limits).unwrap_err(),
        IngestError::TextLimitExceeded
    );

    let limits = Limits {
        max_segments: 1,
        ..Limits::default()
    };
    assert_eq!(
        ingest_bytes_with_limits("segments.docx", &docx, limits).unwrap_err(),
        IngestError::SegmentLimitExceeded
    );
}

#[test]
fn stable_errors_never_include_file_name_or_parser_details() {
    let error = ingest_bytes("private-name.pdf", b"%PDF-1.7\nprivate-body").unwrap_err();
    assert_eq!(error.code(), "corrupt_pdf");
    assert!(!error.to_string().contains("private-name"));
    assert!(!error.to_string().contains("private-body"));
}

#[test]
fn image_extensions_require_magic_match_and_local_ocr() {
    assert_eq!(detect_format("scan.PNG").unwrap(), FileFormat::Png);
    assert_eq!(detect_format("photo.jpg").unwrap(), FileFormat::Jpeg);
    assert_eq!(detect_format("photo.JPEG").unwrap(), FileFormat::Jpeg);

    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01";
    assert_eq!(
        ingest_bytes("scan.png", png).unwrap_err(),
        IngestError::ImageRequiresLocalOcr
    );

    let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9";
    assert_eq!(
        ingest_bytes("photo.jpeg", jpeg).unwrap_err(),
        IngestError::ImageRequiresLocalOcr
    );
    assert_eq!(
        ingest_bytes("renamed.jpg", png).unwrap_err(),
        IngestError::FormatMismatch
    );
}
