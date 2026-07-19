use super::{
    ensure_output_limit, escape_markdown, escape_xml, ArtifactRenderError, ArtifactRenderFormat,
    ArtifactRenderKind, ArtifactRenderMetadata, RenderedArtifact, DOCUMENT_DOCX_MEDIA_TYPE,
    DOCUMENT_MARKDOWN_MEDIA_TYPE, MAX_DOCUMENT_DOCX_BYTES, MAX_DOCUMENT_MARKDOWN_BYTES,
    MAX_DOCUMENT_XML_BYTES,
};
use crate::{
    document::{parse_public_citation, PublicCitationKind},
    DocumentSpec, SourceMaterialKind, ValidationContext,
};
use std::{
    collections::BTreeSet,
    io::{Cursor, Write},
};
use zip::{write::SimpleFileOptions, CompressionMethod, DateTime, ZipWriter};

const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;

const ROOT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Title,
    Heading1,
    Heading2,
    Heading3,
    Body,
    Bullet,
    TableHeader,
    TableRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DocumentBlock {
    kind: BlockKind,
    text: String,
    cells: Vec<String>,
}

impl DocumentBlock {
    fn new(kind: BlockKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            cells: Vec::new(),
        }
    }

    fn table_header(cells: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            kind: BlockKind::TableHeader,
            text: String::new(),
            cells: cells.into_iter().map(Into::into).collect(),
        }
    }

    fn table_row(cells: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            kind: BlockKind::TableRow,
            text: String::new(),
            cells: cells.into_iter().map(Into::into).collect(),
        }
    }
}

pub fn render_document_markdown(
    spec: &DocumentSpec,
    context: &ValidationContext,
) -> Result<RenderedArtifact, ArtifactRenderError> {
    spec.validate(context).map_err(|error| {
        ArtifactRenderError::invalid_spec(ArtifactRenderFormat::DocumentMarkdown, &error)
    })?;
    let markdown = blocks_to_markdown(&document_blocks(spec));
    ensure_output_limit(
        ArtifactRenderFormat::DocumentMarkdown,
        markdown.len(),
        MAX_DOCUMENT_MARKDOWN_BYTES,
    )?;
    let metadata = document_metadata(
        spec,
        ArtifactRenderFormat::DocumentMarkdown,
        DOCUMENT_MARKDOWN_MEDIA_TYPE,
        "md",
        markdown.len(),
    );
    Ok(RenderedArtifact::text(metadata, markdown))
}

pub fn render_document_docx(
    spec: &DocumentSpec,
    context: &ValidationContext,
) -> Result<RenderedArtifact, ArtifactRenderError> {
    spec.validate(context).map_err(|error| {
        ArtifactRenderError::invalid_spec(ArtifactRenderFormat::DocumentDocx, &error)
    })?;
    let document_xml = blocks_to_document_xml(&document_blocks(spec));
    ensure_output_limit(
        ArtifactRenderFormat::DocumentDocx,
        document_xml.len(),
        MAX_DOCUMENT_XML_BYTES,
    )?;
    let bytes = write_minimal_docx(&document_xml)?;
    ensure_output_limit(
        ArtifactRenderFormat::DocumentDocx,
        bytes.len(),
        MAX_DOCUMENT_DOCX_BYTES,
    )?;
    let metadata = document_metadata(
        spec,
        ArtifactRenderFormat::DocumentDocx,
        DOCUMENT_DOCX_MEDIA_TYPE,
        "docx",
        bytes.len(),
    );
    Ok(RenderedArtifact::bytes(metadata, bytes))
}

fn document_metadata(
    spec: &DocumentSpec,
    format: ArtifactRenderFormat,
    media_type: &str,
    file_extension: &str,
    byte_len: usize,
) -> ArtifactRenderMetadata {
    let mut sources = BTreeSet::new();
    sources.extend(spec.source_materials.iter().map(|item| item.id.as_str()));
    sources.extend(
        spec.legal_citations
            .iter()
            .map(|item| item.source_ref.as_str()),
    );
    ArtifactRenderMetadata {
        artifact_kind: ArtifactRenderKind::Document,
        format,
        media_type: media_type.to_owned(),
        file_extension: file_extension.to_owned(),
        byte_len,
        schema_version: spec.schema_version,
        source_reference_count: sources.len(),
        validated_citation_count: spec.legal_citations.len(),
        semantic_label: "法律文书".to_owned(),
    }
}

fn document_blocks(spec: &DocumentSpec) -> Vec<DocumentBlock> {
    let mut blocks = vec![DocumentBlock::new(BlockKind::Title, &spec.title)];

    if !spec.parties.is_empty() {
        blocks.push(DocumentBlock::new(BlockKind::Heading1, "当事人"));
        for party in &spec.parties {
            blocks.push(DocumentBlock::new(
                BlockKind::Heading2,
                format!("{}（{}）", party.name, party.role),
            ));
            if let Some(details) = &party.details {
                blocks.push(DocumentBlock::new(BlockKind::Body, details));
            }
        }
    }

    blocks.push(DocumentBlock::new(BlockKind::Heading1, "正文"));
    for section in &spec.sections {
        blocks.push(DocumentBlock::new(BlockKind::Heading2, &section.heading));
        blocks.push(DocumentBlock::new(BlockKind::Body, &section.body));
        for (index, clause) in section.clauses.iter().enumerate() {
            blocks.push(DocumentBlock::new(
                BlockKind::Heading3,
                clause
                    .heading
                    .clone()
                    .unwrap_or_else(|| format!("条款 {}", index + 1)),
            ));
            blocks.push(DocumentBlock::new(BlockKind::Body, &clause.body));
        }
    }

    if !spec.assumptions.is_empty() || !spec.missing_information.is_empty() {
        blocks.push(DocumentBlock::new(BlockKind::Heading1, "待确认事项"));
        for assumption in &spec.assumptions {
            blocks.push(DocumentBlock::new(BlockKind::Bullet, &assumption.text));
        }
        blocks.extend(
            spec.missing_information
                .iter()
                .map(|item| DocumentBlock::new(BlockKind::Bullet, &item.description)),
        );
    }

    if !spec.risk_warnings.is_empty() {
        blocks.push(DocumentBlock::new(BlockKind::Heading1, "风险提示"));
        blocks.extend(
            spec.risk_warnings
                .iter()
                .map(|item| DocumentBlock::new(BlockKind::Bullet, item)),
        );
    }

    if !spec.source_materials.is_empty() {
        blocks.push(DocumentBlock::new(BlockKind::Heading1, "依据材料"));
        for source in &spec.source_materials {
            blocks.push(DocumentBlock::new(
                BlockKind::Bullet,
                format!(
                    "{}：{}",
                    source_material_kind_label(source.kind),
                    source.label,
                ),
            ));
        }
    }

    blocks.push(DocumentBlock::new(
        BlockKind::Heading1,
        "法律依据与案例引用表",
    ));
    blocks.push(DocumentBlock::table_header([
        "类型",
        "法律或案例名称",
        "条款或案号",
        "施行或裁判年份",
        "引用内容",
    ]));
    if spec.legal_citations.is_empty() {
        blocks.push(DocumentBlock::table_row([
            "未引用",
            "本文未列明法律或案例依据",
            "—",
            "—",
            "—",
        ]));
    } else {
        for citation in &spec.legal_citations {
            let parts = parse_public_citation(&citation.citation)
                .expect("validated document citations have a public citation form");
            blocks.push(DocumentBlock::table_row([
                match parts.kind {
                    PublicCitationKind::Law => "法条".to_owned(),
                    PublicCitationKind::JudicialCase => "案例".to_owned(),
                },
                match parts.kind {
                    PublicCitationKind::Law => format!("《{}》", parts.title),
                    PublicCitationKind::JudicialCase => parts.title.to_owned(),
                },
                match parts.kind {
                    PublicCitationKind::Law => parts.locator.to_owned(),
                    PublicCitationKind::JudicialCase => format!("案号：{}", parts.locator),
                },
                match parts.kind {
                    PublicCitationKind::Law => format!("{}年起施行", parts.year),
                    PublicCitationKind::JudicialCase => format!("{}年裁判", parts.year),
                },
                citation.proposition.clone(),
            ]));
        }
    }
    blocks
}

fn source_material_kind_label(kind: SourceMaterialKind) -> &'static str {
    match kind {
        SourceMaterialKind::UserMaterial => "当事人提供材料",
        SourceMaterialKind::ConfirmedCase => "案件材料",
    }
}

fn blocks_to_markdown(blocks: &[DocumentBlock]) -> String {
    let mut output = String::new();
    for block in blocks {
        match block.kind {
            BlockKind::TableHeader => {
                append_markdown_table_row(&mut output, &block.cells);
                output.push('|');
                for _ in &block.cells {
                    output.push_str(" --- |");
                }
                output.push('\n');
            }
            BlockKind::TableRow => append_markdown_table_row(&mut output, &block.cells),
            _ => {
                let text = escape_markdown(&block.text);
                match block.kind {
                    BlockKind::Title => output.push_str(&format!("# {text}\n\n")),
                    BlockKind::Heading1 => output.push_str(&format!("## {text}\n\n")),
                    BlockKind::Heading2 => output.push_str(&format!("### {text}\n\n")),
                    BlockKind::Heading3 => output.push_str(&format!("#### {text}\n\n")),
                    BlockKind::Body => output.push_str(&format!("{text}\n\n")),
                    BlockKind::Bullet => output.push_str(&format!("- {text}\n\n")),
                    BlockKind::TableHeader | BlockKind::TableRow => unreachable!(),
                }
            }
        }
    }
    if output.ends_with("\n\n") {
        output.pop();
    }
    output
}

fn append_markdown_table_row(output: &mut String, cells: &[String]) {
    output.push('|');
    for cell in cells {
        let cell = escape_markdown(&cell.replace('|', "｜").replace(['\r', '\n'], " "));
        output.push_str(&format!(" {cell} |"));
    }
    output.push('\n');
}

fn blocks_to_document_xml(blocks: &[DocumentBlock]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    let mut index = 0;
    while index < blocks.len() {
        let block = &blocks[index];
        if block.kind == BlockKind::TableHeader {
            let start = index;
            index += 1;
            while index < blocks.len() && block_is_table_row(blocks[index].kind) {
                index += 1;
            }
            append_docx_table(&mut xml, &blocks[start..index]);
            continue;
        }
        let normalized = block.text.replace("\r\n", "\n").replace('\r', "\n");
        for line in normalized.split('\n') {
            append_docx_paragraph(&mut xml, block.kind, line);
        }
        index += 1;
    }
    xml.push_str(
        r#"<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>"#,
    );
    xml
}

fn block_is_table_row(kind: BlockKind) -> bool {
    matches!(kind, BlockKind::TableHeader | BlockKind::TableRow)
}

fn append_docx_table(xml: &mut String, rows: &[DocumentBlock]) {
    xml.push_str(r#"<w:tbl><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/><w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr>"#);
    for row in rows {
        xml.push_str("<w:tr>");
        for cell in &row.cells {
            xml.push_str("<w:tc><w:p><w:r>");
            if row.kind == BlockKind::TableHeader {
                xml.push_str("<w:rPr><w:b/></w:rPr>");
            }
            xml.push_str(r#"<w:t xml:space="preserve">"#);
            xml.push_str(&escape_xml(&cell.replace(['\r', '\n'], " ")));
            xml.push_str("</w:t></w:r></w:p></w:tc>");
        }
        xml.push_str("</w:tr>");
    }
    xml.push_str("</w:tbl>");
}

fn append_docx_paragraph(xml: &mut String, kind: BlockKind, text: &str) {
    xml.push_str("<w:p>");
    if kind == BlockKind::Bullet {
        xml.push_str(r#"<w:pPr><w:ind w:left="360" w:hanging="180"/></w:pPr>"#);
    }
    xml.push_str("<w:r>");
    match kind {
        BlockKind::Title => xml.push_str(r#"<w:rPr><w:b/><w:sz w:val="32"/></w:rPr>"#),
        BlockKind::Heading1 => xml.push_str(r#"<w:rPr><w:b/><w:sz w:val="28"/></w:rPr>"#),
        BlockKind::Heading2 => xml.push_str(r#"<w:rPr><w:b/><w:sz w:val="24"/></w:rPr>"#),
        BlockKind::Heading3 => xml.push_str(r#"<w:rPr><w:b/><w:sz w:val="22"/></w:rPr>"#),
        BlockKind::Body | BlockKind::Bullet => {}
        BlockKind::TableHeader | BlockKind::TableRow => unreachable!(),
    }
    xml.push_str(r#"<w:t xml:space="preserve">"#);
    if kind == BlockKind::Bullet {
        xml.push_str("• ");
    }
    xml.push_str(&escape_xml(text));
    xml.push_str("</w:t></w:r></w:p>");
}

fn write_minimal_docx(document_xml: &str) -> Result<Vec<u8>, ArtifactRenderError> {
    let fixed_time = DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
        .map_err(|_| ArtifactRenderError::archive_failed())?;
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(fixed_time)
        .unix_permissions(0o644);
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    for (name, contents) in [
        ("[Content_Types].xml", CONTENT_TYPES_XML),
        ("_rels/.rels", ROOT_RELS_XML),
        ("word/document.xml", document_xml),
    ] {
        writer
            .start_file(name, options)
            .map_err(|_| ArtifactRenderError::archive_failed())?;
        writer
            .write_all(contents.as_bytes())
            .map_err(|_| ArtifactRenderError::archive_failed())?;
    }
    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|_| ArtifactRenderError::archive_failed())
}
