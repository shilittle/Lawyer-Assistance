use assistant::*;
use quick_xml::{events::Event, Reader};
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

fn minimal_document() -> DocumentSpec {
    DocumentSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        document_type: DocumentType::Contract,
        title: "示例".to_owned(),
        parties: vec![],
        sections: vec![DocumentSection {
            id: "section:1".to_owned(),
            heading: "正文".to_owned(),
            body: "内容".to_owned(),
            factual: false,
            provenance: vec![],
            clauses: vec![],
        }],
        assumptions: vec![],
        missing_information: vec![],
        source_materials: vec![],
        legal_citations: vec![],
        risk_warnings: vec![],
    }
}

fn document_with_sources() -> (DocumentSpec, ValidationContext) {
    let mut context = ValidationContext::default();
    context.allow_source_ref("material:1");
    context.allow_validated_legal_source("law:1");
    let document = DocumentSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        document_type: DocumentType::LawyerLetter,
        title: "A&B <C> \"D\" 'E'".to_owned(),
        parties: vec![DocumentParty {
            id: "party:1".to_owned(),
            name: "甲方".to_owned(),
            role: "委托方".to_owned(),
            details: Some("来自材料".to_owned()),
            provenance: vec![ProvenanceRef {
                kind: ProvenanceKind::UserMaterial,
                source_ref: Some("material:1".to_owned()),
            }],
        }],
        sections: vec![DocumentSection {
            id: "section:1".to_owned(),
            heading: "事实".to_owned(),
            body: "A&B <C> \"D\" 'E'".to_owned(),
            factual: true,
            provenance: vec![ProvenanceRef {
                kind: ProvenanceKind::UserMaterial,
                source_ref: Some("material:1".to_owned()),
            }],
            clauses: vec![DocumentClause {
                id: "clause:1".to_owned(),
                heading: None,
                body: "建议措辞".to_owned(),
                factual: false,
                provenance: vec![ProvenanceRef {
                    kind: ProvenanceKind::ModelWording,
                    source_ref: None,
                }],
            }],
        }],
        assumptions: vec![DocumentAssumption {
            text: "签署日期待确认".to_owned(),
            provenance: vec![ProvenanceRef {
                kind: ProvenanceKind::ModelWording,
                source_ref: None,
            }],
        }],
        missing_information: vec![MissingInformation {
            description: "缺少付款日期".to_owned(),
        }],
        source_materials: vec![SourceMaterial {
            id: "material:1".to_owned(),
            kind: SourceMaterialKind::UserMaterial,
            label: "用户上传材料".to_owned(),
            locator: Some("paragraph:1".to_owned()),
        }],
        legal_citations: vec![LegalCitation {
            id: "citation:1".to_owned(),
            source_ref: "law:1".to_owned(),
            marker: "[SRC:law:1]".to_owned(),
            citation: "《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）".to_owned(),
            proposition: "支持所列命题".to_owned(),
        }],
        risk_warnings: vec!["签署前核验主体".to_owned()],
    };
    (document, context)
}

fn valid_map() -> (MapSpec, ValidationContext) {
    let mut context = ValidationContext::default();
    context.allow_source_ref("material:1");
    let map = MapSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        title: "争点图".to_owned(),
        layout_hint: LayoutHint::Layered,
        nodes: vec![
            MapNode {
                id: "node:root".to_owned(),
                label: "争点".to_owned(),
                summary: "合同履行情况需要结合证据核验".to_owned(),
                parent_id: None,
                source_refs: vec!["material:1".to_owned()],
            },
            MapNode {
                id: "node:child".to_owned(),
                label: "子项".to_owned(),
                summary: "说明".to_owned(),
                parent_id: Some("node:root".to_owned()),
                source_refs: vec![],
            },
        ],
        edges: vec![MapEdge {
            id: "edge:1".to_owned(),
            source: "node:root".to_owned(),
            target: "node:child".to_owned(),
            label: "包含".to_owned(),
            relation: "contains".to_owned(),
            source_refs: vec!["material:1".to_owned()],
        }],
    };
    (map, context)
}

#[test]
fn markdown_is_a_public_legal_document_and_ends_with_a_reference_table() {
    let rendered = render_document_markdown(&minimal_document(), &ValidationContext::default())
        .expect("minimal document should render");
    let expected = concat!(
        "# 示例\n\n",
        "## 正文\n\n",
        "### 正文\n\n",
        "内容\n\n",
        "## 法律依据与案例引用表\n\n",
        "| 类型 | 法律或案例名称 | 条款或案号 | 施行或裁判年份 | 引用内容 |\n",
        "| --- | --- | --- | --- | --- |\n",
        "| 未引用 | 本文未列明法律或案例依据 | — | — | — |\n"
    );
    assert_eq!(rendered.as_text(), Some(expected));
    assert_eq!(
        rendered.metadata.format,
        ArtifactRenderFormat::DocumentMarkdown
    );
    assert_eq!(rendered.metadata.byte_len, expected.len());
    assert_eq!(rendered.metadata.source_reference_count, 0);
}

#[test]
fn markdown_escapes_markup_and_keeps_audit_fields_out_of_the_delivery() {
    let (document, context) = document_with_sources();
    let markdown = render_document_markdown(&document, &context)
        .unwrap()
        .as_text()
        .unwrap()
        .to_owned();
    assert!(markdown.contains("A&amp;B &lt;C&gt; \"D\" 'E'"));
    assert!(!markdown.contains("<C>"));
    assert!(markdown.contains("## 待确认事项"));
    assert!(markdown.contains("签署日期待确认"));
    assert!(markdown.contains("缺少付款日期"));
    assert!(markdown.contains("## 风险提示"));
    assert!(markdown.contains("签署前核验主体"));
    assert!(!markdown.contains("模型措辞"));
    assert!(!markdown.contains("结构化文书"));
    assert!(!markdown.contains("内容属性"));
    assert!(markdown.contains("当事人提供材料：用户上传材料"));
    assert!(markdown.contains("## 法律依据与案例引用表"));
    assert!(markdown.contains("《中华人民共和国民法典》"));
    assert!(markdown.contains("第四百六十五条第一款"));
    assert!(markdown.contains("2021年起施行"));
    assert!(markdown.ends_with("| 法条 | 《中华人民共和国民法典》 | 第四百六十五条第一款 | 2021年起施行 | 支持所列命题 |\n"));
    assert!(!markdown.contains("material:1"));
    assert!(!markdown.contains("law:1"));
    assert!(!markdown.contains("标识："));
    assert!(!markdown.contains("定位："));
}

#[test]
fn docx_is_deterministic_minimal_well_formed_and_fully_escaped() {
    let (document, context) = document_with_sources();
    let first = render_document_docx(&document, &context).unwrap();
    let second = render_document_docx(&document, &context).unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.metadata.format, ArtifactRenderFormat::DocumentDocx);
    assert_eq!(first.metadata.media_type, DOCUMENT_DOCX_MEDIA_TYPE);
    assert_eq!(first.metadata.source_reference_count, 2);
    assert_eq!(first.metadata.validated_citation_count, 1);

    let bytes = first.as_bytes().unwrap();
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut names = Vec::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).unwrap();
        assert_eq!(file.compression(), CompressionMethod::Stored);
        names.push(file.name().to_owned());
    }
    assert_eq!(
        names,
        ["[Content_Types].xml", "_rels/.rels", "word/document.xml"]
    );

    let content_types = read_zip_text(&mut archive, "[Content_Types].xml");
    let relationships = read_zip_text(&mut archive, "_rels/.rels");
    let document_xml = read_zip_text(&mut archive, "word/document.xml");
    assert_well_formed_xml(&content_types);
    assert_well_formed_xml(&relationships);
    assert_well_formed_xml(&document_xml);
    assert!(content_types.contains("wordprocessingml.document.main+xml"));
    assert!(!content_types.to_ascii_lowercase().contains("macro"));
    assert!(!relationships.contains("TargetMode=\"External\""));
    assert_eq!(relationships.matches("<Relationship ").count(), 1);
    assert!(document_xml.contains("A&amp;B &lt;C&gt; &quot;D&quot; &apos;E&apos;"));
    assert!(!document_xml.contains("A&B <C>"));
    assert!(!document_xml.to_ascii_lowercase().contains("<script"));
    for internal in [
        "material:1",
        "law:1",
        "citation:1",
        "section:1",
        "clause:1",
        "[SRC:",
        "schema_version",
        "snippet",
    ] {
        assert!(
            !document_xml.contains(internal),
            "Word document leaked {internal}"
        );
    }
}

#[test]
fn docx_rejects_a_valid_spec_whose_escaped_xml_exceeds_output_cap() {
    let mut document = minimal_document();
    document.title = "x".to_owned();
    document.sections = (0..31)
        .map(|index| DocumentSection {
            id: format!("section:{index}"),
            heading: format!("s{index}"),
            body: "&".repeat(MAX_SECTION_BODY_BYTES),
            factual: false,
            provenance: vec![],
            clauses: vec![],
        })
        .collect();
    document.validate(&ValidationContext::default()).unwrap();
    let error = render_document_docx(&document, &ValidationContext::default()).unwrap_err();
    assert_eq!(error.error_type, ArtifactRenderErrorType::OutputTooLarge);
    assert_eq!(error.format, Some(ArtifactRenderFormat::DocumentDocx));
    assert_eq!(error.limit, Some(MAX_DOCUMENT_XML_BYTES));
    assert!(error.actual.unwrap() > MAX_DOCUMENT_XML_BYTES);
}

#[test]
fn invalid_document_fails_before_render_and_error_does_not_echo_body() {
    let mut document = minimal_document();
    document.title.clear();
    document.sections[0].body = "SECRET-BODY-MUST-NOT-LEAK".to_owned();
    let error = render_document_markdown(&document, &ValidationContext::default()).unwrap_err();
    assert_eq!(error.error_type, ArtifactRenderErrorType::InvalidSpec);
    assert_eq!(
        error.contract_error_type,
        Some(ContractErrorType::EmptyText)
    );
    let serialized = serde_json::to_string(&error).unwrap();
    assert!(!serialized.contains("SECRET-BODY-MUST-NOT-LEAK"));
}

#[test]
fn markdown_and_docx_reject_non_deliverable_model_text_before_serialization() {
    for leaked_text in [
        r#"{"schema_version":1,"snippet":"secret"}"#,
        "[SRC:law:1]",
        r"C:\cases\private\draft.json",
        "https://local.invalid/internal",
        "019f6e3e-6822-70c1-86a7-6f88022a815e",
        "deadbeef0123456789abcdef",
        "结构化文书预览",
        "模型措辞",
        "无标题",
    ] {
        let mut document = minimal_document();
        document.sections[0].body = leaked_text.to_owned();

        let markdown_error = render_document_markdown(&document, &ValidationContext::default())
            .expect_err("Markdown must reject internal model output");
        assert_eq!(
            markdown_error.error_type,
            ArtifactRenderErrorType::InvalidSpec
        );
        assert_eq!(
            markdown_error.contract_error_type,
            Some(ContractErrorType::InvalidEnvelope)
        );

        let docx_error = render_document_docx(&document, &ValidationContext::default())
            .expect_err("Word output must reject internal model output");
        assert_eq!(docx_error.error_type, ArtifactRenderErrorType::InvalidSpec);
        assert_eq!(
            docx_error.contract_error_type,
            Some(ContractErrorType::InvalidEnvelope)
        );

        let serialized = format!(
            "{}{}",
            serde_json::to_string(&markdown_error).unwrap(),
            serde_json::to_string(&docx_error).unwrap()
        );
        assert!(!serialized.contains(leaked_text));
    }
}

#[test]
fn map_json_roundtrips_as_bounded_data_without_renderer_configuration() {
    let (map, context) = valid_map();
    let first = render_map_json(&map, &context).unwrap();
    let second = render_map_json(&map, &context).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.metadata.artifact_kind,
        ArtifactRenderKind::ModelGeneratedMap
    );
    assert_eq!(first.metadata.semantic_label, "案件要素与关系分析");
    assert_eq!(first.metadata.source_reference_count, 1);

    let value: Value = serde_json::from_str(first.as_text().unwrap()).unwrap();
    assert_eq!(value["artifactKind"], "model_generated_map");
    assert_eq!(value["displayLabel"], "案件要素与关系分析");
    assert_eq!(value["layoutHint"], "layered");
    assert_eq!(value["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(value["edges"].as_array().unwrap().len(), 1);
    let object = value.as_object().unwrap();
    assert!(!object.contains_key("cytoscapeConfig"));
    assert!(!object.contains_key("style"));
    assert!(!object.contains_key("script"));

    let mut forbidden = serde_json::to_value(&map).unwrap();
    forbidden
        .as_object_mut()
        .unwrap()
        .insert("cytoscapeConfig".to_owned(), json!({"style": "free"}));
    assert!(serde_json::from_value::<MapSpec>(forbidden).is_err());
}

#[test]
fn map_summary_is_lawyer_facing_and_invalid_map_fails_first() {
    let (mut map, context) = valid_map();
    let summary = render_map_summary(&map, &context).unwrap();
    let text = summary.as_text().unwrap();
    assert!(text.starts_with("# 案件要素与关系分析：争点图"));
    assert!(text.contains("所列内容以案件材料和法律依据为准"));
    assert!(text.contains("分析方式：层次关系"));
    assert!(text.contains("## 案件要点（2）"));
    assert!(text.contains("## 要点关系（1）"));
    assert!(text.contains("争点 → 子项"));
    for internal in [
        "模型",
        "Artifact",
        "artifact",
        "布局",
        "node:root",
        "node:child",
        "edge:1",
        "material:1",
    ] {
        assert!(!text.contains(internal), "map summary leaked {internal}");
    }

    map.edges[0].target = "node:missing".to_owned();
    let error = render_map_json(&map, &context).unwrap_err();
    assert_eq!(error.error_type, ArtifactRenderErrorType::InvalidSpec);
    assert_eq!(
        error.contract_error_type,
        Some(ContractErrorType::InvalidEndpoint)
    );
}

#[test]
fn map_summary_rejects_engineering_text_and_internal_references() {
    let (map, context) = valid_map();
    for leaked_text in [
        "模型生成内容",
        "分析 Artifact",
        "布局参数",
        "来源 material:1",
        "proposalHash",
        "service-a1b2c3d4-1",
        "C:\\cases\\internal.json",
        "019f6e74-d8f3-7771-82a8-715331d4ae45",
        "a1b2c3d4e5f60789",
    ] {
        let mut polluted = map.clone();
        polluted.nodes[0].summary = leaked_text.to_owned();
        let error = render_map_summary(&polluted, &context)
            .expect_err("public map summary must reject non-deliverable text");
        assert_eq!(error.error_type, ArtifactRenderErrorType::InvalidSpec);
        assert_eq!(
            error.contract_error_type,
            Some(ContractErrorType::InvalidEnvelope)
        );
        assert!(!serde_json::to_string(&error).unwrap().contains(leaked_text));
    }
}

fn read_zip_text(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> String {
    let mut value = String::new();
    archive
        .by_name(name)
        .unwrap()
        .read_to_string(&mut value)
        .unwrap();
    value
}

fn assert_well_formed_xml(xml: &str) {
    let mut reader = Reader::from_str(xml);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("XML must be well formed: {error}"),
        }
    }
}
