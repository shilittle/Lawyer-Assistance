use std::fs;

use diagrams::{
    DiagramPatch, DiagramService, DiagramSpec, DiagramUpdateRequest, ExportFormat, NodeStatus,
};
use serde_json::json;

fn fixture_spec() -> DiagramSpec {
    serde_json::from_value(json!({
        "schema_version": "1.0",
        "diagram_type": "case_issue_evidence_law",
        "template_id": "case_issue_evidence_law_v1",
        "title": "虚构借款争议示意图",
        "summary": "全部主体、金额和材料均为测试虚构数据。",
        "nodes": [
            {
                "id": "issue_001",
                "type": "issue",
                "subtype": "payment_nature",
                "label": "款项性质",
                "short_label": "核心争点",
                "details": "争议款项究竟属于借款还是其他往来。",
                "status": "disputed",
                "importance": "critical",
                "source_refs": ["source_file_001"],
                "tags": ["核心争议"],
                "metadata": {}
            },
            {
                "id": "claim_001",
                "type": "claim",
                "subtype": null,
                "label": "请求返还借款",
                "short_label": null,
                "details": "申请方主张返还。",
                "status": "alleged",
                "importance": "high",
                "source_refs": ["source_file_001"],
                "tags": [],
                "metadata": {}
            },
            {
                "id": "defense_001",
                "type": "defense",
                "subtype": null,
                "label": "抗辩并非借款",
                "short_label": null,
                "details": "相对方提出其他款项性质。",
                "status": "alleged",
                "importance": "high",
                "source_refs": ["source_file_001"],
                "tags": [],
                "metadata": {}
            },
            {
                "id": "fact_001",
                "type": "fact",
                "subtype": "transfer",
                "label": "发生一笔转账",
                "short_label": "转账事实",
                "details": "测试用转账事实。",
                "status": "supported",
                "importance": "high",
                "source_refs": ["source_file_001"],
                "tags": [],
                "metadata": {}
            },
            {
                "id": "evidence_001",
                "type": "evidence",
                "subtype": "transfer_record",
                "label": "转账凭证",
                "short_label": null,
                "details": "虚构银行转账凭证。",
                "status": "supported",
                "importance": "high",
                "source_refs": ["source_file_001"],
                "tags": [],
                "metadata": {
                    "evidence_name": "转账凭证",
                    "evidence_type": "electronic_record",
                    "proves": ["fact_001"],
                    "human_confirmation": false
                }
            },
            {
                "id": "rule_001",
                "type": "rule",
                "subtype": "burden_of_proof",
                "label": "借贷关系证明规则",
                "short_label": "证明规则",
                "details": "仅用于测试的规则摘要，正式使用须核对原文和版本。",
                "status": "effective",
                "importance": "high",
                "source_refs": ["source_law_001"],
                "tags": [],
                "metadata": {
                    "full_name": "虚构测试规范",
                    "version": "2026-test",
                    "validity_status": "effective",
                    "verified_by": "database"
                }
            }
        ],
        "edges": [
            {
                "id": "edge_claim_issue",
                "source": "claim_001",
                "target": "issue_001",
                "relation": "raises",
                "label": "提出",
                "strength": "unknown",
                "source_refs": ["source_file_001"],
                "metadata": {}
            },
            {
                "id": "edge_defense_issue",
                "source": "defense_001",
                "target": "issue_001",
                "relation": "disputes",
                "label": "提出抗辩",
                "strength": "moderate",
                "source_refs": ["source_file_001"],
                "metadata": {}
            },
            {
                "id": "edge_evidence_fact",
                "source": "evidence_001",
                "target": "fact_001",
                "relation": "proves",
                "label": "证明转账发生",
                "strength": "strong",
                "source_refs": ["source_file_001"],
                "metadata": {}
            },
            {
                "id": "edge_fact_issue",
                "source": "fact_001",
                "target": "issue_001",
                "relation": "supports",
                "label": "支持但不直接证明款项性质",
                "strength": "moderate",
                "source_refs": ["source_file_001"],
                "metadata": {}
            },
            {
                "id": "edge_rule_issue",
                "source": "rule_001",
                "target": "issue_001",
                "relation": "applies_to",
                "label": "可能适用",
                "strength": "moderate",
                "source_refs": ["source_law_001"],
                "metadata": {}
            }
        ],
        "groups": [],
        "sources": [
            {
                "id": "source_file_001",
                "kind": "file_page",
                "title": "虚构测试材料",
                "locator": "第1页，第2段",
                "artifact_id": "artifact_test_001",
                "uri": null,
                "file_name": "fictional-test.pdf",
                "page": 1,
                "paragraph": "2",
                "table": null,
                "attachment": null,
                "law_document": null,
                "law_version": null,
                "article": null,
                "quote": "虚构摘录",
                "content_hash": null,
                "verification_status": "model_extracted"
            },
            {
                "id": "source_law_001",
                "kind": "law",
                "title": "虚构测试规范",
                "locator": "测试条第一款",
                "artifact_id": "law_test_001",
                "uri": "https://example.invalid/law-test",
                "file_name": null,
                "page": null,
                "paragraph": null,
                "table": null,
                "attachment": null,
                "law_document": "虚构测试规范",
                "law_version": "2026-test",
                "article": "测试条第一款",
                "quote": "仅为软件测试文本。",
                "content_hash": null,
                "verification_status": "database_verified"
            }
        ],
        "layout_hints": {
            "direction": "top_down",
            "preferred_root_ids": ["issue_001"],
            "group_by": "issue",
            "max_initial_nodes": 100,
            "timeline_lane": "single"
        },
        "display_options": {
            "theme": "light",
            "show_legend": true,
            "show_sources": true,
            "hide_weak_edges": false,
            "collapse_low_importance": false,
            "print_page_size": "a4_landscape"
        },
        "provenance": {
            "generated_by": "workbuddy",
            "generated_at": "2026-07-21T10:00:00+08:00",
            "diagram_spec_version": "1.0",
            "template_version": "1.0.0",
            "source_file_ids": ["artifact_test_001"],
            "human_confirmed": false,
            "parent_spec_hash": null,
            "change_summary": null,
            "model_content_scope": "模型只提取并分析结构化数据。",
            "deterministic_content_scope": "HTML、CSS、JavaScript 与布局均来自固定 MCP 模板。"
        }
    }))
    .expect("valid fixture JSON")
}

fn empty_patch() -> DiagramPatch {
    DiagramPatch {
        title: None,
        summary: None,
        layout_hints: None,
        display_options: None,
        upsert_nodes: vec![],
        remove_node_ids: vec![],
        upsert_edges: vec![],
        remove_edge_ids: vec![],
        upsert_groups: vec![],
        remove_group_ids: vec![],
        upsert_sources: vec![],
        remove_source_ids: vec![],
        change_summary: None,
    }
}

#[test]
fn content_addressed_render_update_and_export_are_stable() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let spec = fixture_spec();
    let validation = service.validate(&spec);
    assert!(validation.valid, "{:?}", validation.diagnostics);

    let first = service.render(&spec).expect("first render");
    let second = service.render(&spec).expect("second render");
    assert!(first.valid);
    assert!(!first.reused);
    assert!(second.reused);
    assert_eq!(first.artifact_uri, second.artifact_uri);
    assert_eq!(first.html_sha256, second.html_sha256);

    let uri = first.artifact_uri.clone().expect("artifact URI");
    let exported = service
        .export(&uri, ExportFormat::Html)
        .expect("HTML export");
    assert_eq!(exported.artifact_uri, uri);
    assert_eq!(Some(exported.html_sha256), first.html_sha256);

    let mut patch = empty_patch();
    patch.title = Some("更新后的虚构借款争议示意图".to_owned());
    patch.change_summary = Some("仅修改图示标题".to_owned());
    let updated = service
        .update(DiagramUpdateRequest {
            artifact_uri: first.artifact_uri,
            base_spec: None,
            expected_spec_hash: first.spec_hash.expect("spec hash"),
            patch,
        })
        .expect("update render");
    assert!(updated.valid);
    assert_ne!(updated.artifact_uri, second.artifact_uri);
}

#[test]
fn invalid_spec_never_generates_an_html_artifact() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let mut spec = fixture_spec();
    spec.nodes.push(spec.nodes[0].clone());
    let response = service.render(&spec).expect("structured invalid response");
    assert!(!response.valid);
    assert!(response.artifact_uri.is_none());
    let files = fs::read_dir(directory.path().join("diagrams"))
        .expect("artifact directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory listing");
    assert!(files.is_empty());
}

#[test]
fn injected_text_is_escaped_and_strict_csp_remains_enabled() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let mut spec = fixture_spec();
    spec.nodes[0].details =
        "<script>alert(1)</script><img src=x onerror=alert(2)> javascript:boom".to_owned();
    spec.nodes[0].status = NodeStatus::Disputed;
    let response = service.render(&spec).expect("safe render");
    assert!(response.valid, "{:?}", response.diagnostics);
    let key = response
        .artifact_uri
        .as_deref()
        .and_then(|uri| uri.rsplit('/').next())
        .expect("artifact key");
    let html = fs::read_to_string(
        directory
            .path()
            .join("diagrams")
            .join(key)
            .join("artifact.html"),
    )
    .expect("rendered HTML");
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("<img src=x onerror=alert(2)>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("connect-src 'none'"));
    assert!(!html.contains("STYLE_HASH_PLACEHOLDER"));
    assert!(!html.contains("SCRIPT_HASH_PLACEHOLDER"));
    assert!(!html.contains("unsafe-inline"));
    assert!(!html.contains("innerHTML"));
    assert!(!html.contains("fetch("));
}

#[test]
fn export_rejects_orphan_tamper_and_uri_hash_rebinding() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let response = service.render(&fixture_spec()).expect("safe render");
    let uri = response.artifact_uri.expect("artifact URI");
    let key = uri.rsplit('/').next().expect("artifact key");
    let artifact = directory.path().join("diagrams").join(key);
    let spec_path = artifact.join("artifact.diagram.json");
    let html_path = artifact.join("artifact.html");
    let spec = fs::read(&spec_path).expect("canonical spec");
    let html = fs::read(&html_path).expect("fixed renderer HTML");

    let mut tampered_html = html.clone();
    tampered_html.extend_from_slice(b"<!-- tampered -->");
    fs::write(&html_path, tampered_html).expect("tamper HTML");
    let error = service
        .export(&uri, ExportFormat::Html)
        .expect_err("tampered HTML must never export");
    assert_eq!(error.code(), "artifact_integrity_failed");
    fs::write(&html_path, &html).expect("restore HTML");

    let mut noncanonical_spec = spec.clone();
    noncanonical_spec.push(b'\n');
    fs::write(&spec_path, noncanonical_spec).expect("tamper canonical spec bytes");
    let error = service
        .export(&uri, ExportFormat::Html)
        .expect_err("non-canonical sibling spec bytes must never export");
    assert_eq!(error.code(), "artifact_integrity_failed");
    fs::write(&spec_path, &spec).expect("restore canonical spec");

    let mut tampered_spec: serde_json::Value =
        serde_json::from_slice(&spec).expect("canonical spec JSON");
    tampered_spec["title"] = serde_json::Value::String("被篡改的标题".to_owned());
    fs::write(
        &spec_path,
        serde_json::to_vec(&tampered_spec).expect("tampered JSON"),
    )
    .expect("tamper spec");
    let error = service
        .export(&uri, ExportFormat::Html)
        .expect_err("spec/hash mismatch must never export");
    assert_eq!(error.code(), "artifact_integrity_failed");
    fs::write(&spec_path, &spec).expect("restore spec");

    fs::remove_file(&spec_path).expect("simulate interrupted orphan");
    let error = service
        .export(&uri, ExportFormat::Html)
        .expect_err("orphan HTML must never export");
    assert_eq!(error.code(), "artifact_integrity_failed");
    fs::write(&spec_path, &spec).expect("restore spec again");

    let rebound_key = "0".repeat(64);
    let rebound = directory.path().join("diagrams").join(&rebound_key);
    fs::create_dir(&rebound).expect("rebound artifact directory");
    fs::write(rebound.join("artifact.diagram.json"), &spec).expect("copy sibling spec");
    fs::write(rebound.join("artifact.html"), &html).expect("copy sibling HTML");
    let error = service
        .export(
            &format!("lawyer-assistance://diagrams/{rebound_key}"),
            ExportFormat::Html,
        )
        .expect_err("artifact URI cannot be rebound to a different spec hash");
    assert_eq!(error.code(), "artifact_integrity_failed");
}

#[test]
fn committed_artifact_is_one_atomic_sibling_bundle_without_staging_orphans() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let response = service.render(&fixture_spec()).expect("safe render");
    let key = response
        .artifact_uri
        .as_deref()
        .and_then(|uri| uri.rsplit('/').next())
        .expect("artifact key");
    let entries = fs::read_dir(directory.path().join("diagrams"))
        .expect("diagram root")
        .collect::<Result<Vec<_>, _>>()
        .expect("diagram entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name(), key);
    assert!(entries[0].file_type().expect("artifact type").is_dir());
    let mut siblings = fs::read_dir(entries[0].path())
        .expect("artifact bundle")
        .map(|entry| entry.expect("artifact sibling").file_name())
        .collect::<Vec<_>>();
    siblings.sort();
    assert_eq!(
        siblings,
        vec![
            std::ffi::OsString::from("artifact.diagram.json"),
            std::ffi::OsString::from("artifact.html"),
        ]
    );
}

#[test]
fn after_init_diagram_root_reparse_replacement_fails_closed() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let diagram_root = directory.path().join("diagrams");
    let original = directory.path().join("diagrams-original");
    let outside = directory.path().join("outside-diagrams");
    fs::create_dir(&outside).expect("outside directory");
    fs::rename(&diagram_root, &original).expect("move initialized diagram root");
    create_directory_symlink(&outside, &diagram_root).expect("replace root with reparse point");

    let error = service
        .render(&fixture_spec())
        .expect_err("post-init reparse replacement must fail closed");
    assert_eq!(error.code(), "unsafe_output_root");
    assert_eq!(
        fs::read_dir(&outside)
            .expect("outside remains readable")
            .count(),
        0
    );

    fs::remove_dir(&diagram_root).expect("remove test reparse point");
    fs::rename(&original, &diagram_root).expect("restore diagram root for cleanup");
}

#[cfg(unix)]
fn create_directory_symlink(
    target: &std::path::Path,
    link: &std::path::Path,
) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_symlink(
    target: &std::path::Path,
    link: &std::path::Path,
) -> std::io::Result<()> {
    use std::io;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    match std::os::windows::fs::symlink_dir(target, link) {
        Ok(()) => Ok(()),
        Err(symlink_error) => {
            let status = Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::new(
                    symlink_error.kind(),
                    "failed to create a directory symlink or junction",
                ))
            }
        }
    }
}

#[test]
fn update_rejects_stale_hash_and_malicious_uri() {
    let directory = tempfile::tempdir().expect("temp output");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let spec = fixture_spec();
    let stale = service
        .update(DiagramUpdateRequest {
            artifact_uri: None,
            base_spec: Some(spec),
            expected_spec_hash: format!("sha256:{}", "0".repeat(64)),
            patch: empty_patch(),
        })
        .expect_err("stale update must fail");
    assert_eq!(stale.code(), "stale_spec");
    let traversal = service
        .export(
            "lawyer-assistance://diagrams/../../private",
            ExportFormat::Html,
        )
        .expect_err("path traversal must fail");
    assert_eq!(traversal.code(), "invalid_artifact_uri");
}
