use super::catalog::{ComponentCatalogEntryV1, ComponentCatalogV1};
use super::package::ComponentPackageManifestV1;
use super::{catalog, package, *};
use std::collections::BTreeMap;
use std::ffi::OsString;

const REAL_COMPONENT_EXPECTED_PACKAGE_SHA256_ENV: &str =
    "LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256";

fn parse_real_component_expected_package_sha256(
    value: Option<OsString>,
) -> Result<String, &'static str> {
    let value = value
        .ok_or("LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 is required")?
        .into_string()
        .map_err(|_| "LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 must be UTF-8")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 must be 64 lowercase hex characters",
        );
    }
    Ok(value)
}

fn real_component_expected_package_sha256() -> String {
    parse_real_component_expected_package_sha256(std::env::var_os(
        REAL_COMPONENT_EXPECTED_PACKAGE_SHA256_ENV,
    ))
    .expect("a pinned expected production package SHA-256 is required")
}

fn fixture(version: &str) -> (ComponentPackageManifestV1, Vec<u8>, ComponentCatalogEntryV1) {
    fixture_with_runtime(version, true, true)
}

fn fixture_with_runtime(
    version: &str,
    include_runtime_payload: bool,
    declare_runtime: bool,
) -> (ComponentPackageManifestV1, Vec<u8>, ComponentCatalogEntryV1) {
    let mut payloads = BTreeMap::<String, Vec<u8>>::new();
    payloads.insert(
        "worker/mineru-worker.exe".to_owned(),
        b"MZsynthetic-worker".to_vec(),
    );
    for (root, files) in [
        ("pipeline", package::PIPELINE_MODEL_FILES),
        ("vlm", package::VLM_MODEL_FILES),
    ] {
        for relative in files {
            payloads.insert(
                format!("models/{root}/{relative}"),
                format!("synthetic-model:{root}:{relative}").into_bytes(),
            );
        }
    }
    for (path, bytes) in [
        (
            "licenses/cpython/LICENSE.txt",
            b"synthetic PSF license".as_slice(),
        ),
        (
            "runtime/site-packages/mineru-3.4.3.dist-info/RECORD",
            b"synthetic mineru record".as_slice(),
        ),
        (
            "runtime/site-packages/mineru-3.4.3.dist-info/licenses/LICENSE.md",
            b"synthetic MinerU license".as_slice(),
        ),
        (
            "runtime/site-packages/torch-2.8.0+cu128.dist-info/RECORD",
            b"synthetic torch record".as_slice(),
        ),
        (
            "runtime/site-packages/torch-2.8.0+cu128.dist-info/LICENSE",
            b"synthetic torch license".as_slice(),
        ),
        (
            "runtime/site-packages/torch-2.8.0+cu128.dist-info/NOTICE",
            b"synthetic torch notice".as_slice(),
        ),
        (
            "runtime/site-packages/torchvision-0.23.0+cu128.dist-info/RECORD",
            b"synthetic torchvision record".as_slice(),
        ),
        (
            "runtime/site-packages/torchvision-0.23.0+cu128.dist-info/LICENSE",
            b"synthetic torchvision license".as_slice(),
        ),
    ] {
        payloads.insert(path.to_owned(), bytes.to_vec());
    }
    if include_runtime_payload {
        payloads.insert(
            "python/python.exe".to_owned(),
            b"MZsynthetic-python".to_vec(),
        );
    }
    let record = |logical: &str, relative: &str| {
        let bytes = &payloads[logical];
        serde_json::json!({
            "relativePath": relative,
            "sizeBytes": bytes.len(),
            "sha256": package::sha256_bytes(bytes),
        })
    };
    let distribution = |name: &str,
                        distribution_version: &str,
                        license: &str,
                        record_path: &str,
                        license_paths: &[&str],
                        upstream_artifact: serde_json::Value| {
        serde_json::json!({
            "name": name,
            "version": distribution_version,
            "contentSha256": package::sha256_bytes(format!("content:{name}").as_bytes()),
            "packagedContentSha256": package::sha256_bytes(format!("packaged:{name}").as_bytes()),
            "sourceUrl": format!("https://pypi.org/project/{name}/{distribution_version}/"),
            "license": license,
            "licenseEvidenceKind": "metadata-license-expression",
            "licenseFiles": license_paths.iter().map(|relative| {
                record(&format!("runtime/site-packages/{relative}"), relative)
            }).collect::<Vec<_>>(),
            "installationRecord": record(
                &format!("runtime/site-packages/{record_path}"),
                record_path,
            ),
            "upstreamArtifact": upstream_artifact,
        })
    };
    let model = |root: &str, profile: (&str, &str, &str), evidence_sha256: &str, files: &[&str]| {
        serde_json::json!({
            "root": root,
            "name": profile.0,
            "revision": profile.1,
            "sourceUrl": format!("https://huggingface.co/{}/tree/{}", profile.0, profile.1),
            "license": profile.2,
            "licenseEvidenceUrl": format!(
                "https://huggingface.co/{}/blob/{}/README.md",
                profile.0, profile.1
            ),
            "licenseEvidenceSha256": evidence_sha256,
            "files": files.iter().map(|relative| {
                record(&format!("models/{root}/{relative}"), relative)
            }).collect::<Vec<_>>(),
        })
    };
    let provenance = serde_json::json!({
        "schemaVersion": 1,
        "provenanceVersion": "lawyer-assistance-mineru-component-provenance-v1",
        "provenanceInputSha256": "1".repeat(64),
        "approval": {
            "approvedForRedistribution": true,
            "reviewer": "synthetic-test-fixture",
            "reviewedAtUnix": 1_700_000_000u64,
        },
        "source": {
            "repositoryCommit": "2".repeat(40),
            "buildScriptSha256": "3".repeat(64),
            "workerSourceTreeSha256": "4".repeat(64),
        },
        "cpython": {
            "version": "3.12.13",
            "sourceUrl": "https://www.python.org/downloads/release/python-31213/",
            "contentSha256": "5".repeat(64),
            "license": "PSF-2.0",
            "licenseFileSha256": package::sha256_bytes(&payloads["licenses/cpython/LICENSE.txt"]),
        },
        "runtimeProfile": {
            "platform": "windows-x86_64",
            "rootDistribution": "mineru==3.4.3",
            "extras": ["pipeline", "vlm"],
        },
        "distributions": [
            distribution(
                "mineru",
                "3.4.3",
                "LicenseRef-MinerU-Open-Source-License",
                "mineru-3.4.3.dist-info/RECORD",
                &["mineru-3.4.3.dist-info/licenses/LICENSE.md"],
                serde_json::Value::Null,
            ),
            distribution(
                "torch",
                "2.8.0+cu128",
                "BSD-3-Clause",
                "torch-2.8.0+cu128.dist-info/RECORD",
                &[
                    "torch-2.8.0+cu128.dist-info/LICENSE",
                    "torch-2.8.0+cu128.dist-info/NOTICE",
                ],
                serde_json::json!({
                    "fileName": package::TORCH_WHEEL.0,
                    "sourceUrl": package::TORCH_WHEEL.1,
                    "sha256": package::TORCH_WHEEL.2,
                }),
            ),
            distribution(
                "torchvision",
                "0.23.0+cu128",
                "BSD-3-Clause",
                "torchvision-0.23.0+cu128.dist-info/RECORD",
                &["torchvision-0.23.0+cu128.dist-info/LICENSE"],
                serde_json::json!({
                    "fileName": package::TORCHVISION_WHEEL.0,
                    "sourceUrl": package::TORCHVISION_WHEEL.1,
                    "sha256": package::TORCHVISION_WHEEL.2,
                }),
            ),
        ],
        "excludedDistributions": [],
        "models": [
            model(
                "pipeline",
                package::PIPELINE_MODEL,
                package::PIPELINE_MODEL_LICENSE_EVIDENCE_SHA256,
                package::PIPELINE_MODEL_FILES,
            ),
            model(
                "vlm",
                package::VLM_MODEL,
                package::VLM_MODEL_LICENSE_EVIDENCE_SHA256,
                package::VLM_MODEL_FILES,
            ),
        ],
    });
    let provenance_bytes = privacy::vnext::canonical_json_v1(&provenance).unwrap();
    let provenance_sha256 = package::sha256_bytes(&provenance_bytes);
    let provenance_size_bytes = provenance_bytes.len() as u64;
    payloads.insert(
        "licenses/mineru-component-provenance.json".to_owned(),
        provenance_bytes,
    );
    let manifest = ComponentPackageManifestV1 {
        schema_version: 1,
        package_id: format!("synthetic-mineru-{}", version.replace('.', "-")),
        component_version: Version::parse(version).unwrap(),
        mineru_version: "3.4.3".to_owned(),
        protocol_version: "la-mineru-worker-v1".to_owned(),
        platform: "windows-x86_64".to_owned(),
        worker: "worker/mineru-worker.exe".to_owned(),
        runtime_executables: if declare_runtime {
            vec!["python/python.exe".to_owned()]
        } else {
            Vec::new()
        },
        pipeline_model_directory: "models/pipeline".to_owned(),
        vlm_model_directory: "models/vlm".to_owned(),
        provenance_relative_path: "licenses/mineru-component-provenance.json".to_owned(),
        provenance_size_bytes,
        provenance_sha256: provenance_sha256.clone(),
        files: payloads
            .iter()
            .map(|(relative_path, bytes)| package::PackageFileV1 {
                relative_path: relative_path.to_owned(),
                size_bytes: bytes.len() as u64,
                sha256: package::sha256_bytes(bytes),
            })
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let mut package_bytes = b"LAOCPK1\0".to_vec();
    package_bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
    package_bytes.extend_from_slice(&manifest_bytes);
    for entry in &manifest.files {
        package_bytes.extend_from_slice(&payloads[entry.relative_path.as_str()]);
    }
    let entry = ComponentCatalogEntryV1 {
        package_id: manifest.package_id.clone(),
        component_version: manifest.component_version.clone(),
        mineru_version: manifest.mineru_version.clone(),
        protocol_version: manifest.protocol_version.clone(),
        platform: manifest.platform.clone(),
        package_size_bytes: package_bytes.len() as u64,
        package_sha256: package::sha256_bytes(&package_bytes),
        package_manifest_sha256: package::sha256_bytes(&manifest_bytes),
        provenance_file_name: "mineru-component-provenance.json".to_owned(),
        provenance_size_bytes,
        provenance_sha256,
        provenance_download_url: format!(
            "https://github.com/shilittle/Lawyer-Assistance/releases/download/mineru-components-v{version}/mineru-component-provenance.json"
        ),
        part_set_manifest_size_bytes: None,
        part_set_manifest_sha256: None,
        parts: Vec::new(),
        download_url: format!(
            "https://github.com/shilittle/Lawyer-Assistance/releases/download/mineru-components-v{version}/lawyer-assistance-mineru-{version}-windows-x86_64.laocrpkg"
        ),
        revoked: false,
    };
    (manifest, package_bytes, entry)
}

fn catalog(entries: Vec<ComponentCatalogEntryV1>) -> ComponentCatalogV1 {
    ComponentCatalogV1 {
        schema_version: 1,
        catalog_id: "synthetic-catalog-v1".to_owned(),
        issued_at_unix: 1_700_000_000,
        expires_at_unix: 4_000_000_000,
        entries,
    }
}

#[test]
fn real_component_expected_package_sha256_is_required_and_strictly_lowercase_hex() {
    let valid = "0123456789abcdef".repeat(4);
    assert_eq!(
        parse_real_component_expected_package_sha256(Some(OsString::from(&valid))),
        Ok(valid)
    );
    assert_eq!(
        parse_real_component_expected_package_sha256(None),
        Err("LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 is required")
    );
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("{} ", "a".repeat(63)),
    ] {
        assert_eq!(
            parse_real_component_expected_package_sha256(Some(OsString::from(invalid))),
            Err(
                "LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 must be 64 lowercase hex characters"
            )
        );
    }
}

#[test]
fn package_manifest_ceiling_fits_production_inventory_but_rejects_larger_headers() {
    assert_eq!(package::MAX_MANIFEST_BYTES, 16 * 1024 * 1024);
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("app");
    package::ensure_private_fixed_directory(&root).unwrap();
    let (_, _, mut entry) = fixture("1.2.3");
    let mut bytes = b"LAOCPK1\0".to_vec();
    bytes.extend_from_slice(&((package::MAX_MANIFEST_BYTES + 1) as u32).to_le_bytes());
    entry.package_size_bytes = bytes.len() as u64;
    entry.package_sha256 = package::sha256_bytes(&bytes);
    let path = temporary.path().join("oversized-manifest.laocrpkg");
    fs::write(&path, bytes).unwrap();
    assert_eq!(
        package::install_package(&root, &path, &entry)
            .unwrap_err()
            .code(),
        "package_format_invalid"
    );
}

#[test]
fn provenance_rejects_unknown_fields_and_pinned_license_model_or_wheel_drift() {
    let (manifest, package_bytes, _) = fixture("1.2.3");
    let manifest_size = u32::from_le_bytes(package_bytes[8..12].try_into().unwrap()) as usize;
    let mut offset = 12 + manifest_size;
    let mut provenance = None;
    for file in &manifest.files {
        let end = offset + file.size_bytes as usize;
        if file.relative_path == "licenses/mineru-component-provenance.json" {
            provenance = Some(package_bytes[offset..end].to_vec());
            break;
        }
        offset = end;
    }
    let provenance = provenance.expect("fixture provenance payload");
    package::validate_component_provenance(&provenance, &manifest)
        .expect("strict fixture provenance");

    let mut value: serde_json::Value = serde_json::from_slice(&provenance).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), serde_json::json!(true));
    let unknown = privacy::vnext::canonical_json_v1(&value).unwrap();
    assert_eq!(
        package::validate_component_provenance(&unknown, &manifest)
            .unwrap_err()
            .code(),
        "component_provenance_invalid"
    );

    for (pointer, replacement) in [
        ("/distributions/0/license", serde_json::json!("Apache-2.0")),
        (
            "/distributions/1/upstreamArtifact/sha256",
            serde_json::json!("0".repeat(64)),
        ),
        (
            "/models/1/licenseEvidenceSha256",
            serde_json::json!("0".repeat(64)),
        ),
    ] {
        let mut drifted: serde_json::Value = serde_json::from_slice(&provenance).unwrap();
        *drifted.pointer_mut(pointer).unwrap() = replacement;
        let drifted = privacy::vnext::canonical_json_v1(&drifted).unwrap();
        assert_eq!(
            package::validate_component_provenance(&drifted, &manifest)
                .unwrap_err()
                .code(),
            "component_provenance_invalid",
            "{pointer} must be pinned"
        );
    }
}

#[test]
fn package_accepts_worker_only_and_rejects_undeclared_extra_executable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("app");
    package::ensure_private_fixed_directory(&root).unwrap();
    let (manifest, worker_only_bytes, worker_only_entry) =
        fixture_with_runtime("1.0.0", false, false);
    assert!(manifest.runtime_executables.is_empty());
    let worker_only = temporary.path().join("worker-only.laocrpkg");
    fs::write(&worker_only, worker_only_bytes).unwrap();
    let binding = package::install_package(&root, &worker_only, &worker_only_entry).unwrap();
    assert!(binding.worker_path.ends_with("worker/mineru-worker.exe"));
    assert!(binding.runtime_executable_paths.is_empty());
    let managed_config = fs::read_to_string(&binding.tools_config_path).unwrap();
    assert!(!managed_config.contains(r"\\?\"));
    let managed_config: serde_json::Value = serde_json::from_str(&managed_config).unwrap();
    assert!(Path::new(managed_config["models-dir"]["pipeline"].as_str().unwrap()).is_absolute());

    let undeclared_root = temporary.path().join("undeclared-app");
    package::ensure_private_fixed_directory(&undeclared_root).unwrap();
    let (_, undeclared_bytes, undeclared_entry) = fixture_with_runtime("1.0.1", true, false);
    let undeclared = temporary.path().join("undeclared.laocrpkg");
    fs::write(&undeclared, undeclared_bytes).unwrap();
    assert_eq!(
        package::install_package(&undeclared_root, &undeclared, &undeclared_entry)
            .unwrap_err()
            .code(),
        "package_manifest_invalid"
    );
}

#[test]
fn component_runtime_path_budget_rejects_an_unusable_final_windows_path() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("app");
    package::ensure_private_fixed_directory(&root).unwrap();
    let (mut manifest, _, _) = fixture("1.0.0");
    package::ensure_runtime_path_budget(&root.join("1.0.0"), &manifest)
        .expect("ordinary app-local-data path fits the runtime budget");

    let relative_path = format!("runtime/{}.py", "x".repeat(220));
    manifest.files.push(package::PackageFileV1 {
        relative_path,
        size_bytes: 1,
        sha256: "1".repeat(64),
    });
    assert_eq!(
        package::ensure_runtime_path_budget(&root.join("1.0.0"), &manifest)
            .unwrap_err()
            .code(),
        "component_runtime_path_too_long"
    );
}

#[tokio::test]
async fn sharded_offline_import_is_canonical_atomic_and_rejects_extra_or_tampered_parts() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("app");
    package::ensure_private_fixed_directory(&root).unwrap();
    let (_, package_bytes, mut entry) = fixture("1.2.3");
    let source = temporary.path().join("parts");
    fs::create_dir(&source).unwrap();
    let part_size = 256usize;
    let count = package_bytes.len().div_ceil(part_size);
    let logical_name = "lawyer-assistance-mineru-1.2.3-windows-x86_64.laocrpkg".to_owned();
    let mut descriptor_parts = Vec::new();
    let mut catalog_parts = Vec::new();
    for (offset, bytes) in package_bytes.chunks(part_size).enumerate() {
        let number = u16::try_from(offset + 1).unwrap();
        let file_name = format!("{logical_name}.part{number:04}-of-{count:04}");
        fs::write(source.join(&file_name), bytes).unwrap();
        let sha256 = package::sha256_bytes(bytes);
        descriptor_parts.push(package::PartSetFileV1 {
            number,
            file_name: file_name.clone(),
            size_bytes: bytes.len() as u64,
            sha256: sha256.clone(),
        });
        catalog_parts.push(catalog::ComponentPackagePartV1 {
            number,
            file_name: file_name.clone(),
            size_bytes: bytes.len() as u64,
            sha256,
            download_url: format!(
                "https://github.com/shilittle/Lawyer-Assistance/releases/download/mineru-components-v1.2.3/{file_name}"
            ),
        });
    }
    let descriptor = package::PartSetManifestV1 {
        schema_version: 1,
        package_id: entry.package_id.clone(),
        component_version: entry.component_version.clone(),
        package_filename: logical_name.clone(),
        package_size_bytes: package_bytes.len() as u64,
        package_sha256: package::sha256_bytes(&package_bytes),
        package_manifest_sha256: entry.package_manifest_sha256.clone(),
        part_count: u16::try_from(count).unwrap(),
        parts: descriptor_parts,
    };
    let descriptor_bytes = privacy::vnext::canonical_json_v1(&descriptor).unwrap();
    let descriptor_name = format!("{logical_name}.laocrparts");
    let descriptor_path = source.join(&descriptor_name);
    fs::write(&descriptor_path, &descriptor_bytes).unwrap();
    entry.download_url = format!(
        "https://github.com/shilittle/Lawyer-Assistance/releases/download/mineru-components-v1.2.3/{descriptor_name}"
    );
    entry.package_size_bytes = package_bytes.len() as u64;
    entry.package_sha256 = package::sha256_bytes(&package_bytes);
    entry.part_set_manifest_size_bytes = Some(descriptor_bytes.len() as u64);
    entry.part_set_manifest_sha256 = Some(package::sha256_bytes(&descriptor_bytes));
    entry.parts = catalog_parts;
    let trusted_descriptor = package::read_part_set_manifest(&descriptor_path, &entry).unwrap();
    assert_eq!(
        usize::from(trusted_descriptor.part_count),
        entry.parts.len()
    );
    assert_eq!(trusted_descriptor.parts.len(), entry.parts.len());
    assert!(entry.parts.len() > 1);

    let mut signed_shape = catalog(vec![entry.clone()]);
    signed_shape.schema_version = 2;
    let canonical = privacy::vnext::canonical_json_v1(&signed_shape).unwrap();
    catalog::validate_catalog(&canonical, 2_000_000_000).unwrap();
    let resumed = catalog::download_catalog_parts(&entry, &source)
        .await
        .unwrap();
    assert_eq!(resumed, descriptor_path);

    let (assembly, assembled) =
        package::assemble_offline_part_set(&root, &descriptor_path, &entry).unwrap();
    assert_eq!(fs::read(&assembled).unwrap(), package_bytes);
    package::install_package(&root, &assembled, &entry).unwrap();
    package::cleanup_exact_transient(&assembly, &[assembled]).unwrap();

    fs::write(source.join("undeclared.bin"), b"extra").unwrap();
    assert_eq!(
        package::assemble_offline_part_set(&root, &descriptor_path, &entry)
            .unwrap_err()
            .code(),
        "part_source_file_set_mismatch"
    );
    fs::remove_file(source.join("undeclared.bin")).unwrap();

    let last = source.join(&entry.parts.last().unwrap().file_name);
    let mut tampered = fs::read(&last).unwrap();
    tampered[0] ^= 1;
    fs::write(&last, tampered).unwrap();
    assert_eq!(
        package::assemble_offline_part_set(&root, &descriptor_path, &entry)
            .unwrap_err()
            .code(),
        "part_integrity_mismatch"
    );
}

#[test]
fn lifecycle_installs_upgrades_rolls_back_and_removes_tampered_exact_tree() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = MineruComponentManager::new(temporary.path().join("app")).unwrap();
    let (_, bytes1, entry1) = fixture("1.0.0");
    let path1 = temporary.path().join("one.laocrpkg");
    fs::write(&path1, bytes1).unwrap();
    let first = manager.install_locked(&path1, &entry1).unwrap();
    let first_binding = first.binding.unwrap();
    assert!(first_binding.worker_path.is_file());
    assert_eq!(
        manager.read_current().unwrap().active_version,
        Some(Version::new(1, 0, 0))
    );

    let (_, bytes2, entry2) = fixture("1.1.0");
    let path2 = temporary.path().join("two.laocrpkg");
    fs::write(&path2, bytes2).unwrap();
    manager.install_locked(&path2, &entry2).unwrap();
    let trusted = catalog(vec![entry1.clone(), entry2]);
    let rollback = package::validate_installed_component(
        manager.managed_root(),
        &Version::new(1, 0, 0),
        &trusted,
    )
    .unwrap();
    manager
        .activate_locked(&rollback, Some(Version::new(1, 1, 0)))
        .unwrap();
    assert_eq!(
        manager.read_current().unwrap().active_version,
        Some(Version::new(1, 0, 0))
    );

    fs::write(&rollback.worker_path, b"MZtampered").unwrap();
    assert_eq!(
        package::validate_installed_component(
            manager.managed_root(),
            &Version::new(1, 0, 0),
            &trusted,
        )
        .unwrap_err()
        .code(),
        "component_file_drifted"
    );
    manager.uninstall("1.0.0").unwrap();
    assert!(!rollback.worker_path.exists());
}

#[test]
fn package_rejects_traversal_ads_reparse_shape_and_hardlinks() {
    for value in [
        "../escape",
        "models/file:stream",
        "models\\file",
        "/absolute",
        "CON",
    ] {
        assert!(package::validated_relative(value).is_err(), "{value}");
    }
    let temporary = tempfile::tempdir().unwrap();
    let file = temporary.path().join("package.laocrpkg");
    fs::write(&file, b"synthetic").unwrap();
    fs::hard_link(&file, temporary.path().join("alias.laocrpkg")).unwrap();
    assert_eq!(
        package::read_pinned_local_file(&file, 1024)
            .unwrap_err()
            .code(),
        "filesystem_rejected"
    );
}

#[test]
fn exact_file_set_rejects_manifest_external_model_file() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("app");
    package::ensure_private_fixed_directory(&root).unwrap();
    let (_, bytes, entry) = fixture("1.0.0");
    let source = temporary.path().join("component.laocrpkg");
    fs::write(&source, bytes).unwrap();
    let binding = package::install_package(&root, &source, &entry).unwrap();
    fs::write(binding.model_root.join("pipeline/extra.bin"), b"extra").unwrap();
    let failure =
        package::validate_installed_component(&root, &Version::new(1, 0, 0), &catalog(vec![entry]))
            .unwrap_err();
    assert_eq!(failure.code(), "component_file_set_drifted");
}

#[test]
fn catalog_schema_has_no_case_or_remote_ocr_fields_and_pins_official_https() {
    let (_, bytes, entry) = fixture("1.0.0");
    let mut value = serde_json::to_value(catalog(vec![entry])).unwrap();
    value.as_object_mut().unwrap().insert(
        "caseMaterialUrl".to_owned(),
        serde_json::json!("https://invalid"),
    );
    assert!(
        catalog::validate_catalog(&serde_json::to_vec(&value).unwrap(), 2_000_000_000).is_err()
    );

    let (_, _, mut unsafe_entry) = fixture("1.0.1");
    unsafe_entry.download_url = "https://localhost/component.laocrpkg".to_owned();
    assert!(catalog::validate_catalog(
        &serde_json::to_vec(&catalog(vec![unsafe_entry])).unwrap(),
        2_000_000_000,
    )
    .is_err());
    assert!(!bytes.is_empty());
}

#[test]
fn minisign_gate_binds_exact_bytes_and_catalog_filename() {
    const KEY: &str = "untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==";
    catalog::verify_signature(b"test", SIGNATURE.as_bytes(), "test", KEY).unwrap();
    assert!(catalog::verify_signature(
        b"test",
        SIGNATURE.as_bytes(),
        "test",
        &catalog::embedded_public_key().unwrap(),
    )
    .is_err());
    assert!(catalog::verify_signature(b"Test", SIGNATURE.as_bytes(), "test", KEY).is_err());
    assert!(catalog::verify_signature(b"test", SIGNATURE.as_bytes(), "other", KEY).is_err());
}

#[test]
fn failed_download_artifact_cleanup_is_exact_and_does_not_follow_links() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("download");
    fs::create_dir(&directory).unwrap();
    let package = directory.join("component.laocrpkg");
    fs::write(&package, b"partial").unwrap();
    package::cleanup_exact_transient(&directory, &[package]).unwrap();
    assert!(!directory.exists());

    let unsafe_directory = temporary.path().join("unsafe-download");
    fs::create_dir(&unsafe_directory).unwrap();
    let target = temporary.path().join("outside");
    fs::create_dir(&target).unwrap();
    let sentinel = target.join("sentinel.bin");
    fs::write(&sentinel, b"outside").unwrap();
    let link = unsafe_directory.join("link");
    let created = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("launch the Windows junction fixture command");
    assert!(created.success(), "create the NTFS junction fixture");
    assert_eq!(
        package::cleanup_safe_transient(&unsafe_directory)
            .unwrap_err()
            .code(),
        "cleanup_failed"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
    fs::remove_dir(&link).unwrap();
}

#[test]
fn resumable_download_gc_preserves_only_current_catalog_hashes() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = MineruComponentManager::new(temporary.path().join("app")).unwrap();
    let known_hash = "a".repeat(64);
    let unknown_hash = "b".repeat(64);
    let known = manager
        .managed_root()
        .join(format!(".download-resume-{known_hash}"));
    let unknown = manager
        .managed_root()
        .join(format!(".download-resume-{unknown_hash}"));
    let malformed = manager
        .managed_root()
        .join(".download-resume-not-a-package-hash");
    for directory in [&known, &unknown, &malformed] {
        fs::create_dir(directory).unwrap();
        fs::write(directory.join("partial.bin"), b"partial").unwrap();
    }

    manager
        .cleanup_stale_transients_with_live_resume_hashes(&BTreeSet::from([known_hash]))
        .unwrap();
    assert!(known.is_dir());
    assert!(!unknown.exists());
    assert!(!malformed.exists());

    let (_, _, expired_entry) = fixture("9.9.9");
    let mut expired_catalog = catalog(vec![expired_entry]);
    expired_catalog.issued_at_unix = 100;
    expired_catalog.expires_at_unix = 200;
    assert_eq!(
        catalog::validate_catalog(&serde_json::to_vec(&expired_catalog).unwrap(), 201)
            .unwrap_err()
            .code(),
        "catalog_schema_invalid"
    );
    manager.cleanup_stale_transients().unwrap();
    assert!(
        !known.exists(),
        "a missing, expired, or otherwise untrusted catalog makes every resume hash unknown"
    );
}

#[test]
fn resumable_download_gc_is_bounded_and_fails_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = MineruComponentManager::new(temporary.path().join("app")).unwrap();
    for index in 0..=MAX_RESUMABLE_DOWNLOAD_DIRECTORIES {
        let hash = format!("{index:064x}");
        fs::create_dir(
            manager
                .managed_root()
                .join(format!(".download-resume-{hash}")),
        )
        .unwrap();
    }
    assert_eq!(
        manager
            .cleanup_stale_transients_with_live_resume_hashes(&BTreeSet::new())
            .unwrap_err()
            .code(),
        "transient_gc_limit_exceeded"
    );
}

#[test]
fn authenticated_current_rejects_tamper_and_catalog_high_water_rejects_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = MineruComponentManager::new(temporary.path().join("app")).unwrap();
    let (_, bytes, entry) = fixture("2.0.0");
    let source = temporary.path().join("component.laocrpkg");
    fs::write(&source, bytes).unwrap();
    manager.install_locked(&source, &entry).unwrap();
    let current_path = manager.managed_root().join("current.json");
    let mut current = fs::read(&current_path).unwrap();
    let index = current.iter().position(|byte| *byte == b'2').unwrap();
    current[index] = b'9';
    fs::write(&current_path, current).unwrap();
    assert_eq!(
        manager.read_current().unwrap_err().code(),
        "current_state_signature_invalid"
    );
    assert!(manager.uninstall("2.0.0").is_err());

    let first_hash = package::sha256_bytes(b"catalog-one");
    let second_hash = package::sha256_bytes(b"catalog-two");
    state::authorize_catalog_import(manager.managed_root(), 200, &first_hash).unwrap();
    assert_eq!(
        state::authorize_catalog_import(manager.managed_root(), 199, &first_hash)
            .unwrap_err()
            .code(),
        "catalog_rollback_rejected"
    );
    assert_eq!(
        state::authorize_catalog_import(manager.managed_root(), 200, &second_hash)
            .unwrap_err()
            .code(),
        "catalog_equivocation_rejected"
    );
    state::authorize_catalog_import(manager.managed_root(), 201, &second_hash).unwrap();
}

#[test]
fn package_requires_outer_and_manifest_hash_and_catalog_enforces_url_and_size_caps() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = MineruComponentManager::new(temporary.path().join("app")).unwrap();
    let (_, bytes, entry) = fixture("4.0.0");
    let source = temporary.path().join("component.laocrpkg");
    fs::write(&source, bytes).unwrap();

    let mut wrong_outer_hash = entry.clone();
    wrong_outer_hash.package_sha256 = "0".repeat(64);
    assert_eq!(
        manager
            .install_locked(&source, &wrong_outer_hash)
            .unwrap_err()
            .code(),
        "package_integrity_mismatch"
    );

    let mut wrong_manifest_hash = entry.clone();
    wrong_manifest_hash.package_manifest_sha256 = "0".repeat(64);
    assert_eq!(
        manager
            .install_locked(&source, &wrong_manifest_hash)
            .unwrap_err()
            .code(),
        "package_manifest_untrusted"
    );

    let mut wrong_release_tag = entry.clone();
    wrong_release_tag.download_url = wrong_release_tag
        .download_url
        .replace("mineru-components-v4.0.0", "mineru-components-v3.9.9");
    assert!(catalog::validate_catalog(
        &serde_json::to_vec(&catalog(vec![wrong_release_tag])).unwrap(),
        2_000_000_000,
    )
    .is_err());

    let mut oversized = entry;
    oversized.package_size_bytes = package::MAX_PACKAGE_BYTES + 1;
    assert!(catalog::validate_catalog(
        &serde_json::to_vec(&catalog(vec![oversized])).unwrap(),
        2_000_000_000,
    )
    .is_err());
}

#[test]
#[ignore = "requires the locally built, signed 11+ GiB production MinerU release set"]
fn real_signed_sharded_release_imports_installs_and_remeasures() {
    let expected_package_sha256 = real_component_expected_package_sha256();
    let release = std::env::var_os("LA_REAL_MINERU_COMPONENT_RELEASE_DIRECTORY")
        .map(PathBuf::from)
        .expect("LA_REAL_MINERU_COMPONENT_RELEASE_DIRECTORY is required");
    let state = std::env::var_os("LA_REAL_MINERU_COMPONENT_STATE_DIRECTORY")
        .map(PathBuf::from)
        .expect("LA_REAL_MINERU_COMPONENT_STATE_DIRECTORY is required");
    let offline_set = std::env::var_os("LA_REAL_MINERU_COMPONENT_OFFLINE_SET_DIRECTORY")
        .map(PathBuf::from)
        .expect("LA_REAL_MINERU_COMPONENT_OFFLINE_SET_DIRECTORY is required");
    let catalog_path = release.join("mineru-component-catalog.json");
    let signature_path = release.join("mineru-component-catalog.json.minisig");
    let descriptor_path = offline_set
        .join("lawyer-assistance-mineru-0.4.0-beta.2-windows-x86_64.laocrpkg.laocrparts");
    for path in [&catalog_path, &signature_path, &descriptor_path] {
        assert!(path.is_file(), "required release artifact is missing");
    }

    let manager = MineruComponentManager::new(state).expect("component manager initializes");
    let imported = manager
        .import_catalog(&catalog_path, &signature_path)
        .expect("production catalog signature and epoch verify");
    assert!(imported.catalog_trusted);
    assert_eq!(imported.available_packages.len(), 1);
    assert_eq!(
        imported.available_packages[0].component_version,
        "0.4.0-beta.2"
    );
    assert_eq!(
        imported.available_packages[0].package_sha256,
        expected_package_sha256
    );

    let trusted_catalog =
        catalog::load_trusted_catalog(manager.managed_root()).expect("trusted catalog reloads");
    let trusted_entry = trusted_catalog
        .entries
        .first()
        .expect("one trusted production catalog entry");
    assert_eq!(trusted_entry.package_sha256, expected_package_sha256);
    let trusted_descriptor = package::read_part_set_manifest(&descriptor_path, trusted_entry)
        .expect("descriptor and its dynamic part inventory bind to the trusted catalog");
    assert!(!trusted_entry.parts.is_empty());
    assert_eq!(
        usize::from(trusted_descriptor.part_count),
        trusted_entry.parts.len()
    );
    assert_eq!(trusted_descriptor.parts.len(), trusted_entry.parts.len());
    let expected_manifest_sha256 = trusted_entry.package_manifest_sha256.clone();

    let mutation = manager
        .install_offline_package(&descriptor_path)
        .expect("all catalog-pinned parts assemble and install atomically");
    let binding = mutation.binding.expect("installed component is activated");
    assert_eq!(binding.component_version.to_string(), "0.4.0-beta.2");
    assert_eq!(binding.manifest_sha256, expected_manifest_sha256);
    assert!(binding.worker_path.is_file());
    assert!(binding.model_root.join("pipeline").is_dir());
    assert!(binding.model_root.join("vlm").is_dir());
    assert!(!fs::read_to_string(&binding.tools_config_path)
        .expect("managed config reads")
        .contains(r"\\?\"));

    let restarted = MineruComponentManager::new(
        manager
            .managed_root()
            .parent()
            .and_then(Path::parent)
            .expect("managed root has app-local-data parent")
            .to_path_buf(),
    )
    .expect("component manager restart remeasures installed bytes");
    let status = restarted.status().expect("component status loads");
    assert_eq!(status.active_version.as_deref(), Some("0.4.0-beta.2"));
    assert!(status.active_integrity_valid);
    assert!(status.qualification_recheck_required);
    assert!(!status.remote_ocr_allowed);
    assert!(!status.case_material_downloaded_or_uploaded);
}
