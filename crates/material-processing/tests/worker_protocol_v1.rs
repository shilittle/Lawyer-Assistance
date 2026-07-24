use material_processing::*;

fn hash(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn id(prefix: &str, character: char) -> String {
    format!(
        "{prefix}_{}",
        std::iter::repeat_n(character, 32).collect::<String>()
    )
}

fn ppm(value: u32) -> Ppm {
    Ppm::new(value).expect("fixture ppm")
}

fn completeness() -> OcrPageCompletenessV1 {
    OcrPageCompletenessV1 {
        dimensions_verified: true,
        page_image_hash_verified: true,
        reading_order_contiguous: true,
        geometry_validated: true,
        confidences_complete: true,
        visual_regions_classified: true,
        output_tree_confined: true,
        passed: true,
    }
}

fn fixture_document() -> OcrDocumentV1 {
    OcrDocumentV1 {
        protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
        document_id: id("doc", 'a'),
        source_sha256: hash('a'),
        input_unmodified_sha256: hash('a'),
        page_count: 1,
        pages: vec![OcrPageV1 {
            page_index: 0,
            width_micropoints: 1_000_000,
            height_micropoints: 2_000_000,
            rotation_degrees: 0,
            page_image_sha256: hash('b'),
            status: OcrPageStatusV1::Ok,
            blocks: vec![OcrBlockV1 {
                block_id: id("blk", 'b'),
                block_type: OcrBlockTypeV1::Text,
                reading_order: 0,
                raw_text_ref: id("obj", 'c'),
                normalized_text: "synthetic local OCR text".to_owned(),
                bbox: OcrBoundingBoxV1 {
                    left_micropoints: 100_000,
                    top_micropoints: 200_000,
                    right_micropoints: 900_000,
                    bottom_micropoints: 800_000,
                },
                polygon: vec![
                    OcrPointV1 {
                        x_micropoints: 100_000,
                        y_micropoints: 200_000,
                    },
                    OcrPointV1 {
                        x_micropoints: 900_000,
                        y_micropoints: 200_000,
                    },
                    OcrPointV1 {
                        x_micropoints: 900_000,
                        y_micropoints: 800_000,
                    },
                    OcrPointV1 {
                        x_micropoints: 100_000,
                        y_micropoints: 800_000,
                    },
                ],
                coordinate_system: OcrCoordinateSystemV1::PageMicropoints,
                ocr_confidence_ppm: ppm(910_000),
                layout_confidence_ppm: ppm(920_000),
                confidence_available: true,
                source_locator: OcrSourceLocatorV1 {
                    page_index: 0,
                    source_block_index: 0,
                },
                visual_classification: OcrVisualClassificationV1::Textual,
            }],
            coverage_ppm: ppm(980_000),
            minimum_ocr_confidence_ppm: ppm(910_000),
            mean_ocr_confidence_ppm: ppm(910_000),
            visual_risks: vec![],
            warnings: vec![],
            completeness: completeness(),
        }],
        provenance: OcrProvenanceV1 {
            worker_version: "1.0.0".to_owned(),
            worker_sha256: hash('c'),
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            python_version: "3.12.4".to_owned(),
            mineru_version: "3.4.3".to_owned(),
            pytorch_version: "2.7.1".to_owned(),
            cuda_runtime_version: "12.8".to_owned(),
            gpu_driver_version: "555.99".to_owned(),
            requested_device: WorkerDeviceV1::Cuda {
                indices: vec![0],
                hardware_fingerprint_sha256: hash('d'),
            },
            actual_device: WorkerDeviceV1::Cuda {
                indices: vec![0],
                hardware_fingerprint_sha256: hash('d'),
            },
            model_version: "local-model-v1".to_owned(),
            model_manifest_sha256: hash('e'),
            config_sha256: hash('f'),
            isolation_evidence_id: id("iso", 'd'),
            isolation_evidence_sha256: hash('1'),
            qualification_report_id: id("qual", 'e'),
            processing_parameters_sha256: hash('2'),
            started_at_unix: 1_800_000_000,
            duration_ms: 1_234,
        },
        warnings: vec![],
        completeness: OcrDocumentCompletenessV1 {
            input_hash_verified: true,
            page_count_verified: true,
            pages_contiguous: true,
            block_ids_unique: true,
            all_pages_complete: true,
            provenance_complete: true,
            output_tree_confined: true,
            passed: true,
        },
        output_sha256: hash('3'),
    }
}

fn fixture_expectation(document: &OcrDocumentV1) -> OcrValidationExpectationV1 {
    OcrValidationExpectationV1 {
        document_id: document.document_id.clone(),
        source_sha256: document.source_sha256.clone(),
        input_unmodified_sha256: document.input_unmodified_sha256.clone(),
        page_count: document.page_count,
        output_sha256: document.output_sha256.clone(),
        worker_sha256: document.provenance.worker_sha256.clone(),
        model_manifest_sha256: document.provenance.model_manifest_sha256.clone(),
        config_sha256: document.provenance.config_sha256.clone(),
        processing_parameters_sha256: document.provenance.processing_parameters_sha256.clone(),
        isolation_evidence_id: document.provenance.isolation_evidence_id.clone(),
        isolation_evidence_sha256: document.provenance.isolation_evidence_sha256.clone(),
        qualification_report_id: document.provenance.qualification_report_id.clone(),
        output_tree_confined: true,
    }
}

#[test]
fn complete_synthetic_document_passes_host_validation() {
    let document = fixture_document();
    validate_ocr_document_v1(&document, &fixture_expectation(&document)).expect("complete fixture");

    let response = WorkerResponseV1::Ocr {
        protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
        request_id: id("req", '1'),
        job_id: id("job", '2'),
        payload: OcrResponsePayloadV1::Completed {
            document: Box::new(document),
        },
    };
    validate_worker_response_v1(&response).expect("valid response");
}

#[test]
fn wire_schema_rejects_paths_urls_commands_and_unknown_nested_fields() {
    let request = serde_json::json!({
        "message_type": "ocr",
        "protocol_version": MINERU_WORKER_PROTOCOL_V1,
        "request_id": id("req", '1'),
        "job_id": id("job", '2'),
        "document_id": id("doc", '3'),
        "input_id": id("obj", '4'),
        "expected_output_id": id("obj", '5'),
        "source_sha256": hash('a'),
        "processing_parameters_sha256": hash('b'),
        "expected_page_count": 1,
        "input_path": "C:\\private\\case.pdf",
        "url": "https://example.invalid",
        "command": "mineru --upload"
    });
    assert!(serde_json::from_value::<WorkerRequestV1>(request).is_err());

    let mut document = serde_json::to_value(fixture_document()).expect("serialize fixture");
    document["pages"][0]["blocks"][0]["metadata"] = serde_json::json!({"free_form": true});
    assert!(serde_json::from_value::<OcrDocumentV1>(document).is_err());
}

#[test]
fn ppm_is_integer_only_bounded_and_confidence_fields_are_mandatory() {
    assert_eq!(
        serde_json::from_str::<Ppm>("1000000").expect("max"),
        Ppm::ONE
    );
    assert!(serde_json::from_str::<Ppm>("1000001").is_err());
    assert!(serde_json::from_str::<Ppm>("0.95").is_err());
    assert!(serde_json::from_str::<Ppm>("-1").is_err());

    let mut document = serde_json::to_value(fixture_document()).expect("serialize fixture");
    document["pages"][0]["blocks"][0]
        .as_object_mut()
        .expect("block")
        .remove("ocr_confidence_ppm");
    assert!(serde_json::from_value::<OcrDocumentV1>(document).is_err());
}

#[test]
fn unavailable_or_inconsistent_confidence_fails_closed() {
    let mut document = fixture_document();
    document.pages[0].blocks[0].confidence_available = false;
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::ConfidenceUnavailable)
    );

    let mut document = fixture_document();
    document.pages[0].mean_ocr_confidence_ppm = ppm(900_000);
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::ConfidenceSummaryMismatch)
    );

    let mut false_warning = fixture_document();
    false_warning.pages[0]
        .warnings
        .push(OcrWarningV1::LowConfidence);
    assert_eq!(
        validate_ocr_document_structure_v1(&false_warning),
        Err(OcrIntegrityError::ConfidenceSummaryMismatch)
    );

    let mut missing_warning = fixture_document();
    missing_warning.pages[0].blocks[0].ocr_confidence_ppm = ppm(600_000);
    missing_warning.pages[0].minimum_ocr_confidence_ppm = ppm(600_000);
    missing_warning.pages[0].mean_ocr_confidence_ppm = ppm(600_000);
    assert_eq!(
        validate_ocr_document_structure_v1(&missing_warning),
        Err(OcrIntegrityError::ConfidenceSummaryMismatch)
    );
    missing_warning.pages[0]
        .warnings
        .push(OcrWarningV1::LowConfidence);
    assert_eq!(validate_ocr_document_structure_v1(&missing_warning), Ok(()));
}

#[test]
fn unknown_visual_regions_and_unbounded_geometry_fail_closed() {
    let mut document = fixture_document();
    document.pages[0].blocks[0].visual_classification = OcrVisualClassificationV1::Unknown;
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::UnknownVisualRegion)
    );

    let mut document = fixture_document();
    document.pages[0].visual_risks = vec![OcrVisualRiskV1::UnknownVisualRegion];
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::UnknownVisualRegion)
    );

    let mut document = fixture_document();
    document.pages[0].blocks[0].bbox.right_micropoints = 1_000_001;
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::GeometryInvalid)
    );
}

#[test]
fn page_and_reading_order_are_contiguous_and_block_ids_are_unique() {
    let mut document = fixture_document();
    let mut second = document.pages[0].blocks[0].clone();
    second.reading_order = 2;
    second.source_locator.source_block_index = 2;
    second.block_id = id("blk", '9');
    document.pages[0].blocks.push(second);
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::ReadingOrderInvalid)
    );

    let mut document = fixture_document();
    let mut second_page = document.pages[0].clone();
    second_page.page_index = 1;
    second_page.blocks[0].source_locator.page_index = 1;
    document.page_count = 2;
    document.pages.push(second_page);
    assert_eq!(
        validate_ocr_document_structure_v1(&document),
        Err(OcrIntegrityError::DuplicateBlockId)
    );
}

#[test]
fn host_observed_hashes_and_confinement_cannot_be_replaced_by_worker_claims() {
    let document = fixture_document();
    let mut expected = fixture_expectation(&document);
    expected.worker_sha256 = hash('9');
    assert_eq!(
        validate_ocr_document_v1(&document, &expected),
        Err(OcrIntegrityError::ExpectationMismatch)
    );

    let mut expected = fixture_expectation(&document);
    expected.output_tree_confined = false;
    assert_eq!(
        validate_ocr_document_v1(&document, &expected),
        Err(OcrIntegrityError::CompletenessFailed)
    );
}

#[test]
fn all_request_operations_round_trip_with_strict_envelopes() {
    let requests = [
        WorkerRequestV1::Hello {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: id("req", '1'),
        },
        WorkerRequestV1::Health {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: id("req", '2'),
        },
        WorkerRequestV1::Ocr {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: id("req", '3'),
            job_id: id("job", '4'),
            document_id: id("doc", '5'),
            input_id: id("obj", '6'),
            expected_output_id: id("obj", '7'),
            source_sha256: hash('a'),
            processing_parameters_sha256: hash('b'),
            expected_page_count: 2,
        },
        WorkerRequestV1::Cancel {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: id("req", '8'),
            job_id: id("job", '9'),
        },
        WorkerRequestV1::Shutdown {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: id("req", 'a'),
        },
    ];

    for request in requests {
        validate_worker_request_v1(&request).expect("valid request");
        let bytes = serde_json::to_vec(&request).expect("serialize request");
        let decoded: WorkerRequestV1 = serde_json::from_slice(&bytes).expect("decode request");
        assert_eq!(decoded, request);
    }
}
