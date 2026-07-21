use crate::worker_protocol::*;
use std::collections::BTreeSet;

const MAX_OCR_PAGES: usize = 10_000;
const MAX_BLOCKS_PER_PAGE: usize = 100_000;
const MAX_POLYGON_POINTS: usize = 128;
const MAX_TEXT_BYTES_PER_BLOCK: usize = 16 * 1024 * 1024;
const MAX_REASON_CODES: usize = 128;

pub fn validate_worker_request_v1(request: &WorkerRequestV1) -> Result<(), OcrIntegrityError> {
    match request {
        WorkerRequestV1::Hello {
            protocol_version,
            request_id,
        }
        | WorkerRequestV1::Health {
            protocol_version,
            request_id,
        }
        | WorkerRequestV1::Shutdown {
            protocol_version,
            request_id,
        } => validate_envelope(protocol_version, request_id),
        WorkerRequestV1::Ocr {
            protocol_version,
            request_id,
            job_id,
            document_id,
            input_id,
            expected_output_id,
            source_sha256,
            processing_parameters_sha256,
            expected_page_count,
        } => {
            validate_envelope(protocol_version, request_id)?;
            if !valid_opaque_id(job_id)
                || !valid_opaque_id(document_id)
                || !valid_opaque_id(input_id)
                || !valid_opaque_id(expected_output_id)
                || input_id == expected_output_id
            {
                return Err(OcrIntegrityError::InvalidOpaqueId);
            }
            if !valid_sha256(source_sha256) || !valid_sha256(processing_parameters_sha256) {
                return Err(OcrIntegrityError::InvalidHash);
            }
            if *expected_page_count == 0
                || usize::try_from(*expected_page_count).map_or(true, |count| count > MAX_OCR_PAGES)
            {
                return Err(OcrIntegrityError::PageCountInvalid);
            }
            Ok(())
        }
        WorkerRequestV1::Cancel {
            protocol_version,
            request_id,
            job_id,
        } => {
            validate_envelope(protocol_version, request_id)?;
            if !valid_opaque_id(job_id) {
                return Err(OcrIntegrityError::InvalidOpaqueId);
            }
            Ok(())
        }
    }
}

pub fn validate_worker_response_v1(response: &WorkerResponseV1) -> Result<(), OcrIntegrityError> {
    match response {
        WorkerResponseV1::Hello {
            protocol_version,
            request_id,
            status,
            identity,
            reason_codes,
        } => {
            validate_envelope(protocol_version, request_id)?;
            validate_status_reasons(*status, reason_codes)?;
            validate_identity(identity)
        }
        WorkerResponseV1::Health {
            protocol_version,
            request_id,
            status,
            report,
            reason_codes,
        } => {
            validate_envelope(protocol_version, request_id)?;
            validate_status_reasons(*status, reason_codes)?;
            validate_health(*status, report)
        }
        WorkerResponseV1::Ocr {
            protocol_version,
            request_id,
            job_id,
            payload,
        } => {
            validate_envelope(protocol_version, request_id)?;
            if !valid_opaque_id(job_id) {
                return Err(OcrIntegrityError::InvalidOpaqueId);
            }
            match payload {
                OcrResponsePayloadV1::Completed { document } => {
                    validate_ocr_document_structure_v1(document)
                }
                OcrResponsePayloadV1::Blocked { reason_codes }
                | OcrResponsePayloadV1::Cancelled { reason_codes } => {
                    validate_nonempty_reasons(reason_codes)
                }
            }
        }
        WorkerResponseV1::Progress {
            protocol_version,
            request_id,
            job_id,
            completed_pages,
            total_pages,
            reason_codes,
            ..
        } => {
            validate_envelope(protocol_version, request_id)?;
            if !valid_opaque_id(job_id) {
                return Err(OcrIntegrityError::InvalidOpaqueId);
            }
            validate_reason_codes(reason_codes)?;
            if *total_pages == 0
                || completed_pages > total_pages
                || usize::try_from(*total_pages).map_or(true, |count| count > MAX_OCR_PAGES)
            {
                return Err(OcrIntegrityError::ProgressInvalid);
            }
            Ok(())
        }
        WorkerResponseV1::Cancel {
            protocol_version,
            request_id,
            job_id,
            status,
            reason_codes,
        } => {
            validate_envelope(protocol_version, request_id)?;
            if !valid_opaque_id(job_id) {
                return Err(OcrIntegrityError::InvalidOpaqueId);
            }
            validate_status_reasons(*status, reason_codes)
        }
        WorkerResponseV1::Shutdown {
            protocol_version,
            request_id,
            status,
            reason_codes,
        } => {
            validate_envelope(protocol_version, request_id)?;
            validate_status_reasons(*status, reason_codes)
        }
    }
}

/// Validates an OCR document against facts independently observed by the host.
pub fn validate_ocr_document_v1(
    document: &OcrDocumentV1,
    expected: &OcrValidationExpectationV1,
) -> Result<(), OcrIntegrityError> {
    if !valid_opaque_id(&expected.document_id)
        || !valid_opaque_id(&expected.isolation_evidence_id)
        || !valid_opaque_id(&expected.qualification_report_id)
    {
        return Err(OcrIntegrityError::InvalidOpaqueId);
    }
    for hash in [
        &expected.source_sha256,
        &expected.input_unmodified_sha256,
        &expected.output_sha256,
        &expected.worker_sha256,
        &expected.model_manifest_sha256,
        &expected.config_sha256,
        &expected.processing_parameters_sha256,
        &expected.isolation_evidence_sha256,
    ] {
        if !valid_sha256(hash) {
            return Err(OcrIntegrityError::InvalidHash);
        }
    }
    if !expected.output_tree_confined {
        return Err(OcrIntegrityError::CompletenessFailed);
    }
    if document.document_id != expected.document_id
        || document.source_sha256 != expected.source_sha256
        || document.input_unmodified_sha256 != expected.input_unmodified_sha256
        || document.page_count != expected.page_count
        || document.output_sha256 != expected.output_sha256
        || document.provenance.worker_sha256 != expected.worker_sha256
        || document.provenance.model_manifest_sha256 != expected.model_manifest_sha256
        || document.provenance.config_sha256 != expected.config_sha256
        || document.provenance.processing_parameters_sha256 != expected.processing_parameters_sha256
        || document.provenance.isolation_evidence_id != expected.isolation_evidence_id
        || document.provenance.isolation_evidence_sha256 != expected.isolation_evidence_sha256
        || document.provenance.qualification_report_id != expected.qualification_report_id
    {
        return Err(OcrIntegrityError::ExpectationMismatch);
    }
    validate_ocr_document_structure_v1(document)
}

/// Validates all internally checkable OCR structure and completeness claims.
///
/// Production callers must additionally call [`validate_ocr_document_v1`]
/// with values independently observed by the host.
pub fn validate_ocr_document_structure_v1(
    document: &OcrDocumentV1,
) -> Result<(), OcrIntegrityError> {
    if document.protocol_version != MINERU_WORKER_PROTOCOL_V1
        || document.provenance.protocol_version != MINERU_WORKER_PROTOCOL_V1
    {
        return Err(OcrIntegrityError::ProtocolMismatch);
    }
    if !valid_opaque_id(&document.document_id) {
        return Err(OcrIntegrityError::InvalidOpaqueId);
    }
    for hash in [
        &document.source_sha256,
        &document.input_unmodified_sha256,
        &document.output_sha256,
    ] {
        if !valid_sha256(hash) {
            return Err(OcrIntegrityError::InvalidHash);
        }
    }
    if document.source_sha256 != document.input_unmodified_sha256 {
        return Err(OcrIntegrityError::ExpectationMismatch);
    }
    let page_count =
        usize::try_from(document.page_count).map_err(|_| OcrIntegrityError::PageCountInvalid)?;
    if page_count == 0 || page_count > MAX_OCR_PAGES || document.pages.len() != page_count {
        return Err(OcrIntegrityError::PageCountInvalid);
    }
    validate_warning_set(&document.warnings)?;
    validate_provenance(&document.provenance)?;
    if !document.completeness.input_hash_verified
        || !document.completeness.page_count_verified
        || !document.completeness.pages_contiguous
        || !document.completeness.block_ids_unique
        || !document.completeness.all_pages_complete
        || !document.completeness.provenance_complete
        || !document.completeness.output_tree_confined
        || !document.completeness.passed
    {
        return Err(OcrIntegrityError::CompletenessFailed);
    }

    let mut block_ids = BTreeSet::new();
    for (expected_page_index, page) in document.pages.iter().enumerate() {
        if usize::try_from(page.page_index).ok() != Some(expected_page_index) {
            return Err(OcrIntegrityError::PageOrderInvalid);
        }
        validate_page(page, &mut block_ids)?;
    }
    Ok(())
}

fn validate_page(
    page: &OcrPageV1,
    document_block_ids: &mut BTreeSet<String>,
) -> Result<(), OcrIntegrityError> {
    if page.width_micropoints == 0 || page.height_micropoints == 0 {
        return Err(OcrIntegrityError::PageDimensionsInvalid);
    }
    if !matches!(page.rotation_degrees, 0 | 90 | 180 | 270) {
        return Err(OcrIntegrityError::PageRotationInvalid);
    }
    if !valid_sha256(&page.page_image_sha256) {
        return Err(OcrIntegrityError::InvalidHash);
    }
    validate_warning_set(&page.warnings)?;
    validate_visual_risks(&page.visual_risks)?;
    if !page.completeness.dimensions_verified
        || !page.completeness.page_image_hash_verified
        || !page.completeness.reading_order_contiguous
        || !page.completeness.geometry_validated
        || !page.completeness.confidences_complete
        || !page.completeness.visual_regions_classified
        || !page.completeness.output_tree_confined
        || !page.completeness.passed
    {
        return Err(OcrIntegrityError::CompletenessFailed);
    }
    match page.status {
        OcrPageStatusV1::Blocked => return Err(OcrIntegrityError::PageBlocked),
        OcrPageStatusV1::VerifiedBlank => {
            if !page.blocks.is_empty()
                || !page.visual_risks.is_empty()
                || page.coverage_ppm != Ppm::ONE
                || page.minimum_ocr_confidence_ppm != Ppm::ZERO
                || page.mean_ocr_confidence_ppm != Ppm::ZERO
            {
                return Err(OcrIntegrityError::BlankPageInvalid);
            }
            return Ok(());
        }
        OcrPageStatusV1::Ok => {
            if page.blocks.is_empty() || page.coverage_ppm == Ppm::ZERO {
                return Err(OcrIntegrityError::EmptyPageInvalid);
            }
        }
    }
    if page.blocks.len() > MAX_BLOCKS_PER_PAGE {
        return Err(OcrIntegrityError::BlockCountInvalid);
    }

    let mut confidence_sum = 0u64;
    let mut confidence_min = MAX_PPM;
    for (expected_order, block) in page.blocks.iter().enumerate() {
        if usize::try_from(block.reading_order).ok() != Some(expected_order)
            || block.source_locator.source_block_index != block.reading_order
            || block.source_locator.page_index != page.page_index
        {
            return Err(OcrIntegrityError::ReadingOrderInvalid);
        }
        validate_block(block, page)?;
        if !document_block_ids.insert(block.block_id.clone()) {
            return Err(OcrIntegrityError::DuplicateBlockId);
        }
        confidence_min = confidence_min.min(block.ocr_confidence_ppm.get());
        confidence_sum = confidence_sum
            .checked_add(u64::from(block.ocr_confidence_ppm.get()))
            .ok_or(OcrIntegrityError::ConfidenceSummaryMismatch)?;
    }
    let mean = confidence_sum
        / u64::try_from(page.blocks.len())
            .map_err(|_| OcrIntegrityError::ConfidenceSummaryMismatch)?;
    if page.minimum_ocr_confidence_ppm.get() != confidence_min
        || u64::from(page.mean_ocr_confidence_ppm.get()) != mean
    {
        return Err(OcrIntegrityError::ConfidenceSummaryMismatch);
    }
    validate_visual_risk_evidence(page)
}

fn validate_block(block: &OcrBlockV1, page: &OcrPageV1) -> Result<(), OcrIntegrityError> {
    if !valid_opaque_id(&block.block_id) || !valid_opaque_id(&block.raw_text_ref) {
        return Err(OcrIntegrityError::InvalidOpaqueId);
    }
    if !valid_text(&block.normalized_text)
        || (block_requires_text(block.block_type) && block.normalized_text.trim().is_empty())
    {
        return Err(OcrIntegrityError::TextInvalid);
    }
    if !block.confidence_available {
        return Err(OcrIntegrityError::ConfidenceUnavailable);
    }
    if block.visual_classification == OcrVisualClassificationV1::Unknown {
        return Err(OcrIntegrityError::UnknownVisualRegion);
    }
    if !classification_matches_type(block.block_type, block.visual_classification) {
        return Err(OcrIntegrityError::VisualClassificationInvalid);
    }
    validate_geometry(block, page)
}

fn validate_geometry(block: &OcrBlockV1, page: &OcrPageV1) -> Result<(), OcrIntegrityError> {
    let bbox = block.bbox;
    if bbox.left_micropoints >= bbox.right_micropoints
        || bbox.top_micropoints >= bbox.bottom_micropoints
        || bbox.right_micropoints > page.width_micropoints
        || bbox.bottom_micropoints > page.height_micropoints
        || block.polygon.len() < 3
        || block.polygon.len() > MAX_POLYGON_POINTS
    {
        return Err(OcrIntegrityError::GeometryInvalid);
    }
    let mut unique_points = BTreeSet::new();
    for point in &block.polygon {
        if point.x_micropoints > page.width_micropoints
            || point.y_micropoints > page.height_micropoints
            || point.x_micropoints < bbox.left_micropoints
            || point.x_micropoints > bbox.right_micropoints
            || point.y_micropoints < bbox.top_micropoints
            || point.y_micropoints > bbox.bottom_micropoints
        {
            return Err(OcrIntegrityError::GeometryInvalid);
        }
        unique_points.insert((point.x_micropoints, point.y_micropoints));
    }
    if unique_points.len() < 3 {
        return Err(OcrIntegrityError::GeometryInvalid);
    }
    Ok(())
}

fn validate_visual_risk_evidence(page: &OcrPageV1) -> Result<(), OcrIntegrityError> {
    for risk in &page.visual_risks {
        let evidenced = page.blocks.iter().any(|block| match risk {
            OcrVisualRiskV1::Seal => block.visual_classification == OcrVisualClassificationV1::Seal,
            OcrVisualRiskV1::Signature => {
                block.visual_classification == OcrVisualClassificationV1::Signature
            }
            OcrVisualRiskV1::Handwriting => {
                block.visual_classification == OcrVisualClassificationV1::Handwriting
            }
            OcrVisualRiskV1::Screenshot => {
                block.visual_classification == OcrVisualClassificationV1::Screenshot
            }
            OcrVisualRiskV1::ComplexTable => {
                block.visual_classification == OcrVisualClassificationV1::ComplexTable
            }
            OcrVisualRiskV1::UnknownVisualRegion => false,
        });
        if !evidenced {
            return Err(OcrIntegrityError::VisualClassificationInvalid);
        }
    }
    Ok(())
}

fn validate_provenance(provenance: &OcrProvenanceV1) -> Result<(), OcrIntegrityError> {
    if provenance.protocol_version != MINERU_WORKER_PROTOCOL_V1 {
        return Err(OcrIntegrityError::ProtocolMismatch);
    }
    for version in [
        &provenance.worker_version,
        &provenance.python_version,
        &provenance.mineru_version,
        &provenance.pytorch_version,
        &provenance.cuda_runtime_version,
        &provenance.gpu_driver_version,
        &provenance.model_version,
    ] {
        if !valid_version(version) {
            return Err(OcrIntegrityError::ProvenanceIncomplete);
        }
    }
    for hash in [
        &provenance.worker_sha256,
        &provenance.model_manifest_sha256,
        &provenance.config_sha256,
        &provenance.isolation_evidence_sha256,
        &provenance.processing_parameters_sha256,
    ] {
        if !valid_sha256(hash) {
            return Err(OcrIntegrityError::InvalidHash);
        }
    }
    if !valid_opaque_id(&provenance.isolation_evidence_id)
        || !valid_opaque_id(&provenance.qualification_report_id)
        || provenance.started_at_unix == 0
        || provenance.duration_ms == 0
    {
        return Err(OcrIntegrityError::ProvenanceIncomplete);
    }
    validate_device(&provenance.requested_device)?;
    validate_device(&provenance.actual_device)
}

fn validate_identity(identity: &WorkerIdentityV1) -> Result<(), OcrIntegrityError> {
    for version in [
        &identity.worker_version,
        &identity.python_version,
        &identity.mineru_version,
        &identity.pytorch_version,
        &identity.cuda_runtime_version,
        &identity.gpu_driver_version,
        &identity.model_version,
    ] {
        if !valid_version(version) {
            return Err(OcrIntegrityError::ProvenanceIncomplete);
        }
    }
    for hash in [
        &identity.worker_sha256,
        &identity.model_manifest_sha256,
        &identity.config_sha256,
    ] {
        if !valid_sha256(hash) {
            return Err(OcrIntegrityError::InvalidHash);
        }
    }
    validate_device(&identity.actual_device)
}

fn validate_device(device: &WorkerDeviceV1) -> Result<(), OcrIntegrityError> {
    match device {
        WorkerDeviceV1::Cpu {
            hardware_fingerprint_sha256,
        } => {
            if !valid_sha256(hardware_fingerprint_sha256) {
                return Err(OcrIntegrityError::InvalidHash);
            }
        }
        WorkerDeviceV1::Cuda {
            indices,
            hardware_fingerprint_sha256,
        } => {
            let unique = indices.iter().copied().collect::<BTreeSet<_>>();
            if indices.is_empty()
                || indices.len() > 16
                || unique.len() != indices.len()
                || indices.iter().any(|index| *index > 63)
            {
                return Err(OcrIntegrityError::ProvenanceIncomplete);
            }
            if !valid_sha256(hardware_fingerprint_sha256) {
                return Err(OcrIntegrityError::InvalidHash);
            }
        }
    }
    Ok(())
}

fn validate_health(
    status: WorkerStatusV1,
    report: &WorkerHealthV1,
) -> Result<(), OcrIntegrityError> {
    if report.checked_at_unix == 0 || report.case_material_loaded {
        return Err(OcrIntegrityError::HealthInvalid);
    }
    let required = [
        WorkerHealthCheckIdV1::WorkerIntegrity,
        WorkerHealthCheckIdV1::ConfigIntegrity,
        WorkerHealthCheckIdV1::ModelIntegrity,
        WorkerHealthCheckIdV1::RuntimeVersions,
        WorkerHealthCheckIdV1::GpuRuntime,
        WorkerHealthCheckIdV1::OfflineFlags,
        WorkerHealthCheckIdV1::OsNetworkIsolation,
        WorkerHealthCheckIdV1::JobRootConfinement,
    ];
    if report.checks.len() != required.len() {
        return Err(OcrIntegrityError::HealthInvalid);
    }
    let mut observed = BTreeSet::new();
    for check in &report.checks {
        if !observed.insert(check.check_id) || !valid_sha256(&check.evidence_sha256) {
            return Err(OcrIntegrityError::HealthInvalid);
        }
        validate_reason_codes(&check.reason_codes)?;
        if check.passed != check.reason_codes.is_empty() {
            return Err(OcrIntegrityError::HealthInvalid);
        }
    }
    if required.iter().any(|check| !observed.contains(check)) {
        return Err(OcrIntegrityError::HealthInvalid);
    }
    let all_passed = report.checks.iter().all(|check| check.passed);
    if (status == WorkerStatusV1::Ok) != all_passed {
        return Err(OcrIntegrityError::HealthInvalid);
    }
    Ok(())
}

fn validate_envelope(protocol_version: &str, request_id: &str) -> Result<(), OcrIntegrityError> {
    if protocol_version != MINERU_WORKER_PROTOCOL_V1 {
        return Err(OcrIntegrityError::ProtocolMismatch);
    }
    if !valid_opaque_id(request_id) {
        return Err(OcrIntegrityError::InvalidOpaqueId);
    }
    Ok(())
}

fn validate_status_reasons(
    status: WorkerStatusV1,
    reason_codes: &[WorkerReasonCodeV1],
) -> Result<(), OcrIntegrityError> {
    validate_reason_codes(reason_codes)?;
    if (status == WorkerStatusV1::Ok) != reason_codes.is_empty() {
        return Err(OcrIntegrityError::ReasonCodesInvalid);
    }
    Ok(())
}

fn validate_nonempty_reasons(reason_codes: &[WorkerReasonCodeV1]) -> Result<(), OcrIntegrityError> {
    validate_reason_codes(reason_codes)?;
    if reason_codes.is_empty() {
        return Err(OcrIntegrityError::ReasonCodesInvalid);
    }
    Ok(())
}

fn validate_reason_codes(reason_codes: &[WorkerReasonCodeV1]) -> Result<(), OcrIntegrityError> {
    if reason_codes.len() > MAX_REASON_CODES
        || reason_codes.iter().copied().collect::<BTreeSet<_>>().len() != reason_codes.len()
    {
        return Err(OcrIntegrityError::ReasonCodesInvalid);
    }
    Ok(())
}

fn validate_warning_set(warnings: &[OcrWarningV1]) -> Result<(), OcrIntegrityError> {
    if warnings.len() > MAX_REASON_CODES
        || warnings.iter().copied().collect::<BTreeSet<_>>().len() != warnings.len()
    {
        return Err(OcrIntegrityError::CompletenessFailed);
    }
    Ok(())
}

fn validate_visual_risks(risks: &[OcrVisualRiskV1]) -> Result<(), OcrIntegrityError> {
    if risks.len() > MAX_REASON_CODES
        || risks.iter().copied().collect::<BTreeSet<_>>().len() != risks.len()
    {
        return Err(OcrIntegrityError::VisualClassificationInvalid);
    }
    if risks.contains(&OcrVisualRiskV1::UnknownVisualRegion) {
        return Err(OcrIntegrityError::UnknownVisualRegion);
    }
    Ok(())
}

fn block_requires_text(block_type: OcrBlockTypeV1) -> bool {
    matches!(
        block_type,
        OcrBlockTypeV1::Text
            | OcrBlockTypeV1::Heading
            | OcrBlockTypeV1::Table
            | OcrBlockTypeV1::Formula
            | OcrBlockTypeV1::ImageCaption
    )
}

fn classification_matches_type(
    block_type: OcrBlockTypeV1,
    classification: OcrVisualClassificationV1,
) -> bool {
    match block_type {
        OcrBlockTypeV1::Text | OcrBlockTypeV1::Heading | OcrBlockTypeV1::ImageCaption => {
            classification == OcrVisualClassificationV1::Textual
        }
        OcrBlockTypeV1::Table => matches!(
            classification,
            OcrVisualClassificationV1::Table | OcrVisualClassificationV1::ComplexTable
        ),
        OcrBlockTypeV1::Formula => classification == OcrVisualClassificationV1::Formula,
        OcrBlockTypeV1::Seal => classification == OcrVisualClassificationV1::Seal,
        OcrBlockTypeV1::Signature => classification == OcrVisualClassificationV1::Signature,
        OcrBlockTypeV1::Handwriting => classification == OcrVisualClassificationV1::Handwriting,
        OcrBlockTypeV1::Screenshot => classification == OcrVisualClassificationV1::Screenshot,
        OcrBlockTypeV1::Illustration => {
            classification == OcrVisualClassificationV1::NonSensitiveIllustration
        }
    }
}

fn valid_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES_PER_BLOCK
        && !value.contains('\0')
        && value
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_opaque_id(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once('_') else {
        return false;
    };
    (2..=16).contains(&prefix.len())
        && prefix
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_lowercase() || (index > 0 && byte.is_ascii_digit()))
        && suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
