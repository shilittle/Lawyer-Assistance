use crate::{
    mineru::set_platform_environment,
    mineru_config::{validate_config, ValidatedLocalMineru},
    network_isolation::{verify_network_isolation, RuntimeNetworkIsolationMeasurement},
    process_tree::ProcessTreeGuard,
    types::{DeviceSelection, LocalMineruConfig, ProcessingError},
    validate_worker_request_v1, validate_worker_response_v1, WorkerDeviceV1, WorkerHealthCheckIdV1,
    WorkerHealthV1, WorkerIdentityV1, WorkerProgressStageV1, WorkerRequestV1, WorkerResponseV1,
    WorkerStatusV1, MINERU_WORKER_PROTOCOL_V1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_WIRE_LINE_BYTES: usize = 128 * 1024 * 1024;
const MAX_WIRE_MESSAGES: usize = 50_000;
const CONTROL_GRACE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const JOB_POLICY_V1: &[u8] = b"la-mineru-windows-job-v1\nactive-process-limit=1\nkill-on-close=true\nsuspended-before-assign=true\n";
const OFFLINE_POLICY_V1: &[u8] = b"la-mineru-offline-env-v1\nMINERU_MODEL_SOURCE=local\nHF_HUB_OFFLINE=1\nTRANSFORMERS_OFFLINE=1\nHF_DATASETS_OFFLINE=1\nHF_HUB_DISABLE_TELEMETRY=1\nPIP_NO_INDEX=1\nPYTHONNOUSERSITE=1\nPYTHONSAFEPATH=1\nPYTHONDONTWRITEBYTECODE=1\nDO_NOT_TRACK=1\nNO_PROXY=*\nHTTP_PROXY=http://127.0.0.1:9\nHTTPS_PROXY=http://127.0.0.1:9\nALL_PROXY=socks5://127.0.0.1:9\n";

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerProtocolProbeEvidenceV1 {
    pub protocol_version: String,
    pub identity_sha256: String,
    pub health_evidence_sha256: String,
    pub identity: WorkerIdentityV1,
    pub health: WorkerHealthV1,
}

#[derive(Debug)]
pub(crate) struct WorkerProtocolRunV1 {
    pub document_id: String,
    pub isolation_evidence_id: String,
    pub document: crate::OcrDocumentV1,
    pub probe: WorkerProtocolProbeEvidenceV1,
}

#[derive(Debug)]
enum ReaderEvent {
    Line(Vec<u8>),
    Eof,
    Violation,
}

struct WorkerSession {
    tree: ProcessTreeGuard,
    child: Child,
    stdin: Option<ChildStdin>,
    receiver: Receiver<ReaderEvent>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    finished: bool,
}

pub fn worker_identity_sha256_v1(identity: &WorkerIdentityV1) -> Result<String, ProcessingError> {
    let device = match &identity.actual_device {
        WorkerDeviceV1::Cpu {
            hardware_fingerprint_sha256,
        } => format!("cpu|{hardware_fingerprint_sha256}"),
        WorkerDeviceV1::Cuda {
            indices,
            hardware_fingerprint_sha256,
        } => format!(
            "cuda:{}|{hardware_fingerprint_sha256}",
            indices
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    Ok(sha256_hex(
        format!(
            "la-mineru-worker-identity-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            identity.worker_version,
            identity.worker_sha256,
            identity.python_version,
            identity.mineru_version,
            identity.pytorch_version,
            identity.cuda_runtime_version,
            identity.gpu_driver_version,
            device,
            identity.model_version,
            identity.model_manifest_sha256,
            identity.config_sha256,
        )
        .as_bytes(),
    ))
}

pub fn worker_health_evidence_sha256_v1(
    health: &WorkerHealthV1,
) -> Result<String, ProcessingError> {
    canonical_sha256(b"la-mineru-worker-health-v1\n", health)
}

pub fn probe_local_mineru_worker_v1(
    config: &LocalMineruConfig,
) -> Result<WorkerProtocolProbeEvidenceV1, ProcessingError> {
    let validated = validate_config(config)?;
    let isolation =
        verify_network_isolation(&validated.runtime_programs, &config.network_isolation)?;
    let job = tempfile::Builder::new()
        .prefix("la-ocr-health-")
        .tempdir_in(&config.temporary_root)
        .map_err(|_| ProcessingError::OcrFailed)?;
    let command = configured_worker_command(job.path(), config, &validated, &isolation)?;
    let result = probe_with_command(command, config, &validated, &isolation, false, || {
        reverify(config, &validated, &isolation)
    });
    match (result, job.close()) {
        (_, Err(_)) => Err(ProcessingError::OcrCleanupFailed),
        (result, Ok(())) => result,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_worker_ocr_v1<F>(
    job_root: &std::path::Path,
    config: &LocalMineruConfig,
    validated: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
    source_sha256: &str,
    processing_parameters_sha256: &str,
    page_count: u32,
    cancelled: Option<&Arc<AtomicBool>>,
    pre_resume_reverify: F,
) -> Result<WorkerProtocolRunV1, ProcessingError>
where
    F: FnOnce() -> Result<(), ProcessingError>,
{
    let command = configured_worker_command(job_root, config, validated, isolation)?;
    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms);
    let mut session = WorkerSession::spawn(command, pre_resume_reverify)?;
    let probe = session.perform_probe(config, validated, isolation, true, deadline, cancelled)?;

    let request_id = opaque_id("req", source_sha256.as_bytes());
    let job_id = opaque_id("job", request_id.as_bytes());
    let document_id = opaque_id("doc", source_sha256.as_bytes());
    let input_id = opaque_id("input", job_id.as_bytes());
    let output_id = opaque_id("output", input_id.as_bytes());
    let request = WorkerRequestV1::Ocr {
        protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
        request_id: request_id.clone(),
        job_id: job_id.clone(),
        document_id: document_id.clone(),
        input_id,
        expected_output_id: output_id,
        source_sha256: source_sha256.to_owned(),
        processing_parameters_sha256: processing_parameters_sha256.to_owned(),
        expected_page_count: page_count,
    };
    session.send(&request)?;

    let mut progress_messages = 0usize;
    let mut last_stage = None;
    let mut last_completed = 0u32;
    let mut last_elapsed = 0u64;
    let document = loop {
        if cancellation_requested(cancelled) {
            session.cancel_and_abort(&request_id, &job_id, deadline);
            return Err(ProcessingError::Cancelled);
        }
        if Instant::now() >= deadline {
            session.cancel_and_abort(&request_id, &job_id, deadline);
            return Err(ProcessingError::OcrTimeout);
        }
        let response = match session.receive(deadline, cancelled) {
            Err(ProcessingError::Cancelled) => {
                session.cancel_and_abort(&request_id, &job_id, deadline);
                return Err(ProcessingError::Cancelled);
            }
            result => result?,
        };
        validate_worker_response_v1(&response)
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        match response {
            WorkerResponseV1::Progress {
                protocol_version,
                request_id: response_request_id,
                job_id: response_job_id,
                stage,
                completed_pages,
                total_pages,
                elapsed_ms,
                reason_codes,
            } => {
                if protocol_version != MINERU_WORKER_PROTOCOL_V1
                    || response_request_id != request_id
                    || response_job_id != job_id
                    || total_pages != page_count
                    || !reason_codes.is_empty()
                    || progress_messages >= MAX_WIRE_MESSAGES
                    || last_stage.is_some_and(|previous| stage_rank(stage) < stage_rank(previous))
                    || completed_pages < last_completed
                    || elapsed_ms < last_elapsed
                    || (progress_messages == 0 && stage != WorkerProgressStageV1::Accepted)
                {
                    return Err(ProcessingError::OcrWorkerProtocolViolation);
                }
                progress_messages += 1;
                last_stage = Some(stage);
                last_completed = completed_pages;
                last_elapsed = elapsed_ms;
            }
            WorkerResponseV1::Ocr {
                protocol_version,
                request_id: response_request_id,
                job_id: response_job_id,
                payload,
            } => {
                if protocol_version != MINERU_WORKER_PROTOCOL_V1
                    || response_request_id != request_id
                    || response_job_id != job_id
                    || progress_messages == 0
                    || last_stage != Some(WorkerProgressStageV1::Finalizing)
                    || last_completed != page_count
                {
                    return Err(ProcessingError::OcrWorkerProtocolViolation);
                }
                match payload {
                    crate::OcrResponsePayloadV1::Completed { document } => break *document,
                    crate::OcrResponsePayloadV1::Cancelled { .. } => {
                        return Err(ProcessingError::Cancelled)
                    }
                    crate::OcrResponsePayloadV1::Blocked { .. } => {
                        return Err(ProcessingError::OcrFailed)
                    }
                }
            }
            _ => return Err(ProcessingError::OcrWorkerProtocolViolation),
        }
    };
    session.shutdown(deadline)?;
    Ok(WorkerProtocolRunV1 {
        document_id,
        isolation_evidence_id: isolation_evidence_id(isolation),
        document,
        probe,
    })
}

fn probe_with_command<F>(
    command: Command,
    config: &LocalMineruConfig,
    validated: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
    enforce_expected_identity: bool,
    pre_resume_reverify: F,
) -> Result<WorkerProtocolProbeEvidenceV1, ProcessingError>
where
    F: FnOnce() -> Result<(), ProcessingError>,
{
    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms.min(60_000));
    let mut session = WorkerSession::spawn(command, pre_resume_reverify)?;
    let evidence = session.perform_probe(
        config,
        validated,
        isolation,
        enforce_expected_identity,
        deadline,
        None,
    )?;
    session.shutdown(deadline)?;
    reverify(config, validated, isolation)?;
    Ok(evidence)
}

fn configured_worker_command(
    job_root: &std::path::Path,
    config: &LocalMineruConfig,
    validated: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
) -> Result<Command, ProcessingError> {
    let mut command = Command::new(&config.executable);
    command
        .current_dir(job_root)
        .env_clear()
        .env("PATH", &validated.runtime_search_path)
        .env("MINERU_MODEL_SOURCE", "local")
        .env("MINERU_TOOLS_CONFIG_JSON", &config.mineru_config)
        .env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("HF_DATASETS_OFFLINE", "1")
        .env("HF_HUB_DISABLE_TELEMETRY", "1")
        .env("PIP_NO_INDEX", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env("PYTHONSAFEPATH", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("DO_NOT_TRACK", "1")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "socks5://127.0.0.1:9")
        .env("TEMP", job_root)
        .env("TMP", job_root)
        .env("USERPROFILE", job_root)
        .env("HOME", job_root)
        .env("XDG_CACHE_HOME", job_root.join("cache"))
        .env("HF_HOME", job_root.join("cache/huggingface"))
        .env("PADDLE_HOME", job_root.join("cache/paddle"))
        .env("MPLCONFIGDIR", job_root.join("cache/matplotlib"))
        .env("LA_MINERU_PROTOCOL_VERSION", MINERU_WORKER_PROTOCOL_V1)
        .env("LA_MINERU_WORKER_SHA256", &validated.executable_sha256)
        .env("LA_MINERU_CONFIG_SHA256", &validated.config_sha256)
        .env("LA_MINERU_CONFIG_PATH", &config.mineru_config)
        .env("LA_MINERU_MODEL_ROOT", &config.model_root)
        .env("LA_MINERU_MODEL_MANIFEST_PATH", &config.model_manifest)
        .env("LA_MINERU_RUNTIME_MANIFEST_PATH", &config.runtime_manifest)
        .env("LA_MINERU_SUPPORT_MANIFEST_PATH", &config.support_manifest)
        .env(
            "LA_MINERU_SUPPORT_MANIFEST_SHA256",
            &validated.support_manifest_sha256,
        )
        .env(
            "LA_MINERU_SUPPORT_IDENTITY_SHA256",
            &validated.support_identity_sha256,
        )
        .env("LA_MINERU_BACKEND", config.backend.cli_value())
        .env("LA_MINERU_LANGUAGE", &config.language)
        .env("LA_MINERU_REQUESTED_DEVICE", config.device.display_value())
        .env(
            "LA_MINERU_MAX_OUTPUT_BYTES",
            config.max_output_bytes.to_string(),
        )
        .env(
            "LA_MINERU_MODEL_MANIFEST_SHA256",
            &validated.model_manifest_sha256,
        )
        .env(
            "LA_MINERU_ISOLATION_EVIDENCE_ID",
            isolation_evidence_id(isolation),
        )
        .env(
            "LA_MINERU_ISOLATION_EVIDENCE_SHA256",
            &isolation.bundle_sha256,
        )
        .env(
            "LA_MINERU_QUALIFICATION_REPORT_ID",
            &config.qualification_report_id,
        )
        .env("LA_MINERU_JOB_POLICY_SHA256", job_policy_sha256());
    set_platform_environment(&mut command)?;
    match &config.device {
        DeviceSelection::Auto => {}
        DeviceSelection::Cpu => {
            command.env("CUDA_VISIBLE_DEVICES", "");
        }
        DeviceSelection::Cuda { indices } => {
            command.env(
                "CUDA_VISIBLE_DEVICES",
                indices
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }
    Ok(command)
}

fn reverify(
    config: &LocalMineruConfig,
    expected: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
) -> Result<(), ProcessingError> {
    let actual = validate_config(config)?;
    if !expected.same_identity(&actual) {
        return Err(ProcessingError::OcrRuntimeChanged);
    }
    if verify_network_isolation(&actual.runtime_programs, &config.network_isolation)? != *isolation
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    Ok(())
}

impl WorkerSession {
    fn spawn<F>(mut command: Command, pre_resume_reverify: F) -> Result<Self, ProcessingError>
    where
        F: FnOnce() -> Result<(), ProcessingError>,
    {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut tree = ProcessTreeGuard::new_single_process()?;
        ProcessTreeGuard::configure_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|_| ProcessingError::OcrBackendUnavailable)?;
        if let Err(error) = tree.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = pre_resume_reverify() {
            let _ = tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = tree.resume(&child) {
            let _ = tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let stdin = child
            .stdin
            .take()
            .ok_or(ProcessingError::OcrWorkerProtocolViolation)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessingError::OcrWorkerProtocolViolation)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessingError::OcrWorkerProtocolViolation)?;
        let (sender, receiver) = mpsc::sync_channel(8);
        let stdout_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_line(&mut reader, MAX_WIRE_LINE_BYTES) {
                    Ok(Some(line)) => {
                        if sender.send(ReaderEvent::Line(line)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(ReaderEvent::Eof);
                        break;
                    }
                    Err(()) => {
                        let _ = sender.send(ReaderEvent::Violation);
                        break;
                    }
                }
            }
        });
        let stderr_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        Ok(Self {
            tree,
            child,
            stdin: Some(stdin),
            receiver,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            finished: false,
        })
    }

    fn perform_probe(
        &mut self,
        config: &LocalMineruConfig,
        validated: &ValidatedLocalMineru,
        isolation: &RuntimeNetworkIsolationMeasurement,
        enforce_expected_identity: bool,
        deadline: Instant,
        cancelled: Option<&Arc<AtomicBool>>,
    ) -> Result<WorkerProtocolProbeEvidenceV1, ProcessingError> {
        if cancellation_requested(cancelled) {
            return Err(ProcessingError::Cancelled);
        }
        let hello_id = opaque_id("hello", validated.executable_sha256.as_bytes());
        self.send(&WorkerRequestV1::Hello {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: hello_id.clone(),
        })?;
        let response = self.receive(deadline, cancelled)?;
        validate_worker_response_v1(&response)
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        let identity = match response {
            WorkerResponseV1::Hello {
                protocol_version,
                request_id,
                status: WorkerStatusV1::Ok,
                identity,
                reason_codes,
            } if protocol_version == MINERU_WORKER_PROTOCOL_V1
                && request_id == hello_id
                && reason_codes.is_empty() =>
            {
                *identity
            }
            _ => return Err(ProcessingError::OcrWorkerProtocolViolation),
        };
        if identity.worker_sha256 != validated.executable_sha256
            || identity.model_manifest_sha256 != validated.model_manifest_sha256
            || identity.config_sha256 != validated.config_sha256
            || !device_matches(&config.device, &identity.actual_device)
        {
            return Err(ProcessingError::OcrWorkerIdentityMismatch);
        }
        let identity_sha256 = worker_identity_sha256_v1(&identity)?;
        if enforce_expected_identity
            && identity_sha256 != config.expected_worker_identity_sha256.to_ascii_lowercase()
        {
            return Err(ProcessingError::OcrWorkerIdentityMismatch);
        }

        let health_id = opaque_id("health", identity_sha256.as_bytes());
        self.send(&WorkerRequestV1::Health {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: health_id.clone(),
        })?;
        let response = self.receive(deadline, cancelled)?;
        validate_worker_response_v1(&response)
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        let health = match response {
            WorkerResponseV1::Health {
                protocol_version,
                request_id,
                status: WorkerStatusV1::Ok,
                report,
                reason_codes,
            } if protocol_version == MINERU_WORKER_PROTOCOL_V1
                && request_id == health_id
                && reason_codes.is_empty() =>
            {
                report
            }
            _ => return Err(ProcessingError::OcrWorkerUnhealthy),
        };
        verify_health_bindings(&health, &identity, validated, isolation)?;
        Ok(WorkerProtocolProbeEvidenceV1 {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            identity_sha256,
            health_evidence_sha256: worker_health_evidence_sha256_v1(&health)?,
            identity,
            health,
        })
    }

    fn send(&mut self, request: &WorkerRequestV1) -> Result<(), ProcessingError> {
        validate_worker_request_v1(request)
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        let bytes =
            serde_json::to_vec(request).map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        if bytes.len() > MAX_WIRE_LINE_BYTES {
            return Err(ProcessingError::OcrWorkerProtocolViolation);
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(ProcessingError::OcrWorkerProtocolViolation)?;
        stdin
            .write_all(&bytes)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: Option<&Arc<AtomicBool>>,
    ) -> Result<WorkerResponseV1, ProcessingError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(ProcessingError::OcrTimeout);
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        loop {
            match self.receiver.recv_timeout(wait) {
                Ok(ReaderEvent::Line(line)) => {
                    return serde_json::from_slice(&line)
                        .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)
                }
                Ok(ReaderEvent::Eof | ReaderEvent::Violation) => {
                    return Err(ProcessingError::OcrWorkerProtocolViolation)
                }
                Err(RecvTimeoutError::Timeout) => {
                    if cancellation_requested(cancelled) {
                        return Err(ProcessingError::Cancelled);
                    }
                    if Instant::now() >= deadline {
                        return Err(ProcessingError::OcrTimeout);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ProcessingError::OcrWorkerProtocolViolation)
                }
            }
        }
    }

    fn cancel_and_abort(&mut self, request_id: &str, job_id: &str, deadline: Instant) {
        let _ = self.send(&WorkerRequestV1::Cancel {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: request_id.to_owned(),
            job_id: job_id.to_owned(),
        });
        let grace_deadline = deadline.min(Instant::now() + CONTROL_GRACE);
        let _ = self.receive(grace_deadline, None);
        let _ = self.abort();
    }

    fn shutdown(&mut self, deadline: Instant) -> Result<(), ProcessingError> {
        let request_id = opaque_id("shutdown", b"shutdown");
        self.send(&WorkerRequestV1::Shutdown {
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            request_id: request_id.clone(),
        })?;
        let response = self.receive(deadline.min(Instant::now() + CONTROL_GRACE), None)?;
        validate_worker_response_v1(&response)
            .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
        match response {
            WorkerResponseV1::Shutdown {
                protocol_version,
                request_id: response_id,
                status: WorkerStatusV1::Ok,
                reason_codes,
            } if protocol_version == MINERU_WORKER_PROTOCOL_V1
                && response_id == request_id
                && reason_codes.is_empty() => {}
            _ => return Err(ProcessingError::OcrWorkerProtocolViolation),
        }
        self.stdin.take();
        let exit_deadline = Instant::now() + CONTROL_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(_)) | Err(_) => return Err(ProcessingError::OcrFailed),
                Ok(None) if Instant::now() < exit_deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => return Err(ProcessingError::OcrTimeout),
            }
        }
        self.tree.terminate()?;
        self.join_readers();
        self.finished = true;
        Ok(())
    }

    fn abort(&mut self) -> Result<(), ProcessingError> {
        self.stdin.take();
        let tree_result = self.tree.terminate();
        let _ = self.child.kill();
        let wait_result = self.child.wait();
        self.join_readers();
        self.finished = true;
        tree_result?;
        wait_result
            .map(|_| ())
            .map_err(|_| ProcessingError::OcrProcessContainmentUnavailable)
    }

    fn join_readers(&mut self) {
        if let Some(thread) = self.stdout_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WorkerSession {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.abort();
        }
    }
}

fn verify_health_bindings(
    health: &WorkerHealthV1,
    identity: &WorkerIdentityV1,
    validated: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
) -> Result<(), ProcessingError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProcessingError::OcrWorkerUnhealthy)?
        .as_secs();
    if health.case_material_loaded
        || health.checked_at_unix > now.saturating_add(300)
        || now.saturating_sub(health.checked_at_unix) > 300
    {
        return Err(ProcessingError::OcrWorkerUnhealthy);
    }
    let runtime_versions = sha256_hex(
        format!(
            "la-mineru-runtime-versions-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            identity.worker_version,
            identity.python_version,
            identity.mineru_version,
            identity.pytorch_version,
            identity.cuda_runtime_version,
            identity.gpu_driver_version,
            identity.model_version,
        )
        .as_bytes(),
    );
    let gpu = match &identity.actual_device {
        WorkerDeviceV1::Cpu {
            hardware_fingerprint_sha256,
        }
        | WorkerDeviceV1::Cuda {
            hardware_fingerprint_sha256,
            ..
        } => hardware_fingerprint_sha256.clone(),
    };
    let expected = BTreeMap::from([
        (
            WorkerHealthCheckIdV1::WorkerIntegrity,
            validated.executable_sha256.clone(),
        ),
        (
            WorkerHealthCheckIdV1::ConfigIntegrity,
            validated.config_sha256.clone(),
        ),
        (
            WorkerHealthCheckIdV1::ModelIntegrity,
            validated.model_manifest_sha256.clone(),
        ),
        (
            WorkerHealthCheckIdV1::SupportIntegrity,
            validated.support_identity_sha256.clone(),
        ),
        (WorkerHealthCheckIdV1::RuntimeVersions, runtime_versions),
        (WorkerHealthCheckIdV1::GpuRuntime, gpu),
        (
            WorkerHealthCheckIdV1::OfflineFlags,
            sha256_hex(OFFLINE_POLICY_V1),
        ),
        (
            WorkerHealthCheckIdV1::OsNetworkIsolation,
            isolation.bundle_sha256.clone(),
        ),
        (
            WorkerHealthCheckIdV1::JobRootConfinement,
            job_policy_sha256(),
        ),
    ]);
    if health.checks.len() != expected.len()
        || health.checks.iter().any(|check| {
            !check.passed
                || !check.reason_codes.is_empty()
                || expected.get(&check.check_id) != Some(&check.evidence_sha256)
        })
    {
        return Err(ProcessingError::OcrWorkerUnhealthy);
    }
    Ok(())
}

fn device_matches(requested: &DeviceSelection, actual: &WorkerDeviceV1) -> bool {
    match (requested, actual) {
        (DeviceSelection::Auto, _) => true,
        (DeviceSelection::Cpu, WorkerDeviceV1::Cpu { .. }) => true,
        (
            DeviceSelection::Cuda { indices },
            WorkerDeviceV1::Cuda {
                indices: actual, ..
            },
        ) => indices
            .iter()
            .copied()
            .map(u16::try_from)
            .collect::<Result<Vec<_>, _>>()
            .is_ok_and(|requested| requested == *actual),
        _ => false,
    }
}

fn read_bounded_line<R: BufRead>(reader: &mut R, limit: usize) -> Result<Option<Vec<u8>>, ()> {
    let mut output = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| ())?;
        if available.is_empty() {
            return if output.is_empty() { Ok(None) } else { Err(()) };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        let wire_limit = limit.checked_add(2).ok_or(())?;
        if output
            .len()
            .checked_add(take)
            .is_none_or(|size| size > wire_limit)
        {
            return Err(());
        }
        output.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            output.pop();
            if output.last() == Some(&b'\r') {
                output.pop();
            }
            if output.len() > limit {
                return Err(());
            }
            if output.is_empty() || output.first() != Some(&b'{') || output.last() != Some(&b'}') {
                return Err(());
            }
            return Ok(Some(output));
        }
    }
}

fn canonical_sha256<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ProcessingError> {
    let serialized =
        serde_json::to_vec(value).map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
    Ok(sha256_hex(&[domain, serialized.as_slice()].concat()))
}

fn opaque_id(prefix: &str, seed: &[u8]) -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let digest = Sha256::digest(
        [
            b"la-mineru-opaque-id-v1\n".as_slice(),
            prefix.as_bytes(),
            b"\n",
            seed,
            b"\n",
            &counter.to_le_bytes(),
            &timestamp.to_le_bytes(),
        ]
        .concat(),
    );
    format!("{prefix}_{}", hex(&digest[..16]))
}

fn stage_rank(stage: WorkerProgressStageV1) -> u8 {
    match stage {
        WorkerProgressStageV1::Accepted => 0,
        WorkerProgressStageV1::LoadingModels => 1,
        WorkerProgressStageV1::RenderingPages => 2,
        WorkerProgressStageV1::LayoutAnalysis => 3,
        WorkerProgressStageV1::Ocr => 4,
        WorkerProgressStageV1::ValidatingOutput => 5,
        WorkerProgressStageV1::Finalizing => 6,
    }
}

fn cancellation_requested(cancelled: Option<&Arc<AtomicBool>>) -> bool {
    cancelled.is_some_and(|value| value.load(Ordering::Relaxed))
}

fn isolation_evidence_id(isolation: &RuntimeNetworkIsolationMeasurement) -> String {
    format!("iso_{}", &isolation.bundle_sha256[..32])
}

fn job_policy_sha256() -> String {
    sha256_hex(JOB_POLICY_V1)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_eof_without_newline_and_oversize() {
        assert_eq!(
            read_bounded_line(&mut &b"{}\n"[..], 2),
            Ok(Some(b"{}".to_vec()))
        );
        assert_eq!(read_bounded_line(&mut &b"{}"[..], 2), Err(()));
        assert_eq!(read_bounded_line(&mut &b"{}\n"[..], 1), Err(()));
        assert_eq!(read_bounded_line(&mut &b"[]\n"[..], 2), Err(()));
    }

    #[test]
    fn generated_ids_and_policy_hashes_are_protocol_safe() {
        let id = opaque_id("hello", b"synthetic");
        assert!(id.starts_with("hello_"));
        assert_eq!(id.len(), 38);
        assert_eq!(job_policy_sha256().len(), 64);
        assert_eq!(sha256_hex(OFFLINE_POLICY_V1).len(), 64);
    }
}
