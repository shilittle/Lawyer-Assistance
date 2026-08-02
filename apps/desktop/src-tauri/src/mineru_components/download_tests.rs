use super::{catalog, package};
use reqwest::{redirect, Certificate, Client, Url};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const LOCAL_HTTPS_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const LOCAL_HTTPS_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LOCAL_HTTPS_REQUEST_BYTES: usize = 16 * 1024;

struct LocalHttpsServer {
    worker: Option<JoinHandle<Result<(), String>>>,
    stop: Arc<AtomicBool>,
    certificate_pem: Vec<u8>,
    url: Url,
}

impl LocalHttpsServer {
    fn finish(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .expect("local HTTPS worker is owned")
            .join()
            .map_err(|_| "local HTTPS worker panicked".to_owned())?
    }
}

impl Drop for LocalHttpsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn spawn_local_https_once(body: &[u8]) -> LocalHttpsServer {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["127.0.0.1".to_owned()])
            .expect("generate the ephemeral local HTTPS certificate");
    let certificate_pem = cert.pem().into_bytes();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private_key)
        .expect("ephemeral local HTTPS certificate and key match");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local HTTPS fixture");
    let port = listener
        .local_addr()
        .expect("read local HTTPS fixture address")
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_worker = Arc::clone(&stop);
    let body = body.to_vec();
    let worker = thread::spawn(move || {
        serve_local_https_once(listener, Arc::new(server_config), body, stop_for_worker)
    });

    LocalHttpsServer {
        worker: Some(worker),
        stop,
        certificate_pem,
        url: Url::parse(&format!("https://127.0.0.1:{port}/component.laocrpkg")).unwrap(),
    }
}

fn serve_local_https_once(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    body: Vec<u8>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("local HTTPS listener nonblocking mode failed: {error}"))?;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                thread::sleep(LOCAL_HTTPS_ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(format!("local HTTPS accept failed: {error}")),
        }
    };
    configure_local_https_stream(&stream)?;
    let connection = ServerConnection::new(server_config)
        .map_err(|error| format!("local HTTPS TLS state failed: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if request.len() >= MAX_LOCAL_HTTPS_REQUEST_BYTES {
            return Err("local HTTPS request exceeded the fixed bound".to_owned());
        }
        let read = tls
            .read(&mut buffer)
            .map_err(|error| format!("local HTTPS request read failed: {error}"))?;
        if read == 0 {
            return Err("local HTTPS request ended before its headers".to_owned());
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > MAX_LOCAL_HTTPS_REQUEST_BYTES {
            return Err("local HTTPS request exceeded the fixed bound".to_owned());
        }
    }
    if !request.starts_with(b"GET /component.laocrpkg HTTP/1.1\r\n") {
        return Err("local HTTPS request path or method differed".to_owned());
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(response.as_bytes())
        .and_then(|()| tls.write_all(&body))
        .and_then(|()| tls.flush())
        .map_err(|error| format!("local HTTPS response write failed: {error}"))
}

fn configure_local_https_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(LOCAL_HTTPS_SOCKET_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(LOCAL_HTTPS_SOCKET_TIMEOUT)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|error| format!("local HTTPS socket configuration failed: {error}"))
}

fn pinned_local_client(certificate_pem: &[u8]) -> Client {
    Client::builder()
        .add_root_certificate(Certificate::from_pem(certificate_pem).unwrap())
        .https_only(true)
        .no_proxy()
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_local_https_download_streams_exact_bytes_and_cleans_integrity_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let body = vec![0x5a; 2 * 1024 * 1024 + 17];
    let expected_hash = package::sha256_bytes(&body);

    let success_server = spawn_local_https_once(&body);
    let success_directory = temporary.path().join("success-download");
    fs::create_dir(&success_directory).unwrap();
    let success_destination = success_directory.join("component.laocrpkg");
    let success = catalog::download_exact(
        &pinned_local_client(&success_server.certificate_pem),
        success_server.url.clone(),
        &success_destination,
        body.len() as u64,
        &expected_hash,
        false,
    )
    .await;
    let success_server_result = success_server.finish();
    assert!(
        success.is_ok() && success_server_result.is_ok(),
        "local HTTPS success path failed: client={success:?}, server={success_server_result:?}"
    );
    assert_eq!(fs::read(&success_destination).unwrap(), body);

    let failure_server = spawn_local_https_once(&body);
    let failure_directory = temporary.path().join("failure-download");
    fs::create_dir(&failure_directory).unwrap();
    let failure_destination = failure_directory.join("component.laocrpkg");
    let failure = catalog::download_exact(
        &pinned_local_client(&failure_server.certificate_pem),
        failure_server.url.clone(),
        &failure_destination,
        body.len() as u64,
        &"0".repeat(64),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.code(), "download_integrity_mismatch");
    failure_server
        .finish()
        .expect("integrity-failure server serves the exact bytes");
    package::cleanup_exact_transient(&failure_directory, &[PathBuf::from(&failure_destination)])
        .unwrap();
    assert!(!failure_directory.exists());
}
