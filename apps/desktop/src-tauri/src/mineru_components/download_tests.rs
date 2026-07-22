use super::{catalog, package};
use reqwest::{redirect, Certificate, Client, Url};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

const LOCAL_HTTPS_SERVER: &str = r#"
import http.server
import pathlib
import ssl
import sys

certificate, key, body_file, port_file = sys.argv[1:5]
body = pathlib.Path(body_file).read_bytes()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/component.laocrpkg":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
pathlib.Path(port_file).write_text(str(server.server_address[1]), encoding="ascii")
server.handle_request()
server.server_close()
"#;

struct LocalHttpsServer {
    child: Child,
    certificate_pem: Vec<u8>,
    url: Url,
}

impl Drop for LocalHttpsServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn spawn_local_https_once(root: &Path, body: &[u8]) -> LocalHttpsServer {
    fs::create_dir(root).unwrap();
    let certificate = root.join("certificate.pem");
    let key = root.join("key.pem");
    let body_file = root.join("component.laocrpkg");
    let port_file = root.join("port.txt");
    fs::write(&body_file, body).unwrap();

    let generated = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-config")
        .arg("NUL")
        .arg("-sha256")
        .arg("-days")
        .arg("1")
        .arg("-nodes")
        .arg("-subj")
        .arg("/CN=127.0.0.1")
        .arg("-addext")
        .arg("subjectAltName=IP:127.0.0.1")
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&certificate)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("OpenSSL must be available for the real local HTTPS test");
    assert!(
        generated.success(),
        "failed to generate the ephemeral TLS keypair"
    );

    let child = Command::new("python")
        .arg("-c")
        .arg(LOCAL_HTTPS_SERVER)
        .arg(&certificate)
        .arg(&key)
        .arg(&body_file)
        .arg(&port_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Python must be available for the real local HTTPS test");

    let mut port = None;
    for _ in 0..200 {
        if let Ok(value) = fs::read_to_string(&port_file) {
            if let Ok(parsed) = value.trim().parse::<u16>() {
                port = Some(parsed);
                break;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    let port = port.expect("local HTTPS server did not publish its bound port");

    LocalHttpsServer {
        child,
        certificate_pem: fs::read(certificate).unwrap(),
        url: Url::parse(&format!("https://127.0.0.1:{port}/component.laocrpkg")).unwrap(),
    }
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

    let success_server = spawn_local_https_once(&temporary.path().join("success-server"), &body);
    let success_directory = temporary.path().join("success-download");
    fs::create_dir(&success_directory).unwrap();
    let success_destination = success_directory.join("component.laocrpkg");
    catalog::download_exact(
        &pinned_local_client(&success_server.certificate_pem),
        success_server.url.clone(),
        &success_destination,
        body.len() as u64,
        &expected_hash,
        false,
    )
    .await
    .unwrap();
    assert_eq!(fs::read(&success_destination).unwrap(), body);
    drop(success_server);

    let failure_server = spawn_local_https_once(&temporary.path().join("failure-server"), &body);
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
    package::cleanup_exact_transient(&failure_directory, &[PathBuf::from(&failure_destination)])
        .unwrap();
    assert!(!failure_directory.exists());
}
