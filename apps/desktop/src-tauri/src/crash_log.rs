use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    panic::PanicHookInfo,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_CRASH_LOG_BYTES: u64 = 256 * 1024;
static CRASH_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashEvent<'a> {
    timestamp_unix: u64,
    event: &'static str,
    source_file: Option<&'a str>,
    source_line: Option<u32>,
    app_version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintenanceEvent<'a> {
    timestamp_unix: u64,
    event: &'static str,
    component: &'a str,
    app_version: &'static str,
}

pub fn install(path: PathBuf) {
    let _ = CRASH_LOG_PATH.set(path.clone());
    rotate_if_needed(&path);
    std::panic::set_hook(Box::new(|info| {
        if let Some(path) = CRASH_LOG_PATH.get() {
            write_event(path, info);
        }
    }));
}

pub fn read(path: &Path) -> std::io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

pub fn record_maintenance_failure(path: &Path, component: &str) {
    rotate_if_needed(path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let event = MaintenanceEvent {
        timestamp_unix: timestamp_unix(),
        event: "maintenance_failure",
        component,
        app_version: env!("CARGO_PKG_VERSION"),
    };
    append_json_line(path, &event);
}

fn write_event(path: &Path, info: &PanicHookInfo<'_>) {
    let location = info.location();
    let source_file = location
        .and_then(|value| Path::new(value.file()).file_name())
        .and_then(|value| value.to_str());
    write_event_record(path, source_file, location.map(|value| value.line()));
}

fn write_event_record(path: &Path, source_file: Option<&str>, source_line: Option<u32>) {
    rotate_if_needed(path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let event = CrashEvent {
        timestamp_unix: timestamp_unix(),
        event: "panic",
        source_file,
        source_line,
        app_version: env!("CARGO_PKG_VERSION"),
    };
    append_json_line(path, &event);
}

fn timestamp_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn append_json_line(path: &Path, event: &impl Serialize) {
    if let (Ok(line), Ok(mut file)) = (
        serde_json::to_string(event),
        OpenOptions::new().create(true).append(true).open(path),
    ) {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
    }
}

fn rotate_if_needed(path: &Path) {
    if fs::metadata(path)
        .map(|metadata| metadata.len() <= MAX_CRASH_LOG_BYTES)
        .unwrap_or(true)
    {
        return;
    }
    let archived = path.with_extension("log.1");
    let _ = fs::remove_file(&archived);
    let _ = fs::rename(path, archived);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_event_schema_never_contains_panic_payload() {
        let event = CrashEvent {
            timestamp_unix: 1,
            event: "panic",
            source_file: Some("src/example.rs"),
            source_line: Some(9),
            app_version: "0.0.0-test",
        };
        let serialized = serde_json::to_string(&event).expect("event serializes");
        assert!(serialized.contains("sourceFile"));
        assert!(!serialized.contains("message"));
        assert!(!serialized.contains("payload"));
        assert!(!serialized.contains("request"));
        assert!(!serialized.contains("response"));
    }

    #[test]
    fn crash_event_is_persisted_and_rotated_without_payload_text() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("crash-events.log");
        write_event_record(&path, Some("command.rs"), Some(17));
        let content = read(&path).expect("crash event reads");
        assert!(content.contains("command.rs"));
        assert!(content.contains("\"sourceLine\":17"));
        assert!(!content.contains("payload"));

        fs::write(&path, vec![b'x'; (MAX_CRASH_LOG_BYTES + 1) as usize])
            .expect("oversized crash log writes");
        write_event_record(&path, Some("next.rs"), Some(21));
        assert!(path.with_extension("log.1").is_file());
        assert!(read(&path).expect("rotated log reads").contains("next.rs"));
    }

    #[test]
    fn maintenance_failure_is_payload_free_and_does_not_record_os_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("crash-events.log");
        record_maintenance_failure(&path, "updater_cleanup");
        let content = read(&path).unwrap();
        assert!(content.contains("maintenance_failure"));
        assert!(content.contains("updater_cleanup"));
        assert!(!content.contains("message"));
        assert!(!content.contains("path"));
        assert!(!content.contains("error"));
    }
}
