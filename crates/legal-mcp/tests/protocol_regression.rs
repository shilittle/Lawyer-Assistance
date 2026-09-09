use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

const PUBLIC_TOOLS: [&str; 5] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
];

#[test]
fn public_stdio_has_exactly_five_tools_and_stdout_is_only_jsonrpc() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let legal_db = temporary.path().join("legal_core.sqlite");
    let binary = env!("CARGO_BIN_EXE_lawyer-assistance-mcp");
    let mut child = Command::new(binary)
        .arg("--legal-db")
        .arg(&legal_db)
        .arg("stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start stdio MCP");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    send(
        &mut stdin,
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
        }),
    );
    let initialize = receive(&mut stdout);
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let tools = receive(&mut stdout);
    assert_eq!(
        tools["result"]["tools"]
            .as_array()
            .expect("tool list")
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect::<Vec<_>>(),
        PUBLIC_TOOLS
    );
    drop(stdin);
    let status = child.wait().expect("wait for MCP");
    assert!(status.success());
}

#[test]
fn legacy_profile_exits_with_profile_disabled() {
    let binary = env!("CARGO_BIN_EXE_lawyer-assistance-mcp");
    let output = Command::new(binary)
        .arg("--privacy-profile")
        .arg("diagram_authoring")
        .arg("stdio")
        .output()
        .expect("start disabled profile");
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "lawyer-assistance-mcp: profile_disabled"
    );
}

fn send(writer: &mut impl Write, value: Value) {
    serde_json::to_writer(&mut *writer, &value).expect("serialize request");
    writer.write_all(b"\n").expect("write request");
    writer.flush().expect("flush request");
}

fn receive(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response");
    serde_json::from_str(&line).expect("stdout JSON-RPC frame")
}
