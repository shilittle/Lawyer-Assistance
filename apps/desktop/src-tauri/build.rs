fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=LAWYER_ASSISTANCE_MCP_RELEASE_SHA256");
    if let Ok(value) = std::env::var("LAWYER_ASSISTANCE_MCP_RELEASE_SHA256") {
        assert!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 must be exactly 64 lowercase hex characters"
        );
    }
    let build_unix = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default()
        });
    println!("cargo:rustc-env=LAWYER_ASSISTANCE_BUILD_UNIX={build_unix}");
    tauri_build::build();
}
