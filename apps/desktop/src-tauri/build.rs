fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
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
