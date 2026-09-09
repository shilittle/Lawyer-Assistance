fn main() {
    match legal_mcp::run() {
        Ok(()) => {}
        Err(legal_mcp::StartupError::ProfileDisabled) => {
            eprintln!("lawyer-assistance-mcp: profile_disabled");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("lawyer-assistance-mcp: startup_failed");
            std::process::exit(1);
        }
    }
}
