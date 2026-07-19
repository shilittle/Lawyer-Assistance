fn main() {
    if legal_mcp::run().is_err() {
        eprintln!("lawyer-assistance-mcp: startup_failed");
        std::process::exit(1);
    }
}
