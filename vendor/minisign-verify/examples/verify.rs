use minisign_verify::{PublicKey, Signature};
use std::{env, fs::File, io::Read, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: verify <public-key-text> <signature-text> <artifact>".into());
    }
    let public_key = PublicKey::from_file(Path::new(&arguments[0]))?;
    let signature = Signature::from_file(Path::new(&arguments[1]))?;
    let artifact = Path::new(&arguments[2]);
    let expected_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("artifact filename is not valid UTF-8")?;
    let trusted_name = signature
        .trusted_comment()
        .split('\t')
        .find_map(|field| field.strip_prefix("file:"))
        .ok_or("signature trusted comment has no file field")?;
    if trusted_name != expected_name {
        return Err(format!(
            "signature trusted filename mismatch: expected {expected_name}, found {trusted_name}"
        )
        .into());
    }

    let mut verifier = public_key.verify_stream(&signature)?;
    let mut file = File::open(artifact)?;
    // Keep the release verifier's buffer on the heap. A 1 MiB stack array can
    // exhaust the default Windows process stack before any bytes are checked.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        verifier.update(&buffer[..count]);
    }
    verifier.finalize()?;
    println!("verified {}", artifact.display());
    Ok(())
}
