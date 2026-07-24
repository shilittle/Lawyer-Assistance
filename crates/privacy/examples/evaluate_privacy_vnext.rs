use privacy::{
    evaluation::{evaluate_offline_corpus, EvaluationCorpusV1},
    vnext::strict_json_v1_from_slice,
};
use std::{env, fs, process::ExitCode};

const MAX_CORPUS_BYTES: usize = 128 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), &'static str> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err("usage: evaluate_privacy_vnext <corpus.json> <report.json>");
    }
    let bytes = fs::read(&arguments[0]).map_err(|_| "evaluation_input_read_failed")?;
    if bytes.is_empty() || bytes.len() > MAX_CORPUS_BYTES {
        return Err("evaluation_input_size_invalid");
    }
    let corpus: EvaluationCorpusV1 =
        strict_json_v1_from_slice(&bytes).map_err(|_| "evaluation_input_schema_invalid")?;
    let report = evaluate_offline_corpus(&corpus).map_err(|_| "evaluation_failed")?;
    let mut report_bytes =
        serde_json::to_vec_pretty(&report).map_err(|_| "evaluation_report_encode_failed")?;
    report_bytes.push(b'\n');
    fs::write(&arguments[1], report_bytes).map_err(|_| "evaluation_report_write_failed")?;
    Ok(())
}
