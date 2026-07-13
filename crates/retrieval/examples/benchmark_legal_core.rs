use domain::law::{
    GetArticleRequest, GetLawRelationsRequest, GetLawVersionsRequest, SearchArticlesRequest,
    SearchLawsRequest,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_ITERATIONS: usize = 30;
const WARMUP_ITERATIONS: usize = 3;
const MIN_SIZE_REDUCTION_PERCENT: f64 = 60.0;
const MAX_OPEN_P95_MS: f64 = 10.0;
const MAX_ARTICLE_SEARCH_P95_MS: f64 = 100.0;
const MAX_LAW_SEARCH_P95_MS: f64 = 750.0;
const MAX_DETAIL_P95_MS: f64 = 5.0;
const MAX_VERSION_LIST_P95_MS: f64 = 25.0;

type DynError = Box<dyn Error>;

#[derive(Debug, Serialize)]
struct Metric {
    iterations: usize,
    min_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Serialize)]
struct DatabaseResult {
    path: String,
    size_bytes: u64,
    metrics: BTreeMap<String, Metric>,
    aggregate_query_median_ms: f64,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    generated_at_unix_ms: u128,
    operating_system: &'static str,
    architecture: &'static str,
    warmup_iterations: usize,
    measured_iterations: usize,
    functional_equivalence: bool,
    compared_operations: Vec<&'static str>,
    archive: DatabaseResult,
    runtime: DatabaseResult,
    size_reduction_bytes: u64,
    size_reduction_percent: f64,
    runtime_open_median_improvement_percent: f64,
    runtime_query_median_improvement_percent: f64,
    acceptance: AcceptanceResult,
}

#[derive(Debug, Serialize)]
struct AcceptanceResult {
    passed: bool,
    enforced: bool,
    failures: Vec<String>,
}

fn main() -> Result<(), DynError> {
    let mut arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let enforce_thresholds = arguments
        .last()
        .is_some_and(|argument| argument == "--strict");
    if enforce_thresholds {
        arguments.pop();
    }
    if !(2..=4).contains(&arguments.len()) {
        return Err(
            "usage: benchmark_legal_core <archive.sqlite> <runtime.sqlite> [iterations] [report.json] [--strict]"
                .into(),
        );
    }

    let archive_path = PathBuf::from(&arguments[0]);
    let runtime_path = PathBuf::from(&arguments[1]);
    let iterations = arguments
        .get(2)
        .map(|value| value.to_string_lossy().parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_ITERATIONS);
    if iterations < 5 {
        return Err("iterations must be at least 5".into());
    }
    let output_path = arguments.get(3).map(PathBuf::from);

    let archive_connection = database::open_legal_core_read_only(&archive_path)?;
    let runtime_connection = database::open_legal_core_read_only(&runtime_path)?;

    let mut archive_metrics = BTreeMap::new();
    let mut runtime_metrics = BTreeMap::new();
    let mut compared_operations = Vec::new();

    record_pair(
        "open_metadata",
        iterations,
        &mut archive_metrics,
        &mut runtime_metrics,
        || open_and_read_metadata(&archive_path),
        || open_and_read_metadata(&runtime_path),
    )?;
    compared_operations.push("open_metadata");

    let law_request = || SearchLawsRequest {
        query: "民法典".to_owned(),
        limit: Some(20),
    };
    record_pair(
        "search_laws",
        iterations,
        &mut archive_metrics,
        &mut runtime_metrics,
        || Ok(retrieval::search_laws(&archive_connection, law_request())?),
        || Ok(retrieval::search_laws(&runtime_connection, law_request())?),
    )?;
    compared_operations.push("search_laws");

    for (name, query) in [
        ("search_articles_contract", "合同"),
        ("search_articles_protection", "保护"),
    ] {
        let request = || SearchArticlesRequest {
            query: query.to_owned(),
            document_id: None,
            case_date: Some("2024-01-01".to_owned()),
            limit: Some(20),
        };
        record_pair(
            name,
            iterations,
            &mut archive_metrics,
            &mut runtime_metrics,
            || Ok(retrieval::search_articles(&archive_connection, request())?),
            || Ok(retrieval::search_articles(&runtime_connection, request())?),
        )?;
        compared_operations.push(name);
    }

    let archive_laws = retrieval::search_laws(&archive_connection, law_request())?;
    let runtime_laws = retrieval::search_laws(&runtime_connection, law_request())?;
    ensure_equal("law seed", &archive_laws, &runtime_laws)?;
    let document_id = archive_laws
        .results
        .iter()
        .find(|result| result.title == "中华人民共和国民法典")
        .or_else(|| archive_laws.results.first())
        .ok_or("law benchmark seed returned no results")?
        .document_id
        .clone();

    let article_seed_request = || SearchArticlesRequest {
        query: "合同".to_owned(),
        document_id: Some(document_id.clone()),
        case_date: Some("2024-01-01".to_owned()),
        limit: Some(20),
    };
    let archive_articles = retrieval::search_articles(&archive_connection, article_seed_request())?;
    let runtime_articles = retrieval::search_articles(&runtime_connection, article_seed_request())?;
    ensure_equal("article seed", &archive_articles, &runtime_articles)?;
    let article_id = archive_articles
        .results
        .first()
        .ok_or("article benchmark seed returned no results")?
        .article_id
        .clone();

    record_pair(
        "get_article",
        iterations,
        &mut archive_metrics,
        &mut runtime_metrics,
        || {
            Ok(retrieval::get_article(
                &archive_connection,
                GetArticleRequest {
                    article_id: article_id.clone(),
                },
            )?)
        },
        || {
            Ok(retrieval::get_article(
                &runtime_connection,
                GetArticleRequest {
                    article_id: article_id.clone(),
                },
            )?)
        },
    )?;
    compared_operations.push("get_article");

    record_pair(
        "get_law_versions",
        iterations,
        &mut archive_metrics,
        &mut runtime_metrics,
        || {
            Ok(retrieval::get_law_versions(
                &archive_connection,
                GetLawVersionsRequest {
                    document_id: document_id.clone(),
                },
            )?)
        },
        || {
            Ok(retrieval::get_law_versions(
                &runtime_connection,
                GetLawVersionsRequest {
                    document_id: document_id.clone(),
                },
            )?)
        },
    )?;
    compared_operations.push("get_law_versions");

    record_pair(
        "get_law_relations",
        iterations,
        &mut archive_metrics,
        &mut runtime_metrics,
        || {
            Ok(retrieval::get_law_relations(
                &archive_connection,
                GetLawRelationsRequest {
                    document_id: document_id.clone(),
                    direction: None,
                },
            )?)
        },
        || {
            Ok(retrieval::get_law_relations(
                &runtime_connection,
                GetLawRelationsRequest {
                    document_id: document_id.clone(),
                    direction: None,
                },
            )?)
        },
    )?;
    compared_operations.push("get_law_relations");

    let archive_size = fs::metadata(&archive_path)?.len();
    let runtime_size = fs::metadata(&runtime_path)?.len();
    if runtime_size >= archive_size {
        return Err("runtime database is not smaller than the archival database".into());
    }

    let archive_query_total = aggregate_query_median(&archive_metrics);
    let runtime_query_total = aggregate_query_median(&runtime_metrics);
    let archive_open = archive_metrics["open_metadata"].median_ms;
    let runtime_open = runtime_metrics["open_metadata"].median_ms;
    let size_reduction_percent = percent_improvement(archive_size as f64, runtime_size as f64);
    let acceptance_failures = acceptance_failures(
        size_reduction_percent,
        archive_query_total,
        runtime_query_total,
        &archive_metrics,
        &runtime_metrics,
    );
    let report = BenchmarkReport {
        generated_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        operating_system: env::consts::OS,
        architecture: env::consts::ARCH,
        warmup_iterations: WARMUP_ITERATIONS,
        measured_iterations: iterations,
        functional_equivalence: true,
        compared_operations,
        archive: DatabaseResult {
            path: display_path(&archive_path),
            size_bytes: archive_size,
            metrics: archive_metrics,
            aggregate_query_median_ms: round_ms(archive_query_total),
        },
        runtime: DatabaseResult {
            path: display_path(&runtime_path),
            size_bytes: runtime_size,
            metrics: runtime_metrics,
            aggregate_query_median_ms: round_ms(runtime_query_total),
        },
        size_reduction_bytes: archive_size - runtime_size,
        size_reduction_percent,
        runtime_open_median_improvement_percent: percent_improvement(archive_open, runtime_open),
        runtime_query_median_improvement_percent: percent_improvement(
            archive_query_total,
            runtime_query_total,
        ),
        acceptance: AcceptanceResult {
            passed: acceptance_failures.is_empty(),
            enforced: enforce_thresholds,
            failures: acceptance_failures,
        },
    };

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output_path) = output_path {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, format!("{json}\n"))?;
    }
    println!("{json}");
    if enforce_thresholds && !report.acceptance.passed {
        return Err("runtime database performance acceptance thresholds failed".into());
    }
    Ok(())
}

fn acceptance_failures(
    size_reduction_percent: f64,
    archive_query_total: f64,
    runtime_query_total: f64,
    archive_metrics: &BTreeMap<String, Metric>,
    runtime_metrics: &BTreeMap<String, Metric>,
) -> Vec<String> {
    let mut failures = Vec::new();
    if size_reduction_percent < MIN_SIZE_REDUCTION_PERCENT {
        failures.push(format!(
            "size reduction {size_reduction_percent:.3}% is below {MIN_SIZE_REDUCTION_PERCENT:.1}%"
        ));
    }
    if runtime_query_total > archive_query_total {
        failures.push(format!(
            "aggregate query median {runtime_query_total:.3} ms exceeds archive {archive_query_total:.3} ms"
        ));
    }

    for (name, maximum) in [
        ("open_metadata", MAX_OPEN_P95_MS),
        ("search_articles_contract", MAX_ARTICLE_SEARCH_P95_MS),
        ("search_articles_protection", MAX_ARTICLE_SEARCH_P95_MS),
        ("search_laws", MAX_LAW_SEARCH_P95_MS),
        ("get_article", MAX_DETAIL_P95_MS),
        ("get_law_versions", MAX_VERSION_LIST_P95_MS),
    ] {
        let actual = runtime_metrics[name].p95_ms;
        if actual > maximum {
            failures.push(format!("{name} p95 {actual:.3} ms exceeds {maximum:.3} ms"));
        }
    }

    for name in [
        "search_articles_contract",
        "search_articles_protection",
        "search_laws",
    ] {
        let archive = archive_metrics[name].p95_ms;
        let runtime = runtime_metrics[name].p95_ms;
        if runtime > archive * 1.20 {
            failures.push(format!(
                "{name} p95 {runtime:.3} ms regresses more than 20% from archive {archive:.3} ms"
            ));
        }
    }
    failures
}

fn record_pair<T, ArchiveCall, RuntimeCall>(
    name: &'static str,
    iterations: usize,
    archive_metrics: &mut BTreeMap<String, Metric>,
    runtime_metrics: &mut BTreeMap<String, Metric>,
    archive_call: ArchiveCall,
    runtime_call: RuntimeCall,
) -> Result<(), DynError>
where
    T: Serialize,
    ArchiveCall: FnMut() -> Result<T, DynError>,
    RuntimeCall: FnMut() -> Result<T, DynError>,
{
    let (archive_metric, runtime_metric) =
        measure_pair(name, iterations, archive_call, runtime_call)?;
    archive_metrics.insert(name.to_owned(), archive_metric);
    runtime_metrics.insert(name.to_owned(), runtime_metric);
    Ok(())
}

fn measure_pair<T, ArchiveCall, RuntimeCall>(
    name: &str,
    iterations: usize,
    mut archive_call: ArchiveCall,
    mut runtime_call: RuntimeCall,
) -> Result<(Metric, Metric), DynError>
where
    T: Serialize,
    ArchiveCall: FnMut() -> Result<T, DynError>,
    RuntimeCall: FnMut() -> Result<T, DynError>,
{
    for iteration in 0..WARMUP_ITERATIONS {
        if iteration % 2 == 0 {
            ensure_equal(name, &archive_call()?, &runtime_call()?)?;
        } else {
            let runtime_value = runtime_call()?;
            let archive_value = archive_call()?;
            ensure_equal(name, &archive_value, &runtime_value)?;
        }
    }

    let mut archive_durations = Vec::with_capacity(iterations);
    let mut runtime_durations = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let (archive_duration, archive_value, runtime_duration, runtime_value) =
            if iteration % 2 == 0 {
                let (archive_duration, archive_value) = timed(&mut archive_call)?;
                let (runtime_duration, runtime_value) = timed(&mut runtime_call)?;
                (
                    archive_duration,
                    archive_value,
                    runtime_duration,
                    runtime_value,
                )
            } else {
                let (runtime_duration, runtime_value) = timed(&mut runtime_call)?;
                let (archive_duration, archive_value) = timed(&mut archive_call)?;
                (
                    archive_duration,
                    archive_value,
                    runtime_duration,
                    runtime_value,
                )
            };
        if archive_value != runtime_value {
            return Err(format!("{name} returned different archive/runtime results").into());
        }
        archive_durations.push(archive_duration);
        runtime_durations.push(runtime_duration);
    }

    Ok((summarize(archive_durations), summarize(runtime_durations)))
}

fn timed<T, Call>(call: &mut Call) -> Result<(Duration, Value), DynError>
where
    T: Serialize,
    Call: FnMut() -> Result<T, DynError>,
{
    let started = Instant::now();
    let value = call()?;
    let duration = started.elapsed();
    black_box(&value);
    Ok((duration, serde_json::to_value(value)?))
}

fn ensure_equal<T: Serialize>(name: &str, archive: &T, runtime: &T) -> Result<(), DynError> {
    if serde_json::to_value(archive)? != serde_json::to_value(runtime)? {
        return Err(format!("{name} returned different archive/runtime results").into());
    }
    Ok(())
}

fn summarize(mut durations: Vec<Duration>) -> Metric {
    durations.sort_unstable();
    let iterations = durations.len();
    let median = if iterations.is_multiple_of(2) {
        (duration_ms(durations[iterations / 2 - 1]) + duration_ms(durations[iterations / 2])) / 2.0
    } else {
        duration_ms(durations[iterations / 2])
    };
    let p95_index = ((iterations as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(iterations - 1);
    Metric {
        iterations,
        min_ms: round_ms(duration_ms(durations[0])),
        median_ms: round_ms(median),
        p95_ms: round_ms(duration_ms(durations[p95_index])),
        max_ms: round_ms(duration_ms(durations[iterations - 1])),
    }
}

fn open_and_read_metadata(path: &Path) -> Result<String, DynError> {
    let connection = database::open_legal_core_read_only(path)?;
    Ok(connection.query_row(
        "SELECT value FROM database_metadata WHERE key = 'dataset_version'",
        [],
        |row| row.get(0),
    )?)
}

fn aggregate_query_median(metrics: &BTreeMap<String, Metric>) -> f64 {
    metrics
        .iter()
        .filter(|(name, _)| name.as_str() != "open_metadata")
        .map(|(_, metric)| metric.median_ms)
        .sum()
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn round_ms(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn percent_improvement(baseline: f64, candidate: f64) -> f64 {
    if baseline == 0.0 {
        0.0
    } else {
        ((baseline - candidate) * 100_000.0 / baseline).round() / 1_000.0
    }
}

fn display_path(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}
