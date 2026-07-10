#![cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(unused_imports)
)]

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("Lawyer Assistance currently supports only Windows x86_64.");

use domain::health::HealthCheckResponse;
use std::path::PathBuf;
use tauri::{path::BaseDirectory, Manager};

mod commands;
mod state;

pub fn health_check_response() -> HealthCheckResponse {
    HealthCheckResponse::ok("Lawyer Assistance")
}

#[tauri::command]
fn health_check() -> HealthCheckResponse {
    health_check_response()
}

fn resolve_legal_core_resource(app: &tauri::App) -> tauri::Result<PathBuf> {
    let bundled_path = app.path().resolve(
        PathBuf::from("resources").join(database::LEGAL_CORE_DB_FILE_NAME),
        BaseDirectory::Resource,
    )?;

    if bundled_path.is_file() {
        return Ok(bundled_path);
    }

    let development_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join(database::LEGAL_CORE_DB_FILE_NAME);

    if development_path.is_file() {
        Ok(development_path)
    } else {
        Ok(bundled_path)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_local_data_dir = app.path().app_local_data_dir()?;
            let user_database_path = database::ensure_user_database(&app_local_data_dir)?;
            let legal_core_path = resolve_legal_core_resource(app)?;
            app.manage(state::AppState::new(legal_core_path, user_database_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            commands::case::list_case_projects,
            commands::case::get_case_workspace,
            commands::case::upsert_case_project,
            commands::case::delete_case_project,
            commands::case::upsert_case_file,
            commands::case::upsert_case_party,
            commands::case::upsert_case_fact,
            commands::case::upsert_evidence_item,
            commands::case::upsert_evidence_link,
            commands::case::upsert_legal_issue,
            commands::case::add_case_legal_basis,
            commands::case::delete_case_entity,
            commands::case::analyze_case_gaps_command,
            commands::case::parse_structured_case_extraction,
            commands::legal::search_laws,
            commands::legal::search_articles,
            commands::legal::get_article,
            commands::legal::get_law_versions,
            commands::legal::get_law_relations,
            commands::legal::find_legal_answer_candidates,
            commands::legal::answer_legal_question,
            commands::provider::list_provider_profiles,
            commands::provider::upsert_provider_profile,
            commands::provider::delete_provider_profile,
            commands::provider::get_provider_api_key_status,
            commands::provider::write_provider_api_key,
            commands::provider::delete_provider_api_key,
            commands::provider::test_provider_connection
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Lawyer Assistance");
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::health::HealthStatus;

    #[test]
    fn health_check_reports_ok_for_windows_x86_64() {
        let response = health_check_response();

        assert_eq!(response.status, HealthStatus::Ok);
        assert_eq!(response.app_name, "Lawyer Assistance");
        assert_eq!(response.architecture, "x86_64");
    }
}
