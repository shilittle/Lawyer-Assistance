#![cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(unused_imports)
)]

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("Lawyer Assistance currently supports only Windows x86_64.");

use domain::health::HealthCheckResponse;
use std::path::PathBuf;
use tauri::{path::BaseDirectory, Manager};

mod atomic_file;
mod commands;
mod crash_log;
mod single_instance;
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
    let context = tauri::generate_context!();
    let startup_guard = single_instance::acquire_startup_guard(&context.config().identifier)
        .expect("failed to acquire the single-instance startup guard");
    let lifetime_guard = single_instance::try_acquire_lifetime_guard(&context.config().identifier)
        .expect("failed to acquire the single-instance lifetime guard");
    let is_primary = lifetime_guard.is_some();
    let pending_main_window_reveal = single_instance::new_pending_reveal_flag();

    let app = tauri::Builder::default()
        // Tauri requires this plugin to be registered before every other plugin.
        .plugin(single_instance::plugin(pending_main_window_reveal.clone()))
        .setup(move |app| {
            // The upstream plugin normally terminates a secondary during build,
            // but its Windows message target may be transiently unavailable.
            // Fail closed before touching crash logs, restore markers or either
            // database so that even that rare secondary cannot mutate state.
            if !is_primary {
                return Ok(());
            }
            let app_local_data_dir = app.path().app_local_data_dir()?;
            let crash_log_path = app_local_data_dir.join("crash-events.log");
            crash_log::install(crash_log_path.clone());
            if commands::updater::cleanup_stale_update_downloads(&app_local_data_dir).is_err() {
                // A just-finished installer or antivirus may briefly hold the
                // verified EXE open. Cleanup is retried next startup and must
                // never prevent the updated application from launching.
                crash_log::record_maintenance_failure(&crash_log_path, "updater_cleanup");
            }
            commands::release::apply_pending_database_restore(&app_local_data_dir).map_err(
                |error| {
                    std::io::Error::other(format!(
                        "failed to apply pending user database restore: {}",
                        error.message
                    ))
                },
            )?;
            let user_database_path = database::ensure_user_database(&app_local_data_dir)?;
            commands::document::recover_pending_document_exports(
                &app_local_data_dir,
                &user_database_path,
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to recover pending document export: {}",
                    error.message
                ))
            })?;
            let legal_core_path = resolve_legal_core_resource(app)?;
            app.manage(state::AppState::new(legal_core_path, user_database_path));
            single_instance::flush_pending_main_window_reveal(
                app.handle(),
                &pending_main_window_reveal,
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            commands::case::list_case_projects,
            commands::case::get_case_workspace,
            commands::case::get_pending_structured_case_extraction,
            commands::case::update_pending_structured_case_extraction,
            commands::case::upsert_case_project,
            commands::case::delete_case_project,
            commands::case::upsert_case_file,
            commands::case::upsert_case_party,
            commands::case::upsert_case_fact,
            commands::case::upsert_evidence_item,
            commands::case::upsert_evidence_link,
            commands::case::upsert_fact_issue_link,
            commands::case::upsert_legal_issue,
            commands::case::add_case_legal_basis,
            commands::case::delete_case_entity,
            commands::case::analyze_case_gaps_command,
            commands::case::generate_structured_case_extraction,
            commands::case::confirm_structured_case_extraction,
            commands::case::discard_structured_case_extraction,
            commands::document::list_document_templates,
            commands::document::preview_document,
            commands::document::export_document,
            commands::graph::get_case_graph,
            commands::graph::get_law_graph,
            commands::legal::search_laws,
            commands::legal::search_articles,
            commands::legal::get_article,
            commands::legal::get_law_document,
            commands::legal::get_law_versions,
            commands::legal::get_law_relations,
            commands::legal::find_legal_answer_candidates,
            commands::legal::list_legal_answer_records,
            commands::legal::answer_legal_question,
            commands::legal::cancel_legal_answer,
            commands::provider::list_provider_profiles,
            commands::provider::upsert_provider_profile,
            commands::provider::delete_provider_profile,
            commands::provider::get_provider_api_key_status,
            commands::provider::write_provider_api_key,
            commands::provider::delete_provider_api_key,
            commands::provider::test_provider_connection,
            commands::release::get_version_info,
            commands::release::backup_user_database,
            commands::release::restore_user_database,
            commands::release::export_diagnostic_report,
            commands::updater::check_for_application_update,
            commands::updater::download_install_application_update,
            commands::updater::relaunch_application
        ])
        .build(context)
        .expect("failed to build Lawyer Assistance");

    // The official plugin's lifetime mutex and message target now exist. Releasing
    // this short startup gate lets later processes invoke the official callback.
    drop(startup_guard);

    // A secondary normally exits from inside the official plugin after notifying
    // the primary. If its upstream Windows message target is unexpectedly absent,
    // fail closed here instead of ever running a second application instance.
    let Some(_lifetime_guard) = lifetime_guard else {
        return;
    };
    app.run(|_, _| {});
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

    #[test]
    fn main_window_capability_allows_release_lifecycle_operations() {
        let capability =
            serde_json::from_str::<serde_json::Value>(include_str!("../capabilities/default.json"))
                .expect("desktop capability JSON parses");
        let permissions = capability["permissions"]
            .as_array()
            .expect("desktop permissions are an array");

        assert!(permissions
            .iter()
            .any(|permission| { permission.as_str() == Some("core:window:allow-destroy") }));
        assert!(!permissions.iter().any(|permission| {
            matches!(
                permission.as_str(),
                Some("updater:default" | "process:allow-restart")
            )
        }));
    }
}
