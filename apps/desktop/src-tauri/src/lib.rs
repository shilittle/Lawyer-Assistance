#![cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(unused_imports)
)]

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("Lawyer Assistance currently supports only Windows x86_64.");

use domain::health::HealthCheckResponse;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{path::BaseDirectory, AppHandle, Manager};
mod approved_mcp;

mod atomic_file;
mod commands;
mod crash_log;
mod mcp_manager;
mod mineru_components;
mod privacy_manager;
mod privacy_qualification;
mod privacy_workflow;
mod single_instance;
mod state;

const MCP_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitDrainDecision {
    BeginDrain,
    WaitForDrain,
    AllowExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitDrainPhase {
    Idle,
    LaunchingInstaller { pending_exit: Option<i32> },
    Draining,
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallerLaunchCompletion {
    BeginInstallerExit,
    BeginPendingExit(i32),
    ReturnToApp,
    InvalidState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalExitAction {
    Exit(i32),
    Restart,
}

#[derive(Debug)]
pub(crate) struct ExitDrainCoordinator {
    phase: Mutex<ExitDrainPhase>,
}

impl Default for ExitDrainCoordinator {
    fn default() -> Self {
        Self {
            phase: Mutex::new(ExitDrainPhase::Idle),
        }
    }
}

impl ExitDrainCoordinator {
    fn request(&self, exit_code: i32) -> ExitDrainDecision {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *phase {
            ExitDrainPhase::Idle => {
                *phase = ExitDrainPhase::Draining;
                ExitDrainDecision::BeginDrain
            }
            ExitDrainPhase::LaunchingInstaller { pending_exit } => {
                if pending_exit.is_none() {
                    *pending_exit = Some(exit_code);
                }
                ExitDrainDecision::WaitForDrain
            }
            ExitDrainPhase::Draining => ExitDrainDecision::WaitForDrain,
            ExitDrainPhase::Finalizing => ExitDrainDecision::AllowExit,
        }
    }

    pub(crate) fn begin_programmatic_exit(&self) -> bool {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *phase != ExitDrainPhase::Idle {
            return false;
        }
        *phase = ExitDrainPhase::Draining;
        true
    }

    pub(crate) fn reserve_installer_launch(&self) -> bool {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *phase != ExitDrainPhase::Idle {
            return false;
        }
        *phase = ExitDrainPhase::LaunchingInstaller { pending_exit: None };
        true
    }

    pub(crate) fn complete_installer_launch(&self, succeeded: bool) -> InstallerLaunchCompletion {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ExitDrainPhase::LaunchingInstaller { pending_exit } = *phase else {
            return InstallerLaunchCompletion::InvalidState;
        };
        if succeeded {
            *phase = ExitDrainPhase::Draining;
            InstallerLaunchCompletion::BeginInstallerExit
        } else if let Some(exit_code) = pending_exit {
            *phase = ExitDrainPhase::Draining;
            InstallerLaunchCompletion::BeginPendingExit(exit_code)
        } else {
            *phase = ExitDrainPhase::Idle;
            InstallerLaunchCompletion::ReturnToApp
        }
    }

    pub(crate) fn is_finalizing(&self) -> bool {
        *self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == ExitDrainPhase::Finalizing
    }

    fn mark_finalizing(&self) {
        *self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ExitDrainPhase::Finalizing;
    }
}

pub(crate) async fn drain_mcp_and_finalize(
    app: AppHandle,
    manager: Option<mcp_manager::McpManager>,
    coordinator: Arc<ExitDrainCoordinator>,
    action: FinalExitAction,
) {
    if let Some(manager) = manager {
        if !manager
            .shutdown_for_exit_with_timeout(MCP_EXIT_DRAIN_TIMEOUT)
            .await
        {
            if let Ok(directory) = app.path().app_local_data_dir() {
                crash_log::record_maintenance_failure(
                    &directory.join("crash-events.log"),
                    "mcp_exit_drain_timeout",
                );
            }
        }
    }
    coordinator.mark_finalizing();
    match action {
        FinalExitAction::Exit(code) => app.exit(code),
        FinalExitAction::Restart => app.request_restart(),
    }
}

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
    let exit_drain = Arc::new(ExitDrainCoordinator::default());
    let managed_exit_drain = Arc::clone(&exit_drain);

    let app = tauri::Builder::default()
        // Tauri requires this plugin to be registered before every other plugin.
        .plugin(single_instance::plugin(pending_main_window_reveal.clone()))
        .plugin(tauri_plugin_dialog::init())
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
            commands::application_backup::cleanup_stale_application_backup_snapshots(
                &app_local_data_dir,
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to clean sensitive application-backup temporaries: {}",
                    error.message
                ))
            })?;
            let approved_mcp_workspace =
                approved_mcp::ApprovedMcpWorkspace::new(app_local_data_dir.clone());
            let workspace_identity_preflight = approved_mcp_workspace
                .preflight_startup_workspace_identity()
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to preflight the private workspace identity: {}",
                        error.message()
                    ))
                })?;
            let workspace_instance_id =
                approved_mcp_workspace
                    .workspace_instance_id_after_startup_preflight(workspace_identity_preflight)
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to initialize the private workspace identity: {}",
                            error.message()
                        ))
                    })?;
            commands::application_backup::apply_pending_application_restore_with_approved(
                &app_local_data_dir,
                &workspace_instance_id,
                &approved_mcp_workspace,
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to apply pending five-component application restore: {}",
                    error.message
                ))
            })?;
            commands::release::apply_pending_database_restore(&app_local_data_dir).map_err(
                |error| {
                    std::io::Error::other(format!(
                        "failed to apply pending user database restore: {}",
                        error.message
                    ))
                },
            )?;
            let user_database_path = database::user_database_path(&app_local_data_dir);
            let user_database_existed = match std::fs::symlink_metadata(&user_database_path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "the canonical user database path is not an ordinary file",
                    )
                    .into())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if user_database_existed {
                database::validate_user_database_read_only(&user_database_path)?;
            }
            let legal_core_path = resolve_legal_core_resource(app)?;
            let privacy_manager =
                privacy_manager::PrivacyManager::new_with_ocr_qualification_invalidator(
                    app_local_data_dir.clone(),
                    Arc::new(approved_mcp_workspace.clone()),
                )
                .map_err(|error| {
                    std::io::Error::other(format!("failed to initialize privacy settings: {error}"))
                })?;
            let mineru_components =
                mineru_components::MineruComponentManager::new(app_local_data_dir.clone())
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to initialize local MinerU components: {error}"
                        ))
                    })?;
            let component_status = mineru_components.status().map_err(|error| {
                std::io::Error::other(format!("failed to verify local MinerU components: {error}"))
            })?;
            if privacy_manager
                .current_config()
                .ocr
                .worker_path
                .as_deref()
                .is_some_and(|path| path.starts_with(mineru_components.managed_root()))
                && !component_status.active_integrity_valid
            {
                privacy_manager
                    .revoke_local_mineru_qualification()
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to invalidate drifted MinerU qualification: {error}"
                        ))
                    })?;
            }
            let privacy_workflow =
                privacy_workflow::PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                    app_local_data_dir.clone(),
                    workspace_instance_id,
                    Arc::new(approved_mcp_workspace.clone()),
            )
            .map_err(|error| {
                std::io::Error::other(format!("failed to initialize privacy workflow: {error}"))
            })?;
            if !user_database_existed {
                privacy_workflow
                    .preflight_fresh_user_database_initialization()
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to authorize a fresh user database: {error}"
                        ))
                    })?;
                let initialized = database::ensure_user_database(&app_local_data_dir)?;
                if initialized != user_database_path {
                    return Err(std::io::Error::other(
                        "fresh user database initialization changed the canonical path",
                    )
                    .into());
                }
            }
            let app_state =
                state::AppState::new(legal_core_path.clone(), user_database_path.clone());
            let case_material_migration_required = privacy_workflow
                .case_material_migration_required()
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to preflight the case-material migration: {error}"
                    ))
                })?;
            let case_material_source_fingerprint = if case_material_migration_required {
                Some(
                    privacy_workflow
                        .case_material_migration_source_fingerprint()
                        .map_err(|error| {
                            std::io::Error::other(format!(
                                "failed to fingerprint the case-material migration source: {error}"
                            ))
                        })?,
                )
            } else {
                None
            };
            privacy_workflow
                .prepare_startup_storage_after_preflight()
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to prepare the pre-migration backup sources: {error}"
                    ))
                })?;
            if case_material_migration_required {
                let source_fingerprint =
                    case_material_source_fingerprint.as_deref().ok_or_else(|| {
                        std::io::Error::other(
                            "required case-material migration has no verified source fingerprint",
                        )
                    })?;
                for migration_id in [
                    commands::application_backup::PROJECT_PRIVACY_CASE_BINDING_MIGRATION_ID,
                    commands::application_backup::CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
                ] {
                    let backup =
                        commands::application_backup::ensure_pre_migration_application_backup(
                        &app_local_data_dir,
                        &app_state,
                        &privacy_workflow,
                            &approved_mcp_workspace,
                            migration_id,
                            source_fingerprint,
                        )
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to establish the five-component migration backup gate: {}",
                            error.message
                        ))
                    })?;
                    let _verified_migration_backup = (
                        &backup.path,
                        &backup.metadata.bundle_sha256,
                        backup.created,
                    );
                }
                privacy_workflow
                    .upgrade_privacy_store_schema_after_backup()
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to upgrade the backed-up privacy and Vault stores: {error}"
                        ))
                    })?;
                privacy_workflow
                    .run_case_material_migration_after_backup_for_source(source_fingerprint)
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to migrate the unified case-material model: {error}"
                        ))
                    })?;
            }
            if privacy_workflow
                .approved_projection_migration_required()
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to preflight the approved-only case projection migration: {error}"
                    ))
                })?
            {
                let source_fingerprint = privacy_workflow
                    .approved_projection_migration_source_fingerprint()
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to fingerprint the approved-only case projection source: {error}"
                        ))
                    })?;
                let backup =
                    commands::application_backup::ensure_pre_migration_application_backup(
                        &app_local_data_dir,
                        &app_state,
                        &privacy_workflow,
                        &approved_mcp_workspace,
                        commands::application_backup::APPROVED_CASE_PROJECTION_MIGRATION_ID,
                        &source_fingerprint,
                    )
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to establish the approved-only projection five-component backup gate: {}",
                            error.message
                        ))
                    })?;
                let _verified_projection_backup = (
                    &backup.path,
                    &backup.metadata.bundle_sha256,
                    backup.created,
                );
                privacy_workflow
                    .run_approved_projection_migration_after_backup_for_source(
                        &source_fingerprint,
                    )
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "failed to migrate the approved-only case projection: {error}"
                        ))
                    })?;
            }
            privacy_workflow
                .complete_application_startup_maintenance()
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to complete privacy startup maintenance: {error}"
                    ))
                })?;
            let maintained_user_database = database::ensure_user_database(&app_local_data_dir)?;
            if maintained_user_database != user_database_path {
                return Err(std::io::Error::other(
                    "user database maintenance changed the canonical path",
                )
                .into());
            }
            commands::assistant_run::recover_interrupted_assistant_runs(&user_database_path)
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to recover interrupted assistant runs: {}",
                        error.message
                    ))
                })?;
            commands::assistant::recover_pending_assistant_artifact_exports(&app_local_data_dir)
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to recover pending assistant artifact export: {}",
                        error.message
                    ))
                })?;
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
            let mcp_manager = mcp_manager::McpManager::new_with_approved_workspace(
                app_local_data_dir.clone(),
                legal_core_path.clone(),
                user_database_path.clone(),
                approved_mcp_workspace.clone(),
            )
            .map_err(|error| {
                std::io::Error::other(format!("failed to initialize MCP settings: {error}"))
            })?;
            app.manage(app_state);
            app.manage(mcp_manager.clone());
            app.manage(privacy_manager);
            app.manage(mineru_components);
            app.manage(approved_mcp_workspace);
            app.manage(Arc::clone(&managed_exit_drain));
            app.manage(privacy_workflow);
            if mcp_manager.auto_start_enabled() {
                tauri::async_runtime::spawn(async move {
                    let _ = mcp_manager.auto_start_if_enabled().await;
                });
            }
            single_instance::flush_pending_main_window_reveal(
                app.handle(),
                &pending_main_window_reveal,
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            commands::assistant::get_assistant_capabilities,
            commands::assistant::list_assistant_conversations,
            commands::assistant::create_assistant_conversation,
            commands::assistant::get_assistant_conversation,
            commands::assistant::bind_assistant_conversation,
            commands::assistant::archive_assistant_conversation,
            commands::assistant::add_assistant_legal_source,
            commands::assistant::propose_assistant_legal_basis,
            commands::assistant::list_assistant_artifacts,
            commands::assistant::get_assistant_artifact,
            commands::assistant::bind_assistant_artifact,
            commands::assistant::save_assistant_artifact,
            commands::assistant::export_assistant_artifact,
            commands::assistant::import_assistant_files,
            commands::assistant::delete_assistant_attachment,
            commands::assistant::create_assistant_case_change_proposal,
            commands::assistant::reject_assistant_case_change_proposal,
            commands::assistant::apply_assistant_case_change_proposal,
            commands::assistant_run::start_interactive_assistant_run,
            commands::assistant::cancel_assistant_run,
            commands::case_assistant::create_case_assistant_conversation,
            commands::case_assistant::list_case_assistant_conversations,
            commands::case_assistant::get_case_assistant_conversation,
            commands::case_assistant::list_case_assistant_generations,
            commands::case_assistant::start_case_assistant_run,
            commands::case_assistant::list_case_assistant_pending_outputs,
            commands::case_assistant::confirm_case_assistant_output,
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
            commands::document::export_document_pdf,
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
            commands::mcp::get_mcp_server_config,
            commands::mcp::save_mcp_server_config,
            commands::mcp::get_mcp_server_status,
            commands::mcp::start_mcp_server,
            commands::mcp::stop_mcp_server,
            commands::mcp::write_mcp_bearer_token,
            commands::mcp::delete_mcp_bearer_token,
            commands::approved_mcp::publish_approved_generation,
            commands::approved_mcp::list_approved_generations,
            commands::approved_mcp::list_approved_privacy_review_selections,
            commands::approved_mcp::revoke_approved_generation,
            commands::approved_mcp::approve_review_for_approved_workspace,
            commands::approved_mcp::run_approved_mcp_qualification,
            commands::approved_mcp::get_approved_mcp_qualification_status,
            commands::approved_mcp::revoke_approved_mcp_qualification,
            commands::approved_mcp::create_standalone_approved_mcp_session,
            commands::approved_mcp::list_standalone_approved_mcp_sessions,
            commands::approved_mcp::revoke_standalone_approved_mcp_session,
            commands::privacy::get_privacy_config,
            commands::privacy::save_privacy_config,
            commands::privacy::get_local_ocr_status,
            commands::privacy::discover_local_mineru,
            commands::privacy::install_local_mineru_trust,
            commands::privacy::install_local_mineru_network_isolation,
            commands::privacy::run_local_mineru_qualification,
            commands::privacy::revoke_local_mineru_qualification,
            commands::privacy::inspect_local_mineru_qualification_report,
            commands::mineru_components::get_mineru_component_status,
            commands::mineru_components::import_mineru_component_catalog,
            commands::mineru_components::install_mineru_offline_package,
            commands::mineru_components::download_install_mineru_package,
            commands::mineru_components::rollback_mineru_component,
            commands::mineru_components::uninstall_mineru_component,
            commands::provider::list_provider_profiles,
            commands::privacy_workflow::prepare_privacy_material,
            commands::privacy_workflow::prepare_case_material,
            commands::privacy_workflow::list_case_materials,
            commands::privacy_workflow::list_unassigned_case_materials,
            commands::privacy_workflow::assign_unassigned_case_material,
            commands::privacy_workflow::list_case_redaction_generations,
            commands::privacy_workflow::load_case_redaction_review,
            commands::privacy_workflow::apply_case_redaction_risk_review_action,
            commands::privacy_workflow::undo_case_redaction_risk_review,
            commands::privacy_workflow::redo_case_redaction_risk_review,
            commands::privacy_workflow::approve_case_redaction_review,
            commands::privacy_workflow::delete_case_redaction_review,
            commands::privacy_export::export_approved_case_redaction,
            commands::privacy_lifecycle::get_privacy_lifecycle_status,
            commands::privacy_lifecycle::set_privacy_retention_policy,
            commands::privacy_lifecycle::set_privacy_legal_hold,
            commands::privacy_lifecycle::reveal_privacy_mapping,
            commands::privacy_lifecycle::revoke_privacy_mapping,
            commands::privacy_lifecycle::rotate_privacy_mapping_key,
            commands::privacy_lifecycle::destroy_privacy_mapping_key,
            commands::privacy_lifecycle::run_privacy_retention_sweep,
            commands::privacy_lifecycle::create_privacy_backup,
            commands::privacy_lifecycle::verify_privacy_backup,
            commands::privacy_lifecycle::export_privacy_backup_bundle,
            commands::privacy_lifecycle::import_privacy_backup_bundle,
            commands::privacy_lifecycle::revoke_privacy_backup,
            commands::privacy_lifecycle::stage_privacy_restore,
            commands::privacy_provider::approve_approved_provider_task,
            commands::privacy_provider::dispatch_approved_provider,
            commands::privacy_provider::get_provider_qualification_status,
            commands::privacy_provider::run_provider_qualification,
            commands::privacy_provider::revoke_provider_qualification,
            commands::privacy_provider::list_approved_provider_outputs,
            commands::privacy_provider::load_approved_provider_output,
            commands::privacy_provider::revoke_approved_provider_output,
            commands::provider::upsert_provider_profile,
            commands::provider::delete_provider_profile,
            commands::provider::get_provider_api_key_status,
            commands::provider::write_provider_api_key,
            commands::provider::delete_provider_api_key,
            commands::provider::test_provider_connection,
            commands::application_backup::export_application_backup,
            commands::application_backup::verify_application_backup,
            commands::application_backup::stage_application_restore,
            commands::release::get_version_info,
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
    app.run(move |handle, event| match event {
        tauri::RunEvent::ExitRequested { code, api, .. } => {
            // Tauri ignores `prevent_exit` for its reserved restart code. Every
            // in-app restart path drains MCP before requesting that event.
            if code == Some(tauri::RESTART_EXIT_CODE) {
                if !exit_drain.is_finalizing() {
                    if let Some(manager) = handle.try_state::<mcp_manager::McpManager>() {
                        manager.cancel_for_exit();
                    }
                    if let Ok(directory) = handle.path().app_local_data_dir() {
                        crash_log::record_maintenance_failure(
                            &directory.join("crash-events.log"),
                            "mcp_uncoordinated_restart",
                        );
                    }
                }
                return;
            }
            let exit_code = code.unwrap_or(0);
            match exit_drain.request(exit_code) {
                ExitDrainDecision::BeginDrain => {
                    api.prevent_exit();
                    let manager = handle
                        .try_state::<mcp_manager::McpManager>()
                        .map(|state| state.inner().clone());
                    tauri::async_runtime::spawn(drain_mcp_and_finalize(
                        handle.clone(),
                        manager,
                        Arc::clone(&exit_drain),
                        FinalExitAction::Exit(exit_code),
                    ));
                }
                ExitDrainDecision::WaitForDrain => api.prevent_exit(),
                ExitDrainDecision::AllowExit => {}
            }
        }
        tauri::RunEvent::Exit => {
            if let Some(manager) = handle.try_state::<mcp_manager::McpManager>() {
                manager.cancel_for_exit();
            }
        }
        _ => {}
    });
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
    fn renderer_registers_only_current_assistant_and_project_scoped_review_commands() {
        let source = include_str!("lib.rs");
        let registrations = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .and_then(|value| value.split("])").next())
            .expect("Tauri invoke registration list");

        for scoped in [
            "commands::assistant_run::start_interactive_assistant_run,",
            "commands::case_assistant::create_case_assistant_conversation,",
            "commands::case_assistant::list_case_assistant_conversations,",
            "commands::case_assistant::get_case_assistant_conversation,",
            "commands::case_assistant::list_case_assistant_generations,",
            "commands::case_assistant::start_case_assistant_run,",
            "commands::case_assistant::list_case_assistant_pending_outputs,",
            "commands::case_assistant::confirm_case_assistant_output,",
            "commands::privacy_workflow::list_unassigned_case_materials,",
            "commands::privacy_workflow::assign_unassigned_case_material,",
            "commands::privacy_workflow::load_case_redaction_review,",
            "commands::privacy_workflow::apply_case_redaction_risk_review_action,",
            "commands::privacy_workflow::undo_case_redaction_risk_review,",
            "commands::privacy_workflow::redo_case_redaction_risk_review,",
            "commands::privacy_workflow::approve_case_redaction_review,",
            "commands::privacy_workflow::delete_case_redaction_review,",
            "commands::privacy_export::export_approved_case_redaction,",
        ] {
            assert!(
                registrations.contains(scoped),
                "missing case-scoped renderer command {scoped}"
            );
        }
        for unscoped in [
            "commands::assistant_run::start_assistant_run,",
            "commands::privacy_workflow::load_privacy_review,",
            "commands::privacy_workflow::load_latest_privacy_review,",
            "commands::privacy_workflow::load_privacy_risk_review,",
            "commands::privacy_workflow::apply_privacy_risk_review_action,",
            "commands::privacy_workflow::undo_privacy_risk_review,",
            "commands::privacy_workflow::redo_privacy_risk_review,",
            "commands::privacy_workflow::approve_privacy_review,",
            "commands::privacy_workflow::delete_privacy_review,",
            "commands::privacy_export::export_approved_privacy_review,",
        ] {
            assert!(
                !registrations.contains(unscoped),
                "unscoped legacy review command remains renderer-callable: {unscoped}"
            );
        }
    }

    #[test]
    fn startup_defers_user_database_writes_until_case_material_gate_finishes() {
        let source = include_str!("lib.rs");
        let setup = source
            .split(".setup(move |app| {")
            .nth(1)
            .and_then(|value| value.split(".invoke_handler").next())
            .expect("desktop setup source");
        let existing_read_only = setup
            .find("database::validate_user_database_read_only(&user_database_path)")
            .expect("existing user database read-only preflight");
        let identity_read_only = setup
            .find(".preflight_startup_workspace_identity()")
            .expect("approved MCP identity read-only preflight");
        let identity_initialization = setup
            .find(".workspace_instance_id_after_startup_preflight")
            .expect("fresh-only approved MCP identity initialization");
        let fresh_authorization = setup
            .find(".preflight_fresh_user_database_initialization()")
            .expect("fresh user database authorization");
        let fresh_initialization = setup
            .find("let initialized = database::ensure_user_database")
            .expect("fresh user database initialization");
        let migration_probe = setup
            .find(".case_material_migration_required()")
            .expect("case-material migration probe");
        let migration_run = setup
            .find(".run_case_material_migration_after_backup_for_source")
            .expect("source-bound case-material migration");
        let projection_probe = setup
            .find(".approved_projection_migration_required()")
            .expect("approved-only projection migration probe");
        let projection_fingerprint = setup
            .find(".approved_projection_migration_source_fingerprint()")
            .expect("approved-only projection source fingerprint");
        let projection_backup = setup
            .find("APPROVED_CASE_PROJECTION_MIGRATION_ID")
            .expect("approved-only projection five-component backup");
        let projection_run = setup
            .find(".run_approved_projection_migration_after_backup_for_source")
            .expect("source-bound approved-only projection migration");
        let privacy_maintenance = setup
            .find(".complete_application_startup_maintenance()")
            .expect("privacy startup maintenance");
        let user_maintenance = setup
            .find("let maintained_user_database = database::ensure_user_database")
            .expect("deferred user database maintenance");
        let assistant_recovery = setup
            .find("recover_interrupted_assistant_runs")
            .expect("deferred assistant recovery");
        let document_recovery = setup
            .find("recover_pending_document_exports")
            .expect("deferred document recovery");

        assert!(identity_read_only < identity_initialization);
        assert!(!setup.contains(".workspace_instance_id()"));
        assert!(existing_read_only < migration_probe);
        assert!(fresh_authorization < fresh_initialization);
        assert!(fresh_initialization < migration_probe);
        assert!(migration_probe < migration_run);
        assert!(migration_run < projection_probe);
        assert!(projection_probe < projection_fingerprint);
        assert!(projection_fingerprint < projection_backup);
        assert!(projection_backup < projection_run);
        assert!(projection_run < privacy_maintenance);
        assert!(privacy_maintenance < user_maintenance);
        assert!(user_maintenance < assistant_recovery);
        assert!(user_maintenance < document_recovery);
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

    #[test]
    fn exit_drain_coordinator_prevents_reentrant_exit_until_finalization() {
        let coordinator = ExitDrainCoordinator::default();
        assert_eq!(coordinator.request(7), ExitDrainDecision::BeginDrain);
        assert_eq!(coordinator.request(9), ExitDrainDecision::WaitForDrain);
        coordinator.mark_finalizing();
        assert_eq!(coordinator.request(11), ExitDrainDecision::AllowExit);
    }

    #[test]
    fn concurrent_exit_requests_start_exactly_one_drain() {
        let coordinator = Arc::new(ExitDrainCoordinator::default());
        let decisions = (0..8)
            .map(|_| {
                let coordinator = Arc::clone(&coordinator);
                std::thread::spawn(move || coordinator.request(0))
            })
            .map(|thread| thread.join().expect("exit request thread joins"))
            .collect::<Vec<_>>();
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| **decision == ExitDrainDecision::BeginDrain)
                .count(),
            1
        );
        assert!(decisions.iter().all(|decision| matches!(
            decision,
            ExitDrainDecision::BeginDrain | ExitDrainDecision::WaitForDrain
        )));
    }

    #[test]
    fn failed_installer_launch_restores_idle_or_honors_a_pending_window_exit() {
        let coordinator = ExitDrainCoordinator::default();
        assert!(coordinator.reserve_installer_launch());
        assert_eq!(
            coordinator.complete_installer_launch(false),
            InstallerLaunchCompletion::ReturnToApp
        );
        assert!(coordinator.begin_programmatic_exit());

        let coordinator = ExitDrainCoordinator::default();
        assert!(coordinator.reserve_installer_launch());
        assert_eq!(coordinator.request(23), ExitDrainDecision::WaitForDrain);
        assert_eq!(
            coordinator.complete_installer_launch(false),
            InstallerLaunchCompletion::BeginPendingExit(23)
        );
        assert!(!coordinator.begin_programmatic_exit());
    }

    #[test]
    fn successful_installer_launch_claims_the_single_exit_sequence() {
        let coordinator = ExitDrainCoordinator::default();
        assert!(coordinator.reserve_installer_launch());
        assert_eq!(
            coordinator.complete_installer_launch(true),
            InstallerLaunchCompletion::BeginInstallerExit
        );
        assert!(!coordinator.reserve_installer_launch());
        assert_eq!(coordinator.request(0), ExitDrainDecision::WaitForDrain);
        coordinator.mark_finalizing();
        assert_eq!(coordinator.request(0), ExitDrainDecision::AllowExit);
    }
}
