//! The raeva integration tests, built as one test binary so that they link
//! once. The tests run the `raeva` binary.

mod common;

mod artifact_provenance;
mod artifact_types;
mod fixture_inventory;
mod schemas;

mod auth_hints;
mod cause_diffs;
mod command_help;
mod doctor_redaction;
mod env_proxies;
mod export_destination;
mod export_plan;
mod host_inputs;
mod host_properties;
mod integration;
mod json_output;
mod json_payloads;
mod lock_diff;
mod lock_exit_codes;
mod lock_golden;
mod lock_merging;
#[cfg(unix)]
mod lock_read_errors;
mod lock_verify_download;
mod managed_sources;
mod maven39_reads;
mod maven_modes;
mod maven_options;
mod maven_parity;
mod maven_user_home;
mod metadata_cache;
mod mirror_changes;
mod network_failures;
mod offline_project;
mod parent_lookup_failures;
mod plugin_lock;
mod project_file_repository;
mod reactor_sync;
mod remote_parent_repositories;
mod repository_filters;
mod repository_hosts;
mod repository_ids;
mod repository_url_secrets;
mod request_counts;
mod sbom_cli;
mod schema_validation;
mod seed;
mod sync_semantics;
mod system_scope;
mod tls_roots;
mod transitive_repositories;
mod vex_cli;
mod vuln_cli;
