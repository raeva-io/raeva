//! The raeva integration tests, built as one test binary so that they link
//! once. The tests run the `raeva` binary.

mod common;

mod artifact_provenance;
mod fixture_inventory;
mod schemas;

mod auth_hints;
mod command_help;
mod doctor_redaction;
mod env_proxies;
mod export_destination;
mod host_inputs;
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
mod maven_options;
mod maven_parity;
mod metadata_cache;
mod network_failures;
mod offline_project;
mod parent_lookup_failures;
mod project_file_repository;
mod reactor_sync;
mod remote_parent_repositories;
mod repository_hosts;
mod repository_ids;
mod repository_url_secrets;
mod request_counts;
mod sbom_cli;
mod schema_validation;
mod sync_semantics;
mod system_scope;
mod tls_roots;
mod transitive_repositories;
mod vex_cli;
mod vuln_cli;
