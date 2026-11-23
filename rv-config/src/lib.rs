//! Configuration handling for Raeva.
//!
//! [`Config::load`] merges the project `raeva.toml`, the user `config.toml`, and
//! Maven's `settings.xml`, and applies the `RAEVA_HOME` and network
//! environment overrides.
//! [`ResolvedPaths`] locates the config, store, and cache directories.
//! The `read_*project_input*` functions read POMs and config files with a
//! size limit.
//!
//! # The environment layer
//!
//! The environment variables that change raeva's configuration are read here,
//! while the configuration loads:
//!
//! - `RAEVA_HOME` roots all of raeva's directories (see
//!   [`ResolvedPaths::discover`]). Without it they come from the platform:
//!   `XDG_*` and `HOME`, or the Windows known folders.
//! - `RAEVA_TIMEOUT`, `RAEVA_RETRIES`, `RAEVA_LOW_SPEED_LIMIT` and
//!   `RAEVA_LOW_SPEED_TIME` override the `[network]` keys of the same name,
//!   and `RAEVA_MAX_ARTIFACT_SIZE` ([`MAX_ARTIFACT_SIZE_ENV`]) sets
//!   [`NetworkConfig::max_artifact_size`].
//! - `MAVEN_REPO_CENTRAL`, like `-Dmaven.repo.central`, replaces the Maven
//!   Central URL in the Maven 3.10 mode.
//! - `${env.X}` in settings.xml expands from the process environment across
//!   Maven-interpolated string fields: mirrors, servers, proxies, profile
//!   repositories, `<localRepository>`, and active profile ids.
//! - The variables `[security] allow_env_substitution` names, and the JDK,
//!   are captured once in [`Config::host`] for `${env.X}` and profile
//!   activation in POMs.
//! - With the `testing` feature only, `RAEVA_TEST_MAVEN_USER_HOME` replaces
//!   the home directory whose `.m2` holds `settings.xml`.
//!
//! # What it leaves to other crates
//!
//! This crate fetches nothing and does not apply what it reads: mirror
//! selection, repository authentication and proxies are `rv-repo`'s (which
//! also reads a proxy's `token_env` variable), the POM model is
//! `rv-maven-model`'s, and the lockfile model lives in the `rv-lock` crate.
//! Outside the test constructors, it writes nothing.

mod config;
mod credential_scope;
mod encryption;
mod error;
mod file_transport;
mod jvm_options;
pub use jvm_options::{
    argument_file_words, changed_option_file, jvm_words, unread_jvm_option, working_dir_read,
};
mod limited_read;
pub mod maven_config;
mod maven_mode;
mod maven_settings;
mod paths;
mod plugins;
mod pom_mentions;
mod prime;
mod proxy_env;
mod redact;
pub mod repository_filters;
mod settings;
#[cfg(test)]
mod test_warnings;
mod user_home;

pub use config::{
    AuthConfigLayers, Config, LockConfig, MAX_ARTIFACT_SIZE_ENV, NetworkConfig, PropertyInput,
    PropertyInputs, SecurityConfig, is_valid_jdk, jdk_matches_target,
};
pub use credential_scope::CredentialScope;
pub use error::{ConfigError, ConfigOrigin};
pub use limited_read::{
    MAX_PROJECT_INPUT_SIZE, read_optional_project_input, read_optional_project_input_string,
    read_project_input, read_project_input_string,
};
pub use maven_mode::{MavenModeSource, MavenSelection};
pub use maven_settings::{expand_local_repository, unset_env_references};
#[cfg(any(test, feature = "testing"))]
pub use paths::{MAVEN_USER_HOME_TEST_ENV, PASSWD_HOME_TEST_ENV, REAL_HOME_GUARD_TEST_ENV};
pub use paths::{ResolvedPaths, UNKNOWN_USER_HOME, is_unknown_user_home};
pub use plugins::{PluginTrace, PluginsConfig};
pub use prime::prime_secrets;
pub use proxy_env::{EnvironmentProxy, NoProxy, environment_proxies};
pub use redact::{
    Redactor, UNPARSABLE_URL, UNRECORDED_REPOSITORY, UNRECORDED_URL, redact_repository_url,
    redact_secrets, redact_secrets_in_json, redact_url, redacted_url, register_named_secret,
    register_option_secrets, register_secret, register_stored_name, restored_urls,
    secret_input_in_path, secret_named, secret_part_refusal, secret_read, secret_url_part,
    stored_repository, stored_urls, url_holds_secret, url_path_holds, url_refusal,
    without_secret_values,
};
pub use repository_filters::RepositoryFilters;
pub use settings::{
    AuthConfig, ChecksumPolicy, MirrorConfig, ProxyAuthType, ProxyConfig, RepoConfig, UpdatePolicy,
};
