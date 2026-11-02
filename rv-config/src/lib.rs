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
mod encryption;
mod error;
mod limited_read;
pub mod maven_config;
mod maven_settings;
mod paths;
mod proxy_env;
mod redact;
mod settings;
#[cfg(test)]
mod test_warnings;

pub use config::{
    AuthConfigLayers, Config, LockConfig, MAX_ARTIFACT_SIZE_ENV, NetworkConfig, SecurityConfig,
    is_valid_jdk, jdk_matches_target,
};
pub use error::{ConfigError, ConfigOrigin};
pub use limited_read::{
    MAX_PROJECT_INPUT_SIZE, read_optional_project_input, read_optional_project_input_string,
    read_project_input, read_project_input_string,
};
pub use maven_settings::{expand_local_repository, unset_env_references};
#[cfg(any(test, feature = "testing"))]
pub use paths::MAVEN_USER_HOME_TEST_ENV;
pub use paths::ResolvedPaths;
pub use proxy_env::{EnvironmentProxy, NoProxy, environment_proxies};
pub use redact::{
    UNPARSABLE_URL, redact_url, redacted_url, secret_input_in_path, secret_named, secret_url_part,
    url_path_holds, without_secret_values,
};
pub use settings::{
    AuthConfig, ChecksumPolicy, MirrorConfig, ProxyAuthType, ProxyConfig, RepoConfig, UpdatePolicy,
};
