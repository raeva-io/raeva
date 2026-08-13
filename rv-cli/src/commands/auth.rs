use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;

use clap::{Args, Subcommand, ValueEnum};
use rv_config::{
    AuthType, Config, CredentialIndex, CredentialManager, CredentialRecord, MirrorConfig,
    NormalizedEndpoint, RepoConfig, ResolvedPaths,
};

use crate::error::{CliError, Result};
use crate::output::{Table, is_json_mode, json_result};

const MAX_STDIN_SECRET_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LoginAuthType {
    Basic,
    Bearer,
}

impl From<LoginAuthType> for AuthType {
    fn from(value: LoginAuthType) -> Self {
        match value {
            LoginAuthType::Basic => Self::Basic,
            LoginAuthType::Bearer => Self::Bearer,
        }
    }
}

#[derive(Debug, Args)]
#[command(
    about = "Store repository credentials in the OS credential store",
    long_about = "Store credentials for an exact normalized repository endpoint.\n\
An ID must resolve to exactly one configured repository or mirror URL.\n\
Credentials are stored locally and are not remotely verified.",
    after_help = "On success, rv reports \"stored; not remotely verified\"."
)]
pub struct LoginArgs {
    /// Repository URL or an unambiguous configured repository/mirror ID
    #[arg(value_name = "URL_OR_ID")]
    pub target: String,
    /// Authentication scheme
    #[arg(long, value_enum, default_value = "basic")]
    pub auth_type: LoginAuthType,
    /// Username for Basic authentication
    #[arg(long, value_name = "USER")]
    pub username: Option<String>,
    /// Read the password or bearer token from stdin
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
#[command(
    about = "Remove repository credentials from the OS credential store",
    long_about = "Remove credentials for an exact normalized repository endpoint.\n\
An ID must resolve to exactly one configured repository or mirror URL."
)]
pub struct LogoutArgs {
    /// Repository URL or an unambiguous configured repository/mirror ID
    #[arg(value_name = "URL_OR_ID")]
    pub target: String,
}

#[derive(Debug, Args)]
#[command(about = "Inspect stored repository credential metadata")]
pub struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// List stored endpoints without reading or displaying secrets
    List,
}

pub fn run_login(args: &LoginArgs, project_root: &Path) -> Result<()> {
    let target = resolve_target(project_root, &args.target)?;
    let auth_type = AuthType::from(args.auth_type);
    if auth_type == AuthType::Bearer && args.username.is_some() {
        return Err(CliError::Message(
            "--username applies only to basic auth; omit it for bearer auth".to_string(),
        ));
    }

    let username = match auth_type {
        AuthType::Basic => Some(resolve_username(args.username.as_deref())?),
        AuthType::Bearer => None,
    };
    let secret = resolve_secret(args.password_stdin, auth_type)?;
    let record = match auth_type {
        AuthType::Basic => {
            CredentialRecord::basic(username.expect("basic username resolved"), secret)?
        }
        AuthType::Bearer => CredentialRecord::bearer(secret)?,
    };

    let paths = ResolvedPaths::discover()?;
    let manager = CredentialManager::new(paths.credentials_index_path());
    manager.store(&target.endpoint, target.id.clone(), &record)?;

    if is_json_mode() {
        json_result(
            true,
            serde_json::json!({
                "endpoint": target.endpoint,
                "id": target.id,
                "username": record.username,
                "auth_type": record.auth_type,
                "message": "stored; not remotely verified",
            }),
        );
    } else {
        println!(
            "stored; not remotely verified: {}",
            target.endpoint.as_str()
        );
    }
    Ok(())
}

pub fn run_logout(args: &LogoutArgs, project_root: &Path) -> Result<()> {
    let target = resolve_target(project_root, &args.target)?;
    let paths = ResolvedPaths::discover()?;
    let manager = CredentialManager::new(paths.credentials_index_path());
    let removed = manager.delete(&target.endpoint)?;

    if is_json_mode() {
        json_result(
            true,
            serde_json::json!({
                "endpoint": target.endpoint,
                "id": target.id,
                "removed": removed,
            }),
        );
    } else if removed {
        println!("removed credentials for {}", target.endpoint);
    } else {
        println!("no stored credentials for {}", target.endpoint);
    }
    Ok(())
}

pub fn run_auth(args: &AuthArgs) -> Result<()> {
    match args.command {
        AuthCommand::List => run_list(),
    }
}

fn run_list() -> Result<()> {
    let paths = ResolvedPaths::discover()?;
    let index = CredentialIndex::load(&paths.credentials_index_path())?;

    if is_json_mode() {
        json_result(true, serde_json::to_value(index.entries())?);
        return Ok(());
    }

    let mut table = Table::new(["Endpoint", "ID", "Username", "Auth type"]);
    for entry in index.entries() {
        table.add_row([
            entry.endpoint.as_str(),
            entry.id.as_deref().unwrap_or("-"),
            entry.username.as_deref().unwrap_or("-"),
            &entry.auth_type.to_string(),
        ]);
    }
    println!("{}", table.render());
    Ok(())
}

#[derive(Debug)]
struct ResolvedTarget {
    endpoint: NormalizedEndpoint,
    id: Option<String>,
}

fn resolve_target(project_root: &Path, value: &str) -> Result<ResolvedTarget> {
    if value.contains("://") {
        return Ok(ResolvedTarget {
            endpoint: NormalizedEndpoint::parse(value)?,
            id: None,
        });
    }

    let config = Config::load(project_root)?;
    resolve_configured_id(value, config.repositories(), config.mirrors())
}

fn resolve_configured_id(
    id: &str,
    repositories: &[RepoConfig],
    mirrors: &[MirrorConfig],
) -> Result<ResolvedTarget> {
    let mut matches: Vec<&str> = repositories
        .iter()
        .filter(|repo| repo.id.as_deref() == Some(id))
        .map(|repo| repo.url.as_str())
        .chain(
            mirrors
                .iter()
                .filter(|mirror| mirror.id.as_deref() == Some(id))
                .map(|mirror| mirror.url.as_str()),
        )
        .collect();
    matches.sort_unstable();
    matches.dedup();

    match matches.as_slice() {
        [url] => Ok(ResolvedTarget {
            endpoint: NormalizedEndpoint::parse(url)?,
            id: Some(id.to_string()),
        }),
        [] => Err(CliError::Message(format!(
            "repository or mirror id {id:?} is not configured; pass a repository URL"
        ))),
        _ => Err(CliError::Message(format!(
            "repository or mirror id {id:?} resolves to multiple URLs; pass a repository URL"
        ))),
    }
}

fn resolve_username(value: Option<&str>) -> Result<String> {
    if let Some(value) = value {
        if value.is_empty() {
            return Err(CliError::Message(
                "basic auth username must not be empty".to_string(),
            ));
        }
        return Ok(value.to_string());
    }
    if !io::stdin().is_terminal() {
        return Err(CliError::Message(
            "username is required when stdin is not a terminal; pass --username USER".to_string(),
        ));
    }

    eprint!("Username: ");
    io::stderr().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim_end_matches(['\r', '\n']).to_string();
    if username.is_empty() {
        return Err(CliError::Message(
            "basic auth username must not be empty".to_string(),
        ));
    }
    Ok(username)
}

fn resolve_secret(password_stdin: bool, auth_type: AuthType) -> Result<String> {
    if password_stdin {
        return read_secret(io::stdin().lock());
    }
    if !io::stdin().is_terminal() {
        return Err(CliError::Message(
            "password or token is required when stdin is not a terminal; pass --password-stdin"
                .to_string(),
        ));
    }

    let prompt = match auth_type {
        AuthType::Basic => "Password: ",
        AuthType::Bearer => "Token: ",
    };
    rpassword::prompt_password(prompt).map_err(CliError::Io)
}

fn read_secret(reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_STDIN_SECRET_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STDIN_SECRET_SIZE {
        return Err(CliError::Message(format!(
            "password or token from stdin exceeds {MAX_STDIN_SECRET_SIZE}-byte limit"
        )));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        CliError::Message("password or token from stdin is not valid UTF-8".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{read_secret, resolve_configured_id};
    use rv_config::{MirrorConfig, RepoConfig};

    fn repo(id: &str, url: &str) -> RepoConfig {
        RepoConfig {
            id: Some(id.to_string()),
            url: url.to_string(),
            releases: None,
            snapshots: None,
            snapshots_update_policy: None,
        }
    }

    #[test]
    fn configured_id_must_resolve_to_exactly_one_url() {
        let repositories = [
            repo("corp", "https://repo.example/maven2"),
            repo("duplicate", "https://one.example/"),
        ];
        let mirrors = [
            MirrorConfig {
                id: Some("duplicate".to_string()),
                url: "https://two.example/".to_string(),
                mirror_of: vec!["*".to_string()],
            },
            MirrorConfig {
                id: Some("same".to_string()),
                url: "https://same.example/".to_string(),
                mirror_of: vec!["*".to_string()],
            },
        ];

        let target = resolve_configured_id("corp", &repositories, &mirrors).expect("unique");
        assert_eq!(target.endpoint.as_str(), "https://repo.example/maven2/");
        assert_eq!(target.id.as_deref(), Some("corp"));

        let missing = resolve_configured_id("missing", &repositories, &mirrors)
            .expect_err("missing id must fail")
            .to_string();
        assert!(missing.contains("pass a repository URL"));

        let ambiguous = resolve_configured_id(
            "duplicate",
            &repositories,
            &[
                mirrors[0].clone(),
                MirrorConfig {
                    id: Some("duplicate".to_string()),
                    ..mirrors[1].clone()
                },
            ],
        )
        .expect_err("ambiguous id must fail")
        .to_string();
        assert!(ambiguous.contains("multiple URLs"));
    }

    #[test]
    fn password_stdin_removes_only_one_line_ending() {
        assert_eq!(read_secret(&b"secret\n"[..]).expect("LF"), "secret");
        assert_eq!(read_secret(&b"secret\r\n"[..]).expect("CRLF"), "secret");
        assert_eq!(
            read_secret(&b" secret \n\n"[..]).expect("preserve"),
            " secret \n"
        );
    }
}
