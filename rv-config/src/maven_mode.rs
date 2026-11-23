//! Which Maven line raeva resolves as: `[lock] maven` in raeva.toml, else the
//! version `.mvn/wrapper/maven-wrapper.properties` downloads, else 3.9.

use std::path::{Path, PathBuf};

use rv_maven_types::{MavenMode, quoted};

use crate::{ConfigError, ConfigOrigin};

/// The Maven mode a project selects, and what selected it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MavenSelection {
    /// The selected mode.
    pub mode: MavenMode,
    /// What selected it.
    pub source: MavenModeSource,
}

/// What selected a [`MavenSelection`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MavenModeSource {
    /// Neither the configuration nor a Maven wrapper names a version.
    #[default]
    Default,
    /// `[lock] maven` in this raeva.toml.
    Config(PathBuf),
    /// The `distributionUrl` of this `maven-wrapper.properties`, which
    /// downloads this version (for mvnd, the mvnd version).
    Wrapper {
        /// The properties file.
        path: PathBuf,
        /// The version its distribution file names.
        version: String,
    },
}

impl std::fmt::Display for MavenModeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => f.write_str("the default"),
            Self::Config(path) => write!(f, "[lock] maven in {}", path.display()),
            Self::Wrapper { path, version } => {
                write!(f, "{} (Maven {})", path.display(), quoted(version))
            }
        }
    }
}

/// The selection with the `[lock] maven` value of `config` (the raeva.toml
/// at `config_path`), which wins over the wrapper in `mvn_dir`, the `.mvn`
/// directory of the launcher's project directory.
/// `strict` reports an unreadable or unsupported wrapper; otherwise, for a
/// command that only reads raeva.lock, such a wrapper selects nothing.
pub(crate) fn select(
    mvn_dir: &Path,
    config: Option<&str>,
    config_path: &Path,
    strict: bool,
) -> Result<MavenSelection, ConfigError> {
    if let Some(text) = config {
        let mode = MavenMode::parse(text).ok_or_else(|| ConfigError::Invalid {
            origin: ConfigOrigin::ProjectConfig(config_path.to_path_buf()),
            message: format!(
                "lock.maven is {}; it must be \"3.9\" or \"3.10\"",
                quoted(text)
            ),
        })?;
        return Ok(MavenSelection {
            mode,
            source: MavenModeSource::Config(config_path.to_path_buf()),
        });
    }
    let path = mvn_dir.join("wrapper").join("maven-wrapper.properties");
    match wrapper_selection(&path) {
        Ok(selection) => Ok(selection.unwrap_or_default()),
        Err(error) if strict => Err(error),
        Err(_) => Ok(MavenSelection::default()),
    }
}

fn wrapper_selection(path: &Path) -> Result<Option<MavenSelection>, ConfigError> {
    let Some(bytes) = crate::read_optional_project_input(path)? else {
        return Ok(None);
    };
    // java.util.Properties reads ISO-8859-1, where every byte is a
    // character.
    let text: String = bytes.iter().map(|&byte| char::from(byte)).collect();
    let Some(url) = property(&text, "distributionUrl") else {
        return Ok(None);
    };
    let invalid = |message: String| ConfigError::Invalid {
        origin: ConfigOrigin::MavenWrapper(path.to_path_buf()),
        message: format!(
            "{message}; set maven = \"3.9\" or maven = \"3.10\" under [lock] in raeva.toml to \
             choose how raeva resolves"
        ),
    };
    let file = distribution_file(&url);
    let Some((mode, version)) = distribution_mode(file) else {
        return Err(invalid(format!(
            "distributionUrl names {}, which is no Maven 3 distribution raeva knows",
            quoted(file)
        )));
    };
    let Some(mode) = mode else {
        return Err(invalid(format!(
            "distributionUrl names {}, a Maven raeva does not resolve as",
            quoted(file)
        )));
    };
    Ok(Some(MavenSelection {
        mode,
        source: MavenModeSource::Wrapper {
            path: path.to_path_buf(),
            version: version.to_string(),
        },
    }))
}

/// The last path segment of `url`, without a query or fragment.
fn distribution_file(url: &str) -> &str {
    let url = url.trim();
    let url = url.split(['?', '#']).next().unwrap_or(url);
    // No `user:password@` part, even where no path follows it.
    url.rsplit(['/', '\\', '@']).next().unwrap_or(url)
}

/// The version an `apache-maven-<version>-bin.zip` (or `.tar.gz`) or
/// `maven-mvnd-<version>-<platform>.zip` file name carries, and its mode:
/// `None` for a Maven line raeva does not resolve as. `None` overall for a
/// file of no known distribution.
fn distribution_mode(file: &str) -> Option<(Option<MavenMode>, &str)> {
    if let Some(rest) = file.strip_prefix("apache-maven-") {
        let version = [".zip", ".tar.gz"]
            .iter()
            .find_map(|suffix| rest.strip_suffix(suffix))?
            .strip_suffix("-bin")?;
        let (major, rest) = version.split_once('.')?;
        let major: u32 = major.parse().ok()?;
        let minor: u32 = rest.split(['.', '-']).next()?.parse().ok()?;
        let mode = match (major, minor) {
            (3, 0..=9) => Some(MavenMode::Maven39),
            (3, 10) => Some(MavenMode::Maven310),
            _ => None,
        };
        return Some((mode, version));
    }
    // mvnd 1 embeds Maven 3.9, and mvnd 2 Maven 4.
    let rest = [".zip", ".tar.gz"]
        .iter()
        .find_map(|suffix| file.strip_prefix("maven-mvnd-")?.strip_suffix(suffix))?;
    // The platform follows the version.
    let (version, _platform) = rest.split_once('-')?;
    let major = version.split('.').next()?;
    let mode = match major.parse::<u32>().ok()? {
        1 => Some(MavenMode::Maven39),
        _ => None,
    };
    Some((mode, version))
}

/// The value of `key` in a `java.util.Properties` text: the last line that
/// sets it, after continuations and escapes.
fn property(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    // `\r\n`, `\n` and `\r` each end a line.
    let text = text.replace("\r\n", "\n");
    let mut lines = text.split(['\n', '\r']);
    while let Some(line) = lines.next() {
        let mut logical = line.trim_start_matches([' ', '\t', '\x0c']).to_string();
        if logical.starts_with(['#', '!']) || logical.is_empty() {
            continue;
        }
        // An odd run of trailing backslashes continues the line.
        while logical.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1 {
            logical.pop();
            match lines.next() {
                Some(next) => logical.push_str(next.trim_start_matches([' ', '\t', '\x0c'])),
                None => break,
            }
        }
        let (name, value) = split_entry(&logical);
        if name == key {
            found = Some(value);
        }
    }
    found
}

/// The unescaped key and value of a logical properties line.
fn split_entry(line: &str) -> (String, String) {
    let mut chars = line.chars().peekable();
    let mut key = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    key.push(unescape(next, &mut chars));
                }
            }
            '=' | ':' => break,
            ' ' | '\t' | '\x0c' => {
                while chars
                    .peek()
                    .is_some_and(|c| matches!(c, ' ' | '\t' | '\x0c'))
                {
                    chars.next();
                }
                if chars.peek().is_some_and(|c| matches!(c, '=' | ':')) {
                    chars.next();
                }
                break;
            }
            ch => key.push(ch),
        }
    }
    while chars
        .peek()
        .is_some_and(|c| matches!(c, ' ' | '\t' | '\x0c'))
    {
        chars.next();
    }
    let mut value = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    value.push(unescape(next, &mut chars));
                }
            }
            ch => value.push(ch),
        }
    }
    (key, value)
}

fn unescape(ch: char, rest: &mut std::iter::Peekable<std::str::Chars<'_>>) -> char {
    match ch {
        't' => '\t',
        'n' => '\n',
        'r' => '\r',
        'f' => '\x0c',
        'u' => {
            let hex: String = (0..4).filter_map(|_| rest.next()).collect();
            u32::from_str_radix(&hex, 16)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or('\u{fffd}')
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_with(wrapper: Option<&str>, config: Option<&str>) -> Result<MavenSelection, String> {
        let dir = tempfile::tempdir().unwrap();
        if let Some(text) = wrapper {
            let path = dir.path().join(".mvn/wrapper");
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("maven-wrapper.properties"), text).unwrap();
        }
        select(
            &dir.path().join(".mvn"),
            config,
            &dir.path().join("raeva.toml"),
            true,
        )
        .map_err(|error| error.to_string())
    }

    fn mode(wrapper: &str) -> Result<MavenMode, String> {
        select_with(Some(wrapper), None).map(|selection| selection.mode)
    }

    const CENTRAL: &str = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven";

    #[test]
    fn the_wrapper_distribution_selects_the_mode() {
        for (url, expected) in [
            (
                format!("{CENTRAL}/3.9.9/apache-maven-3.9.9-bin.zip"),
                MavenMode::Maven39,
            ),
            (
                format!("{CENTRAL}/3.8.4/apache-maven-3.8.4-bin.tar.gz"),
                MavenMode::Maven39,
            ),
            (
                format!("{CENTRAL}/3.10.0/apache-maven-3.10.0-bin.zip"),
                MavenMode::Maven310,
            ),
            (
                format!("{CENTRAL}/3.10.0-rc-1/apache-maven-3.10.0-rc-1-bin.zip?token=x#y"),
                MavenMode::Maven310,
            ),
            (
                "https://downloads.apache.org/maven/mvnd/1.0.6/maven-mvnd-1.0.6-linux-amd64.zip"
                    .to_string(),
                MavenMode::Maven39,
            ),
        ] {
            assert_eq!(
                mode(&format!("distributionUrl={url}\n")),
                Ok(expected),
                "{url}"
            );
        }
        // Escapes, separators, continuations and the last of repeated keys.
        let escaped = "# comment\n! also\nwrapperVersion=3.3.2\ndistributionUrl = \
                       https\\://repo/apache-maven-3.9.12-bin.zip\n  distributionUrl : https\\://repo/\\\n    \
                       apache-maven-3.10.0-bin.zip  \r\n";
        let selection = select_with(Some(escaped), None).unwrap();
        assert_eq!(selection.mode, MavenMode::Maven310);
        assert!(
            matches!(&selection.source, MavenModeSource::Wrapper { version, .. } if version == "3.10.0"),
            "{selection:?}"
        );
        // A continuation before `\r\n` goes on on the next line.
        let crlf = "distributionUrl=https://repo/\\\r\n  apache-maven-3.10.0-bin.zip\r\n";
        assert_eq!(mode(crlf), Ok(MavenMode::Maven310));
    }

    #[test]
    fn no_wrapper_or_url_is_maven_39_and_config_wins() {
        assert_eq!(select_with(None, None), Ok(MavenSelection::default()));
        assert_eq!(
            mode("wrapperUrl=https://repo/maven-wrapper.jar\n"),
            Ok(MavenMode::Maven39)
        );
        let wrapper = format!("distributionUrl={CENTRAL}/4.0.0/apache-maven-4.0.0-bin.zip\n");
        let selection = select_with(Some(&wrapper), Some("3.10")).unwrap();
        assert_eq!(selection.mode, MavenMode::Maven310);
        assert!(matches!(selection.source, MavenModeSource::Config(_)));
        let error = select_with(None, Some("3.10.0")).unwrap_err();
        assert!(
            error.contains("lock.maven is \"3.10.0\"; it must be \"3.9\" or \"3.10\""),
            "{error}"
        );
    }

    #[test]
    fn an_unsupported_wrapper_fails_naming_the_override() {
        for (url, named) in [
            (
                format!("{CENTRAL}/4.0.0/apache-maven-4.0.0-bin.zip"),
                "apache-maven-4.0.0-bin.zip",
            ),
            (
                format!("{CENTRAL}/3.11.0/apache-maven-3.11.0-bin.zip"),
                "apache-maven-3.11.0-bin.zip",
            ),
            (
                "https://u:secret@host/maven-mvnd-2.0.0-linux-amd64.zip".to_string(),
                "maven-mvnd-2.0.0-linux-amd64.zip",
            ),
            ("https://u:secret@host/maven.zip".to_string(), "maven.zip"),
            ("https://u:secret@host".to_string(), "host"),
            (
                "https://u:secret@host?f=apache-maven-3.9.9-bin.zip".to_string(),
                "host",
            ),
            (
                "https://h/maven-mvnd-1.0.6.jar".to_string(),
                "maven-mvnd-1.0.6.jar",
            ),
            (
                "https://h/maven-mvnd-1.0.6.zip".to_string(),
                "maven-mvnd-1.0.6.zip",
            ),
            (
                "https://h/apache-maven-3-10-bin.zip".to_string(),
                "apache-maven-3-10-bin.zip",
            ),
            ("".to_string(), ""),
        ] {
            let error = mode(&format!("distributionUrl={url}\n")).unwrap_err();
            assert!(error.contains(&format!("\"{named}\"")), "{error}");
            assert!(
                error.contains("set maven = \"3.9\" or maven = \"3.10\" under [lock]"),
                "{error}"
            );
            assert!(!error.contains("secret"), "{error}");
        }
        // A command that only reads the lock is not blocked by the wrapper.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".mvn/wrapper")).unwrap();
        std::fs::write(
            dir.path().join(".mvn/wrapper/maven-wrapper.properties"),
            format!("distributionUrl={CENTRAL}/4.0.0/apache-maven-4.0.0-bin.zip\n"),
        )
        .unwrap();
        let lenient = select(
            &dir.path().join(".mvn"),
            None,
            &dir.path().join("raeva.toml"),
            false,
        );
        assert_eq!(lenient.unwrap(), MavenSelection::default());
    }
}
