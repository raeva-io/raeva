use std::env;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Environment variable that, when set, roots Raeva's config, store, and cache
/// directories instead of the platform-specific defaults.
pub(crate) const RAEVA_HOME_ENV: &str = "RAEVA_HOME";

/// Test hook: when set, `.m2/settings.xml` and `.m2/settings-security.xml`
/// are read below this directory instead of the user's home. Tests set `HOME`
/// for the same purpose, but on Windows the home directory comes from the
/// user profile and ignores `HOME` and `USERPROFILE`. Only builds with the
/// `testing` feature read it, so a release binary ignores it.
#[cfg(any(test, feature = "testing"))]
pub const MAVEN_USER_HOME_TEST_ENV: &str = "RAEVA_TEST_MAVEN_USER_HOME";

pub(crate) fn maven_user_home() -> Option<PathBuf> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(home) = env::var_os(MAVEN_USER_HOME_TEST_ENV).filter(|home| !home.is_empty()) {
        return Some(PathBuf::from(home));
    }
    dirs::home_dir()
}

/// The directories raeva keeps its own state in.
///
/// [`ResolvedPaths::discover`] roots them at `RAEVA_HOME` when it is set and
/// at the platform's config, local data and cache directories otherwise.
/// Discovery does not create them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResolvedPaths {
    /// Holds `config.toml`.
    pub config_dir: PathBuf,
    /// The content-addressed artifact store.
    pub store_dir: PathBuf,
    /// State raeva can recreate, such as the per-project `raeva sync` guard files.
    pub cache_dir: PathBuf,
    #[cfg(any(test, feature = "testing"))]
    #[serde(skip)]
    test_home: Option<TestHome>,
}

/// Keeps the directory made by [`ResolvedPaths::for_testing`] alive while any
/// clone of the paths exists, and removes it with the last one.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone)]
struct TestHome(std::sync::Arc<tempfile::TempDir>);

#[cfg(any(test, feature = "testing"))]
impl PartialEq for TestHome {
    fn eq(&self, other: &Self) -> bool {
        self.0.path() == other.0.path()
    }
}

#[cfg(any(test, feature = "testing"))]
impl Eq for TestHome {}

impl ResolvedPaths {
    /// Discovers standard paths for configuration, store, and cache directories.
    ///
    /// If `RAEVA_HOME` is set, all paths are rooted there.
    /// Otherwise, uses platform-specific directories (e.g., `~/.config`, `~/.local/share`).
    ///
    /// # Errors
    ///
    /// Returns an error if platform-specific directories cannot be determined
    /// and `RAEVA_HOME` is not set.
    pub fn discover() -> Result<Self, ConfigError> {
        if let Some(base) = raeva_home_override(env::var_os(RAEVA_HOME_ENV))? {
            return Ok(Self::from_raeva_home(base));
        }

        let config_base = platform::config_dir().ok_or(ConfigError::ConfigDirUnavailable)?;
        // The local, not roaming, app data directory on Windows: a roaming
        // profile would copy the whole artifact store on every sign-in.
        let data_base = platform::data_local_dir().ok_or(ConfigError::DataDirUnavailable)?;
        let cache_base = platform::cache_dir().ok_or(ConfigError::CacheDirUnavailable)?;

        let config_dir = config_base.join("raeva");
        let store_dir = data_base.join("raeva").join("store");
        let cache_dir = cache_base.join("raeva");

        Ok(Self {
            config_dir,
            store_dir,
            cache_dir,
            #[cfg(any(test, feature = "testing"))]
            test_home: None,
        })
    }

    /// Paths under a fresh directory in the system temp dir. Tests use this so
    /// they never share the user's metadata cache: test servers reuse
    /// loopback ports, and a cached POM keyed by an earlier server's URL would
    /// be served in place of a request. The directory is removed when the last
    /// clone of the returned paths is dropped.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing() -> Result<Self, ConfigError> {
        let home = tempfile::Builder::new()
            .prefix("raeva-test-")
            .tempdir()
            .map_err(|_| ConfigError::DataDirUnavailable)?;
        let mut paths = Self::from_raeva_home(home.path());
        paths.test_home = Some(TestHome(std::sync::Arc::new(home)));
        Ok(paths)
    }

    /// The layout `RAEVA_HOME` gives: `base` itself as the config directory,
    /// with `store` and `cache` below it. `base` is used as given, not
    /// checked for being absolute.
    pub fn from_raeva_home(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        let store_dir = base.join("store");
        let cache_dir = base.join("cache");
        Self {
            config_dir: base,
            store_dir,
            cache_dir,
            #[cfg(any(test, feature = "testing"))]
            test_home: None,
        }
    }

    /// The user `config.toml`, in [`Self::config_dir`].
    pub fn config_file_path(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// `metadata.db`, next to [`Self::store_dir`] rather than inside it.
    pub fn metadata_db_path(&self) -> PathBuf {
        self.store_dir.with_file_name("metadata.db")
    }
}

#[cfg(not(windows))]
mod platform {
    pub(super) use dirs::{cache_dir, config_dir, data_local_dir};
}

/// The platform directories raeva's own directories live in.
///
/// Windows expands these known folders from the process environment, from
/// `%USERPROFILE%\AppData\...` unless redirected, and by default fails when
/// the folder does not exist. `dirs` asks with those defaults, so a
/// `USERPROFILE` pointed at a new directory, as test isolation does, made
/// every raeva command fail. raeva creates its directories itself, so it asks
/// without the existence check and rejects only a relative result.
#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_RoamingAppData, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
    };
    use windows_sys::core::{GUID, PWSTR};

    pub(super) fn config_dir() -> Option<PathBuf> {
        known_folder(&FOLDERID_RoamingAppData)
    }

    pub(super) fn data_local_dir() -> Option<PathBuf> {
        known_folder(&FOLDERID_LocalAppData)
    }

    pub(super) fn cache_dir() -> Option<PathBuf> {
        known_folder(&FOLDERID_LocalAppData)
    }

    #[allow(unsafe_code)]
    fn known_folder(id: &GUID) -> Option<PathBuf> {
        let mut path: PWSTR = std::ptr::null_mut();
        // SAFETY: `id` and `path` are valid for the call. On success `path`
        // is a NUL-terminated wide string the shell allocated, read before
        // it is freed below; on failure it is null or must still be freed.
        let folder = unsafe {
            let result = SHGetKnownFolderPath(
                id,
                KF_FLAG_DONT_VERIFY as u32,
                std::ptr::null_mut(),
                &mut path,
            );
            let folder = (result == 0 && !path.is_null()).then(|| {
                let len = (0..).take_while(|&index| *path.add(index) != 0).count();
                PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, len)))
            });
            CoTaskMemFree(path.cast());
            folder
        };
        folder.filter(|folder| folder.is_absolute())
    }
}

/// Which of raeva's platform directories could not be found.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PlatformDir {
    Config,
    Data,
    Cache,
}

/// Why the platform has no directory of `kind`, and what to set, for `os`
/// as `std::env::consts::OS` names it.
pub(crate) fn platform_dir_unavailable(kind: PlatformDir, os: &str) -> String {
    let name = match kind {
        PlatformDir::Config => "config",
        PlatformDir::Data => "data",
        PlatformDir::Cache => "cache",
    };
    let cause = match (os, kind) {
        ("windows", PlatformDir::Config) => {
            "Windows returned no absolute roaming application data folder, which is \
             %USERPROFILE%\\AppData\\Roaming unless redirected; if USERPROFILE is set, it \
             must be an absolute path"
                .to_string()
        }
        ("windows", _) => "Windows returned no absolute local application data folder, which \
             is %USERPROFILE%\\AppData\\Local unless redirected; if USERPROFILE is set, it \
             must be an absolute path"
            .to_string(),
        ("macos", _) => {
            "HOME is not set and the user's home directory could not be looked up".to_string()
        }
        (_, kind) => {
            let xdg = match kind {
                PlatformDir::Config => "XDG_CONFIG_HOME",
                PlatformDir::Data => "XDG_DATA_HOME",
                PlatformDir::Cache => "XDG_CACHE_HOME",
            };
            format!(
                "{xdg} is not an absolute path, HOME is not set, and the user's home \
                 directory could not be looked up"
            )
        }
    };
    format!(
        "{name} directory is unavailable: {cause}. Set {RAEVA_HOME_ENV} to an absolute \
         directory to keep all of raeva's directories there instead"
    )
}

/// Interpret the raw `RAEVA_HOME` value.
///
/// A set-but-empty (or whitespace-only) value is treated as unset with a
/// warning. A relative value is rejected outright: silently
/// resolving it against the current working directory would scatter the
/// store and cache across whichever directory raeva happens to run from.
fn raeva_home_override(value: Option<std::ffi::OsString>) -> Result<Option<PathBuf>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.to_string_lossy().trim().is_empty() {
        tracing::warn!(
            sec_code = "SETTING_IGNORED",
            env = RAEVA_HOME_ENV,
            "ignoring empty RAEVA_HOME; using platform default directories"
        );
        return Ok(None);
    }
    let path = PathBuf::from(value);
    if path.is_relative() {
        return Err(ConfigError::RaevaHomeNotAbsolute(path));
    }
    // A missing directory is created on first use.
    if std::fs::metadata(&path).is_ok_and(|meta| !meta.is_dir()) {
        return Err(ConfigError::RaevaHomeNotADirectory(path));
    }
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::{PlatformDir, ResolvedPaths, platform_dir_unavailable, raeva_home_override};
    use std::env;
    use std::ffi::OsString;

    #[test]
    fn raeva_home_roots_every_directory() {
        assert_eq!(raeva_home_override(None).unwrap(), None);
        for blank in ["", "   "] {
            assert_eq!(
                raeva_home_override(Some(OsString::from(blank))).unwrap(),
                None
            );
        }
        let message = raeva_home_override(Some(OsString::from("relative/raeva")))
            .unwrap_err()
            .to_string();
        assert!(message.contains("absolute") && message.contains("relative/raeva"));
        let file = tempfile::NamedTempFile::new().unwrap();
        let message = raeva_home_override(Some(file.path().as_os_str().to_owned()))
            .unwrap_err()
            .to_string();
        assert!(message.contains("not a directory"), "{message}");
        let base = env::temp_dir().join("raeva-abs");
        let resolved = raeva_home_override(Some(base.clone().into_os_string())).unwrap();
        assert_eq!(resolved.as_ref(), Some(&base));

        let paths = ResolvedPaths::from_raeva_home(&base);
        assert_eq!(paths.config_dir, base);
        assert_eq!(paths.store_dir, base.join("store"));
        assert_eq!(paths.cache_dir, base.join("cache"));
        assert_eq!(paths.config_file_path(), base.join("config.toml"));
        assert_eq!(paths.metadata_db_path(), base.join("metadata.db"));

        temp_env::with_var_unset(super::RAEVA_HOME_ENV, || {
            let paths = ResolvedPaths::discover().expect("discover default paths");
            let local = dirs::data_local_dir().expect("local data dir");
            assert!(paths.store_dir.starts_with(&local));
        });
    }

    #[test]
    fn unavailable_platform_dirs_name_what_each_platform_reads() {
        for (kind, os, needles, absent) in [
            (
                PlatformDir::Config,
                "linux",
                &["config directory", "XDG_CONFIG_HOME"][..],
                "USERPROFILE",
            ),
            (PlatformDir::Config, "macos", &["HOME is not set"], "XDG"),
            (
                PlatformDir::Cache,
                "windows",
                &["cache directory", r"AppData\Local"],
                "HOME is",
            ),
        ] {
            let message = platform_dir_unavailable(kind, os);
            assert!(
                needles.iter().all(|needle| message.contains(needle)),
                "{message}"
            );
            assert!(!message.contains(absent), "{message}");
            assert!(message.contains("Set RAEVA_HOME to an absolute directory"));
        }
    }

    /// A USERPROFILE without the AppData folders, as a test run that isolates
    /// itself sets up, still yields directories below it. Windows resolves
    /// known folders once per process, so a child process asks.
    #[cfg(windows)]
    #[test]
    fn windows_known_folders_need_not_exist() {
        let profile = tempfile::tempdir().expect("profile");
        let roaming = profile.path().join("AppData").join("Roaming").join("raeva");
        for (value, expected) in [
            (
                profile.path().as_os_str(),
                format!("config_dir={}", roaming.display()),
            ),
            (
                std::ffi::OsStr::new("relative-profile"),
                "error=config directory is unavailable".to_string(),
            ),
        ] {
            let output = std::process::Command::new(env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "paths::tests::print_discovered_paths",
                    "--ignored",
                ])
                .arg("--nocapture")
                .env("USERPROFILE", value)
                .env_remove(super::RAEVA_HOME_ENV)
                .output()
                .expect("run child");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains(&expected), "{stdout}");
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "run by windows_known_folders_need_not_exist"]
    fn print_discovered_paths() {
        match ResolvedPaths::discover() {
            Ok(paths) => println!("config_dir={}", paths.config_dir.display()),
            Err(err) => println!("error={err}"),
        }
    }
}
