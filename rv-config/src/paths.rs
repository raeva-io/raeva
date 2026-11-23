use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Environment variable that, when set, roots Raeva's config, store, and cache
/// directories instead of the platform-specific defaults.
pub(crate) const RAEVA_HOME_ENV: &str = "RAEVA_HOME";

/// Test hook: when set, it stands in for the home the JVM reads
/// ([`jvm_user_home`]) in a test that runs raeva in its own process. Only
/// builds with the `testing` feature read it, so a release binary ignores it.
#[cfg(any(test, feature = "testing"))]
pub const MAVEN_USER_HOME_TEST_ENV: &str = "RAEVA_TEST_MAVEN_USER_HOME";

/// Test hook: when set, it stands in for the passwd entry's home in
/// [`jvm_user_home`]; empty stands for no entry. Only builds with the
/// `testing` feature read it.
#[cfg(any(test, feature = "testing"))]
pub const PASSWD_HOME_TEST_ENV: &str = "RAEVA_TEST_PASSWD_HOME";

/// The `user.home` the JVM sets when it finds no home: Maven then takes
/// `~/.m2` as `?/.m2` under the directory it runs in.
pub const UNKNOWN_USER_HOME: &str = "?";

/// Whether `home`, as `maven_user_home` gives it, is the JVM's
/// [`UNKNOWN_USER_HOME`], no home at all.
pub fn is_unknown_user_home(home: &Path) -> bool {
    home.file_name() == Some(std::ffi::OsStr::new(UNKNOWN_USER_HOME))
}

/// Test guard: when set, a run whose Maven user home is the passwd entry's
/// fails, so a test cannot read the real `~/.m2`. Only builds with the
/// `testing` feature read it.
#[cfg(any(test, feature = "testing"))]
pub const REAL_HOME_GUARD_TEST_ENV: &str = "RAEVA_TEST_FORBID_REAL_HOME";

/// The JDK Maven's launcher runs, as far as raeva knows it: its feature
/// release, and whether its JVM is OpenJ9 rather than HotSpot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LauncherJdk {
    pub(crate) feature: Option<u32>,
    pub(crate) openj9: bool,
}

impl LauncherJdk {
    /// The JDK whose `release` file names `version`, such as `21.0.4` or
    /// `1.8.0_442`.
    pub(crate) fn of(version: Option<&str>, openj9: bool) -> Self {
        let feature = version.and_then(|version| {
            let version = version.trim();
            let version = version.strip_prefix("1.").unwrap_or(version);
            let digits: String = version.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        });
        Self { feature, openj9 }
    }

    /// Whether this is a HotSpot JDK of at least `feature`.
    pub(crate) fn hotspot_from(self, feature: u32) -> bool {
        !self.openj9 && self.feature.is_some_and(|known| known >= feature)
    }

    /// Whether this is a HotSpot JDK known to be older than `feature`.
    pub(crate) fn hotspot_before(self, feature: u32) -> bool {
        !self.openj9 && self.feature.is_some_and(|known| known < feature)
    }
}

/// Maven's user home, the JVM's `user.home`: `define`, the last
/// `-Duser.home` Maven's JVM takes, else [`jvm_user_home`] for `jdk`. It
/// decides the default settings.xml, `${user.home}` in it and the local
/// repository.
///
/// # Errors
///
/// [`ConfigError::UnreadHostProperty`] when the JVM's own value depends on
/// a JDK raeva does not know; see [`jvm_user_home`].
pub(crate) fn maven_user_home(
    define: Option<&str>,
    jdk: LauncherJdk,
) -> Result<Option<PathBuf>, ConfigError> {
    if define.is_some_and(|define| !define.is_empty() && Path::new(define).is_relative()) {
        crate::jvm_options::record_working_dir_read("-Duser.home");
    }
    let home = match define {
        Some(define) => Some(std::ffi::OsString::from(define)),
        None => jvm_user_home(jdk)
            .map_err(ConfigError::UnreadHostProperty)?
            .map(PathBuf::into_os_string),
    };
    let home = home.map(|home| match home.to_str() {
        // `java.io.File` takes a relative one from the working directory.
        // `new File("", ".m2")` resolves against the root of the current
        // drive, as an empty `user.home` puts `~/.m2` there.
        Some("") => std::path::absolute(std::path::MAIN_SEPARATOR_STR)
            .unwrap_or_else(|_| PathBuf::from(std::path::MAIN_SEPARATOR_STR)),
        _ => std::path::absolute(&home).unwrap_or_else(|_| PathBuf::from(home)),
    });
    #[cfg(any(test, feature = "testing"))]
    if env::var_os(REAL_HOME_GUARD_TEST_ENV).is_some() && home.is_some() && home == passwd_home() {
        panic!("this test run reads the real Maven user home {home:?}; pass -Duser.home");
    }
    Ok(home)
}

/// The `user.home` the JVM that runs `jdk` sets. On Unix it is the passwd
/// entry's home. When there is no entry or its home is shorter than two
/// bytes, such as `/`, HotSpot JDK 18 and later take `HOME` when it is set
/// and not empty, else [`UNKNOWN_USER_HOME`]; JDK 17 and earlier keep the
/// short home and give [`UNKNOWN_USER_HOME`] for no entry, without reading
/// `HOME` (OpenJDK's `java_props_md.c`). On Windows it is the profile
/// folder, which reads neither `HOME` nor `USERPROFILE`.
///
/// # Errors
///
/// Why raeva cannot tell the value, when the JDKs differ on it and `jdk`
/// is not one raeva knows.
pub(crate) fn jvm_user_home(jdk: LauncherJdk) -> Result<Option<PathBuf>, String> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(home) = env::var_os(MAVEN_USER_HOME_TEST_ENV).filter(|home| !home.is_empty()) {
        return Ok(Some(PathBuf::from(home)));
    }
    let home = platform_home()?;
    if cfg!(windows) {
        return Ok(home);
    }
    unix_user_home(home, env::var_os("HOME"), jdk).map(Some)
}

/// Whether [`jvm_user_home`] takes `HOME` for `jdk`.
pub(crate) fn jvm_reads_home(jdk: LauncherJdk) -> bool {
    #[cfg(any(test, feature = "testing"))]
    if env::var_os(MAVEN_USER_HOME_TEST_ENV).is_some_and(|home| !home.is_empty()) {
        return false;
    }
    !cfg!(windows)
        && platform_home().is_ok_and(|home| home.is_none_or(|home| home.as_os_str().len() < 2))
        && jdk.hotspot_from(18)
}

/// Foundation's environment variable that replaces the home
/// `NSHomeDirectory()` gives on macOS.
pub(crate) const CF_FIXED_USER_HOME: &str = "CFFIXED_USER_HOME";

/// The home the JVM starts from before its `HOME` fallback: the passwd
/// entry's, or on macOS `NSHomeDirectory()` (`java_props_macosx.c`).
fn platform_home() -> Result<Option<PathBuf>, String> {
    let passwd = passwd_entry_home();
    if cfg!(target_os = "macos") {
        return ns_home_directory(passwd, env::var_os(CF_FIXED_USER_HOME)).map(Some);
    }
    Ok(passwd)
}

/// `NSHomeDirectory()` as measured on macOS 27: a non-empty
/// `CFFIXED_USER_HOME` over the passwd home, with `.`, `..`, repeated and
/// trailing slashes removed, and `HOME` not read. With a `..`, Foundation
/// resolves links, some of them, so raeva refuses one with a `..` on a
/// path through a link; without, it resolves none. A relative one resolves
/// against the working directory with its links resolved, which raeva does
/// not know for `mvn`, so it refuses; so does a user without a passwd
/// home, whom raeva has not measured.
fn ns_home_directory(
    passwd: Option<PathBuf>,
    fixed: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    use std::path::Component;
    match fixed.filter(|fixed| !fixed.is_empty()).map(PathBuf::from) {
        Some(fixed)
            if fixed.components().any(|part| part == Component::ParentDir)
                && (fixed.ancestors())
                    .any(|dir| dir.symlink_metadata().is_ok_and(|meta| meta.is_symlink())) =>
        {
            Err(format!(
                "{CF_FIXED_USER_HOME} is '{}', whose .. macOS resolves through a symbolic link \
                 there, which raeva does not; write the directory out, or pass \
                 -Duser.home=<dir> on the command line of both raeva and mvn",
                fixed.display()
            ))
        }
        Some(fixed) if fixed.is_absolute() => {
            let mut home = PathBuf::new();
            for component in fixed.components() {
                match component {
                    Component::ParentDir => {
                        home.pop();
                    }
                    Component::CurDir => {}
                    component => home.push(component),
                }
            }
            Ok(home)
        }
        Some(fixed) => Err(format!(
            "{CF_FIXED_USER_HOME} is the relative '{}', which macOS resolves against the \
             directory mvn runs in, so raeva cannot tell the JVM's user.home; make it absolute, \
             or pass -Duser.home=<dir> on the command line of both raeva and mvn",
            fixed.display()
        )),
        None => passwd
            .filter(|home| !home.as_os_str().is_empty())
            .ok_or_else(|| {
                "this user has no passwd home, and raeva does not model the user.home macOS \
             gives then; pass -Duser.home=<dir> on the command line of both raeva and mvn"
                    .to_string()
            }),
    }
}

/// Refuses a non-ASCII path among `paths`, Maven's user home and its
/// settings.xml, unless the JVM `mvn` starts decodes it as UTF-8, as it
/// does under a UTF-8 locale: under another, such as the C locale of most
/// containers, Maven reads `h??` for `hé`. The JVM's native encoding is
/// the code set of `setlocale(LC_ALL, "")`, the C locale's when that
/// fails, and on macOS UTF-8 when it is US-ASCII and no `LC_ALL`,
/// `LC_CTYPE` or `LANG` is set (OpenJDK's `java_props_md.c`); `mvn.cmd`'s
/// JVM reads Windows' wide strings.
///
/// # Errors
///
/// [`ConfigError::UnreadHostProperty`], naming the path.
pub(crate) fn refuse_unread_encoding<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    shell: &crate::user_home::Shell,
) -> Result<(), ConfigError> {
    let Some(path) = (paths.into_iter())
        .find(|path| !cfg!(windows) && !path.as_os_str().as_encoded_bytes().is_ascii())
    else {
        return Ok(());
    };
    for name in LOCALE_VARIABLES {
        if let Some(file) = shell.changing(name) {
            return Err(crate::user_home::mavenrc_changes(&file, name));
        }
    }
    match jvm_native_encoding() {
        Some(encoding) if encoding == "UTF-8" => Ok(()),
        encoding => Err(ConfigError::UnreadHostProperty(format!(
            "'{}' is not ASCII, and the JVM mvn starts decodes such a path in its native \
             encoding, {}, so Maven reads another; set LC_ALL or LANG to a UTF-8 locale that \
             is installed, such as C.UTF-8, or use an ASCII directory",
            path.display(),
            encoding.map_or_else(
                || "which raeva cannot ask the system's locale command for".to_string(),
                |encoding| format!("here {encoding}, not UTF-8"),
            )
        ))),
    }
}

const LOCALE_VARIABLES: [&str; 3] = ["LC_ALL", "LC_CTYPE", "LANG"];

/// The JVM's native encoding for this process's locale variables, where
/// raeva links the C library the JVM does.
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
#[allow(unsafe_code)]
fn jvm_native_encoding() -> Option<String> {
    use std::ffi::CStr;
    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn nl_langinfo_l(item: libc::nl_item, locale: libc::locale_t) -> *mut libc::c_char;
    }
    #[cfg(not(target_os = "macos"))]
    use libc::nl_langinfo_l;
    // SAFETY: `newlocale` with an empty name reads the locale variables
    // into a new object, or fails with null; `nl_langinfo_l` returns a
    // NUL-terminated string owned by it, copied before `freelocale`.
    let codeset = unsafe {
        let locale = libc::newlocale(libc::LC_ALL_MASK, c"".as_ptr(), std::ptr::null_mut());
        if locale.is_null() {
            None
        } else {
            let codeset = CStr::from_ptr(nl_langinfo_l(libc::CODESET, locale))
                .to_string_lossy()
                .into_owned();
            libc::freelocale(locale);
            Some(codeset)
        }
    };
    let c_locale = if cfg!(target_os = "macos") {
        "US-ASCII"
    } else {
        "ANSI_X3.4-1968"
    };
    let encoding = match codeset {
        None => c_locale.to_string(),
        Some(codeset) if codeset.is_empty() => "ISO8859-1".to_string(),
        Some(codeset) => codeset,
    };
    let unset = |name: &str| env::var_os(name).is_none_or(|value| value.is_empty());
    if cfg!(target_os = "macos")
        && encoding == "US-ASCII"
        && LOCALE_VARIABLES.iter().all(|name| unset(name))
    {
        return Some("UTF-8".to_string());
    }
    Some(encoding)
}

/// The same where raeva links another C library than the JVM, as a musl
/// build on glibc does: the code set `locale charmap` gives, or the C
/// locale's where it warns that it cannot set a locale variable's, as
/// glibc's does where `newlocale` fails.
#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
fn jvm_native_encoding() -> Option<String> {
    let output = (std::process::Command::new("locale").arg("charmap"))
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    if !output.stderr.is_empty() {
        return Some("ANSI_X3.4-1968".to_string());
    }
    let codeset = String::from_utf8(output.stdout).ok()?;
    Some(codeset.trim_end().to_string()).filter(|codeset| !codeset.is_empty())
}

/// The passwd entry's home, or the test hook's.
fn passwd_entry_home() -> Option<PathBuf> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(home) = env::var_os(PASSWD_HOME_TEST_ENV) {
        return Some(home)
            .filter(|home| !home.is_empty())
            .map(PathBuf::from);
    }
    passwd_home()
}

/// [`jvm_user_home`] on Unix, for the passwd home `passwd` and `HOME`.
fn unix_user_home(
    passwd: Option<PathBuf>,
    home: Option<std::ffi::OsString>,
    jdk: LauncherJdk,
) -> Result<PathBuf, String> {
    match passwd {
        Some(passwd) if passwd.as_os_str().len() >= 2 => Ok(passwd),
        _ if jdk.hotspot_from(18) => Ok(home
            .filter(|home| !home.is_empty())
            .map_or_else(|| PathBuf::from(UNKNOWN_USER_HOME), PathBuf::from)),
        passwd if jdk.hotspot_before(18) => {
            Ok(passwd.unwrap_or_else(|| PathBuf::from(UNKNOWN_USER_HOME)))
        }
        passwd => Err(format!(
            "{}, so the JVM's user.home depends on its JDK: JDK 18 and later take HOME, JDK 17 \
             and earlier do not, and raeva cannot tell which JDK mvn runs; set JAVA_HOME to \
             it, or pass -Duser.home",
            match passwd {
                None => "this user has no passwd entry".to_string(),
                Some(home) => format!("this user's passwd home is '{}'", home.display()),
            }
        )),
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsString};
    use std::os::unix::ffi::OsStringExt;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `passwd` and `buffer` outlive the call, which writes the
    // entry's strings into `buffer` and points `found` at `passwd` on
    // success. `pw_dir` is read as a NUL-terminated string before either
    // goes out of scope.
    let home = unsafe {
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut found = std::ptr::null_mut();
        let status = libc::getpwuid_r(
            libc::getuid(),
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        );
        (status == 0 && !found.is_null() && !passwd.pw_dir.is_null())
            .then(|| OsString::from_vec(CStr::from_ptr(passwd.pw_dir).to_bytes().to_vec()))
    };
    // An entry with an empty home is not a missing entry: JDK 17 keeps it.
    home.map(PathBuf::from)
}

#[cfg(windows)]
fn passwd_home() -> Option<PathBuf> {
    dirs::home_dir()
}

#[cfg(not(any(unix, windows)))]
fn passwd_home() -> Option<PathBuf> {
    None
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
    use super::{
        LauncherJdk, PlatformDir, ResolvedPaths, platform_dir_unavailable, raeva_home_override,
        unix_user_home,
    };
    use std::env;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

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

    /// OpenJDK's `user.home` on Unix: the passwd home unless it is missing
    /// or shorter than two bytes; then `HOME` from JDK 18, else `?`; JDK 17
    /// keeps the short home and gives `?` for no entry; an unknown JDK
    /// refuses where they differ.
    #[test]
    fn the_jvm_user_home_follows_the_jdk() {
        let jdk = |feature| LauncherJdk {
            feature,
            openj9: false,
        };
        let home = |value: &str| Some(std::ffi::OsString::from(value));
        let path = |value: &str| Some(PathBuf::from(value));
        let cases = [
            // (passwd, HOME, JDK, user.home)
            (path("/home/u"), home("/h"), jdk(None), Ok("/home/u")),
            (path("/home/u"), home("/h"), jdk(Some(17)), Ok("/home/u")),
            (None, home("/h"), jdk(Some(21)), Ok("/h")),
            (path("/"), home("/h"), jdk(Some(18)), Ok("/h")),
            (path(""), home("/h"), jdk(Some(27)), Ok("/h")),
            (path("/"), home(""), jdk(Some(21)), Ok("?")),
            (None, None, jdk(Some(21)), Ok("?")),
            (path("ab"), home("/h"), jdk(Some(21)), Ok("ab")),
            (None, home("/h"), jdk(Some(17)), Ok("?")),
            (path("/"), home("/h"), jdk(Some(17)), Ok("/")),
            (path("/"), home("/h"), jdk(Some(8)), Ok("/")),
            (path(""), home("/h"), jdk(Some(17)), Ok("")),
            (None, home("/h"), jdk(None), Err(())),
            (
                path("/"),
                home("/h"),
                LauncherJdk {
                    feature: Some(21),
                    openj9: true,
                },
                Err(()),
            ),
        ];
        for (passwd, home, jdk, expected) in cases {
            let case = format!("{passwd:?} {home:?} {jdk:?}");
            let got = unix_user_home(passwd, home, jdk).map_err(|_| ());
            assert_eq!(got, expected.map(PathBuf::from), "{case}");
        }
    }

    #[test]
    fn launcher_jdk_reads_the_feature_release() {
        for (version, feature) in [
            ("21.0.4", Some(21)),
            ("1.8.0_442", Some(8)),
            ("17", Some(17)),
            ("27-ea", Some(27)),
            ("", None),
        ] {
            assert_eq!(
                LauncherJdk::of(Some(version), false).feature,
                feature,
                "{version}"
            );
        }
        assert!(super::is_unknown_user_home(Path::new("/w/?")));
        assert!(!super::is_unknown_user_home(Path::new("/w/x")));
    }

    /// `NSHomeDirectory()` as macOS 27 gave it through
    /// `osascript -l JavaScript`, with `HOME=/tmp/h` making no difference.
    #[cfg(unix)]
    #[test]
    fn ns_home_directory_follows_foundation() {
        let passwd = || Some(PathBuf::from("/Users/u"));
        for (fixed, expected) in [
            (None, Some("/Users/u")),
            (Some(""), Some("/Users/u")),
            (Some("/tmp/fixed"), Some("/tmp/fixed")),
            (Some("/tmp/fixed/"), Some("/tmp/fixed")),
            (Some("/"), Some("/")),
            (Some("/a//b/../c"), Some("/a/c")),
            (Some("/a/./b"), Some("/a/b")),
            (Some("/../x"), Some("/x")),
            (Some("//x"), Some("/x")),
            (Some("/Users/u/.."), Some("/Users")),
            (Some("/var/x"), Some("/var/x")),
            (Some("/x y"), Some("/x y")),
            (Some("rel"), None),
            (Some("~/x"), None),
        ] {
            let got = super::ns_home_directory(passwd(), fixed.map(Into::into)).ok();
            assert_eq!(got, expected.map(PathBuf::from), "{fixed:?}");
        }
        assert!(super::ns_home_directory(None, None).is_err());
        assert!(super::ns_home_directory(Some(PathBuf::new()), None).is_err());
        // The JVM's check then runs on it: "/" takes HOME from JDK 18.
        let root = super::ns_home_directory(passwd(), Some("/".into())).ok();
        let jdk = |feature| LauncherJdk {
            feature: Some(feature),
            openj9: false,
        };
        assert_eq!(
            unix_user_home(root.clone(), Some("/h".into()), jdk(21)),
            Ok(PathBuf::from("/h"))
        );
        assert_eq!(
            unix_user_home(root, Some("/h".into()), jdk(17)),
            Ok(PathBuf::from("/"))
        );
    }

    /// The JVM's native encoding follows the locale variables, as OpenJDK
    /// 17, 21 and 27 gave `native.encoding`: where any of them names a
    /// locale that is not installed, it is the C locale's.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_native_encoding_follows_the_locale() {
        let unset =
            ["LC_ALL", "LC_CTYPE", "LC_TIME", "LC_MESSAGES", "LANG"].map(|name| (name, None));
        for (vars, utf8) in [
            (vec![("LC_ALL", Some("C.UTF-8"))], true),
            (vec![("LANG", Some("C.UTF-8"))], true),
            (vec![("LC_ALL", Some("C"))], false),
            (vec![("LANG", Some("C.UTF-8")), ("LC_ALL", Some(""))], true),
            (vec![("LC_ALL", Some("xx_XX.UTF-8"))], false),
            (
                vec![("LANG", Some("C.UTF-8")), ("LC_TIME", Some("xx"))],
                false,
            ),
        ] {
            let vars: Vec<_> = unset.iter().copied().chain(vars).collect();
            let encoding = temp_env::with_vars(vars.clone(), super::jvm_native_encoding);
            assert_eq!(
                encoding.as_deref() == Some("UTF-8"),
                utf8,
                "{vars:?}: {encoding:?}"
            );
        }
    }

    /// A9: with a `..`, Foundation resolves links, as macOS 27 gave
    /// `CFFIXED_USER_HOME=<dir>/x/l/../C` as `<l's target>/../C`, so a `..`
    /// on a path through a link refuses; one through none does not.
    #[cfg(unix)]
    #[test]
    fn a_cffixed_user_home_with_dotdot_through_a_link_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(base.join("x/real")).unwrap();
        std::os::unix::fs::symlink(base.join("x/real"), base.join("x/l")).unwrap();
        let passwd = || Some(PathBuf::from("/Users/u"));
        for (fixed, expected) in [
            ("x/l/../C", None),
            ("x/../x/l", None),
            ("x/l/sub/../C", None),
            ("x/real/../C", Some("x/C")),
            ("x/l", Some("x/l")),
        ] {
            let got = super::ns_home_directory(passwd(), Some(base.join(fixed).into())).ok();
            assert_eq!(got, expected.map(|path| base.join(path)), "{fixed}");
        }
    }

    /// Foundation itself agrees, where `osascript` can ask it.
    #[cfg(target_os = "macos")]
    #[test]
    fn ns_home_directory_matches_foundation_on_this_mac() {
        let ask = |fixed: &str| {
            let output = std::process::Command::new("osascript")
                .args([
                    "-l",
                    "JavaScript",
                    "-e",
                    "ObjC.import('Foundation'); $.NSHomeDirectory().js",
                ])
                .env(super::CF_FIXED_USER_HOME, fixed)
                .output()
                .ok()
                .filter(|output| output.status.success())?;
            Some(PathBuf::from(
                String::from_utf8(output.stdout).ok()?.trim_end(),
            ))
        };
        let passwd = super::passwd_home();
        for fixed in ["", "/tmp/fixed/", "/a//b/../c", "/../x", "/var/x"] {
            let Some(foundation) = ask(fixed) else {
                return;
            };
            assert_eq!(
                super::ns_home_directory(passwd.clone(), Some(fixed.into())),
                Ok(foundation),
                "{fixed:?}"
            );
        }
    }
}
