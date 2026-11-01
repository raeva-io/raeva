use std::fmt;
use std::str::FromStr;

/// A platform name that is not `os-arch` with ASCII letters, digits and
/// `_` in each part. Holds the rejected text, already escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPlatform(String);

impl fmt::Display for InvalidPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid platform: {}", self.0)
    }
}

impl std::error::Error for InvalidPlatform {}

/// The operating system, architecture and optional target JDK a resolution
/// is recorded for. The platform part is written `os-arch`, such as
/// `linux-x86_64`, with non-empty ASCII letters, digits and `_` in each
/// part; [`Platform::current`] takes the names from [`std::env::consts`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Platform {
    os: String,
    arch: String,
    jdk: Option<String>,
}

impl Platform {
    /// # Errors
    ///
    /// Fails unless OS and architecture are both non-empty and made of ASCII
    /// letters, digits and `_`.
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Result<Self, InvalidPlatform> {
        let os = os.into();
        let arch = arch.into();
        // Each part is non-empty ASCII letters, digits and `_`.
        let valid = |token: &str| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        };
        if !valid(&os) || !valid(&arch) {
            return Err(InvalidPlatform(format!("{:?}", format!("{os}-{arch}"))));
        }
        Ok(Self {
            os,
            arch,
            jdk: None,
        })
    }

    /// Returns the current platform based on compile-time constants.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform cannot be determined (should not happen
    /// in practice as OS and ARCH are always set by the compiler).
    pub fn current() -> Result<Self, InvalidPlatform> {
        Self::new(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// This platform with `jdk` as its target JDK version.
    #[must_use]
    pub fn with_jdk(mut self, jdk: impl Into<String>) -> Self {
        self.jdk = Some(jdk.into());
        self
    }

    /// This platform without a target JDK.
    #[must_use]
    pub fn without_jdk(&self) -> Self {
        Self {
            os: self.os.clone(),
            arch: self.arch.clone(),
            jdk: None,
        }
    }

    /// The operating system part.
    pub fn os(&self) -> &str {
        &self.os
    }

    /// The architecture part.
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// The target JDK version, when set.
    pub fn jdk(&self) -> Option<&str> {
        self.jdk.as_deref()
    }

    /// The `os-arch` identifier without any target JDK suffix.
    pub fn os_arch(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.jdk {
            None => write!(f, "{}-{}", self.os, self.arch),
            Some(jdk) => write!(f, "{}-{} (JDK {jdk})", self.os, self.arch),
        }
    }
}

impl FromStr for Platform {
    type Err = InvalidPlatform;

    /// Parses `os-arch` exactly as written: surrounding whitespace is part
    /// of the text and makes it invalid.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (os, arch) = value
            .split_once('-')
            .ok_or_else(|| InvalidPlatform(format!("{value:?}")))?;
        Platform::new(os, arch)
    }
}

#[cfg(test)]
mod tests {
    use super::Platform;

    /// Each part is ASCII letters, digits and `_`: an un-split
    /// `--platforms a,b` list or a hostile raeva.lock key fails, and the
    /// message is escaped.
    #[test]
    fn platforms_parse_exactly_as_written() {
        let platform = "linux-x86_64".parse::<Platform>().unwrap();
        assert_eq!((platform.os(), platform.arch()), ("linux", "x86_64"));
        assert_eq!(platform.to_string(), "linux-x86_64");
        for bad in [
            "",
            "linux",
            "linux-",
            "-x86_64",
            "linux-x86_64,darwin-aarch64",
            " linux-x86_64",
            "linux-x86_64\n",
            "li nux-x86_64",
            "linux\u{1b}[31m-x86_64",
            "linux-x86_64-musl",
            "linux-x86/64",
        ] {
            let err = bad.parse::<Platform>().expect_err(bad).to_string();
            assert!(!err.chars().any(char::is_control), "{err}");
        }
        assert!(Platform::new("linux", "x86 64").is_err());
        assert!(Platform::new("", "x86_64").is_err());
        assert!("linux-x86_64 (JDK 21)".parse::<Platform>().is_err());

        let jdk21 = platform.clone().with_jdk("21");
        assert_eq!(jdk21.jdk(), Some("21"));
        assert_eq!(jdk21.os_arch(), "linux-x86_64");
        assert_eq!(jdk21.to_string(), "linux-x86_64 (JDK 21)");
        assert_ne!(jdk21, platform);
        assert_eq!(jdk21.without_jdk(), platform);
    }
}
