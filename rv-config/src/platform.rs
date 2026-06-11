use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Platform {
    os: String,
    arch: String,
}

impl Platform {
    /// Creates a new platform from OS and architecture strings.
    ///
    /// # Errors
    ///
    /// Returns an error if either OS or architecture is empty or contains
    /// commas or whitespace.
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Result<Self, ConfigError> {
        let os = os.into();
        let arch = arch.into();
        if !valid_token(&os) || !valid_token(&arch) {
            return Err(ConfigError::InvalidPlatform(format!("{}-{}", os, arch)));
        }
        Ok(Self { os, arch })
    }

    /// Returns the current platform based on compile-time constants.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform cannot be determined (should not happen
    /// in practice as OS and ARCH are always set by the compiler).
    pub fn current() -> Result<Self, ConfigError> {
        Self::new(std::env::consts::OS, std::env::consts::ARCH)
    }

    pub fn os(&self) -> &str {
        &self.os
    }

    pub fn arch(&self) -> &str {
        &self.arch
    }
}

// An os or arch token containing a comma or whitespace is always an input
// error (e.g. an un-split `--platforms a,b` list arriving as one string);
// accepting it would bake a garbage platform key into rv.lock.
fn valid_token(token: &str) -> bool {
    !token.is_empty() && !token.chars().any(|c| c == ',' || c.is_whitespace())
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.os, self.arch)
    }
}

impl FromStr for Platform {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ConfigError::InvalidPlatform(value.to_string()));
        }
        let (os, arch) = value
            .split_once('-')
            .ok_or_else(|| ConfigError::InvalidPlatform(value.to_string()))?;
        Platform::new(os, arch)
    }
}

impl TryFrom<String> for Platform {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Platform::from_str(&value)
    }
}

impl From<Platform> for String {
    fn from(value: Platform) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, Platform};

    #[test]
    fn parses_platform_string() {
        let platform = "linux-x86_64".parse::<Platform>().unwrap();
        assert_eq!(platform.os(), "linux");
        assert_eq!(platform.arch(), "x86_64");
    }

    #[test]
    fn rejects_invalid_platform_string() {
        assert!(matches!(
            "linux".parse::<Platform>(),
            Err(ConfigError::InvalidPlatform(_))
        ));
    }

    #[test]
    fn rejects_comma_joined_platform_list() {
        // A documented-looking `--platforms a,b` list that arrives un-split
        // must fail loudly instead of producing one garbage platform.
        assert!(matches!(
            "linux-x86_64,darwin-aarch64".parse::<Platform>(),
            Err(ConfigError::InvalidPlatform(_))
        ));
    }

    #[test]
    fn rejects_empty_os_or_arch() {
        assert!("linux-".parse::<Platform>().is_err());
        assert!("-x86_64".parse::<Platform>().is_err());
        assert!(Platform::new("linux", "").is_err());
        assert!(Platform::new("", "x86_64").is_err());
    }

    #[test]
    fn rejects_whitespace_inside_tokens() {
        assert!("li nux-x86_64".parse::<Platform>().is_err());
        assert!(Platform::new("linux", "x86 64").is_err());
        assert!(Platform::new(" linux", "x86_64").is_err());
    }

    #[test]
    fn serde_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrapper {
            platform: Platform,
        }

        let wrapper = Wrapper {
            platform: Platform::new("macos", "aarch64").unwrap(),
        };
        let encoded = toml::to_string(&wrapper).unwrap();
        assert!(encoded.contains("macos-aarch64"));

        let decoded: Wrapper = toml::from_str("platform = \"windows-x86_64\"").unwrap();
        assert_eq!(decoded.platform.to_string(), "windows-x86_64");
    }
}
