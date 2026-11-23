use std::fmt;

/// The Maven release line whose resolution raeva reproduces.
///
/// Maven 3.9 collects with maven-resolver 1.9 depth first. Maven 3.10
/// collects with maven-resolver 2 breadth first, orders a version that
/// starts with text below every version that starts with a number, and
/// builds models with stricter rules; see docs/verification.md.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MavenMode {
    /// Maven 3.9, and the releases before it.
    #[default]
    Maven39,
    /// Maven 3.10.
    Maven310,
}

impl MavenMode {
    /// `3.9` or `3.10`, as `[lock] maven` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            MavenMode::Maven39 => "3.9",
            MavenMode::Maven310 => "3.10",
        }
    }

    /// The Maven release raeva reproduces for this line, its
    /// `maven.version`.
    pub fn version(self) -> &'static str {
        match self {
            MavenMode::Maven39 => "3.9.12",
            MavenMode::Maven310 => "3.10.0",
        }
    }

    /// That release's `maven.build.version`.
    pub fn build_version(self) -> &'static str {
        match self {
            MavenMode::Maven39 => "Apache Maven 3.9.12 (848fbb4bf2d427b72bdb2471c22fced7ebd9a7a1)",
            MavenMode::Maven310 => "Apache Maven 3.10.0 (c43a36b8d67be7e0805a411bc0898af1a51f5472)",
        }
    }

    /// The mode `3.9` or `3.10` names.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "3.9" => Some(MavenMode::Maven39),
            "3.10" => Some(MavenMode::Maven310),
            _ => None,
        }
    }
}

impl fmt::Display for MavenMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
