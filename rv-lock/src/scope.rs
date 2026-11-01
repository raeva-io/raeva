use std::fmt;
use std::str::FromStr;

/// A Maven dependency scope as raeva.lock records it.
///
/// Parsing is strict: only the six lowercase names Maven defines are
/// accepted. The variants are declared in the order of their names as text,
/// which is how the lock sorts package rows and edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// `compile`, Maven's default.
    Compile,
    /// `import`: Maven's scope for a BOM imported into
    /// `<dependencyManagement>`.
    Import,
    /// `provided`.
    Provided,
    /// `runtime`.
    Runtime,
    /// `system`: a file named by `<systemPath>`, see [`crate::SystemFile`].
    System,
    /// `test`.
    Test,
}

impl Scope {
    /// Every scope, in Maven's order.
    pub const ALL: [Scope; 6] = [
        Self::Compile,
        Self::Provided,
        Self::Runtime,
        Self::Test,
        Self::System,
        Self::Import,
    ];

    /// The lowercase name raeva.lock writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Provided => "provided",
            Self::Runtime => "runtime",
            Self::Test => "test",
            Self::System => "system",
            Self::Import => "import",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A scope name that is not one of the six Maven defines. Holds the
/// rejected text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidScope(pub String);

impl fmt::Display for InvalidScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scope {:?} is not one of compile, provided, runtime, test, system, import",
            self.0
        )
    }
}

impl std::error::Error for InvalidScope {}

impl FromStr for Scope {
    type Err = InvalidScope;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.as_str() == value)
            .ok_or_else(|| InvalidScope(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_strictly_and_sort_as_text() {
        for scope in Scope::ALL {
            assert_eq!(scope.as_str().parse::<Scope>(), Ok(scope));
        }
        for bad in ["", "Compile", " compile", "compile ", "optional"] {
            assert!(bad.parse::<Scope>().is_err(), "{bad:?}");
        }
        let mut sorted = Scope::ALL.to_vec();
        sorted.sort();
        let names: Vec<&str> = sorted.iter().map(|scope| scope.as_str()).collect();
        let mut expected = names.clone();
        expected.sort();
        assert_eq!(names, expected);
    }
}
