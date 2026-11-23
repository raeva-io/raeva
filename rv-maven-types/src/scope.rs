use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};

/// A Maven dependency scope, which decides classpath inclusion and
/// transitivity.
///
/// `FromStr` is strict: only the six lowercase names Maven defines and
/// `compile-only` are accepted. [`Scope::declared`] also keeps a scope Maven
/// does not know, as Maven does, and [`Scope::read`] one that raeva.lock
/// can record. Scopes compare and sort by their text, which is how
/// raeva.lock sorts package rows and edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Scope {
    /// `compile`, the default: on every classpath and transitive.
    #[default]
    Compile,
    /// `compile-only`, which Maven resolves as a scope it does not know: its
    /// dependencies are `runtime` and any known scope wins over it.
    CompileOnly,
    /// `import`: in `<dependencyManagement>`, a BOM whose managed
    /// dependencies are inlined; elsewhere a scope Maven's resolver does not
    /// know.
    Import,
    /// `provided`: supplied by the runtime container; not transitive.
    Provided,
    /// `runtime`: needed to run, not to compile.
    Runtime,
    /// `system`: like `provided`, with the file `<systemPath>` names instead
    /// of a repository artifact.
    System,
    /// `test`: only for compiling and running tests; not transitive.
    Test,
    /// Any other scope, such as `RUNTIME`, `optional`, `foo:bar` or an
    /// unresolved `${scope}`, kept as written, which Maven resolves as
    /// [`Scope::CompileOnly`]. raeva.lock records only those
    /// [`Scope::recordable`] accepts.
    Other(&'static str),
    /// The empty scope Maven's JavaScopeSelector gives a node it reaches
    /// only in scopes it does not know, two or more of them: its
    /// dependencies keep their own scopes, as below `compile`. raeva.lock
    /// writes it as `?`.
    Empty,
}

impl Scope {
    /// Every scope Maven or raeva names, in Maven's order.
    pub const ALL: [Scope; 7] = [
        Self::Compile,
        Self::Provided,
        Self::Runtime,
        Self::Test,
        Self::System,
        Self::Import,
        Self::CompileOnly,
    ];

    /// The scope a POM's non-empty `<scope>` text names, kept as written
    /// when Maven does not know it, as Maven keeps it.
    pub fn declared(text: &str) -> Scope {
        text.parse().unwrap_or_else(|_| Self::Other(intern(text)))
    }

    /// The scope `text` names in raeva.lock: [`Scope::declared`], or `None`
    /// for text the lock cannot record (see [`Scope::recordable`]).
    pub fn read(text: &str) -> Option<Scope> {
        Some(Self::declared(text)).filter(|scope| scope.recordable())
    }

    /// Whether raeva.lock can record this scope: a scope Maven does not know
    /// must be 1 to 255 characters with no whitespace, which separates an edge
    /// line's fields, no control or invisible character, and not `?`, the
    /// empty scope's mark.
    pub fn recordable(self) -> bool {
        match self {
            Self::Other(text) => {
                (1..=255).contains(&text.chars().count())
                    && text != "?"
                    && crate::is_terminal_safe(text)
                    && !text.chars().any(char::is_whitespace)
            }
            _ => true,
        }
    }

    /// The name raeva.lock writes, empty for [`Scope::Empty`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Provided => "provided",
            Self::Runtime => "runtime",
            Self::Test => "test",
            Self::System => "system",
            Self::Import => "import",
            Self::CompileOnly => "compile-only",
            Self::Other(text) => text,
            Self::Empty => "",
        }
    }
}

/// `text` as a `&'static str`, leaked once per distinct text, so that
/// [`Scope`] stays `Copy`.
fn intern(text: &str) -> &'static str {
    static TEXTS: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let mut texts = TEXTS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(&known) = texts.get(text) {
        return known;
    }
    let leaked: &'static str = Box::leak(text.into());
    texts.insert(leaked);
    leaked
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("no scope"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// A scope name that is not one [`Scope`] accepts. Holds the rejected text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidScope(pub String);

impl fmt::Display for InvalidScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scope {:?} is not one of compile, provided, runtime, test, system, import, \
             compile-only",
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
        sorted.extend(
            ["RUNTIME", "optional", "${scope}", "a"].map(|text| Scope::read(text).unwrap()),
        );
        sorted.sort();
        let names: Vec<&str> = sorted.iter().map(|scope| scope.as_str()).collect();
        let mut expected = names.clone();
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(Scope::default(), Scope::Compile);
    }

    #[test]
    fn read_keeps_a_scope_raeva_lock_can_write() {
        assert_eq!(Scope::read("runtime"), Some(Scope::Runtime));
        assert_eq!(Scope::read("RUNTIME"), Some(Scope::Other("RUNTIME")));
        for kept in [
            "${scope}",
            "foo:bar",
            "a/b",
            "?x",
            "\"q\\",
            "étendu",
            &"x".repeat(255),
            &"é".repeat(255),
        ] {
            assert_eq!(Scope::read(kept).map(Scope::as_str), Some(kept), "{kept:?}");
        }
        for bad in [
            "",
            "?",
            "two words",
            "tab\there",
            "line\nbreak",
            "no\u{a0}break",
            "esc\u{1b}[31m",
            "zero\u{200b}width",
            &"x".repeat(256),
            &"é".repeat(256),
            "x\u{e0100}y",
        ] {
            assert_eq!(Scope::read(bad), None, "{bad:?}");
            assert!(!Scope::declared(bad).recordable(), "{bad:?}");
        }
        assert_eq!(Scope::declared("two words").as_str(), "two words");
        assert_eq!(Scope::declared("test"), Scope::Test);
    }
}
