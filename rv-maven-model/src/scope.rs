use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use strum::{AsRefStr, Display, EnumString};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    serde::Serialize,
    AsRefStr,
    Display,
    EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
/// Maven dependency scope controlling classpath inclusion and transitivity.
pub enum Scope {
    #[default]
    Compile,
    Runtime,
    Test,
    Provided,
    System,
    Import,
}

/// Custom deserializer that accepts invalid scope values.
///
/// Some POMs use `<scope>optional</scope>` even though "optional" is not a valid
/// Maven scope (it's a separate `<optional>` element). Unknown scopes are
/// treated as `Compile` with a warning, matching Maven's lenient behavior.
impl<'de> serde::Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Scope::parse(&s))
    }
}

/// Process-wide set of unknown scope strings already warned about. Lenient
/// parsing runs once per dependency per resolution pass, and the same POM is
/// re-resolved across passes, so an unguarded `tracing::warn!` repeats the
/// identical message many times. Deduplicating by the offending value keeps a
/// single warning per distinct unknown scope for the life of the process.
fn warned_unknown_scopes() -> &'static Mutex<HashSet<String>> {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Emit the unknown-scope warning at most once per distinct value. Returns
/// whether a warning was actually emitted (used by tests).
fn warn_unknown_scope_once(scope: &str) -> bool {
    let Ok(mut seen) = warned_unknown_scopes().lock() else {
        // A poisoned lock means a previous warn panicked (it cannot). Fall
        // back to warning rather than silently dropping the diagnostic.
        tracing::warn!(scope, "unknown dependency scope, treating as compile");
        return true;
    };
    if seen.insert(scope.to_string()) {
        tracing::warn!(scope, "unknown dependency scope, treating as compile");
        true
    } else {
        false
    }
}

impl Scope {
    /// Parses a scope string leniently, matching Maven's behavior.
    /// Unknown scopes (including unresolved property references) are treated as compile.
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        match Scope::from_str(trimmed) {
            Ok(scope) => scope,
            Err(_) => {
                warn_unknown_scope_once(trimmed);
                Scope::Compile
            }
        }
    }

    pub fn is_transitive(&self) -> bool {
        matches!(self, Scope::Compile | Scope::Runtime)
    }

    /// Returns the scope to use when traversing a child dependency, or `None` when the
    /// child should not be traversed.
    ///
    /// Raeva intentionally simplifies Maven's scope transitivity rules: only
    /// compile/runtime dependencies are traversed. Test and provided dependencies
    /// are treated as non-transitive (unlike standard Maven where test->compile
    /// still traverses), which reduces graph size but can omit some transitive deps.
    ///
    /// The (parent, child) -> propagated scope table this implements is:
    /// ```text
    /// parent ↓ / child →   compile   provided   runtime   test
    /// compile              compile   —          runtime   —
    /// provided             provided  —          provided  —
    /// runtime              runtime   —          runtime   —
    /// test                 test      —          test      —
    /// ```
    /// `provided` and `test` children always return `None` since
    /// [`Scope::is_transitive`] excludes them.
    pub fn transitive_from(parent: Scope, child: Scope) -> Option<Scope> {
        if !child.is_transitive() {
            return None;
        }

        match parent {
            Scope::Compile => Some(child),
            Scope::Runtime => Some(Scope::Runtime),
            Scope::Test => Some(Scope::Test),
            // Maven: a provided parent propagates as provided for both compile and
            // runtime children; the runtime child is not dropped.
            Scope::Provided => Some(Scope::Provided),
            Scope::System | Scope::Import => None,
        }
    }

    /// Returns the scope to use when traversing a child dependency using full Maven
    /// transitivity rules, or `None` when the child should not be traversed.
    ///
    /// This differs from [`transitive_from`] in one way: when `parent = Compile` and
    /// `child = Test`, Maven propagates with scope `Test` (so that compile-scoped
    /// children of a test dependency appear on the test classpath). The simplified
    /// [`transitive_from`] skips test-scoped children entirely.
    ///
    /// Use this variant when processing `pom.xml` sources where full Maven
    /// compatibility is required.
    pub fn transitive_from_maven_compat(parent: Scope, child: Scope) -> Option<Scope> {
        // Maven rule: compile -> test = test (test dep's compile children are test-scoped)
        if parent == Scope::Compile && child == Scope::Test {
            return Some(Scope::Test);
        }

        // All other cases follow the same logic as the simplified version.
        Self::transitive_from(parent, child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_and_display() {
        let scope: Scope = "runtime".parse().unwrap();
        assert_eq!(scope, Scope::Runtime);
        assert_eq!(scope.to_string(), "runtime");
    }

    #[test]
    fn scope_default_compile() {
        assert_eq!(Scope::default(), Scope::Compile);
    }

    #[test]
    fn scope_is_transitive() {
        assert!(Scope::Compile.is_transitive());
        assert!(Scope::Runtime.is_transitive());
        assert!(!Scope::Test.is_transitive());
        assert!(!Scope::Provided.is_transitive());
        assert!(!Scope::System.is_transitive());
        assert!(!Scope::Import.is_transitive());
    }

    #[test]
    fn scope_transitive_from() {
        assert_eq!(
            Scope::transitive_from(Scope::Compile, Scope::Compile),
            Some(Scope::Compile)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Compile, Scope::Runtime),
            Some(Scope::Runtime)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Runtime, Scope::Compile),
            Some(Scope::Runtime)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Runtime, Scope::Runtime),
            Some(Scope::Runtime)
        );
        assert_eq!(Scope::transitive_from(Scope::Compile, Scope::Test), None);
        assert_eq!(
            Scope::transitive_from(Scope::Compile, Scope::Provided),
            None
        );
        assert_eq!(Scope::transitive_from(Scope::Compile, Scope::System), None);
        assert_eq!(Scope::transitive_from(Scope::Compile, Scope::Import), None);
        assert_eq!(
            Scope::transitive_from(Scope::Provided, Scope::Compile),
            Some(Scope::Provided)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Provided, Scope::Runtime),
            Some(Scope::Provided)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Test, Scope::Compile),
            Some(Scope::Test)
        );
        assert_eq!(
            Scope::transitive_from(Scope::Test, Scope::Runtime),
            Some(Scope::Test)
        );
        assert_eq!(Scope::transitive_from(Scope::System, Scope::Compile), None);
        assert_eq!(Scope::transitive_from(Scope::Import, Scope::Compile), None);
    }

    #[test]
    fn scope_transitive_from_matrix_matches_maven() {
        // Reference matrix (rows = parent, cols = child); `—` means propagation is
        // dropped (child is non-transitive). The transitive children are Compile
        // and Runtime; Provided/Test/System/Import children always return None.
        //
        // parent ↓ / child →   compile     provided  runtime   test
        // compile              compile     —         runtime   —
        // provided             provided    —         provided  —
        // runtime              runtime     —         runtime   —
        // test                 test        —         test      —
        let table = [
            (Scope::Compile, Scope::Compile, Some(Scope::Compile)),
            (Scope::Compile, Scope::Provided, None),
            (Scope::Compile, Scope::Runtime, Some(Scope::Runtime)),
            (Scope::Compile, Scope::Test, None),
            (Scope::Provided, Scope::Compile, Some(Scope::Provided)),
            (Scope::Provided, Scope::Provided, None),
            (Scope::Provided, Scope::Runtime, Some(Scope::Provided)),
            (Scope::Provided, Scope::Test, None),
            (Scope::Runtime, Scope::Compile, Some(Scope::Runtime)),
            (Scope::Runtime, Scope::Provided, None),
            (Scope::Runtime, Scope::Runtime, Some(Scope::Runtime)),
            (Scope::Runtime, Scope::Test, None),
            (Scope::Test, Scope::Compile, Some(Scope::Test)),
            (Scope::Test, Scope::Provided, None),
            (Scope::Test, Scope::Runtime, Some(Scope::Test)),
            (Scope::Test, Scope::Test, None),
        ];
        for (parent, child, expected) in table {
            assert_eq!(
                Scope::transitive_from(parent, child),
                expected,
                "transitive_from({parent:?}, {child:?})"
            );
        }
    }

    #[test]
    fn scope_invalid_strict_parse_errors_but_lenient_parse_defaults() {
        "weird"
            .parse::<Scope>()
            .expect_err("strict parse rejects unknown scope");
        assert_eq!(Scope::parse("weird"), Scope::Compile);
    }

    /// The unknown-scope warning must fire only once per distinct value, even
    /// when the same scope is parsed repeatedly across resolution passes.
    #[test]
    fn unknown_scope_warns_only_once_per_value() {
        // Use a value unlikely to collide with other tests' warnings so the
        // dedup set's "already seen" state is deterministic for this value.
        let scope = "totally-bogus-scope-39";
        assert!(
            warn_unknown_scope_once(scope),
            "first occurrence of an unknown scope should warn"
        );
        assert!(
            !warn_unknown_scope_once(scope),
            "a repeated unknown scope must NOT warn again"
        );
        // Parsing through the public API also reuses the dedup set.
        assert_eq!(Scope::parse(scope), Scope::Compile);
        assert!(
            !warn_unknown_scope_once(scope),
            "parsing the same unknown scope must not re-arm the warning"
        );
        // A distinct unknown value still warns once.
        assert!(warn_unknown_scope_once("another-bogus-scope-39"));
    }

    #[test]
    fn scope_transitive_from_maven_compat() {
        // The only difference from transitive_from: compile -> test = Some(Test)
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Compile, Scope::Test),
            Some(Scope::Test)
        );
        // All other cases match transitive_from exactly.
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Compile, Scope::Compile),
            Some(Scope::Compile)
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Compile, Scope::Runtime),
            Some(Scope::Runtime)
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Compile, Scope::Provided),
            None
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Runtime, Scope::Test),
            None
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Test, Scope::Compile),
            Some(Scope::Test)
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Test, Scope::Runtime),
            Some(Scope::Test)
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Provided, Scope::Compile),
            Some(Scope::Provided)
        );
        assert_eq!(
            Scope::transitive_from_maven_compat(Scope::Provided, Scope::Runtime),
            Some(Scope::Provided)
        );
    }

    #[test]
    fn scope_deserialize_optional_as_compile() {
        // Some POMs use <scope>optional</scope> which is invalid Maven.
        // The raw string is preserved; effective_scope() treats it as Compile.
        use crate::dependency::Dependency;
        let xml = r#"<dependency>
            <groupId>test</groupId>
            <artifactId>lib</artifactId>
            <version>1.0</version>
            <scope>optional</scope>
        </dependency>"#;
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.scope.as_deref(), Some("optional"));
        assert_eq!(dep.effective_scope(), Scope::Compile);
    }

    #[test]
    fn scope_deserialize_unknown_as_compile() {
        use crate::dependency::Dependency;
        let xml = r#"<dependency>
            <groupId>test</groupId>
            <artifactId>lib</artifactId>
            <version>1.0</version>
            <scope>weird</scope>
        </dependency>"#;
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.scope.as_deref(), Some("weird"));
        assert_eq!(dep.effective_scope(), Scope::Compile);
    }

    #[test]
    fn scope_deserialize_valid_values() {
        use crate::dependency::Dependency;
        for (scope_str, expected) in [
            ("compile", Scope::Compile),
            ("test", Scope::Test),
            ("runtime", Scope::Runtime),
            ("provided", Scope::Provided),
            ("import", Scope::Import),
            ("system", Scope::System),
        ] {
            let xml = format!(
                r#"<dependency>
                    <groupId>test</groupId>
                    <artifactId>lib</artifactId>
                    <version>1.0</version>
                    <scope>{}</scope>
                </dependency>"#,
                scope_str
            );
            let dep: Dependency = quick_xml::de::from_str(&xml).unwrap();
            assert_eq!(
                dep.scope.as_deref(),
                Some(scope_str),
                "raw scope mismatch for: {}",
                scope_str
            );
            assert_eq!(
                dep.effective_scope(),
                expected,
                "effective scope mismatch for: {}",
                scope_str
            );
        }
    }
}
