use std::str::FromStr;

use rv_maven_types::quoted;
use strum::{AsRefStr, Display, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, AsRefStr, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
/// Maven dependency scope controlling classpath inclusion and transitivity.
pub enum Scope {
    /// The default: on every classpath and transitive.
    #[default]
    Compile,
    /// Needed to run, not to compile.
    Runtime,
    /// Only for compiling and running tests; not transitive.
    Test,
    /// Supplied by the runtime container; not transitive.
    Provided,
    /// Like provided, with the file named by `<systemPath>` instead of a
    /// repository artifact.
    System,
    /// Only in `<dependencyManagement>`: a BOM whose managed dependencies
    /// are inlined.
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

impl Scope {
    /// Unknown scopes (including unresolved property references) become compile, as Maven does.
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        match Scope::from_str(trimmed) {
            Ok(scope) => scope,
            Err(_) => {
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    scope = %quoted(trimmed),
                    "unknown dependency scope, treating as compile"
                );
                Scope::Compile
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_strictly_or_leniently() {
        for (text, scope) in [
            ("compile", Scope::Compile),
            ("test", Scope::Test),
            ("runtime", Scope::Runtime),
            ("provided", Scope::Provided),
            ("import", Scope::Import),
            ("system", Scope::System),
        ] {
            assert_eq!(text.parse::<Scope>().unwrap(), scope);
            assert_eq!(scope.to_string(), text);
        }
        assert_eq!(Scope::default(), Scope::Compile);
        "weird"
            .parse::<Scope>()
            .expect_err("strict parse rejects unknown scope");
        assert_eq!(Scope::parse("weird"), Scope::Compile);
        // Maven compares scopes with their case, so `SYSTEM` is unknown.
        assert_eq!(Scope::parse("SYSTEM"), Scope::Compile);
        // Some POMs use the invalid <scope>optional</scope>; the text is kept
        // and counts as compile.
        let dep: crate::dependency::Dependency = quick_xml::de::from_str(
            "<dependency><groupId>g</groupId><artifactId>a</artifactId>\
             <scope>optional</scope></dependency>",
        )
        .unwrap();
        assert_eq!(dep.scope.as_deref(), Some("optional"));
        assert_eq!(dep.effective_scope(), Scope::Compile);
    }
}
