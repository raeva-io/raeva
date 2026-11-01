//! The OpenVEX subset `raeva vuln --vex`, `raeva vuln triage` and
//! `raeva sbom --vex` read: statements whose product is a module purl and
//! whose subcomponent is a dependency purl. A product purl without a version
//! covers every version of the module. docs/vulnerabilities-and-sboms.md
//! lists the rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CliError, Result};
use crate::output::{Output, Warning, WarningCode};

const CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, strum::IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(crate) enum Status {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum, strum::IntoStaticStr,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub(crate) enum Justification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

impl Status {
    pub(crate) fn as_str(self) -> &'static str {
        self.into()
    }
}

impl Justification {
    pub(crate) fn as_str(self) -> &'static str {
        self.into()
    }
}

/// What a statement says about one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Assessment {
    pub status: Status,
    pub justification: Option<Justification>,
    pub impact_statement: Option<String>,
}

impl Assessment {
    pub(crate) fn suppresses(&self) -> bool {
        self.status == Status::NotAffected
    }

    /// Statements agree when status and justification match; the impact
    /// statement is prose.
    fn agrees(&self, other: &Self) -> bool {
        self.status == other.status && self.justification == other.justification
    }
}

#[derive(Deserialize)]
struct Document {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    timestamp: String,
    version: u64,
    statements: Vec<Statement>,
}

#[derive(Deserialize)]
struct Statement {
    vulnerability: Vulnerability,
    products: Vec<Product>,
    status: Status,
    justification: Option<Justification>,
    impact_statement: Option<String>,
}

#[derive(Deserialize)]
struct Vulnerability {
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Deserialize)]
struct Product {
    #[serde(flatten)]
    component: Component,
    #[serde(default)]
    subcomponents: Vec<Component>,
}

#[derive(Deserialize)]
struct Component {
    #[serde(rename = "@id")]
    id: Option<String>,
    identifiers: Option<Identifiers>,
}

#[derive(Deserialize)]
struct Identifiers {
    purl: Option<String>,
}

impl Component {
    /// `identifiers.purl`, else an `@id` that is a purl, in the canonical
    /// form raeva writes.
    fn purl(&self) -> std::result::Result<String, &'static str> {
        // A subpath names content inside the package, which a finding about
        // the whole package does not match; canonicalizing would drop it.
        let canonical = |purl: &str| {
            if purl.contains('#') {
                return Err("purl has a subpath");
            }
            rv_maven_types::canonicalize_purl(purl).ok_or("purl does not parse")
        };
        let id = self.id.as_deref().filter(|id| id.starts_with("pkg:"));
        let purl = self
            .identifiers
            .as_ref()
            .and_then(|ids| ids.purl.as_deref());
        match (
            purl.map(canonical).transpose()?,
            id.map(canonical).transpose()?,
        ) {
            (Some(purl), Some(id)) if purl != id => Err("@id and identifiers.purl differ"),
            (Some(purl), _) | (None, Some(purl)) => Ok(purl),
            (None, None) => Err("names no purl"),
        }
    }
}

/// One statement for one product and subcomponent.
#[derive(Debug)]
struct Entry {
    names: Vec<String>,
    assessment: Assessment,
    path: PathBuf,
    statement: usize,
    /// Set once the entry applied to a finding or a package.
    used: AtomicBool,
}

impl Entry {
    fn names_any(&self, ids: &[&str]) -> bool {
        self.names.iter().any(|name| ids.contains(&name.as_str()))
    }

    fn origin(&self) -> String {
        format!(
            "statement {} of {}",
            self.statement + 1,
            self.path.display()
        )
    }
}

/// Statements from every `--vex` file, by product and subcomponent purl.
#[derive(Debug, Default)]
pub(crate) struct VexSet {
    entries: BTreeMap<(String, String), Vec<Entry>>,
}

impl VexSet {
    pub(crate) fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut set = Self::default();
        for path in paths {
            let text = rv_config::read_project_input_string(path).map_err(|err| {
                CliError::InvalidProjectInput {
                    path: path.clone(),
                    reason: format!("cannot read --vex file: {err}"),
                }
            })?;
            set.add(path, &text)?;
        }
        Ok(set)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn add(&mut self, path: &Path, text: &str) -> Result<()> {
        let invalid = |reason: String| CliError::InvalidProjectInput {
            path: path.to_path_buf(),
            reason,
        };
        let document: Document = serde_json::from_str(text)
            .map_err(|err| invalid(format!("not an OpenVEX document raeva reads: {err}")))?;
        if document.context != CONTEXT {
            return Err(invalid(format!(
                "@context is not {CONTEXT}, the only OpenVEX version raeva reads"
            )));
        }
        if document.id.is_empty() || document.author.is_empty() || document.version == 0 {
            return Err(invalid(
                "@id, author and a version of 1 or more are required".to_string(),
            ));
        }
        if chrono::DateTime::parse_from_rfc3339(&document.timestamp).is_err() {
            return Err(invalid("timestamp is not an RFC 3339 time".to_string()));
        }
        for (index, statement) in document.statements.into_iter().enumerate() {
            let statement_error =
                |reason: &str| invalid(format!("statement {}: {reason}", index + 1));
            if statement.vulnerability.name.is_empty() {
                return Err(statement_error("vulnerability.name is empty"));
            }
            match (statement.status, statement.justification) {
                (Status::NotAffected, None) => {
                    return Err(statement_error(
                        "not_affected needs a justification in the subset raeva reads",
                    ));
                }
                (Status::NotAffected, Some(_)) | (_, None) => {}
                (_, Some(_)) => {
                    return Err(statement_error("only not_affected takes a justification"));
                }
            }
            if statement.products.is_empty() {
                return Err(statement_error("products is empty"));
            }
            let mut names = vec![statement.vulnerability.name];
            names.extend(statement.vulnerability.aliases);
            let assessment = Assessment {
                status: statement.status,
                justification: statement.justification,
                impact_statement: statement.impact_statement,
            };
            for product in &statement.products {
                let product_purl = product
                    .component
                    .purl()
                    .map_err(|reason| statement_error(&format!("a product {reason}")))?;
                if product.subcomponents.is_empty() {
                    return Err(statement_error(
                        "a product has no subcomponents; raeva reads statements whose product \
                         is a module purl and whose subcomponent is a dependency purl",
                    ));
                }
                for subcomponent in &product.subcomponents {
                    let purl = subcomponent
                        .purl()
                        .map_err(|reason| statement_error(&format!("a subcomponent {reason}")))?;
                    let entry = Entry {
                        names: names.clone(),
                        assessment: assessment.clone(),
                        path: path.to_path_buf(),
                        statement: index,
                        used: AtomicBool::new(false),
                    };
                    let entries = (self.entries)
                        .entry((product_purl.clone(), purl.clone()))
                        .or_default();
                    let names: Vec<&str> = entry.names.iter().map(String::as_str).collect();
                    if let Some(other) = entries.iter().find(|other| {
                        other.names_any(&names) && !other.assessment.agrees(&entry.assessment)
                    }) {
                        return Err(conflict(other, &entry, &purl, &product_purl));
                    }
                    entries.push(entry);
                }
            }
        }
        Ok(())
    }

    /// The entries about `component` in the module whose purl is `module`:
    /// those for exactly that purl, then those for the purl without its
    /// version.
    fn applying<'a>(&'a self, module: &str, component: &str) -> impl Iterator<Item = &'a Entry> {
        let versionless = versionless_purl(module);
        let keys = [
            Some(module.to_string()),
            versionless.filter(|v| v != module),
        ];
        keys.into_iter().flatten().flat_map(move |product| {
            self.entries
                .get(&(product, component.to_string()))
                .into_iter()
                .flatten()
        })
    }

    /// The statement for `component` in the module `product` about the
    /// advisory known by `ids`, or an error when two such statements
    /// disagree, as they can through an alias or through a versioned and a
    /// versionless product.
    pub(crate) fn assess(
        &self,
        product: &str,
        component: &str,
        ids: &[&str],
    ) -> Result<Option<&Assessment>> {
        let mut found: Option<&Entry> = None;
        for entry in (self.applying(product, component)).filter(|entry| entry.names_any(ids)) {
            entry.used.store(true, Ordering::Relaxed);
            match found {
                Some(first) if !first.assessment.agrees(&entry.assessment) => {
                    return Err(conflict(first, entry, component, product));
                }
                Some(_) => {}
                None => found = Some(entry),
            }
        }
        Ok(found.map(|entry| &entry.assessment))
    }

    /// Every statement about `component` in the module `product`, as
    /// (vulnerability name and aliases, assessment).
    pub(crate) fn statements<'a>(
        &'a self,
        product: &str,
        component: &str,
    ) -> impl Iterator<Item = (&'a [String], &'a Assessment)> {
        self.applying(product, component).map(|entry| {
            entry.used.store(true, Ordering::Relaxed);
            (entry.names.as_slice(), &entry.assessment)
        })
    }

    /// Warn about each statement nothing used. `in_scope` tells whether a
    /// product purl names a module the command looked at, in any version;
    /// a statement that also names a module left out may apply there and
    /// is not reported.
    pub(crate) fn warn_unused(&self, output: &Output, in_scope: impl Fn(&str) -> bool) {
        let mut statements = BTreeMap::<(&Path, usize), (bool, &Entry)>::new();
        for ((product, _), entries) in &self.entries {
            let in_scope = in_scope(product);
            for entry in entries {
                let unused = in_scope && !entry.used.load(Ordering::Relaxed);
                (statements.entry((&entry.path, entry.statement)))
                    .and_modify(|(all_unused, _)| *all_unused &= unused)
                    .or_insert((unused, entry));
            }
        }
        for (_, entry) in statements.into_values().filter(|(unused, _)| *unused) {
            output.warn(
                Warning::new(
                    WarningCode::VexStatementUnused,
                    format!(
                        "{} about {} matched nothing; remove it if it no longer applies",
                        entry.origin(),
                        entry.names[0],
                    ),
                )
                .with_context(serde_json::json!({
                    "path": crate::commands::path_to_forward_slashes(&entry.path),
                    "statement": entry.statement + 1,
                    "vulnerability": entry.names[0],
                })),
            );
        }
    }
}

/// `purl` without its version, which as a statement's product covers every
/// version of the module, or `None` when it has none.
pub(crate) fn versionless_purl(purl: &str) -> Option<String> {
    let (name, qualifiers) = match purl.split_once('?') {
        Some((name, qualifiers)) => (name, Some(qualifiers)),
        None => (purl, None),
    };
    let (path, _) = name.rsplit_once('@')?;
    Some(match qualifiers {
        Some(qualifiers) => format!("{path}?{qualifiers}"),
        None => path.to_string(),
    })
}

/// Whether the purls `product` and `module` name one module, whatever
/// versions they give.
pub(crate) fn same_module(product: &str, module: &str) -> bool {
    let module_of = |purl: &str| versionless_purl(purl).unwrap_or_else(|| purl.to_string());
    module_of(product) == module_of(module)
}

fn conflict(first: &Entry, second: &Entry, component: &str, product: &str) -> CliError {
    CliError::InvalidProjectInput {
        path: second.path.clone(),
        reason: format!(
            "{} and {} say different things about {} for {component} in {product}; raeva \
             does not order statements by time, so remove the one that no longer holds",
            first.origin(),
            second.origin(),
            second.names[0],
        ),
    }
}

/// The statement `raeva vuln triage` records. `product` is `module`, the
/// module's purl, or that purl without its version.
pub(crate) struct NewStatement<'a> {
    pub name: &'a str,
    pub module: &'a str,
    pub product: &'a str,
    pub subcomponent: &'a str,
    pub justification: Justification,
    pub impact_statement: Option<&'a str>,
}

/// Whether [`record`] wrote the file, and the document version it holds.
pub(crate) struct Recorded {
    pub written: bool,
    pub version: u64,
}

/// Add `statement` to the OpenVEX file at `path`, creating it with `author`
/// when it does not exist. `ids` are the advisory's names, which an existing
/// statement may use instead of `statement.name`. An identical statement
/// leaves the file as it is; a different one fails and changes nothing.
pub(crate) fn record(
    path: &Path,
    statement: &NewStatement<'_>,
    ids: &[&str],
    author: Option<&str>,
) -> Result<Recorded> {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let assessment = Assessment {
        status: Status::NotAffected,
        justification: Some(statement.justification),
        impact_statement: statement.impact_statement.map(str::to_string),
    };
    let mut document = match rv_config::read_optional_project_input_string(path)? {
        Some(text) => {
            let mut existing = VexSet::default();
            existing.add(path, &text)?;
            // A statement for this module version or for every version can
            // contradict the new one, and a new versionless one also covers
            // every other version; only one for the same product makes the
            // write a no-op.
            let versionless = versionless_purl(statement.module);
            let overlaps = |product: &str| {
                product == statement.module
                    || versionless.as_deref() == Some(product)
                    || (statement.product != statement.module
                        && same_module(product, statement.module))
            };
            let found: Vec<(&str, &Entry)> = (existing.entries.iter())
                .filter(|((product, subcomponent), _)| {
                    subcomponent == statement.subcomponent && overlaps(product)
                })
                .flat_map(|((product, _), entries)| {
                    entries.iter().map(move |entry| (product.as_str(), entry))
                })
                .filter(|(_, entry)| entry.names_any(ids) || entry.names_any(&[statement.name]))
                .collect();
            if let Some((product, entry)) =
                (found.iter()).find(|(_, entry)| entry.assessment != assessment)
            {
                return Err(CliError::Usage(format!(
                    "{} already records {} as {} for {} in {product}; edit that statement to \
                     change it",
                    entry.origin(),
                    entry.names[0],
                    describe(&entry.assessment),
                    statement.subcomponent,
                )));
            }
            let document = serde_json::from_str::<serde_json::Value>(&text).map_err(|err| {
                CliError::InvalidProjectInput {
                    path: path.to_path_buf(),
                    reason: format!("raeva cannot rewrite it: {err}"),
                }
            })?;
            if found
                .iter()
                .any(|(product, _)| *product == statement.product)
            {
                return Ok(Recorded {
                    written: false,
                    version: document["version"].as_u64().unwrap_or_default(),
                });
            }
            document
        }
        None => {
            let author = new_file_author(path, author)?;
            serde_json::json!({
                "@context": CONTEXT,
                "@id": document_id(path, &now),
                "author": author,
                "timestamp": now,
                "version": 0,
                "statements": [],
            })
        }
    };

    let mut new = serde_json::json!({
        "vulnerability": { "name": statement.name },
        "products": [{
            "@id": statement.product,
            "subcomponents": [{ "@id": statement.subcomponent }],
        }],
        "status": Status::NotAffected,
        "justification": statement.justification,
        "timestamp": now,
    });
    if let Some(impact) = statement.impact_statement {
        new["impact_statement"] = impact.into();
    }
    let version = (document["version"].as_u64().unwrap_or(0).checked_add(1)).ok_or_else(|| {
        CliError::InvalidProjectInput {
            path: path.to_path_buf(),
            reason: "version cannot be raised".to_string(),
        }
    })?;
    document["version"] = version.into();
    document["last_updated"] = now.into();
    document["statements"]
        .as_array_mut()
        .ok_or_else(|| CliError::Internal("OpenVEX statements is not a list".to_string()))?
        .push(new);
    let mut text = serde_json::to_string_pretty(&document)?;
    text.push('\n');
    rv_fs::write_file_atomic(path, text.as_bytes(), rv_fs::NewFileAccess::Shared)
        .map_err(CliError::io_at(path))?;
    Ok(Recorded {
        written: true,
        version,
    })
}

/// The trimmed `author` a new file at `path` needs, or a usage error
/// without one. `raeva vuln triage` checks this before it scans.
pub(crate) fn new_file_author<'a>(path: &Path, author: Option<&'a str>) -> Result<&'a str> {
    author
        .map(str::trim)
        .filter(|author| !author.is_empty())
        .ok_or_else(|| {
            CliError::Usage(format!(
                "{} does not exist; pass --author to create it",
                path.display()
            ))
        })
}

pub(crate) fn describe(assessment: &Assessment) -> String {
    match assessment.justification {
        Some(justification) => format!(
            "{} ({})",
            assessment.status.as_str(),
            justification.as_str()
        ),
        None => assessment.status.as_str().to_string(),
    }
}

/// A `urn:uuid` for a new document, from its path and creation time.
fn document_id(path: &Path, now: &str) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(absolute.to_string_lossy().as_bytes());
    hasher.update(now.as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    format!(
        "urn:uuid:{}",
        crate::commands::util::uuid_v8(&hasher.finalize())
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{Justification, NewStatement, Status, VexSet, record};

    const APP: &str = "pkg:maven/com.example/app@1";
    const LIB: &str = "pkg:maven/org.example/lib@2?classifier=jdk11&type=test-jar";

    fn document(statements: serde_json::Value) -> String {
        serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:test",
            "author": "Example",
            "timestamp": "2026-10-01T00:00:00Z",
            "version": 1,
            "statements": statements,
        })
        .to_string()
    }

    fn statement(name: &str, status: &str, justification: Option<&str>) -> serde_json::Value {
        let mut statement = serde_json::json!({
            "vulnerability": { "name": name },
            "products": [{
                "@id": APP,
                "subcomponents": [{ "identifiers": { "purl": LIB } }],
            }],
            "status": status,
        });
        if let Some(justification) = justification {
            statement["justification"] = justification.into();
        }
        statement
    }

    fn load(files: &[(&str, String)]) -> Result<VexSet, String> {
        let mut set = VexSet::default();
        for (name, text) in files {
            set.add(Path::new(name), text)
                .map_err(|err| err.to_string())?;
        }
        Ok(set)
    }

    #[test]
    fn statements_match_by_alias_and_canonical_purl() {
        let set = load(&[(
            "vex.json",
            document(serde_json::json!([statement(
                "CVE-2024-1",
                "not_affected",
                Some("vulnerable_code_not_in_execute_path")
            )])),
        )])
        .expect("load");
        // The subcomponent's qualifiers are written in another order.
        let lib = "pkg:maven/org.example/lib@2?type=test-jar&classifier=jdk11";
        let lib = rv_maven_types::canonicalize_purl(lib).expect("purl");
        let found = set
            .assess(APP, &lib, &["GHSA-1", "CVE-2024-1"])
            .expect("assess")
            .expect("statement");
        assert_eq!(found.status, Status::NotAffected);
        assert!(found.suppresses());
        assert!(
            set.assess(APP, &lib, &["GHSA-2"])
                .expect("assess")
                .is_none()
        );
        let other = "pkg:maven/com.example/other@1";
        assert!(
            set.assess(other, &lib, &["CVE-2024-1"])
                .expect("assess")
                .is_none()
        );
    }

    /// A product purl without a version covers every version of the
    /// module; a versioned one only that version. The dependency's version
    /// always has to match.
    #[test]
    fn a_versionless_product_covers_every_module_version() {
        let mut versionless = statement("CVE-1", "not_affected", Some("component_not_present"));
        versionless["products"][0]["@id"] = "pkg:maven/com.example/app".into();
        let mut war = statement("CVE-2", "not_affected", Some("component_not_present"));
        war["products"][0]["@id"] = "pkg:maven/com.example/web?type=war".into();
        let set = load(&[(
            "vex.json",
            document(serde_json::json!([
                versionless,
                war,
                statement("CVE-3", "not_affected", Some("component_not_present")),
            ])),
        )])
        .expect("load");
        let found = |module: &str, lib: &str, id: &str| {
            set.assess(module, lib, &[id]).expect("assess").is_some()
        };
        assert!(found(APP, LIB, "CVE-1"));
        assert!(found(
            "pkg:maven/com.example/app@1.0.1-SNAPSHOT",
            LIB,
            "CVE-1"
        ));
        assert!(!found(
            "pkg:maven/com.example/app@1.0.1-SNAPSHOT",
            "pkg:maven/org.example/lib@3?classifier=jdk11&type=test-jar",
            "CVE-1"
        ));
        assert!(!found("pkg:maven/com.example/application@1", LIB, "CVE-1"));
        assert!(found("pkg:maven/com.example/web@7?type=war", LIB, "CVE-2"));
        assert!(!found("pkg:maven/com.example/web@7", LIB, "CVE-2"));
        assert!(found(APP, LIB, "CVE-3"));
        assert!(!found("pkg:maven/com.example/app@2", LIB, "CVE-3"));
        assert_eq!(
            super::versionless_purl(APP).as_deref(),
            Some("pkg:maven/com.example/app")
        );
        assert!(super::same_module(
            "pkg:maven/com.example/app",
            "pkg:maven/com.example/app@9"
        ));
        assert!(super::same_module(
            "pkg:maven/com.example/app@1",
            "pkg:maven/com.example/app@9"
        ));
        assert!(!super::same_module(
            "pkg:maven/com.example/app@1",
            "pkg:maven/com.example/app@1?type=war"
        ));
    }

    /// A versionless and a versioned statement that disagree about one
    /// finding fail when both apply.
    #[test]
    fn a_versionless_and_a_versioned_statement_must_agree() {
        let mut versionless = statement("CVE-1", "not_affected", Some("component_not_present"));
        versionless["products"][0]["@id"] = "pkg:maven/com.example/app".into();
        let set = load(&[(
            "vex.json",
            document(serde_json::json!([
                versionless,
                statement("CVE-1", "affected", None)
            ])),
        )])
        .expect("load");
        let error = set
            .assess(APP, LIB, &["CVE-1"])
            .expect_err("conflict")
            .to_string();
        assert!(error.contains("say different things"), "{error}");
        assert!(
            set.assess("pkg:maven/com.example/app@2", LIB, &["CVE-1"])
                .expect("assess")
                .is_some()
        );
    }

    /// A statement is reported only when no product and dependency it
    /// names matched, and every module it names was in scope.
    #[test]
    fn unused_statements_are_reported_for_modules_in_scope() {
        let mut two_dependencies =
            statement("CVE-1", "not_affected", Some("component_not_present"));
        two_dependencies["products"][0]["subcomponents"]
            .as_array_mut()
            .expect("subcomponents")
            .push(serde_json::json!({"@id": "pkg:maven/org.example/other@1"}));
        let mut two_modules = statement("CVE-4", "not_affected", Some("component_not_present"));
        two_modules["products"]
            .as_array_mut()
            .expect("products")
            .push(serde_json::json!({
                "@id": "pkg:maven/com.example/web@1",
                "subcomponents": [{"@id": LIB}],
            }));
        let set = load(&[(
            "vex.json",
            document(serde_json::json!([
                statement("CVE-1", "not_affected", Some("component_not_present")),
                statement("CVE-2", "not_affected", Some("component_not_present")),
                two_dependencies,
                two_modules,
            ])),
        )])
        .expect("load");
        assert!(set.assess(APP, LIB, &["CVE-1"]).expect("assess").is_some());
        let output = crate::output::Output::for_tests();
        set.warn_unused(&output, |_| false);
        assert!(output.take_warnings().is_empty());
        set.warn_unused(&output, |product| product == APP);
        let warnings = output.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0].code.as_str(), "VEX_STATEMENT_UNUSED");
        assert!(
            warnings[0].message.contains("statement 2 of vex.json"),
            "{}",
            warnings[0].message
        );
        assert_eq!(warnings[0].context["vulnerability"], "CVE-2");
    }

    #[test]
    fn documents_outside_the_subset_fail() {
        let not_affected = |justification| statement("CVE-1", "not_affected", justification);
        let cases = [
            ("{}".to_string(), "not an OpenVEX document"),
            (
                document(serde_json::json!([])).replace("v0.2.0", "v0.0.1"),
                "@context",
            ),
            (
                document(serde_json::json!([not_affected(None)])),
                "needs a justification",
            ),
            (
                document(serde_json::json!([statement(
                    "CVE-1",
                    "affected",
                    Some("component_not_present")
                )])),
                "only not_affected",
            ),
            (
                document(serde_json::json!([not_affected(Some("because"))])),
                "unknown variant `because`",
            ),
            (
                document(serde_json::json!([statement("CVE-1", "unknown", None)])),
                "unknown variant `unknown`",
            ),
            (
                document(serde_json::json!([{
                    "vulnerability": { "name": "CVE-1" },
                    "products": [{ "@id": APP }],
                    "status": "affected",
                }])),
                "no subcomponents",
            ),
            (
                document(serde_json::json!([{
                    "vulnerability": { "name": "CVE-1" },
                    "products": [{ "@id": "urn:x", "subcomponents": [{ "@id": LIB }] }],
                    "status": "affected",
                }])),
                "names no purl",
            ),
            (
                document(serde_json::json!([{
                    "vulnerability": { "name": "CVE-1" },
                    "products": [{ "@id": APP, "subcomponents": [{ "@id": format!("{LIB}#safe") }] }],
                    "status": "affected",
                }])),
                "a subcomponent purl has a subpath",
            ),
            (
                document(serde_json::json!([{
                    "vulnerability": { "name": "CVE-1" },
                    "products": [{ "@id": format!("{APP}#web"), "subcomponents": [{ "@id": LIB }] }],
                    "status": "affected",
                }])),
                "a product purl has a subpath",
            ),
        ];
        for (text, expected) in cases {
            let error = load(&[("vex.json", text)]).expect_err(expected);
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    /// No statement supersedes another: two that disagree fail, in one file,
    /// across files, or through an alias. Agreeing ones are fine.
    #[test]
    fn conflicting_statements_fail() {
        let fixed = statement("CVE-1", "fixed", None);
        let unaffected = statement("CVE-1", "not_affected", Some("component_not_present"));
        let error = load(&[
            ("a.json", document(serde_json::json!([unaffected.clone()]))),
            ("b.json", document(serde_json::json!([fixed.clone()]))),
        ])
        .expect_err("conflict across files");
        assert!(
            error.contains("statement 1 of a.json and statement 1 of b.json"),
            "{error}"
        );
        assert!(
            load(&[(
                "a.json",
                document(serde_json::json!([unaffected.clone(), fixed]))
            )])
            .is_err()
        );
        load(&[(
            "a.json",
            document(serde_json::json!([unaffected.clone(), unaffected.clone()])),
        )])
        .expect("agreeing statements");

        let set = load(&[(
            "a.json",
            document(serde_json::json!([
                unaffected,
                statement("GHSA-1", "affected", None)
            ])),
        )])
        .expect("different names load");
        let error = set
            .assess(APP, LIB, &["GHSA-1", "CVE-1"])
            .expect_err("alias conflict")
            .to_string();
        assert!(error.contains("say different things"), "{error}");
    }

    fn new_statement(justification: Justification) -> NewStatement<'static> {
        NewStatement {
            name: "CVE-1",
            module: APP,
            product: APP,
            subcomponent: LIB,
            justification,
            impact_statement: Some("never called"),
        }
    }

    #[test]
    fn record_creates_appends_and_keeps_identical_statements_once() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        let statement = new_statement(Justification::VulnerableCodeNotInExecutePath);
        let error = record(&path, &statement, &["CVE-1"], None)
            .err()
            .expect("a new file needs an author");
        assert!(error.to_string().contains("--author"), "{error}");
        assert!(!path.exists());

        let recorded = record(&path, &statement, &["CVE-1"], Some("Example")).expect("create");
        assert!(recorded.written);
        assert_eq!(recorded.version, 1);
        let created: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("JSON");
        assert_eq!(created["@context"], "https://openvex.dev/ns/v0.2.0");
        assert!(
            created["@id"]
                .as_str()
                .is_some_and(|id| id.starts_with("urn:uuid:"))
        );
        assert_eq!(created["author"], "Example");
        assert_eq!(created["timestamp"], created["last_updated"]);
        let written = &created["statements"][0];
        assert_eq!(written["status"], "not_affected");
        assert_eq!(
            written["justification"],
            "vulnerable_code_not_in_execute_path"
        );
        assert_eq!(written["impact_statement"], "never called");
        assert_eq!(written["products"][0]["@id"], APP);
        assert_eq!(written["products"][0]["subcomponents"][0]["@id"], LIB);
        let set = load(&[("vex.json", fs::read_to_string(&path).expect("read"))]).expect("reload");
        assert!(set.assess(APP, LIB, &["CVE-1"]).expect("assess").is_some());

        // The same statement, found through an alias, changes nothing.
        let before = fs::read(&path).expect("read");
        let alias = NewStatement {
            name: "GHSA-1",
            ..new_statement(Justification::VulnerableCodeNotInExecutePath)
        };
        let again = record(&path, &alias, &["GHSA-1", "CVE-1"], None).expect("no-op");
        assert!(!again.written);
        assert_eq!(again.version, 1);
        assert_eq!(fs::read(&path).expect("read"), before);

        // Another finding bumps the version and keeps what was there.
        let other = NewStatement {
            name: "CVE-2",
            ..new_statement(Justification::ComponentNotPresent)
        };
        let appended = record(&path, &other, &["CVE-2"], None).expect("append");
        assert_eq!(appended.version, 2);
        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("JSON");
        assert_eq!(updated["@id"], created["@id"]);
        assert_eq!(updated["statements"].as_array().map(Vec::len), Some(2));
        assert_eq!(updated["version"], 2);
    }

    /// A versionless statement is written next to an agreeing versioned
    /// one, and refused next to a contradicting one.
    #[test]
    fn record_writes_the_versionless_product_beside_a_versioned_one() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        let versioned = new_statement(Justification::ComponentNotPresent);
        record(&path, &versioned, &["CVE-1"], Some("Example")).expect("versioned");
        let wide = NewStatement {
            product: "pkg:maven/com.example/app",
            ..new_statement(Justification::ComponentNotPresent)
        };
        let recorded = record(&path, &wide, &["CVE-1"], None).expect("versionless");
        assert!(recorded.written);
        assert!(
            !record(&path, &wide, &["CVE-1"], None)
                .expect("again")
                .written
        );
        let other = NewStatement {
            product: "pkg:maven/com.example/app",
            ..new_statement(Justification::VulnerableCodeNotPresent)
        };
        let error = record(&path, &other, &["CVE-1"], None)
            .err()
            .expect("contradiction");
        assert!(
            error.to_string().contains("already records CVE-1"),
            "{error}"
        );
    }

    /// A versionless statement covers every module version, so one that
    /// contradicts a statement about another version is refused.
    #[test]
    fn record_refuses_a_versionless_product_another_version_contradicts() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        fs::write(
            &path,
            document(serde_json::json!([statement("CVE-1", "affected", None)])),
        )
        .expect("write");
        let next = NewStatement {
            module: "pkg:maven/com.example/app@2",
            product: "pkg:maven/com.example/app",
            ..new_statement(Justification::ComponentNotPresent)
        };
        let error = record(&path, &next, &["CVE-1"], None)
            .err()
            .expect("contradiction");
        assert!(error.to_string().contains(&format!("in {APP}")), "{error}");
        let narrow = NewStatement {
            module: "pkg:maven/com.example/app@2",
            product: "pkg:maven/com.example/app@2",
            ..new_statement(Justification::ComponentNotPresent)
        };
        assert!(
            record(&path, &narrow, &["CVE-1"], None)
                .expect("narrow")
                .written
        );
    }

    #[test]
    fn record_refuses_a_contradiction_without_touching_the_file() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        fs::write(
            &path,
            document(serde_json::json!([statement("GHSA-1", "affected", None)])),
        )
        .expect("write");
        let before = fs::read(&path).expect("read");
        for justification in [
            Justification::ComponentNotPresent,
            Justification::VulnerableCodeNotPresent,
        ] {
            let error = record(
                &path,
                &new_statement(justification),
                &["CVE-1", "GHSA-1"],
                None,
            )
            .err()
            .expect("contradiction");
            assert!(
                error
                    .to_string()
                    .contains("already records GHSA-1 as affected"),
                "{error}"
            );
            assert_eq!(fs::read(&path).expect("read"), before);
        }
        // A different justification contradicts too.
        record(
            &path,
            &NewStatement {
                name: "CVE-9",
                ..new_statement(Justification::ComponentNotPresent)
            },
            &["CVE-9"],
            None,
        )
        .expect("record");
        let before = fs::read(&path).expect("read");
        let error = record(
            &path,
            &NewStatement {
                name: "CVE-9",
                ..new_statement(Justification::VulnerableCodeNotPresent)
            },
            &["CVE-9"],
            None,
        )
        .err()
        .expect("other justification");
        assert!(
            error.to_string().contains("component_not_present"),
            "{error}"
        );
        assert_eq!(fs::read(&path).expect("read"), before);
    }

    /// A document raeva reads but cannot extend fails as input, and the file
    /// keeps its bytes.
    #[test]
    fn record_refuses_documents_it_cannot_rewrite() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        let statement = new_statement(Justification::ComponentNotPresent);
        let maximum = document(serde_json::json!([]))
            .replace("\"version\":1", &format!("\"version\":{}", u64::MAX));
        let huge =
            document(serde_json::json!([])).replace("\"version\":1", "\"version\":1,\"x\":1e999");
        for (text, expected) in [
            (maximum, "version cannot be raised"),
            (huge, "cannot rewrite"),
        ] {
            fs::write(&path, &text).expect("write");
            let error = record(&path, &statement, &["CVE-1"], None)
                .err()
                .expect("refused");
            assert!(
                matches!(error, crate::error::CliError::InvalidProjectInput { .. }),
                "{error:?}"
            );
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(fs::read_to_string(&path).expect("read"), text);
        }
        fs::remove_file(&path).expect("remove");
        let error = record(&path, &statement, &["CVE-1"], Some("  "))
            .err()
            .expect("an empty author");
        assert!(error.to_string().contains("--author"), "{error}");
        assert!(!path.exists());
    }

    #[test]
    fn an_id_and_identifiers_purl_may_spell_one_purl_differently() {
        let mut same = statement("CVE-1", "affected", None);
        same["products"][0]["subcomponents"][0]["@id"] =
            "pkg:maven/org.example/lib@2?type=test-jar&classifier=jdk11".into();
        load(&[("vex.json", document(serde_json::json!([same.clone()])))]).expect("one purl");
        same["products"][0]["subcomponents"][0]["@id"] = "pkg:maven/org.example/lib@3".into();
        let error = load(&[("vex.json", document(serde_json::json!([same])))]).expect_err("two");
        assert!(error.contains("differ"), "{error}");
    }

    /// The file is replaced by a rename, so a reader never sees a partial
    /// document: a hard link to the old file keeps the old bytes.
    #[cfg(unix)]
    #[test]
    fn record_replaces_the_file_atomically() {
        let dir = tempfile::TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        let statement = new_statement(Justification::ComponentNotPresent);
        record(&path, &statement, &["CVE-1"], Some("Example")).expect("create");
        let old = fs::read(&path).expect("read");
        let link = dir.path().join("old.json");
        fs::hard_link(&path, &link).expect("link");
        let other = NewStatement {
            name: "CVE-2",
            ..new_statement(Justification::ComponentNotPresent)
        };
        record(&path, &other, &["CVE-2"], None).expect("append");
        assert_eq!(fs::read(&link).expect("old"), old);
        assert_ne!(fs::read(&path).expect("new"), old);
        let leftovers = fs::read_dir(dir.path()).expect("dir").count();
        assert_eq!(leftovers, 2, "no temporary file is left behind");
    }
}
