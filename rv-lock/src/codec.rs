//! The TOML form of raeva.lock and the conversion between it and the model.
//!
//! The `Raw*` structs mirror the file: their field names, field order and
//! skip rules decide the bytes `raeva sync` writes, so they change only with
//! the schema. Reading goes text, then a check of the table shape that
//! names the first unknown or missing key, then the raw structs, then
//! [`Lockfile`] through `TryFrom`, which decodes every field into its type
//! and runs every check a written lockfile passes. A value of the model
//! therefore always holds a valid lockfile, however it was read.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use rv_maven_types::{ArtifactCoord, Digest, Gav, HashAlgorithm, Sha256, SnapshotStamp};
use serde::{Deserialize, Serialize};

use crate::ambient::AmbientInput;
use crate::error::{LockError, printable};
use crate::lock::{
    LockArtifact, LockEdge, LockModule, LockModulePackage, LockPlatform, LockResolution, Lockfile,
    ModelInputs, SupportPom, check_schema_version,
};
use crate::lock_origin::{decode_repo_id_lines, encode_repo_id_lines};
use crate::platform::Platform;
use crate::scope::Scope;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLockfile {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolution: Option<RawResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    platforms: Vec<RawPlatform>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inputs: Vec<RawInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<RawMetadata>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResolution {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ambient_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command_line: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) repo_ids: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlatform {
    targets: Vec<String>,
    #[serde(default)]
    artifacts: Vec<RawArtifact>,
    #[serde(default)]
    modules: Vec<RawModule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    support_poms: Vec<RawSupportPom>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInputs {
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ambient_inputs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    poms: Option<Vec<RawPomInput>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repo_ids: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_inputs: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPomInput {
    path: String,
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    graph: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ambient_inputs: Option<Vec<String>>,
}

fn target_name(platform: &Platform) -> String {
    match platform.jdk() {
        Some(jdk) => format!("{}@{jdk}", platform.os_arch()),
        None => platform.os_arch(),
    }
}

fn parse_target(name: &str) -> Result<Platform, LockError> {
    let (name, jdk) = name
        .split_once('@')
        .map_or((name, None), |(p, j)| (p, Some(j)));
    let platform = Platform::from_str(name).map_err(|err| LockError::Invalid(err.to_string()))?;
    match jdk {
        Some(jdk) if rv_config::is_valid_jdk(jdk) => Ok(platform.with_jdk(jdk)),
        Some(_) => Err(LockError::Invalid("invalid jdk in lock target".to_string())),
        None => Ok(platform),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    coordinate: RawCoordinate,
    repo_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    other_repo_urls: Vec<String>,
    checksums: Vec<RawChecksum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<RawSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pom_snapshot: Option<RawSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pom_base: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pom_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pom_repo_urls: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSupportPom {
    coordinate: String,
    repo_url: String,
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<RawSnapshot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCoordinate {
    group: String,
    artifact: String,
    version: String,
    packaging: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    classifier: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChecksum {
    algorithm: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    timestamp: String,
    /// Any TOML integer, so a value outside `u32` gets a message that names
    /// the row instead of a serde type error.
    build_number: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModule {
    path: String,
    /// `group:artifact:version`.
    gav: String,
    packaging: String,
    /// One package per line, in tab-separated columns: `group:artifact:version`,
    /// `packaging[:classifier]`, the direct scope, the workspace module, the
    /// system path and the system SHA-256. Empty trailing columns are left
    /// out. A reactor version or a path may hold `:` or spaces, never a tab.
    packages: String,
    /// One edge per line: `from to`, then the scope and `optional`, each
    /// only when set.
    edges: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    parent_ranges: Vec<crate::ParentRange>,
    /// One support POM coordinate per line.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    support_poms: String,
}

/// Parse `contents`, the text of the lockfile at `path`, into a valid
/// [`Lockfile`]. The origin check against the project directory is the
/// caller's.
pub(crate) fn decode(contents: &str, path: &Path) -> Result<Lockfile, LockError> {
    if let Some(line) = conflict_marker_line(contents) {
        return Err(LockError::Toml {
            path: path.to_path_buf(),
            message: format!("it has a Git merge conflict marker at line {line}"),
        });
    }
    // A Git checkout on Windows may turn the line endings raeva wrote into
    // CRLF, which would otherwise reach the line-based `repo_ids` block.
    let contents = match contents.contains('\r') {
        true => std::borrow::Cow::Owned(contents.replace("\r\n", "\n")),
        false => std::borrow::Cow::Borrowed(contents),
    };
    let doc =
        crate::split_parse::parse(&contents).map_err(|err| toml_error(path, &err, &contents))?;
    let version = doc
        .get("schema_version")
        .ok_or_else(|| {
            LockError::Invalid("missing field \"schema_version\" in the top level".to_string())
        })?
        .as_integer()
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| LockError::Invalid("schema_version must be a whole number".to_string()))?;
    // A lock of another schema is refused as such before its keys are
    // judged by this schema's rules.
    check_schema_version(version)?;
    check_shape(&doc)?;
    let raw: RawLockfile = toml::Value::Table(doc)
        .try_into()
        .map_err(|err| toml_error(path, &err, ""))?;
    Lockfile::try_from(raw)
}

/// The first line, counted from 1, that a Git merge left as a conflict
/// marker. It can be valid TOML inside a multiline string, but never a
/// valid lockfile row.
fn conflict_marker_line(contents: &str) -> Option<usize> {
    contents
        .lines()
        .position(|line| {
            ["<<<<<<<", "|||||||", "=======", ">>>>>>>"]
                .iter()
                .any(|marker| {
                    line.strip_prefix(marker)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
                })
        })
        .map(|index| index + 1)
}

/// `err` at its line and column in `contents`, noting a file that ends
/// there, as a cut-off copy or write does.
fn toml_error(path: &Path, err: &toml::de::Error, contents: &str) -> LockError {
    let mut message = printable(err.message());
    if let Some(before) = err.span().and_then(|span| contents.get(..span.start)) {
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit('\n')
            .next()
            .unwrap_or_default()
            .chars()
            .count()
            + 1;
        message = format!("{message} (line {line}, column {column})");
        if contents[before.len()..].trim().is_empty() {
            message.push_str("; the file ends there, so it may be cut off");
        }
    }
    LockError::Toml {
        path: path.to_path_buf(),
        message,
    }
}

impl TryFrom<RawLockfile> for Lockfile {
    type Error = LockError;

    fn try_from(raw: RawLockfile) -> Result<Self, LockError> {
        check_schema_version(raw.schema_version)?;
        let resolution = raw
            .resolution
            .map(decode_resolution)
            .transpose()?
            .unwrap_or_default();
        let mut inputs = BTreeMap::new();
        for input in raw.inputs {
            parse_target(&input.target)?;
            let target = input.target.clone();
            if inputs.insert(target.clone(), input).is_some() {
                return Err(LockError::Invalid(format!(
                    "duplicate inputs for target '{target}'"
                )));
            }
        }
        let mut platforms = Vec::new();
        for mut graph in raw.platforms {
            if graph.targets.is_empty() {
                return Err(LockError::Invalid(
                    "a platform graph must cover at least one target".to_string(),
                ));
            }
            let targets = std::mem::take(&mut graph.targets);
            let mut decoded = decode_platform(graph, parse_target(&targets[0])?)?;
            for (index, target) in targets.iter().enumerate() {
                let input = inputs.remove(target).ok_or_else(|| {
                    LockError::Invalid(format!("missing or duplicate inputs for target '{target}'"))
                })?;
                decoded.platform = parse_target(target)?;
                decoded.repo_ids = (input.repo_ids.as_deref())
                    .map(decode_repo_id_lines)
                    .transpose()?;
                let on = format!("the inputs of target '{target}'");
                decoded.host_inputs = (input.host_inputs.as_deref())
                    .map(|names| decode_host_inputs(names, &on))
                    .transpose()?;
                decoded.model_inputs = match (input.profiles, input.poms, input.model_hash) {
                    (Some(profiles), Some(poms), None) => {
                        let mut pom_hashes = BTreeMap::new();
                        let mut graphs = BTreeMap::new();
                        let mut module_ambient_inputs = BTreeMap::new();
                        for pom in poms {
                            if let Some(names) = &pom.ambient_inputs {
                                if !(decoded.modules.iter()).any(|module| module.path == pom.path) {
                                    return Err(LockError::Invalid(format!(
                                        "POM input {:?} of {on} lists ambient inputs but is no module",
                                        printable(&pom.path)
                                    )));
                                }
                                module_ambient_inputs
                                    .insert(pom.path.clone(), decode_read_names(names, &on)?);
                            }
                            let invalid = || {
                                LockError::Invalid(format!(
                                    "POM input {:?} must have 64 lowercase hex characters",
                                    pom.path
                                ))
                            };
                            let digest = lowercase_sha256(&pom.sha256).ok_or_else(invalid)?;
                            if let Some(graph) = &pom.graph {
                                let graph = lowercase_sha256(graph).ok_or_else(invalid)?;
                                graphs.insert(pom.path.clone(), graph);
                            }
                            if pom_hashes.insert(pom.path, digest).is_some() {
                                return Err(LockError::Invalid(
                                    "duplicate POM input path".to_string(),
                                ));
                            }
                        }
                        decoded.model_hash =
                            crate::inputs::model_records_hash(&profiles, &pom_hashes);
                        let ambient_inputs = (input.ambient_inputs.as_deref())
                            .map(|names| decode_read_names(names, &on))
                            .transpose()?
                            .unwrap_or_default();
                        if let Some(name) = (module_ambient_inputs.values())
                            .flatten()
                            .find(|name| ambient_inputs.contains(name))
                        {
                            return Err(LockError::Invalid(format!(
                                "ambient input {:?} of {on} is listed for the target and for a \
                                 module",
                                name.to_string()
                            )));
                        }
                        Some(ModelInputs {
                            profiles,
                            pom_hashes,
                            graphs,
                            ambient_inputs,
                            module_ambient_inputs,
                        })
                    }
                    (None, None, Some(hash)) if input.ambient_inputs.is_none() => {
                        decoded.model_hash = hash;
                        None
                    }
                    _ => {
                        return Err(LockError::Invalid(
                            "target inputs need profiles and poms, or only model_hash".to_string(),
                        ));
                    }
                };
                if index + 1 == targets.len() {
                    platforms.push(decoded);
                    break;
                }
                platforms.push(decoded.clone());
            }
        }
        if !inputs.is_empty() {
            return Err(LockError::Invalid(
                "target inputs have no platform graph".to_string(),
            ));
        }
        platforms.sort_by_key(|entry| entry.platform.to_string());
        let metadata = raw.metadata.unwrap_or_default();
        let lock = Lockfile {
            config_hash: raw.config_hash,
            resolution,
            platforms,
            repo_ids: decode_repo_id_lines(metadata.repo_ids.as_deref().unwrap_or_default())?,
        };
        lock.check()?;
        Ok(lock)
    }
}

/// The property and variable names a graph read, as `on` lists them.
fn decode_read_names(names: &[String], on: &str) -> Result<BTreeSet<AmbientInput>, LockError> {
    if names.is_empty() {
        return Err(LockError::Invalid(format!(
            "an empty ambient_inputs list in {on}; raeva leaves it out"
        )));
    }
    let mut decoded = BTreeSet::new();
    for name in names {
        let input =
            AmbientInput::from_str(name).map_err(|err| LockError::Invalid(err.to_string()))?;
        if !input.is_property_name() {
            return Err(LockError::Invalid(format!(
                "ambient input {name:?} of {on} is not a property or variable name"
            )));
        }
        if !decoded.insert(input) {
            return Err(LockError::Invalid(format!(
                "duplicate ambient input {name:?} in {on}"
            )));
        }
    }
    Ok(decoded)
}

/// The conditions and host values a target consulted, as `on` lists them.
fn decode_host_inputs(names: &[String], on: &str) -> Result<BTreeSet<AmbientInput>, LockError> {
    let mut decoded = BTreeSet::new();
    for name in names {
        let input =
            AmbientInput::from_str(name).map_err(|err| LockError::Invalid(err.to_string()))?;
        if !decoded.insert(input) {
            return Err(LockError::Invalid(format!(
                "duplicate host input {name:?} in {on}"
            )));
        }
    }
    Ok(decoded)
}

fn read_name_texts(names: &BTreeSet<AmbientInput>) -> Option<Vec<String>> {
    (!names.is_empty()).then(|| names.iter().map(ToString::to_string).collect())
}

fn decode_resolution(raw: RawResolution) -> Result<LockResolution, LockError> {
    if raw.ambient_inputs.is_empty() && raw.command_line.is_empty() {
        return Err(LockError::Invalid(
            "the [resolution] table is empty; raeva writes it only with entries".to_string(),
        ));
    }
    let mut ambient_inputs = BTreeSet::new();
    for name in &raw.ambient_inputs {
        let input =
            AmbientInput::from_str(name).map_err(|err| LockError::Invalid(err.to_string()))?;
        if let AmbientInput::Condition { condition, holds } = &input {
            let opposite = AmbientInput::Condition {
                condition: condition.clone(),
                holds: !holds,
            };
            if ambient_inputs.contains(&opposite) {
                return Err(LockError::Invalid(format!(
                    "ambient input {name:?} in [resolution] is listed with both outcomes"
                )));
            }
        }
        if !ambient_inputs.insert(input) {
            return Err(LockError::Invalid(format!(
                "duplicate ambient input {name:?} in [resolution]"
            )));
        }
    }
    let mut command_line = BTreeSet::new();
    for option in &raw.command_line {
        if !is_command_line_name(option) {
            return Err(LockError::Invalid(format!(
                "command-line option {:?} in [resolution] is not -DNAME or -PID",
                printable(option)
            )));
        }
        if !command_line.insert(option.clone()) {
            return Err(LockError::Invalid(format!(
                "duplicate command-line option {:?} in [resolution]",
                printable(option)
            )));
        }
    }
    Ok(LockResolution {
        ambient_inputs,
        command_line,
    })
}

/// A `[resolution] command_line` entry: `-D` or `-P`, then a name of 1 to
/// 256 printable ASCII characters other than `=` and space.
pub fn is_command_line_name(option: &str) -> bool {
    (option
        .strip_prefix("-D")
        .or_else(|| option.strip_prefix("-P")))
    .is_some_and(is_option_name)
}

/// The name of an [`is_command_line_name`] entry.
pub(crate) fn is_option_name(name: &str) -> bool {
    (1..=256).contains(&name.len())
        && (name.bytes()).all(|byte| byte.is_ascii_graphic() && byte != b'=')
}

fn decode_platform(raw: RawPlatform, platform: Platform) -> Result<LockPlatform, LockError> {
    let on = format!("platform '{platform}'");
    let artifacts = raw
        .artifacts
        .into_iter()
        .map(|artifact| decode_artifact(artifact, &platform))
        .collect::<Result<_, _>>()?;
    let modules = rv_maven_types::par_map(&raw.modules, |module| decode_module(module, &platform))
        .into_iter()
        .collect::<Result<_, _>>()?;
    let mut support_poms = BTreeMap::new();
    for pom in raw.support_poms {
        let coord = printable(&pom.coordinate);
        let sha256 = lowercase_sha256(&pom.sha256).ok_or_else(|| {
            LockError::Invalid(format!(
                "sha256 {:?} of support POM '{coord}' on {on} must be 64 lowercase hex characters",
                pom.sha256
            ))
        })?;
        let snapshot = pom
            .snapshot
            .map(|snapshot| decode_snapshot(snapshot, || format!("support POM '{coord}' on {on}")))
            .transpose()?;
        let pin = SupportPom {
            repo_url: pom.repo_url,
            sha256,
            snapshot,
        };
        if support_poms.insert(pom.coordinate, pin).is_some() {
            return Err(LockError::Invalid(format!(
                "duplicate support POM '{coord}' on {on}"
            )));
        }
    }
    Ok(LockPlatform {
        platform,
        model_hash: String::new(),
        artifacts,
        modules,
        support_poms,
        model_inputs: None,
        repo_ids: None,
        host_inputs: None,
    })
}

fn decode_snapshot(
    snapshot: RawSnapshot,
    row: impl Fn() -> String,
) -> Result<SnapshotStamp, LockError> {
    let build = u32::try_from(snapshot.build_number).map_err(|_| {
        LockError::Invalid(format!(
            "snapshot build_number {} for {} must be between 0 and {}",
            snapshot.build_number,
            row(),
            u32::MAX
        ))
    })?;
    SnapshotStamp::new(&snapshot.timestamp, build).ok_or_else(|| {
        LockError::Invalid(format!(
            "snapshot timestamp {:?} for {} must use YYYYMMDD.HHMMSS",
            snapshot.timestamp,
            row()
        ))
    })
}

fn encode_snapshot(stamp: &SnapshotStamp) -> RawSnapshot {
    RawSnapshot {
        timestamp: stamp.timestamp().to_string(),
        build_number: i64::from(stamp.build()),
    }
}

/// `row` names the table for the error about an empty classifier, which
/// [`ArtifactCoord`] cannot hold apart from none: `classifier = ""` would be
/// a second row for the classifier-less file, one path in a repository.
fn decode_coordinate(
    raw: RawCoordinate,
    row: impl Fn() -> String,
) -> Result<ArtifactCoord, LockError> {
    if raw.classifier.as_deref() == Some("") {
        return Err(LockError::Invalid(format!(
            "invalid {}: classifier must be omitted rather than empty",
            row()
        )));
    }
    Ok(ArtifactCoord::new(
        &raw.group,
        &raw.artifact,
        &raw.version,
        &raw.packaging,
        raw.classifier.as_deref(),
    ))
}

fn decode_artifact(raw: RawArtifact, platform: &Platform) -> Result<LockArtifact, LockError> {
    let coordinate = decode_coordinate(raw.coordinate, || {
        format!("artifact table on platform '{platform}'")
    })?;
    let coord = printable(&coordinate.to_string());
    let mut checksums = Vec::with_capacity(raw.checksums.len());
    for row in raw.checksums {
        let Some(algorithm) = HashAlgorithm::parse(&row.algorithm) else {
            return Err(LockError::Invalid(format!(
                "unsupported checksum algorithm '{}' on {coord} (platform {platform}); \
                 supported algorithms are sha256 and sha1",
                printable(&row.algorithm)
            )));
        };
        let digest = Digest::parse(algorithm.as_str(), &row.digest)
            .ok()
            .filter(|_| row.digest.len() == algorithm.hex_len())
            .ok_or_else(|| {
                LockError::Invalid(format!(
                    "invalid {algorithm} digest for {coord} (platform {platform}): expected {} \
                     hex characters, got {:?}",
                    algorithm.hex_len(),
                    row.digest
                ))
            })?;
        checksums.push(digest);
    }
    let decode = |snapshot| {
        decode_snapshot(snapshot, || {
            format!("artifact '{coord}' on platform '{platform}'")
        })
    };
    let snapshot = raw.snapshot.map(decode).transpose()?;
    let pom_snapshot = raw.pom_snapshot.map(decode).transpose()?;
    // Written only when true, so a lock has one spelling.
    let pom_base = match raw.pom_base {
        Some(false) => {
            return Err(LockError::Invalid(format!(
                "pom_base for artifact '{coord}' on platform '{platform}' is written only as true"
            )));
        }
        pom_base => pom_base.is_some(),
    };
    // Hex in either case is accepted and kept lowercase: every comparison
    // downstream (blob id, lock equality, the frozen match) is byte-wise.
    let pom_sha256 = raw
        .pom_sha256
        .map(|digest| {
            Sha256::from_str(&digest).map_err(|_| {
                LockError::Invalid(format!(
                    "pom_sha256 {digest:?} for artifact '{coord}' on platform '{platform}' must \
                     be 64 hex characters"
                ))
            })
        })
        .transpose()?;
    if !raw.other_repo_urls.is_sorted_by(|left, right| left < right)
        || raw.other_repo_urls.contains(&raw.repo_url)
    {
        return Err(LockError::Invalid(format!(
            "other_repo_urls for artifact '{coord}' on platform '{platform}' must be sorted \
             distinct origins other than repo_url"
        )));
    }
    if !raw.pom_repo_urls.is_sorted_by(|left, right| left < right) {
        return Err(LockError::Invalid(format!(
            "pom_repo_urls for artifact '{coord}' on platform '{platform}' must be sorted \
             distinct origins"
        )));
    }
    Ok(LockArtifact {
        coordinate,
        repo_url: raw.repo_url,
        other_repo_urls: raw.other_repo_urls,
        checksums,
        snapshot,
        pom_snapshot,
        pom_base,
        pom_sha256,
        pom_repo_urls: raw.pom_repo_urls,
    })
}

fn decode_scope(
    scope: Option<String>,
    what: impl FnOnce() -> String,
) -> Result<Option<Scope>, LockError> {
    scope
        .map(|scope| {
            Scope::from_str(&scope).map_err(|_| {
                LockError::Invalid(format!(
                    "{} is {scope:?}; expected one of {}",
                    what(),
                    Scope::ALL.map(Scope::as_str).join(", ")
                ))
            })
        })
        .transpose()
}

fn decode_module(raw: &RawModule, platform: &Platform) -> Result<LockModule, LockError> {
    let row = format!("module '{}' on platform '{platform}'", printable(&raw.path));
    let packages = lines(&raw.packages)
        .enumerate()
        .map(|(index, line)| {
            decode_package(line, || format!("package line {} of {row}", index + 1))
        })
        .collect::<Result<_, _>>()?;
    let edges = lines(&raw.edges)
        .enumerate()
        .map(|(index, line)| decode_edge(line, || format!("edge line {} of {row}", index + 1)))
        .collect::<Result<_, _>>()?;
    let Some((group, artifact, version)) = crate::lock::split_reactor_gav(&raw.gav) else {
        return Err(LockError::Invalid(format!(
            "gav {:?} of {row} must be 'group:artifact:version'",
            printable(&raw.gav)
        )));
    };
    let support_poms = lines(&raw.support_poms)
        .map(|coord| {
            crate::lock::validate_support_pom_coord(coord)?;
            Ok(coord.to_owned())
        })
        .collect::<Result<_, LockError>>()?;
    Ok(LockModule {
        path: raw.path.clone(),
        gav: Gav::new(group, artifact, version),
        packaging: raw.packaging.clone(),
        packages,
        edges,
        parent_ranges: raw.parent_ranges.clone(),
        support_poms,
    })
}

fn lines(block: &str) -> impl Iterator<Item = &str> {
    block.split('\n').filter(|_| !block.is_empty())
}

fn decode_package(line: &str, row: impl Fn() -> String) -> Result<LockModulePackage, LockError> {
    let invalid = |what: &str| LockError::Invalid(format!("invalid {}: {what}", row()));
    let mut columns = line.split('\t');
    let mut column = || columns.next().filter(|value| !value.is_empty());
    let (gav, kind) = (column(), column());
    let coordinate = gav
        .and_then(crate::lock::split_reactor_gav)
        .zip(kind)
        .and_then(|((group, artifact, version), kind)| {
            let (packaging, classifier) = match kind.split_once(':') {
                Some((packaging, classifier)) => (packaging, Some(classifier)),
                None => (kind, None),
            };
            (!classifier.is_some_and(str::is_empty))
                .then(|| ArtifactCoord::new(group, artifact, version, packaging, classifier))
        })
        .ok_or_else(|| {
            invalid("it must start with group:artifact:version and packaging[:classifier]")
        })?;
    let direct_scope = decode_scope(column().map(str::to_string), || {
        format!("the direct scope in the {}", row())
    })?;
    let mut package = LockModulePackage::new(coordinate, direct_scope);
    if let Some(scope) = decode_scope(column().map(str::to_string), || {
        format!("the scope in the {}", row())
    })? {
        if scope == package.scope {
            return Err(invalid(
                "its scope column must be empty when it is the direct scope or compile",
            ));
        }
        package.scope = scope;
    }
    package.workspace_module = column().map(str::to_string);
    package.system_path = column().map(str::to_string);
    package.system_sha256 = column()
        .map(|digest| {
            lowercase_sha256(digest)
                .ok_or_else(|| invalid("the system SHA-256 must be 64 lowercase hex characters"))
        })
        .transpose()?;
    if columns.next().is_some() {
        return Err(invalid("it has more than seven columns"));
    }
    Ok(package)
}

fn decode_edge(line: &str, row: impl Fn() -> String) -> Result<LockEdge, LockError> {
    let invalid = || {
        LockError::Invalid(format!(
            "invalid {}: {:?} is not 'from to [scope] [optional]'",
            row(),
            printable(line)
        ))
    };
    let mut fields = line.split(' ');
    let mut index = || -> Result<usize, LockError> {
        let field = fields.next().ok_or_else(invalid)?;
        field
            .parse()
            .ok()
            .filter(|_| field.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(invalid)
    };
    let (from, to) = (index()?, index()?);
    let mut edge = LockEdge::new(from, to, None, false);
    for field in fields {
        if edge.optional {
            return Err(invalid());
        } else if field == "optional" {
            edge.optional = true;
        } else if edge.scope.is_none() {
            edge.scope = decode_scope(Some(field.to_string()), || {
                format!("the scope in the {}", row())
            })?;
        } else {
            return Err(invalid());
        }
    }
    Ok(edge)
}

pub(crate) fn encode_packages(module: &LockModule) -> String {
    let mut block = String::new();
    for (index, package) in module.packages.iter().enumerate() {
        let coordinate = &package.coordinate;
        let gav = coordinate.gav.to_string();
        let kind = match coordinate.classifier() {
            Some(classifier) => Cow::Owned(format!("{}:{classifier}", coordinate.extension())),
            None => Cow::Borrowed(coordinate.extension()),
        };
        let system_sha256 = package.system_sha256.as_ref().map(ToString::to_string);
        let columns = [
            gav.as_str(),
            &kind,
            package.direct_scope.map_or("", Scope::as_str),
            match package.direct_scope.unwrap_or(Scope::Compile) {
                scope if scope == package.scope => "",
                _ => package.scope.as_str(),
            },
            package.workspace_module.as_deref().unwrap_or_default(),
            package.system_path.as_deref().unwrap_or_default(),
            system_sha256.as_deref().unwrap_or_default(),
        ];
        let kept = columns.iter().rposition(|column| !column.is_empty());
        if index > 0 {
            block.push('\n');
        }
        for (at, column) in columns[..kept.map_or(0, |last| last + 1)]
            .iter()
            .enumerate()
        {
            if at > 0 {
                block.push('\t');
            }
            block.push_str(column);
        }
    }
    block
}

pub(crate) fn encode_edges(module: &LockModule) -> String {
    use std::fmt::Write;
    let mut block = String::new();
    for (index, edge) in module.edges.iter().enumerate() {
        if index > 0 {
            block.push('\n');
        }
        let _ = write!(block, "{} {}", edge.from, edge.to);
        if let Some(scope) = edge.scope {
            block.push(' ');
            block.push_str(scope.as_str());
        }
        if edge.optional {
            block.push_str(" optional");
        }
    }
    block
}

pub(crate) fn encode(lock: &Lockfile) -> Result<RawLockfile, LockError> {
    let repo_ids = (!lock.repo_ids.is_empty())
        .then(|| encode_repo_id_lines(&lock.repo_ids))
        .transpose()?;
    let metadata = repo_ids.is_some().then_some(RawMetadata { repo_ids });
    Ok(RawLockfile {
        schema_version: crate::lock::LOCKFILE_SCHEMA_VERSION,
        config_hash: lock.config_hash.clone(),
        resolution: (lock.resolution != LockResolution::default()).then(|| RawResolution {
            ambient_inputs: lock
                .resolution
                .ambient_inputs
                .iter()
                .map(ToString::to_string)
                .collect(),
            command_line: lock.resolution.command_line.iter().cloned().collect(),
        }),
        platforms: {
            let mut graphs: Vec<(&LockPlatform, RawPlatform)> = Vec::new();
            for platform in &lock.platforms {
                if let Some((_, graph)) = graphs.iter_mut().find(|(other, _)| {
                    other.artifacts == platform.artifacts
                        && other.modules == platform.modules
                        && other.support_poms == platform.support_poms
                }) {
                    graph.targets.push(target_name(&platform.platform));
                } else {
                    graphs.push((platform, encode_platform(platform)?));
                }
            }
            graphs.into_iter().map(|(_, graph)| graph).collect()
        },
        inputs: lock
            .platforms
            .iter()
            .map(|platform| {
                Ok(RawInputs {
                    target: target_name(&platform.platform),
                    model_hash: platform
                        .model_inputs
                        .is_none()
                        .then(|| platform.model_hash.clone()),
                    profiles: platform
                        .model_inputs
                        .as_ref()
                        .map(|inputs| inputs.profiles.clone()),
                    ambient_inputs: (platform.model_inputs.as_ref())
                        .and_then(|inputs| read_name_texts(&inputs.ambient_inputs)),
                    poms: platform.model_inputs.as_ref().map(|inputs| {
                        inputs
                            .pom_hashes
                            .iter()
                            .map(|(path, digest)| RawPomInput {
                                path: path.clone(),
                                sha256: digest.to_string(),
                                graph: inputs.graphs.get(path).map(ToString::to_string),
                                ambient_inputs: (inputs.module_ambient_inputs.get(path))
                                    .and_then(read_name_texts),
                            })
                            .collect()
                    }),
                    repo_ids: (platform.repo_ids.as_ref())
                        .map(encode_repo_id_lines)
                        .transpose()?,
                    host_inputs: (platform.host_inputs.as_ref())
                        .map(|inputs| inputs.iter().map(ToString::to_string).collect()),
                })
            })
            .collect::<Result<_, LockError>>()?,
        metadata,
    })
}

fn encode_platform(platform: &LockPlatform) -> Result<RawPlatform, LockError> {
    Ok(RawPlatform {
        targets: vec![target_name(&platform.platform)],
        artifacts: platform
            .artifacts
            .iter()
            .map(|artifact| RawArtifact {
                coordinate: RawCoordinate {
                    group: artifact.coordinate.group_id().to_string(),
                    artifact: artifact.coordinate.artifact_id().to_string(),
                    version: artifact.coordinate.version().to_string(),
                    packaging: artifact.coordinate.extension().to_string(),
                    classifier: artifact.coordinate.classifier().map(str::to_string),
                },
                repo_url: artifact.repo_url.clone(),
                other_repo_urls: artifact.other_repo_urls.clone(),
                checksums: artifact
                    .checksums
                    .iter()
                    .map(|digest| RawChecksum {
                        algorithm: digest.algorithm().as_str().to_string(),
                        digest: digest.hex().to_string(),
                    })
                    .collect(),
                snapshot: artifact.snapshot.as_ref().map(encode_snapshot),
                pom_snapshot: artifact.pom_snapshot.as_ref().map(encode_snapshot),
                pom_base: artifact.pom_base.then_some(true),
                pom_sha256: artifact.pom_sha256.as_ref().map(ToString::to_string),
                pom_repo_urls: artifact.pom_repo_urls.clone(),
            })
            .collect(),
        modules: rv_maven_types::par_map(&platform.modules, |module| RawModule {
            path: module.path.clone(),
            gav: module.gav.to_string(),
            packaging: module.packaging.clone(),
            packages: encode_packages(module),
            edges: encode_edges(module),
            parent_ranges: module.parent_ranges.clone(),
            support_poms: module.support_poms.join("\n"),
        }),
        support_poms: platform
            .support_poms
            .iter()
            .map(|(coord, pin)| RawSupportPom {
                coordinate: coord.clone(),
                repo_url: pin.repo_url.clone(),
                sha256: pin.sha256.to_string(),
                snapshot: pin.snapshot.as_ref().map(encode_snapshot),
            })
            .collect(),
    })
}

fn lowercase_sha256(value: &str) -> Option<Sha256> {
    is_sha256_hex(value).then(|| Sha256::from_str(value).ok())?
}

/// True for a canonical SHA-256 digest: 64 lowercase hex characters.
pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

type Shape = [&'static str];

const TOP: &Shape = &[
    "schema_version",
    "config_hash?",
    "resolution?",
    "platforms?",
    "inputs?",
    "metadata?",
];
const RESOLUTION: &Shape = &["ambient_inputs?", "command_line?"];
const METADATA: &Shape = &["repo_ids?"];
const PLATFORM: &Shape = &["targets", "artifacts?", "modules?", "support_poms?"];
const INPUTS: &Shape = &[
    "target",
    "model_hash?",
    "profiles?",
    "ambient_inputs?",
    "poms?",
    "repo_ids?",
    "host_inputs?",
];
const POM_INPUT: &Shape = &["path", "sha256", "graph?", "ambient_inputs?"];
const SUPPORT_POM: &Shape = &["coordinate", "repo_url", "sha256", "snapshot?"];
const ARTIFACT: &Shape = &[
    "coordinate",
    "repo_url",
    "other_repo_urls?",
    "checksums",
    "snapshot?",
    "pom_snapshot?",
    "pom_base?",
    "pom_sha256?",
    "pom_repo_urls?",
];
const COORDINATE: &Shape = &["group", "artifact", "version", "packaging", "classifier?"];
const CHECKSUM: &Shape = &["algorithm", "digest"];
const SNAPSHOT: &Shape = &["timestamp", "build_number"];
const MODULE: &Shape = &[
    "path",
    "gav",
    "packaging",
    "packages",
    "edges",
    "parent_ranges?",
    "support_poms?",
];

/// `None` when `table` has the keys of `shape`; otherwise the first unknown
/// key, then the first missing one, as the clause of a message.
fn shape_problem(table: &toml::Table, shape: &Shape) -> Option<String> {
    let name = |key: &str| key.strip_suffix('?').unwrap_or(key).to_string();
    if let Some(key) = table
        .keys()
        .find(|key| !shape.iter().any(|known| name(known) == **key))
    {
        return Some(format!("unknown field {key:?}"));
    }
    shape
        .iter()
        .find(|key| !key.ends_with('?') && !table.contains_key(**key))
        .map(|key| format!("missing field {key:?}"))
}

fn rows<'a>(table: &'a toml::Table, key: &str) -> impl Iterator<Item = &'a toml::Table> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
}

fn text<'a>(table: &'a toml::Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(toml::Value::as_str)
}

fn row_coord(row: &toml::Table) -> Option<String> {
    let coordinate = row.get("coordinate")?.as_table()?;
    let mut coord = ["group", "artifact", "version", "packaging"]
        .map(|key| text(coordinate, key).unwrap_or_default())
        .join(":");
    if let Some(classifier) = text(coordinate, "classifier").filter(|c| !c.is_empty()) {
        coord.push(':');
        coord.push_str(classifier);
    }
    Some(printable(&coord))
}

/// Check that every table of `doc` holds only the keys its kind may hold
/// and every key it must, naming the key and the row of the first that does
/// not. Serde would refuse the same document, but its message either quotes
/// the key unescaped or names neither the key nor the row.
fn check_shape(doc: &toml::Table) -> Result<(), LockError> {
    let invalid = |problem: String, place: String| {
        Err(LockError::Invalid(format!(
            "{problem} in {place}; raeva.lock holds only the fields this raeva writes"
        )))
    };
    if let Some(problem) = shape_problem(doc, TOP) {
        return invalid(problem, "the top level".to_string());
    }
    for (key, shape) in [("resolution", RESOLUTION), ("metadata", METADATA)] {
        if let Some(table) = doc.get(key).and_then(toml::Value::as_table)
            && let Some(problem) = shape_problem(table, shape)
        {
            return invalid(problem, format!("the [{key}] table"));
        }
    }
    for input in rows(doc, "inputs") {
        if let Some(problem) = shape_problem(input, INPUTS) {
            return invalid(problem, "target inputs".to_string());
        }
        for pom in rows(input, "poms") {
            if let Some(problem) = shape_problem(pom, POM_INPUT) {
                return invalid(problem, "POM inputs".to_string());
            }
        }
    }
    for (index, platform) in rows(doc, "platforms").enumerate() {
        let targets: Vec<&str> = (platform.get("targets").and_then(toml::Value::as_array))
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .collect();
        let on = if targets.is_empty() {
            format!("platform #{}", index + 1)
        } else {
            format!("platform '{}'", printable(&targets.join(", ")))
        };
        if let Some(problem) = shape_problem(platform, PLATFORM) {
            return invalid(problem, on);
        }
        for (index, artifact) in rows(platform, "artifacts").enumerate() {
            let row = match row_coord(artifact) {
                Some(coord) => format!("artifact '{coord}' on {on}"),
                None => format!("artifact #{} on {on}", index + 1),
            };
            if let Some(problem) = shape_problem(artifact, ARTIFACT) {
                return invalid(problem, row);
            }
            let mut nested: Vec<(&str, &toml::Table, &Shape)> = Vec::new();
            if let Some(table) = artifact.get("coordinate").and_then(toml::Value::as_table) {
                nested.push(("coordinate", table, COORDINATE));
            }
            if let Some(table) = artifact.get("snapshot").and_then(toml::Value::as_table) {
                nested.push(("snapshot", table, SNAPSHOT));
            }
            if let Some(table) = artifact.get("pom_snapshot").and_then(toml::Value::as_table) {
                nested.push(("pom_snapshot", table, SNAPSHOT));
            }
            for checksum in rows(artifact, "checksums") {
                nested.push(("checksum", checksum, CHECKSUM));
            }
            for (name, table, shape) in nested {
                if let Some(problem) = shape_problem(table, shape) {
                    return invalid(problem, format!("the {name} table of {row}"));
                }
            }
        }
        for (index, pom) in rows(platform, "support_poms").enumerate() {
            let row = match text(pom, "coordinate") {
                Some(coord) => format!("support POM '{}' on {on}", printable(coord)),
                None => format!("support POM #{} on {on}", index + 1),
            };
            if let Some(problem) = shape_problem(pom, SUPPORT_POM) {
                return invalid(problem, row);
            }
            if let Some(table) = pom.get("snapshot").and_then(toml::Value::as_table)
                && let Some(problem) = shape_problem(table, SNAPSHOT)
            {
                return invalid(problem, format!("the snapshot table of {row}"));
            }
        }
        for (index, module) in rows(platform, "modules").enumerate() {
            let row = match text(module, "path") {
                Some(path) => format!("module '{}' on {on}", printable(path)),
                None => format!("module #{} on {on}", index + 1),
            };
            if let Some(problem) = shape_problem(module, MODULE) {
                return invalid(problem, row);
            }
            for selection in rows(module, "parent_ranges") {
                if let Some(problem) = shape_problem(selection, &["model", "parent", "selected"]) {
                    return invalid(problem, format!("parent range selection of {row}"));
                }
            }
        }
    }
    Ok(())
}
