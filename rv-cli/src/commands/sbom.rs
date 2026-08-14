use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use rv_maven_model::{Pom, PomError};
use rv_sbom::{Component, CycloneDxGenerator, SpdxGenerator};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::commands::module_selector::ModuleSelector;
use crate::error::{CliError, Result};
use crate::output::{is_json_mode, json_result};

#[derive(Debug, Args)]
#[command(
    about = "Generate an SBOM from rv.lock",
    after_long_help = "\
Formats:
  cyclonedx    CycloneDX 1.5 JSON (default)
  spdx         SPDX 2.3 JSON

Output:
  Writes the document to stdout unless -o/--output is provided.

Examples:
  rv sbom
  rv sbom --module app/pom.xml
  rv sbom --module com.acme:app
  rv sbom --format spdx
  rv sbom --format cyclonedx -o bom.json
"
)]
pub struct SbomArgs {
    #[command(flatten)]
    module: ModuleSelector,
    #[arg(
        long,
        value_enum,
        default_value = "cyclonedx",
        help = "SBOM format: cyclonedx or spdx"
    )]
    format: SbomFormat,
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        help = "Write the SBOM to a file instead of stdout"
    )]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SbomFormat {
    Cyclonedx,
    Spdx,
}

impl SbomFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cyclonedx => "cyclonedx",
            Self::Spdx => "spdx",
        }
    }
}

pub fn run(args: &SbomArgs, project_root: &Path) -> Result<()> {
    let config = rv_config::Config::load(project_root)?;
    let (lock, pom_xml) = crate::commands::read_fresh_lockfile_with_pom(&config)?;
    let platform = crate::commands::select_platform(&lock)?;
    let platform_name = platform.platform.to_string();
    let selection = args.module.select(platform)?;
    let fallback_root = parse_root_component(&pom_xml, Vec::new())?;
    let adapted = crate::commands::lock_adapter::adapt_sbom_modules(
        platform,
        selection.modules(),
        fallback_root,
    )
    .map_err(|err| CliError::Message(format!("failed to map rv.lock: {err}")))?;
    let root = adapted.root;
    let components = adapted.components;
    let document = match args.format {
        SbomFormat::Cyclonedx => {
            let identity = document_identity(&platform_name, &root, &components, None)?;
            generate_cyclonedx(root, &components, &identity)?
        }
        SbomFormat::Spdx => {
            let created = creation_timestamp()?;
            let identity = document_identity(&platform_name, &root, &components, Some(created))?;
            generate_spdx(root, &components, &identity, created)?
        }
    };

    if let Some(path) = &args.output {
        crate::commands::write_atomic(path, format!("{document}\n").as_bytes())?;
        if is_json_mode() {
            json_result(
                true,
                serde_json::json!({
                    "format": args.format.as_str(),
                    "path": crate::commands::path_to_forward_slashes(path),
                }),
            );
        } else {
            crate::output::result("Wrote", path.display().to_string());
        }
    } else {
        println!("{document}");
    }

    Ok(())
}

fn parse_root_component(xml: &str, dependencies: Vec<String>) -> Result<Component> {
    let pom = Pom::parse(xml)?;
    let group_id = root_field(
        &pom,
        pom.group_id.as_deref(),
        pom.parent.as_ref().map(|parent| parent.group_id.as_str()),
        "groupId",
    )?;
    let artifact_id = root_field(&pom, pom.artifact_id.as_deref(), None, "artifactId")?;
    let version = root_field(
        &pom,
        pom.version.as_deref(),
        pom.parent.as_ref().map(|parent| parent.version.as_str()),
        "version",
    )?;
    let packaging = pom
        .properties
        .interpolate_str_no_project(pom.packaging.as_deref().unwrap_or("jar"))?;
    let packaging = packaging.trim().to_string();
    let purl = crate::commands::lock_adapter::maven_purl(
        group_id.clone(),
        artifact_id.clone(),
        version.clone(),
        packaging,
    )
    .map_err(|err| CliError::Message(format!("invalid project coordinates: {err}")))?;

    Ok(Component {
        name: artifact_id,
        version,
        group: Some(group_id),
        purl,
        license_expression: None,
        hashes: Vec::new(),
        dependencies,
    })
}

fn root_field(
    pom: &Pom,
    value: Option<&str>,
    inherited: Option<&str>,
    field: &'static str,
) -> Result<String> {
    let raw = value.or(inherited).ok_or(PomError::MissingField(field))?;
    let resolved = pom.properties.interpolate_str_no_project(raw)?;
    let resolved = resolved.trim();
    if resolved.is_empty() {
        return Err(PomError::InvalidModel(format!("{field} must not be empty")).into());
    }
    Ok(resolved.to_string())
}

fn generate_cyclonedx(root: Component, components: &[Component], identity: &str) -> Result<String> {
    let generator = CycloneDxGenerator {
        tool_name: "rv".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        root_component: Some(root),
        timestamp: None,
        serial_number: Some(format!("urn:uuid:{identity}")),
        ..CycloneDxGenerator::default()
    };
    Ok(generator.generate(components)?)
}

fn generate_spdx(
    root: Component,
    components: &[Component],
    identity: &str,
    created: DateTime<Utc>,
) -> Result<String> {
    let group = root.group.as_deref().unwrap_or_default();
    let generator = SpdxGenerator {
        document_name: format!("{group}:{}:{}", root.name, root.version),
        creators: vec![format!("Tool: rv-{}", env!("CARGO_PKG_VERSION"))],
        root_component: Some(root),
        document_namespace: Some(format!("https://raeva.io/spdx/{identity}")),
        created: Some(created),
        ..SpdxGenerator::default()
    };
    Ok(generator.generate(components)?)
}

fn document_identity(
    platform: &str,
    root: &Component,
    components: &[Component],
    created: Option<DateTime<Utc>>,
) -> Result<String> {
    #[derive(Serialize)]
    struct IdentityInput<'a> {
        tool_version: &'static str,
        platform: &'a str,
        root: &'a Component,
        components: &'a [Component],
        created: Option<DateTime<Utc>>,
    }

    let input = serde_json::to_vec(&IdentityInput {
        tool_version: env!("CARGO_PKG_VERSION"),
        platform,
        root,
        components,
        created,
    })?;
    let digest = Sha256::digest(input);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &value[0..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    ))
}

fn creation_timestamp() -> Result<DateTime<Utc>> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => {
            let seconds = value.parse::<i64>().map_err(|_| {
                CliError::Message("SOURCE_DATE_EPOCH must be a Unix timestamp".to_string())
            })?;
            DateTime::from_timestamp(seconds, 0).ok_or_else(|| {
                CliError::Message("SOURCE_DATE_EPOCH is outside the supported range".to_string())
            })
        }
        Err(std::env::VarError::NotPresent) => Ok(Utc::now()),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::Message(
            "SOURCE_DATE_EPOCH contains non-Unicode data".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use chrono::{DateTime, Utc};

    use super::{document_identity, parse_root_component};

    #[test]
    fn root_component_uses_parent_coordinates_and_properties() {
        let temp = TempDir::new().expect("tempdir");
        let pom_path = temp.path().join("pom.xml");
        fs::write(
            &pom_path,
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>demo</artifactId>
  <version>${revision}</version>
  <properties><revision>2.0.0</revision></properties>
</project>"#,
        )
        .expect("write pom");

        let xml = rv_config::read_project_input_string(&pom_path).expect("read pom");
        let root = parse_root_component(&xml, vec!["pkg:maven/org.example/lib@1".to_string()])
            .expect("root component");
        assert_eq!(root.group.as_deref(), Some("com.example"));
        assert_eq!(root.name, "demo");
        assert_eq!(root.version, "2.0.0");
        assert_eq!(root.purl, "pkg:maven/com.example/demo@2.0.0");
        assert_eq!(root.dependencies.len(), 1);
    }

    #[test]
    fn document_identity_is_stable_and_uses_uuid_v8() {
        let temp = TempDir::new().expect("tempdir");
        let pom_path = temp.path().join("pom.xml");
        fs::write(
            &pom_path,
            r#"<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
</project>"#,
        )
        .expect("write pom");
        let xml = rv_config::read_project_input_string(&pom_path).expect("read pom");
        let root = parse_root_component(&xml, Vec::new()).expect("root component");

        let created = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let first = document_identity("linux-x86_64", &root, &[], Some(created)).expect("identity");
        let second =
            document_identity("linux-x86_64", &root, &[], Some(created)).expect("identity");
        assert_eq!(first, second);
        assert_eq!(first.as_bytes()[14], b'8');

        let later = document_identity(
            "linux-x86_64",
            &root,
            &[],
            Some(DateTime::<Utc>::from_timestamp(1_700_000_001, 0).unwrap()),
        )
        .expect("identity");
        assert_ne!(first, later);
    }

    #[test]
    fn root_component_rejects_oversized_pom() {
        let temp = TempDir::new().expect("tempdir");
        let pom_path = temp.path().join("pom.xml");
        fs::write(&pom_path, vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1])
            .expect("write oversized pom");

        let error =
            rv_config::read_project_input_string(&pom_path).expect_err("oversized POM must fail");
        assert!(matches!(
            error,
            rv_config::ConfigError::ProjectInputTooLarge { .. }
        ));
    }
}
