use rv_config::{LockPackage, LockPlatform};
use rv_sbom::{Component, Hash, HashAlgorithm};
use rv_vuln::Dependency;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LockAdapterError {
    #[error(transparent)]
    Purl(#[from] rv_vuln::VulnError),
    #[error("lockfile edge out of bounds: {from} -> {to} for {packages} packages")]
    InvalidEdge {
        from: usize,
        to: usize,
        packages: usize,
    },
}

pub(crate) struct AdaptedDependencies {
    pub vuln_dependencies: Vec<Dependency>,
    pub components: Vec<Component>,
    pub root_dependencies: Vec<String>,
}

impl AdaptedDependencies {
    pub fn into_parts(self) -> (Vec<Dependency>, Vec<Component>, Vec<String>) {
        (
            self.vuln_dependencies,
            self.components,
            self.root_dependencies,
        )
    }
}

pub(crate) fn adapt_platform(
    platform: &LockPlatform,
) -> Result<AdaptedDependencies, LockAdapterError> {
    let mut dependencies = Vec::with_capacity(platform.packages.len());
    let mut purls = Vec::with_capacity(platform.packages.len());

    for package in &platform.packages {
        let dependency = dependency_from_package(package);
        purls.push(dependency.purl()?);
        dependencies.push(dependency);
    }

    let mut component_dependencies = vec![Vec::new(); platform.packages.len()];
    let mut has_incoming = vec![false; platform.packages.len()];
    for edge in &platform.edges {
        if edge.from >= platform.packages.len() || edge.to >= platform.packages.len() {
            return Err(LockAdapterError::InvalidEdge {
                from: edge.from,
                to: edge.to,
                packages: platform.packages.len(),
            });
        }
        component_dependencies[edge.from].push(purls[edge.to].clone());
        has_incoming[edge.to] = true;
    }
    for dependency_purls in &mut component_dependencies {
        dependency_purls.sort();
        dependency_purls.dedup();
    }

    let mut components: Vec<Component> = platform
        .packages
        .iter()
        .zip(purls.iter())
        .zip(component_dependencies)
        .map(|((package, purl), dependencies)| Component {
            name: package.artifact_id.clone(),
            version: package.version.clone(),
            group: Some(package.group_id.clone()),
            purl: purl.clone(),
            license_expression: None,
            hashes: sha256_hash(package).into_iter().collect(),
            dependencies,
        })
        .collect();
    components.sort_by(|left, right| left.purl.cmp(&right.purl));

    let mut vuln_dependencies: Vec<(String, Dependency)> =
        purls.iter().cloned().zip(dependencies).collect();
    vuln_dependencies.sort_by(|left, right| left.0.cmp(&right.0));

    let has_direct_scope = platform
        .packages
        .iter()
        .any(|package| package.direct_scope.is_some());
    let mut root_dependencies: Vec<String> = if has_direct_scope {
        purls
            .iter()
            .zip(&platform.packages)
            .filter(|(_, package)| package.direct_scope.is_some())
            .map(|(purl, _)| purl.clone())
            .collect()
    } else {
        purls
            .iter()
            .zip(has_incoming)
            .filter(|(_, incoming)| !incoming)
            .map(|(purl, _)| purl.clone())
            .collect()
    };
    if !has_direct_scope && root_dependencies.is_empty() && !purls.is_empty() {
        root_dependencies.clone_from(&purls);
    }
    root_dependencies.sort();
    root_dependencies.dedup();

    Ok(AdaptedDependencies {
        vuln_dependencies: vuln_dependencies
            .into_iter()
            .map(|(_, dependency)| dependency)
            .collect(),
        components,
        root_dependencies,
    })
}

pub(crate) fn dependency_from_package(package: &LockPackage) -> Dependency {
    Dependency {
        group_id: package.group_id.clone(),
        artifact_id: package.artifact_id.clone(),
        version: package.version.clone(),
        packaging: package.packaging.clone(),
        classifier: package.classifier.clone().filter(|value| !value.is_empty()),
    }
}

pub(crate) fn maven_purl(
    group_id: impl Into<String>,
    artifact_id: impl Into<String>,
    version: impl Into<String>,
    packaging: impl Into<String>,
) -> Result<String, LockAdapterError> {
    let mut dependency = Dependency::new(group_id, artifact_id, version);
    dependency.packaging = packaging.into();
    Ok(dependency.purl()?)
}

fn sha256_hash(package: &LockPackage) -> Option<Hash> {
    let checksum = package.checksum.as_ref()?;
    let algorithm = checksum.algorithm.replace('-', "");
    if !algorithm.eq_ignore_ascii_case("sha256") {
        return None;
    }
    Some(Hash {
        algorithm: HashAlgorithm::Sha256,
        value: checksum.digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rv_config::{Checksum, LockEdge, LockPackage, LockPlatform, Platform};
    use rv_sbom::{Component, CycloneDxGenerator, SpdxGenerator};

    use super::adapt_platform;

    fn package(packaging: &str, classifier: Option<&str>, checksum: Checksum) -> LockPackage {
        LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: classifier.map(str::to_string),
            repo_url: "https://repo.example/maven2".to_string(),
            checksum: Some(checksum),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn maps_qualifiers_hashes_and_edges_without_collapsing_artifacts() {
        let platform = LockPlatform {
            platform: "linux-x86_64".parse::<Platform>().expect("platform"),
            packages: vec![
                package(
                    "jar",
                    None,
                    Checksum::new(
                        "sha256",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                ),
                package("test-jar", Some("tests"), Checksum::new("sha1", "abcd")),
            ],
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("test".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        };

        let adapted = adapt_platform(&platform).expect("adapt lock platform");
        assert_eq!(adapted.vuln_dependencies.len(), 2);
        assert_eq!(adapted.components.len(), 2);

        let purls: Vec<&str> = adapted
            .components
            .iter()
            .map(|component| component.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            vec![
                "pkg:maven/org.example/demo@1.0.0",
                "pkg:maven/org.example/demo@1.0.0?classifier=tests&type=test-jar",
            ]
        );
        assert_eq!(adapted.components[0].hashes.len(), 1);
        assert!(adapted.components[0].license_expression.is_none());
        assert!(adapted.components[1].hashes.is_empty());
        assert_eq!(
            adapted.components[0].dependencies,
            vec!["pkg:maven/org.example/demo@1.0.0?classifier=tests&type=test-jar"]
        );
        assert_eq!(
            adapted.root_dependencies,
            vec![
                "pkg:maven/org.example/demo@1.0.0",
                "pkg:maven/org.example/demo@1.0.0?classifier=tests&type=test-jar",
            ]
        );
    }

    #[test]
    fn direct_dependencies_remain_root_dependencies_when_they_have_incoming_edges() {
        let mut direct_a = package(
            "jar",
            None,
            Checksum::new(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        direct_a.artifact_id = "a".to_string();
        let mut direct_b = package(
            "jar",
            None,
            Checksum::new(
                "sha256",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        );
        direct_b.artifact_id = "b".to_string();
        let platform = LockPlatform {
            platform: "linux-x86_64".parse::<Platform>().expect("platform"),
            packages: vec![direct_a, direct_b],
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        };
        let adapted = adapt_platform(&platform).expect("adapt lock platform");
        assert_eq!(
            adapted.root_dependencies,
            vec![
                "pkg:maven/org.example/a@1.0.0",
                "pkg:maven/org.example/b@1.0.0"
            ]
        );

        let root = Component {
            name: "root".to_string(),
            version: "1.0.0".to_string(),
            group: Some("org.example".to_string()),
            purl: "pkg:maven/org.example/root@1.0.0".to_string(),
            license_expression: None,
            hashes: Vec::new(),
            dependencies: adapted.root_dependencies.clone(),
        };
        let cyclonedx = CycloneDxGenerator {
            root_component: Some(root.clone()),
            timestamp: None,
            serial_number: None,
            ..CycloneDxGenerator::default()
        }
        .generate(&adapted.components)
        .expect("CycloneDX");
        let cyclonedx: serde_json::Value =
            serde_json::from_str(&cyclonedx).expect("CycloneDX JSON");
        let root_dependencies = cyclonedx["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["ref"] == root.purl)
            .unwrap()["dependsOn"]
            .as_array()
            .unwrap();
        assert_eq!(root_dependencies.len(), 2);

        let spdx = SpdxGenerator {
            root_component: Some(root),
            ..SpdxGenerator::default()
        }
        .generate(&adapted.components)
        .expect("SPDX");
        let spdx: serde_json::Value = serde_json::from_str(&spdx).expect("SPDX JSON");
        let root_id = spdx["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "root")
            .unwrap()["SPDXID"]
            .as_str()
            .unwrap();
        let root_dependencies = spdx["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|relationship| {
                relationship["spdxElementId"] == root_id
                    && relationship["relationshipType"] == "DEPENDS_ON"
            })
            .count();
        assert_eq!(root_dependencies, 2);
    }

    #[test]
    fn old_locks_fall_back_to_no_incoming_root_heuristic() {
        let mut a = package("jar", None, Checksum::new("sha1", "abcd"));
        a.artifact_id = "a".to_string();
        a.direct_scope = None;
        let mut b = package("jar", None, Checksum::new("sha1", "abcd"));
        b.artifact_id = "b".to_string();
        b.direct_scope = None;
        let platform = LockPlatform {
            platform: "linux-x86_64".parse::<Platform>().expect("platform"),
            packages: vec![a, b],
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: None,
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        };

        let adapted = adapt_platform(&platform).expect("adapt lock platform");
        assert_eq!(
            adapted.root_dependencies,
            vec!["pkg:maven/org.example/a@1.0.0"]
        );
    }
}
