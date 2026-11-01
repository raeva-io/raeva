//! Small valid lockfiles for unit tests.

use rv_maven_types::{ArtifactCoord, Digest, Gav};

use crate::lock::{LockArtifact, LockPlatform, Lockfile, SupportPom};
use crate::platform::Platform;

pub(crate) fn platform(name: &str) -> Platform {
    name.parse().expect("platform")
}

pub(crate) fn package(artifact: &str, version: &str, digest: char) -> LockArtifact {
    LockArtifact {
        checksums: vec![Digest::parse("sha256", &digest.to_string().repeat(64)).expect("digest")],
        ..LockArtifact::new(
            ArtifactCoord::new("com.example", artifact, version, "jar", None),
            "https://repo.example/",
        )
    }
}

pub(crate) fn locked_platform(name: &str, packages: Vec<LockArtifact>, pom: char) -> LockPlatform {
    let mut entry = LockPlatform::single_module(
        platform(name),
        Gav::new("com.example", "root", "1"),
        "jar",
        packages,
    );
    entry.model_hash = "a".repeat(64);
    for artifact in &mut entry.artifacts {
        artifact.pom_sha256 = Some(pom.to_string().repeat(64).parse().expect("digest"));
    }
    entry
}

pub(crate) fn lock(platforms: Vec<LockPlatform>) -> Lockfile {
    let mut lock = Lockfile::new();
    lock.config_hash = Some("c".repeat(64));
    lock.platforms = platforms;
    lock
}

/// Pin support POM `coord` to bytes `sha` on every platform of `lock`.
pub(crate) fn set_support_pom(lock: &mut Lockfile, coord: &str, sha: char) {
    for platform in &mut lock.platforms {
        platform.support_poms.insert(
            coord.to_string(),
            SupportPom::new(
                "https://repo.example/",
                sha.to_string().repeat(64).parse().expect("digest"),
            ),
        );
    }
}

pub(crate) fn linux_lock(version: &str, digest: char) -> Lockfile {
    let packages = vec![package("a", version, digest)];
    lock(vec![locked_platform("linux-x86_64", packages, '7')])
}
