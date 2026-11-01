use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use rv_maven_model::{Parent, Pom};

/// Maven's dynamic version tokens: the exact words `RELEASE` and `LATEST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DynamicVersionToken {
    Release,
    Integration,
}

impl DynamicVersionToken {
    pub(crate) fn requirement_label(self) -> &'static str {
        match self {
            Self::Release => "RELEASE",
            Self::Integration => "LATEST",
        }
    }

    /// `RELEASE` selects no snapshot.
    pub(crate) fn admits(self, version: &str) -> bool {
        self == Self::Integration || !rv_maven_types::is_snapshot_version(version)
    }
}

pub(crate) fn parse_dynamic_version_token(token: &str) -> Option<DynamicVersionToken> {
    match token.trim() {
        "RELEASE" => Some(DynamicVersionToken::Release),
        "LATEST" => Some(DynamicVersionToken::Integration),
        _ => None,
    }
}

/// Free `value` on a thread of its own: freeing a resolution's large maps
/// and graphs takes a while and nothing waits for it.
pub(crate) fn drop_in_background<T: Send + 'static>(value: T) {
    let freed = std::thread::Builder::new().spawn(move || drop(value));
    drop(freed);
}

/// Locks `mutex`, recovering the data from a panicked holder.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// [`RwLock::read`], recovering the data from a panicked holder.
pub(crate) fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// [`RwLock::write`], recovering the data from a panicked holder.
pub(crate) fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

/// Returns true if `pom` could be the parent referenced by `parent`, by
/// Maven 3.9's `readParentLocally` check, on the coordinates as written: the
/// candidate's `groupId` (or its own parent's) and `artifactId` must equal
/// the declaration's, and so must its version (or its own parent's) when it
/// has one, or fall in the declaration's version range.
pub(crate) fn pom_matches_parent(pom: &Pom, parent: &Parent) -> bool {
    let inherited = pom.parent.as_ref();
    let group_id = pom
        .group_id
        .as_deref()
        .or_else(|| inherited.map(|p| p.group_id.as_str()));
    let version = pom
        .version
        .as_deref()
        .or_else(|| inherited.map(|p| p.version.as_str()));
    group_id == Some(parent.group_id.as_str())
        && pom.artifact_id.as_deref() == Some(parent.artifact_id.as_str())
        && version.is_none_or(|version| {
            version == parent.version
                || (rv_maven_model::parent_version_range(parent).is_some()
                    && rv_maven_model::local_parent_in_range(version, &parent.version))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded with Maven 3.9.11 where noted: a `${revision}` parent is
    /// found locally only when the local POM declares the same text.
    #[test]
    fn pom_matches_parent_as_written() {
        let pom = |group_id: Option<&str>, version: Option<&str>, parent: Option<&str>| {
            let mut pom = Pom::default();
            pom.group_id = group_id.map(String::from);
            pom.artifact_id = Some("parent".to_string());
            pom.version = version.map(String::from);
            pom.properties.insert("revision", "0.0.20");
            pom.parent = parent.map(|version| Parent {
                group_id: "com.example".to_string(),
                artifact_id: "grandparent".to_string(),
                version: version.to_string(),
                relative_path: None,
            });
            pom
        };
        let declared = |artifact_id: &str, version: &str| Parent {
            group_id: "com.example".to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            relative_path: None,
        };
        let example = Some("com.example");
        for (candidate, artifact_id, version, matches) in [
            (pom(example, Some("1.0"), None), "parent", "1.0", true),
            (pom(example, Some("2.0"), None), "parent", "1.0", false),
            (pom(example, Some("1.0"), None), "other", "1.0", false),
            (
                pom(Some("com.other"), Some("1.0"), None),
                "parent",
                "1.0",
                false,
            ),
            (
                pom(example, Some("${revision}"), None),
                "parent",
                "${revision}",
                true,
            ),
            (
                pom(example, Some("${revision}"), None),
                "parent",
                "0.0.20",
                false,
            ),
            (
                pom(example, Some("0.0.20"), None),
                "parent",
                "${revision}",
                false,
            ),
            (pom(None, None, None), "parent", "1.0", false),
            (pom(None, None, Some("1.0")), "parent", "1.0", true),
            (pom(None, None, Some("1.0")), "parent", "2.0", false),
            (pom(example, None, None), "parent", "1.0", true),
            (pom(example, Some("1-1"), None), "parent", "[1.0,1.1)", true),
            (
                pom(example, Some("1.1"), None),
                "parent",
                "[1.0,1.1)",
                false,
            ),
            (pom(None, None, Some("1-1")), "parent", "[1.0,1.1)", true),
            (
                pom(example, Some("1.0${changelist}"), None),
                "parent",
                "[1.0,1.0-custom)",
                true,
            ),
        ] {
            assert_eq!(
                pom_matches_parent(&candidate, &declared(artifact_id, version)),
                matches,
                "{:?}:{:?} against {artifact_id}:{version}",
                candidate.group_id,
                candidate.version
            );
        }
    }
}
