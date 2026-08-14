use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use fs2::FileExt;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::{Host, Url};

const CREDENTIAL_RECORD_VERSION: u32 = 1;
const CREDENTIAL_INDEX_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "raeva";
const MAX_INDEX_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Basic,
    Bearer,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic => f.write_str("basic"),
            Self::Bearer => f.write_str("bearer"),
        }
    }
}

impl FromStr for AuthType {
    type Err = CredentialError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            "bearer" => Ok(Self::Bearer),
            _ => Err(CredentialError::InvalidAuthType(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NormalizedEndpoint(String);

impl NormalizedEndpoint {
    pub fn parse(value: &str) -> Result<Self, CredentialError> {
        let value = value.trim();
        let parsed = Url::parse(value)
            .map_err(|err| CredentialError::InvalidEndpoint(format!("url is not valid: {err}")))?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(CredentialError::InvalidEndpoint(
                "scheme must be http or https".to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(CredentialError::InvalidEndpoint(
                "userinfo is not allowed".to_string(),
            ));
        }
        if parsed.query().is_some() {
            return Err(CredentialError::InvalidEndpoint(
                "query is not allowed".to_string(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(CredentialError::InvalidEndpoint(
                "fragment is not allowed".to_string(),
            ));
        }

        let host = match parsed.host() {
            Some(Host::Domain(host)) => host.to_ascii_lowercase(),
            Some(Host::Ipv4(host)) => host.to_string(),
            Some(Host::Ipv6(host)) => format!("[{host}]"),
            None => {
                return Err(CredentialError::InvalidEndpoint(
                    "host is required".to_string(),
                ));
            }
        };
        let port = parsed
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let mut path = parsed.path().to_string();
        if !path.ends_with('/') {
            path.push('/');
        }

        Ok(Self(format!(
            "{}://{host}{port}{path}",
            parsed.scheme().to_ascii_lowercase()
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NormalizedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NormalizedEndpoint {
    type Err = CredentialError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    version: u32,
    pub auth_type: AuthType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    secret: Secret<String>,
}

impl Serialize for CredentialRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct SerializedRecord<'a> {
            version: u32,
            auth_type: AuthType,
            #[serde(skip_serializing_if = "Option::is_none")]
            username: &'a Option<String>,
            secret: &'a str,
        }

        SerializedRecord {
            version: self.version,
            auth_type: self.auth_type,
            username: &self.username,
            secret: self.secret.expose_secret(),
        }
        .serialize(serializer)
    }
}

impl CredentialRecord {
    pub fn basic(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty() {
            return Err(CredentialError::IncompleteRecord(
                "basic auth requires a non-empty username".to_string(),
            ));
        }
        if password.is_empty() {
            return Err(CredentialError::IncompleteRecord(
                "basic auth requires a non-empty password".to_string(),
            ));
        }
        Ok(Self {
            version: CREDENTIAL_RECORD_VERSION,
            auth_type: AuthType::Basic,
            username: Some(username),
            secret: Secret::new(password),
        })
    }

    pub fn bearer(token: impl Into<String>) -> Result<Self, CredentialError> {
        let token = token.into();
        if token.is_empty() {
            return Err(CredentialError::IncompleteRecord(
                "bearer auth requires a non-empty token".to_string(),
            ));
        }
        Ok(Self {
            version: CREDENTIAL_RECORD_VERSION,
            auth_type: AuthType::Bearer,
            username: None,
            secret: Secret::new(token),
        })
    }

    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }

    fn validate(&self) -> Result<(), CredentialError> {
        if self.version != CREDENTIAL_RECORD_VERSION {
            return Err(CredentialError::CorruptRecord(format!(
                "unsupported credential record version {}",
                self.version
            )));
        }
        match self.auth_type {
            AuthType::Basic if self.username.as_deref().is_none_or(str::is_empty) => {
                Err(CredentialError::CorruptRecord(
                    "basic credential record has no username".to_string(),
                ))
            }
            AuthType::Bearer if self.username.is_some() => Err(CredentialError::CorruptRecord(
                "bearer credential record must not contain a username".to_string(),
            )),
            _ if self.secret.expose_secret().is_empty() => Err(CredentialError::CorruptRecord(
                "credential record has an empty secret".to_string(),
            )),
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("version", &self.version)
            .field("auth_type", &self.auth_type)
            .field("username", &self.username)
            .field("secret", &"***")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid credential endpoint {0}")]
    InvalidEndpoint(String),
    #[error("invalid auth type {0:?}; expected basic or bearer")]
    InvalidAuthType(String),
    #[error("incomplete credential: {0}")]
    IncompleteRecord(String),
    #[error("credential store is unavailable: {0}")]
    BackendUnavailable(String),
    #[error("credential record is corrupt: {0}; run 'rv login <url>' to replace it")]
    CorruptRecord(String),
    #[error("credential index at {path} is invalid: {details}")]
    InvalidIndex { path: PathBuf, details: String },
    #[error("credential index I/O failed at {path}: {source}")]
    IndexIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub trait CredentialStore: Send + Sync {
    fn get(
        &self,
        endpoint: &NormalizedEndpoint,
    ) -> Result<Option<CredentialRecord>, CredentialError>;
    fn set(
        &self,
        endpoint: &NormalizedEndpoint,
        record: &CredentialRecord,
    ) -> Result<(), CredentialError>;
    fn delete(&self, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringCredentialStore;

impl KeyringCredentialStore {
    fn entry(endpoint: &NormalizedEndpoint) -> Result<keyring::Entry, CredentialError> {
        keyring::Entry::new(KEYRING_SERVICE, endpoint.as_str()).map_err(map_keyring_error)
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn get(
        &self,
        endpoint: &NormalizedEndpoint,
    ) -> Result<Option<CredentialRecord>, CredentialError> {
        let entry = Self::entry(endpoint)?;
        let serialized = match entry.get_password() {
            Ok(serialized) => serialized,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(keyring::Error::BadEncoding(_)) | Err(keyring::Error::BadDataFormat(_, _)) => {
                return Err(CredentialError::CorruptRecord(format!(
                    "record for {endpoint} is not valid UTF-8"
                )));
            }
            Err(err) => return Err(map_keyring_error(err)),
        };
        let record: CredentialRecord = serde_json::from_str(&serialized).map_err(|err| {
            CredentialError::CorruptRecord(format!(
                "record for {endpoint} is not valid JSON: {err}"
            ))
        })?;
        record.validate()?;
        Ok(Some(record))
    }

    fn set(
        &self,
        endpoint: &NormalizedEndpoint,
        record: &CredentialRecord,
    ) -> Result<(), CredentialError> {
        record.validate()?;
        let serialized = serde_json::to_string(record).map_err(|err| {
            CredentialError::CorruptRecord(format!("could not serialize credential record: {err}"))
        })?;
        Self::entry(endpoint)?
            .set_password(&serialized)
            .map_err(map_keyring_error)
    }

    fn delete(&self, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError> {
        let entry = Self::entry(endpoint)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_keyring_error(err)),
        }
    }
}

fn map_keyring_error(err: keyring::Error) -> CredentialError {
    match err {
        keyring::Error::BadEncoding(_) | keyring::Error::BadDataFormat(_, _) => {
            CredentialError::CorruptRecord("record is not valid UTF-8".to_string())
        }
        other => CredentialError::BackendUnavailable(other.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIndexEntry {
    pub endpoint: NormalizedEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub auth_type: AuthType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIndex {
    version: u32,
    entries: Vec<CredentialIndexEntry>,
}

impl Default for CredentialIndex {
    fn default() -> Self {
        Self {
            version: CREDENTIAL_INDEX_VERSION,
            entries: Vec::new(),
        }
    }
}

impl CredentialIndex {
    pub fn load(path: &Path) -> Result<Self, CredentialError> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(CredentialError::IndexIo {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if metadata.len() > MAX_INDEX_SIZE {
            return Err(CredentialError::InvalidIndex {
                path: path.to_path_buf(),
                details: format!("file exceeds {MAX_INDEX_SIZE}-byte limit"),
            });
        }
        let contents = fs::read_to_string(path).map_err(|source| CredentialError::IndexIo {
            path: path.to_path_buf(),
            source,
        })?;
        let index: Self =
            serde_json::from_str(&contents).map_err(|err| CredentialError::InvalidIndex {
                path: path.to_path_buf(),
                details: err.to_string(),
            })?;
        if index.version != CREDENTIAL_INDEX_VERSION {
            return Err(CredentialError::InvalidIndex {
                path: path.to_path_buf(),
                details: format!("unsupported version {}", index.version),
            });
        }
        Ok(index)
    }

    pub fn entries(&self) -> &[CredentialIndexEntry] {
        &self.entries
    }

    pub fn upsert(path: &Path, entry: CredentialIndexEntry) -> Result<(), CredentialError> {
        let lock = IndexLock::acquire(path)?;
        Self::upsert_locked(path, entry, &lock)
    }

    pub fn remove(path: &Path, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError> {
        let lock = IndexLock::acquire(path)?;
        Ok(Self::remove_locked(path, endpoint, &lock)?.is_some())
    }

    fn upsert_locked(
        path: &Path,
        entry: CredentialIndexEntry,
        lock: &IndexLock,
    ) -> Result<(), CredentialError> {
        Self::update_locked(path, lock, |index| {
            index
                .entries
                .retain(|existing| existing.endpoint != entry.endpoint);
            index.entries.push(entry);
            index
                .entries
                .sort_by(|left, right| left.endpoint.as_str().cmp(right.endpoint.as_str()));
        })
    }

    fn remove_locked(
        path: &Path,
        endpoint: &NormalizedEndpoint,
        lock: &IndexLock,
    ) -> Result<Option<CredentialIndexEntry>, CredentialError> {
        let mut removed = None;
        Self::update_locked(path, lock, |index| {
            if let Some(position) = index
                .entries
                .iter()
                .position(|entry| &entry.endpoint == endpoint)
            {
                removed = Some(index.entries.remove(position));
            }
        })?;
        Ok(removed)
    }

    /// The caller-held `lock` must cover this read-modify-write; taking it here
    /// instead would deadlock against a caller that already holds it.
    fn update_locked(
        path: &Path,
        _lock: &IndexLock,
        mutate: impl FnOnce(&mut CredentialIndex),
    ) -> Result<(), CredentialError> {
        let mut index = Self::load(path)?;
        mutate(&mut index);
        index.write_atomic(path)
    }

    fn write_atomic(&self, path: &Path) -> Result<(), CredentialError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let serialized =
            serde_json::to_vec_pretty(self).map_err(|err| CredentialError::InvalidIndex {
                path: path.to_path_buf(),
                details: err.to_string(),
            })?;
        let mut temp =
            NamedTempFile::new_in(parent).map_err(|source| CredentialError::IndexIo {
                path: path.to_path_buf(),
                source,
            })?;
        temp.as_file_mut()
            .write_all(&serialized)
            .and_then(|_| temp.as_file_mut().write_all(b"\n"))
            .and_then(|_| temp.as_file().sync_all())
            .map_err(|source| CredentialError::IndexIo {
                path: path.to_path_buf(),
                source,
            })?;
        temp.persist(path).map_err(|err| CredentialError::IndexIo {
            path: path.to_path_buf(),
            source: err.error,
        })?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

/// Advisory interprocess lock guarding an endpoint's secret and its index
/// entry as one unit, so a concurrent `rv login` or `rv logout` cannot
/// interleave its keyring write with our index write. Released on drop.
struct IndexLock {
    _file: fs::File,
}

impl IndexLock {
    fn acquire(index_path: &Path) -> Result<Self, CredentialError> {
        let parent = index_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| CredentialError::IndexIo {
            path: parent.to_path_buf(),
            source,
        })?;
        let lock_path = index_path.with_extension("json.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|source| CredentialError::IndexIo {
                path: lock_path.clone(),
                source,
            })?;
        file.lock_exclusive()
            .map_err(|source| CredentialError::IndexIo {
                path: lock_path,
                source,
            })?;
        Ok(Self { _file: file })
    }
}

pub struct CredentialManager<S = KeyringCredentialStore> {
    store: S,
    index_path: PathBuf,
}

impl CredentialManager<KeyringCredentialStore> {
    pub fn new(index_path: PathBuf) -> Self {
        Self::with_store(index_path, KeyringCredentialStore)
    }
}

impl<S: CredentialStore> CredentialManager<S> {
    pub fn with_store(index_path: PathBuf, store: S) -> Self {
        Self { store, index_path }
    }

    pub fn store(
        &self,
        endpoint: &NormalizedEndpoint,
        id: Option<String>,
        record: &CredentialRecord,
    ) -> Result<(), CredentialError> {
        let lock = IndexLock::acquire(&self.index_path)?;
        // A previous record that cannot be read back (corrupt, or an
        // unavailable backend) is not restorable, and `rv login` must still be
        // able to replace it, so a failed lookup means "nothing to roll back to".
        let previous = self.store.get(endpoint).ok().flatten();
        self.store.set(endpoint, record)?;
        let entry = CredentialIndexEntry {
            endpoint: endpoint.clone(),
            id,
            username: record.username.clone(),
            auth_type: record.auth_type,
        };
        if let Err(index_err) = CredentialIndex::upsert_locked(&self.index_path, entry, &lock) {
            match &previous {
                Some(previous) => {
                    let _ = self.store.set(endpoint, previous);
                }
                None => {
                    let _ = self.store.delete(endpoint);
                }
            }
            return Err(index_err);
        }
        Ok(())
    }

    pub fn delete(&self, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError> {
        let lock = IndexLock::acquire(&self.index_path)?;
        // Index first: an orphaned secret is inert, while metadata whose secret
        // is gone makes `rv auth list` advertise a credential that cannot work.
        let removed_entry = CredentialIndex::remove_locked(&self.index_path, endpoint, &lock)?;
        match self.store.delete(endpoint) {
            Ok(deleted_secret) => Ok(deleted_secret || removed_entry.is_some()),
            Err(store_err) => {
                if let Some(entry) = removed_entry {
                    let _ = CredentialIndex::upsert_locked(&self.index_path, entry, &lock);
                }
                Err(store_err)
            }
        }
    }

    pub fn list(&self) -> Result<CredentialIndex, CredentialError> {
        CredentialIndex::load(&self.index_path)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        AuthType, CredentialError, CredentialIndex, CredentialIndexEntry, CredentialManager,
        CredentialRecord, CredentialStore, NormalizedEndpoint,
    };

    #[derive(Clone, Default)]
    struct MemoryStore {
        records: Arc<Mutex<HashMap<NormalizedEndpoint, CredentialRecord>>>,
        fail_delete: Arc<AtomicBool>,
    }

    impl CredentialStore for MemoryStore {
        fn get(
            &self,
            endpoint: &NormalizedEndpoint,
        ) -> Result<Option<CredentialRecord>, CredentialError> {
            Ok(self.records.lock().expect("lock").get(endpoint).cloned())
        }

        fn set(
            &self,
            endpoint: &NormalizedEndpoint,
            record: &CredentialRecord,
        ) -> Result<(), CredentialError> {
            self.records
                .lock()
                .expect("lock")
                .insert(endpoint.clone(), record.clone());
            Ok(())
        }

        fn delete(&self, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(CredentialError::BackendUnavailable(
                    "test backend refuses deletes".to_string(),
                ));
            }
            Ok(self
                .records
                .lock()
                .expect("lock")
                .remove(endpoint)
                .is_some())
        }
    }

    /// Wraps [`MemoryStore`] and records how many `set` calls are in flight at
    /// once, which is how the tests observe whether the lock serializes stores.
    #[derive(Clone, Default)]
    struct TrackingStore {
        inner: MemoryStore,
        overlap: Arc<Mutex<(usize, usize)>>,
    }

    impl TrackingStore {
        fn peak_overlap(&self) -> usize {
            self.overlap.lock().expect("lock").1
        }
    }

    impl CredentialStore for TrackingStore {
        fn get(
            &self,
            endpoint: &NormalizedEndpoint,
        ) -> Result<Option<CredentialRecord>, CredentialError> {
            self.inner.get(endpoint)
        }

        fn set(
            &self,
            endpoint: &NormalizedEndpoint,
            record: &CredentialRecord,
        ) -> Result<(), CredentialError> {
            {
                let mut overlap = self.overlap.lock().expect("lock");
                overlap.0 += 1;
                overlap.1 = overlap.1.max(overlap.0);
            }
            // Widen the keyring window so unserialized stores would overlap.
            std::thread::sleep(Duration::from_millis(20));
            let result = self.inner.set(endpoint, record);
            self.overlap.lock().expect("lock").0 -= 1;
            result
        }

        fn delete(&self, endpoint: &NormalizedEndpoint) -> Result<bool, CredentialError> {
            self.inner.delete(endpoint)
        }
    }

    fn corrupt_index(path: &Path) {
        std::fs::write(path, "{ not json").expect("write corrupt index");
    }

    #[test]
    fn endpoint_normalization_table() {
        let cases = [
            (
                "HTTPS://Repo.Example.COM:443/maven2",
                "https://repo.example.com/maven2/",
            ),
            ("http://Repo.Example.COM:80/", "http://repo.example.com/"),
            (
                "https://repo.example.com:8443/a/../base",
                "https://repo.example.com:8443/base/",
            ),
            (
                "https://[2001:db8::1]:443/repository",
                "https://[2001:db8::1]/repository/",
            ),
            (
                "https://xn--bcher-kva.example/repo/",
                "https://xn--bcher-kva.example/repo/",
            ),
        ];

        for (input, expected) in cases {
            let endpoint = NormalizedEndpoint::parse(input).expect(input);
            assert_eq!(endpoint.as_str(), expected, "input: {input}");
        }
    }

    #[test]
    fn endpoint_rejects_ambiguous_or_unsafe_parts() {
        for (input, expected) in [
            ("https://user@repo.example/path", "userinfo"),
            ("https://repo.example/path?q=1", "query"),
            ("https://repo.example/path#frag", "fragment"),
            ("file:///tmp/repo", "scheme"),
            ("https://", "host"),
        ] {
            let err = NormalizedEndpoint::parse(input).expect_err(input);
            assert!(
                err.to_string().contains(expected),
                "{input} should mention {expected}: {err}"
            );
        }
    }

    #[test]
    fn credential_record_debug_and_errors_redact_secrets() {
        let secret = "do-not-print-this";
        let record = CredentialRecord::basic("alice", secret).expect("record");
        let debug = format!("{record:?}");
        assert!(!debug.contains(secret));
        assert!(debug.contains("***"));
    }

    #[test]
    fn unsupported_record_version_is_corrupt() {
        let serialized = r#"{"version":99,"auth_type":"bearer","secret":"do-not-print-this"}"#;
        let record: CredentialRecord = serde_json::from_str(serialized).expect("parse shape");
        let err = record.validate().expect_err("version must be rejected");
        assert!(matches!(err, CredentialError::CorruptRecord(_)));
        assert!(!err.to_string().contains("do-not-print-this"));
    }

    #[test]
    fn index_upsert_replaces_endpoint_and_contains_no_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/maven2").expect("endpoint");
        CredentialIndex::upsert(
            &path,
            CredentialIndexEntry {
                endpoint: endpoint.clone(),
                id: Some("first".to_string()),
                username: Some("alice".to_string()),
                auth_type: AuthType::Basic,
            },
        )
        .expect("first write");
        CredentialIndex::upsert(
            &path,
            CredentialIndexEntry {
                endpoint: endpoint.clone(),
                id: Some("second".to_string()),
                username: None,
                auth_type: AuthType::Bearer,
            },
        )
        .expect("replacement write");

        let index = CredentialIndex::load(&path).expect("load");
        assert_eq!(index.entries().len(), 1);
        assert_eq!(index.entries()[0].id.as_deref(), Some("second"));
        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(!contents.contains("password"));
        assert!(!contents.contains("token"));

        assert!(CredentialIndex::remove(&path, &endpoint).expect("remove"));
        assert!(
            CredentialIndex::load(&path)
                .expect("reload")
                .entries()
                .is_empty()
        );
    }

    #[test]
    fn manager_uses_trait_store_without_a_real_keyring() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/").expect("endpoint");
        let store = MemoryStore::default();
        let manager = CredentialManager::with_store(path, store.clone());
        let record = CredentialRecord::basic("alice", "test-password").expect("record");

        manager
            .store(&endpoint, Some("corp".to_string()), &record)
            .expect("store");
        let stored = store
            .get(&endpoint)
            .expect("lookup")
            .expect("stored record");
        assert_eq!(stored.username.as_deref(), Some("alice"));
        assert_eq!(stored.expose_secret(), "test-password");
        let listed = manager.list().expect("list");
        assert_eq!(listed.entries().len(), 1);
        assert_eq!(listed.entries()[0].id.as_deref(), Some("corp"));

        assert!(manager.delete(&endpoint).expect("delete"));
        assert!(store.get(&endpoint).expect("lookup").is_none());
        assert!(manager.list().expect("list").entries().is_empty());
    }

    #[test]
    fn failed_index_write_restores_the_previous_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/").expect("endpoint");
        let store = MemoryStore::default();
        let manager = CredentialManager::with_store(path.clone(), store.clone());
        let old = CredentialRecord::basic("alice", "old-password").expect("record");
        manager
            .store(&endpoint, Some("corp".to_string()), &old)
            .expect("initial store");

        corrupt_index(&path);
        let new = CredentialRecord::basic("bob", "new-password").expect("record");
        let err = manager
            .store(&endpoint, Some("corp".to_string()), &new)
            .expect_err("index write must fail");
        assert!(matches!(err, CredentialError::InvalidIndex { .. }));

        let kept = store
            .get(&endpoint)
            .expect("lookup")
            .expect("previous credential must survive");
        assert_eq!(kept.username.as_deref(), Some("alice"));
        assert_eq!(kept.expose_secret(), "old-password");
    }

    #[test]
    fn failed_index_write_removes_a_secret_that_had_no_predecessor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/").expect("endpoint");
        let store = MemoryStore::default();
        let manager = CredentialManager::with_store(path.clone(), store.clone());
        corrupt_index(&path);

        let record = CredentialRecord::bearer("new-token").expect("record");
        manager
            .store(&endpoint, None, &record)
            .expect_err("index write must fail");
        assert!(store.get(&endpoint).expect("lookup").is_none());
    }

    #[test]
    fn failed_index_update_during_delete_keeps_the_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/").expect("endpoint");
        let store = MemoryStore::default();
        let manager = CredentialManager::with_store(path.clone(), store.clone());
        let record = CredentialRecord::basic("alice", "test-password").expect("record");
        manager
            .store(&endpoint, Some("corp".to_string()), &record)
            .expect("store");

        corrupt_index(&path);
        let err = manager.delete(&endpoint).expect_err("delete must fail");
        assert!(matches!(err, CredentialError::InvalidIndex { .. }));
        assert!(
            store.get(&endpoint).expect("lookup").is_some(),
            "the secret must outlive its metadata, never the other way around"
        );
    }

    #[test]
    fn failed_secret_delete_restores_the_index_entry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let endpoint = NormalizedEndpoint::parse("https://repo.example/").expect("endpoint");
        let store = MemoryStore::default();
        let manager = CredentialManager::with_store(path, store.clone());
        let record = CredentialRecord::basic("alice", "test-password").expect("record");
        manager
            .store(&endpoint, Some("corp".to_string()), &record)
            .expect("store");

        store.fail_delete.store(true, Ordering::SeqCst);
        let err = manager.delete(&endpoint).expect_err("delete must fail");
        assert!(matches!(err, CredentialError::BackendUnavailable(_)));

        let listed = manager.list().expect("list");
        assert_eq!(listed.entries().len(), 1);
        assert_eq!(listed.entries()[0].id.as_deref(), Some("corp"));
        assert!(store.get(&endpoint).expect("lookup").is_some());
    }

    #[test]
    fn concurrent_stores_are_serialized_by_the_index_lock() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let store = TrackingStore::default();
        let manager = CredentialManager::with_store(path, store.clone());

        std::thread::scope(|scope| {
            for slot in 0..4 {
                let manager = &manager;
                scope.spawn(move || {
                    let endpoint =
                        NormalizedEndpoint::parse(&format!("https://repo{slot}.example/"))
                            .expect("endpoint");
                    let record = CredentialRecord::bearer(format!("token-{slot}")).expect("record");
                    manager
                        .store(&endpoint, Some(format!("id-{slot}")), &record)
                        .expect("store");
                });
            }
        });

        assert_eq!(
            store.peak_overlap(),
            1,
            "keyring and index updates must not interleave"
        );
        assert_eq!(manager.list().expect("list").entries().len(), 4);
    }
}
