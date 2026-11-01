use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use rv_maven_model::{Pom, PomError};
use rv_maven_types::BlobId;

use crate::util::lock;

const MAX_PARSED_POM_ENTRIES: usize = 1_024;
const MAX_PARSED_POM_SOURCE_BYTES: usize = 32 * 1024 * 1024;

struct Entry {
    pom: Arc<Pom>,
    source_bytes: usize,
}

struct Cache {
    entries: LruCache<BlobId, Entry>,
    source_bytes: usize,
}

pub(crate) struct ParsedPomCache {
    inner: Mutex<Cache>,
}

impl std::fmt::Debug for ParsedPomCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedPomCache")
            .finish_non_exhaustive()
    }
}

impl Default for ParsedPomCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Cache {
                entries: LruCache::new(NonZeroUsize::new(MAX_PARSED_POM_ENTRIES).unwrap()),
                source_bytes: 0,
            }),
        }
    }
}

impl ParsedPomCache {
    // The digest must identify the original bytes, including any UTF-8 BOM.
    // A coordinate index can change independently of the bytes being parsed.
    // Callers that mutate must clone the Arc's contents once; the cache keeps
    // the shared model.
    pub(crate) fn parse(&self, blob: &BlobId, bytes: &[u8]) -> Result<Arc<Pom>, PomError> {
        let cached = {
            let mut cache = lock(&self.inner);
            cache.entries.get(blob).map(|entry| Arc::clone(&entry.pom))
        };
        if let Some(pom) = cached {
            return Ok(pom);
        }

        let xml = rv_maven_model::decode_pom(bytes)?;
        let pom = Arc::new(Pom::parse(&xml)?);
        self.insert(blob.clone(), Arc::clone(&pom), bytes.len());
        Ok(pom)
    }

    fn insert(&self, blob: BlobId, pom: Arc<Pom>, source_bytes: usize) {
        let mut cache = lock(&self.inner);
        if let Some((_, previous)) = cache.entries.push(blob, Entry { pom, source_bytes }) {
            cache.source_bytes -= previous.source_bytes;
        }
        cache.source_bytes += source_bytes;
        while cache.source_bytes > MAX_PARSED_POM_SOURCE_BYTES {
            let Some((_, entry)) = cache.entries.pop_lru() else {
                break;
            };
            cache.source_bytes -= entry.source_bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(name: usize) -> String {
        format!(
            "<project><groupId>test</groupId><artifactId>shared</artifactId>\
             <version>1</version><properties><value>{name}</value></properties></project>"
        )
    }

    fn cached(cache: &ParsedPomCache, blob: &BlobId) -> Option<Arc<Pom>> {
        lock(&cache.inner)
            .entries
            .peek(blob)
            .map(|entry| Arc::clone(&entry.pom))
    }

    fn parse(cache: &ParsedPomCache, xml: &str) -> (BlobId, Arc<Pom>) {
        let blob = BlobId::from_bytes(xml.as_bytes());
        let pom = cache.parse(&blob, xml.as_bytes()).unwrap();
        (blob, pom)
    }

    /// Entries are keyed by the exact source bytes, a UTF-8 BOM included, and
    /// a hit returns the same Arc. A caller that mutates must clone first so
    /// the cached model stays unchanged. Parse errors are not cached, and an
    /// anonymous profile is cached with the default id.
    #[test]
    fn entries_are_keyed_by_source_bytes() {
        let cache = ParsedPomCache::default();
        let (first, second) = (xml(0), xml(1));
        let (first_blob, first_pom) = parse(&cache, &first);
        let entry = cached(&cache, &first_blob).unwrap();
        assert!(Arc::ptr_eq(&parse(&cache, &first).1, &first_pom));
        assert!(Arc::ptr_eq(&entry, &cached(&cache, &first_blob).unwrap()));
        let second_pom = parse(&cache, &second).1;
        assert_eq!(first_pom.artifact_id, second_pom.artifact_id);
        assert_ne!(first_pom.as_ref(), second_pom.as_ref());
        let bom = format!("\u{feff}{first}");
        assert_eq!(parse(&cache, &bom).1.as_ref(), first_pom.as_ref());
        {
            let state = lock(&cache.inner);
            assert_eq!(state.entries.len(), 3);
            assert_eq!(state.source_bytes, first.len() + second.len() + bom.len());
        }

        let mut pom = Arc::unwrap_or_clone(parse(&cache, &first).1);
        pom.properties.insert("value", "modified");
        pom.mark_root_repositories();
        assert_eq!(parse(&cache, &first).1.as_ref(), first_pom.as_ref());

        let anonymous = "<project><profiles><profile/></profiles></project>";
        assert_eq!(parse(&cache, anonymous).1.profiles[0].id, "default");
        let broken = "<project><artifactId>broken</project>";
        let blob = BlobId::from_bytes(broken.as_bytes());
        assert!(cache.parse(&blob, broken.as_bytes()).is_err());
        assert!(cached(&cache, &blob).is_none());
    }

    /// Eviction keeps the source bytes within budget, and a POM inserted twice
    /// by racing misses counts once.
    #[test]
    fn source_byte_limit_evicts_until_within_budget() {
        let cache = ParsedPomCache::default();
        let weight = MAX_PARSED_POM_SOURCE_BYTES / 8;
        let mut blobs = Vec::new();
        for id in 0..9 {
            let size = weight + usize::from(id == 8);
            let mut xml = xml(id);
            xml.push_str("<!--");
            xml.extend(std::iter::repeat_n(' ', size - xml.len() - 3));
            xml.push_str("-->");
            blobs.push(parse(&cache, &xml).0);
        }
        for (index, blob) in blobs.iter().enumerate() {
            assert_eq!(cached(&cache, blob).is_some(), index >= 2, "{index}");
        }
        {
            let state = lock(&cache.inner);
            assert_eq!(state.entries.len(), 7);
            assert_eq!(state.source_bytes, MAX_PARSED_POM_SOURCE_BYTES - weight + 1);
        }

        let cache = ParsedPomCache::default();
        let xml = xml(0);
        let blob = BlobId::from_bytes(xml.as_bytes());
        for _ in 0..2 {
            cache.insert(blob.clone(), Arc::new(Pom::parse(&xml).unwrap()), xml.len());
        }
        let state = lock(&cache.inner);
        assert_eq!((state.entries.len(), state.source_bytes), (1, xml.len()));
    }
}
