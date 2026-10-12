use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use rv_config::BlobId;
use rv_maven_model::{Pom, PomError};

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
    pub(crate) fn parse(&self, blob: &BlobId, xml: &str) -> Result<Pom, PomError> {
        let cached = {
            let mut cache = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.entries.get(blob).map(|entry| Arc::clone(&entry.pom))
        };
        if let Some(pom) = cached {
            return Ok((*pom).clone());
        }

        let pom = Pom::parse(xml)?;
        // Profiles without an id get process-global generated ids on each parse.
        // Reusing those ids would change profile activation and inheritance.
        if !pom
            .profiles
            .iter()
            .any(|profile| profile.id.starts_with("__anonymous_"))
        {
            self.insert(blob.clone(), Arc::new(pom.clone()), xml.len());
        }
        Ok(pom)
    }

    fn insert(&self, blob: BlobId, pom: Arc<Pom>, source_bytes: usize) {
        let mut cache = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        cache
            .inner
            .lock()
            .unwrap()
            .entries
            .peek(blob)
            .map(|entry| Arc::clone(&entry.pom))
    }

    #[test]
    fn hit_returns_equal_pom_without_replacing_entry() {
        let cache = ParsedPomCache::default();
        let xml = xml(0);
        let blob = BlobId::from_bytes(xml.as_bytes());
        let first = cache.parse(&blob, &xml).unwrap();
        let entry = cached(&cache, &blob).unwrap();

        assert_eq!(cache.parse(&blob, &xml).unwrap(), first);
        assert!(Arc::ptr_eq(&entry, &cached(&cache, &blob).unwrap()));
    }

    #[test]
    fn changed_bytes_at_same_coordinate_miss() {
        let cache = ParsedPomCache::default();
        let first = xml(0);
        let second = xml(1);
        let first_blob = BlobId::from_bytes(first.as_bytes());
        let second_blob = BlobId::from_bytes(second.as_bytes());
        let first_pom = cache.parse(&first_blob, &first).unwrap();

        assert!(cached(&cache, &second_blob).is_none());
        let second_pom = cache.parse(&second_blob, &second).unwrap();
        assert_eq!(first_pom.artifact_id, second_pom.artifact_id);
        assert_ne!(first_pom, second_pom);
        assert_eq!(cache.parse(&first_blob, &first).unwrap(), first_pom);
        assert_eq!(cache.inner.lock().unwrap().entries.len(), 2);
    }

    #[test]
    fn original_utf8_bom_counts_toward_identity_and_weight() {
        let cache = ParsedPomCache::default();
        let plain = xml(0);
        let bom = format!("\u{feff}{plain}");
        let plain_blob = BlobId::from_bytes(plain.as_bytes());
        let bom_blob = BlobId::from_bytes(bom.as_bytes());
        assert_ne!(plain_blob, bom_blob);
        assert_eq!(
            cache.parse(&plain_blob, &plain).unwrap(),
            cache.parse(&bom_blob, &bom).unwrap()
        );
        let state = cache.inner.lock().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.source_bytes, plain.len() + bom.len());
    }

    #[test]
    fn anonymous_profiles_are_parsed_with_fresh_ids() {
        let cache = ParsedPomCache::default();
        let xml = "<project><profiles><profile/></profiles></project>";
        let blob = BlobId::from_bytes(xml.as_bytes());
        let first = cache.parse(&blob, xml).unwrap();
        let second = cache.parse(&blob, xml).unwrap();

        assert!(first.profiles[0].id.starts_with("__anonymous_"));
        assert_ne!(first.profiles[0].id, second.profiles[0].id);
        assert!(cached(&cache, &blob).is_none());
        assert_eq!(cache.inner.lock().unwrap().source_bytes, 0);
    }

    #[test]
    fn authored_anonymous_profile_id_is_not_cached() {
        let cache = ParsedPomCache::default();
        let xml = "<project><profiles><profile><id>__anonymous_authored</id></profile></profiles></project>";
        let blob = BlobId::from_bytes(xml.as_bytes());
        assert_eq!(cache.parse(&blob, xml).unwrap(), Pom::parse(xml).unwrap());
        assert!(cached(&cache, &blob).is_none());
    }

    #[test]
    fn parse_errors_are_not_cached() {
        let cache = ParsedPomCache::default();
        let xml = "<project><artifactId>broken</project>";
        let blob = BlobId::from_bytes(xml.as_bytes());
        for _ in 0..2 {
            assert!(cache.parse(&blob, xml).is_err());
            assert!(cached(&cache, &blob).is_none());
        }
        assert_eq!(cache.inner.lock().unwrap().source_bytes, 0);
    }

    #[test]
    fn returned_pom_mutations_do_not_change_cached_model() {
        let cache = ParsedPomCache::default();
        let xml = "<project><properties><value>original</value></properties>\
            <repositories><repository><id>custom</id><url>https://example.test/</url>\
            </repository></repositories></project>";
        let blob = BlobId::from_bytes(xml.as_bytes());
        let expected = Pom::parse(xml).unwrap();
        for _ in 0..2 {
            let mut pom = cache.parse(&blob, xml).unwrap();
            assert_eq!(pom, expected);
            pom.properties.insert("value", "modified");
            pom.mark_root_repositories();
            assert_ne!(pom, expected);
        }
        assert_eq!(cache.parse(&blob, xml).unwrap(), expected);
    }

    #[test]
    fn entry_limit_evicts_least_recently_used() {
        let cache = ParsedPomCache::default();
        for id in 0..MAX_PARSED_POM_ENTRIES {
            let xml = xml(id);
            cache
                .parse(&BlobId::from_bytes(xml.as_bytes()), &xml)
                .unwrap();
        }
        let first = xml(0);
        let first_blob = BlobId::from_bytes(first.as_bytes());
        cache.parse(&first_blob, &first).unwrap();
        let extra = xml(MAX_PARSED_POM_ENTRIES);
        cache
            .parse(&BlobId::from_bytes(extra.as_bytes()), &extra)
            .unwrap();

        assert!(cached(&cache, &first_blob).is_some());
        assert!(cached(&cache, &BlobId::from_bytes(xml(1).as_bytes())).is_none());
        let state = cache.inner.lock().unwrap();
        assert_eq!(state.entries.len(), MAX_PARSED_POM_ENTRIES);
        assert_eq!(
            state.source_bytes,
            state
                .entries
                .iter()
                .map(|(_, e)| e.source_bytes)
                .sum::<usize>()
        );
    }

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
            let blob = BlobId::from_bytes(xml.as_bytes());
            cache.parse(&blob, &xml).unwrap();
            blobs.push(blob);
        }

        assert!(cached(&cache, &blobs[0]).is_none());
        assert!(cached(&cache, &blobs[1]).is_none());
        for blob in &blobs[2..] {
            assert!(cached(&cache, blob).is_some());
        }
        let state = cache.inner.lock().unwrap();
        assert_eq!(state.entries.len(), 7);
        assert_eq!(state.source_bytes, MAX_PARSED_POM_SOURCE_BYTES - weight + 1);
    }

    #[test]
    fn duplicate_miss_insertions_count_source_bytes_once() {
        let cache = ParsedPomCache::default();
        let xml = xml(0);
        let blob = BlobId::from_bytes(xml.as_bytes());
        let first = Arc::new(Pom::parse(&xml).unwrap());
        let second = Arc::new(Pom::parse(&xml).unwrap());
        cache.insert(blob.clone(), first, xml.len());
        cache.insert(blob, second, xml.len());

        let state = cache.inner.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.source_bytes, xml.len());
    }
}
