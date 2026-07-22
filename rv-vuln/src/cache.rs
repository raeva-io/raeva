use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::sync::Cache;

use crate::Vulnerability;

const DEFAULT_MAX_ENTRIES: u64 = 10_000;
const DEFAULT_TTL_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub entry_count: usize,
    pub hits: u64,
    pub misses: u64,
}

#[derive(Clone)]
pub struct VulnCache {
    cache: Cache<String, Vec<Vulnerability>>,
    stats: Arc<CacheStatsInternal>,
}

struct CacheStatsInternal {
    hits: AtomicU64,
    misses: AtomicU64,
}

impl std::fmt::Debug for VulnCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VulnCache")
            .field("entry_count", &self.cache.entry_count())
            .finish()
    }
}

impl VulnCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_max_entries(ttl: Duration, max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();

        Self {
            cache,
            stats: Arc::new(CacheStatsInternal {
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
            }),
        }
    }

    pub fn get(&self, purl: &str) -> Option<Vec<Vulnerability>> {
        match self.cache.get(purl) {
            Some(vulns) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Some(vulns)
            }
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn insert(&self, purl: String, vulnerabilities: Vec<Vulnerability>) {
        self.cache.insert(purl, vulnerabilities);
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.cache.entry_count() as usize,
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
        }
    }

    pub fn len(&self) -> usize {
        self.cache.entry_count() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.cache.entry_count() == 0
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

impl Default for VulnCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_TTL_SECS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn make_vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: vec![],
            summary: String::new(),
            details: None,
            severity: None,
            references: vec![],
            affected: vec![],
        }
    }

    #[test]
    fn test_basic_cache_operations() {
        let cache = VulnCache::new(Duration::from_secs(60));

        cache.insert(
            "pkg:maven/com.example/foo@1.0".to_string(),
            vec![make_vuln("CVE-1")],
        );
        let result = cache.get("pkg:maven/com.example/foo@1.0");
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0].id, "CVE-1");

        let result = cache.get("pkg:maven/com.example/unknown@1.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_ttl_expiration() {
        let cache = VulnCache::new(Duration::from_millis(50));

        cache.insert(
            "pkg:maven/com.example/foo@1.0".to_string(),
            vec![make_vuln("CVE-1")],
        );

        assert!(cache.get("pkg:maven/com.example/foo@1.0").is_some());

        sleep(Duration::from_millis(100));

        // Moka uses lazy expiration, so we need to trigger a sync
        cache.cache.run_pending_tasks();

        assert!(cache.get("pkg:maven/com.example/foo@1.0").is_none());
    }

    #[test]
    fn test_max_entries_eviction() {
        let cache = VulnCache::with_max_entries(Duration::from_secs(60), 10);

        for i in 0..15 {
            cache.insert(
                format!("pkg:maven/com.example/dep{}@1.0", i),
                vec![make_vuln(&format!("CVE-{}", i))],
            );
        }

        // Sync to ensure evictions are processed
        cache.cache.run_pending_tasks();

        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_stats() {
        let cache = VulnCache::new(Duration::from_secs(60));

        cache.insert(
            "pkg:maven/com.example/foo@1.0".to_string(),
            vec![make_vuln("CVE-1")],
        );

        let _ = cache.get("pkg:maven/com.example/foo@1.0");
        let _ = cache.get("pkg:maven/com.example/unknown@1.0");

        cache.cache.run_pending_tasks();
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }
}
