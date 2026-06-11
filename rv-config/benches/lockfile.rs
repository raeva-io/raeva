use std::collections::BTreeMap;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use rv_config::{Checksum, LockEdge, LockPackage, LockPlatform, Lockfile, Platform};

/// Build a realistic lockfile with `n` packages and dependency edges.
fn build_lockfile(n: usize) -> Lockfile {
    let platform = Platform::new("linux", "x86_64").unwrap();
    let packages: Vec<LockPackage> = (0..n)
        .map(|i| LockPackage {
            group_id: format!("org.example.group{}", i / 10),
            artifact_id: format!("artifact-{}", i),
            version: format!("{}.{}.{}", i / 100, (i / 10) % 10, i % 10),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", format!("{:064x}", i))),
            system_path: None,
            direct_scope: if i < 10 {
                Some("compile".to_string())
            } else {
                None
            },
            extra: BTreeMap::new(),
        })
        .collect();

    // Create a realistic dependency graph: each package depends on 0-3 earlier packages.
    let edges: Vec<LockEdge> = (1..n)
        .flat_map(|i| {
            let mut e = vec![LockEdge {
                from: i,
                to: i.saturating_sub(1),
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }];
            if i > 5 {
                e.push(LockEdge {
                    from: i,
                    to: i / 2,
                    scope: Some("runtime".to_string()),
                    optional: false,
                    extra: BTreeMap::new(),
                });
            }
            e
        })
        .collect();

    Lockfile {
        schema_version: 3,
        config_hash: Some("abc123def456".to_string()),
        platforms: vec![LockPlatform {
            platform,
            packages,
            edges,
            extra: BTreeMap::new(),
        }],
        metadata: BTreeMap::new(),
        extra: BTreeMap::new(),
    }
}

fn bench_lockfile_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfile_serialize");

    for size in [50, 200, 500] {
        let lock = build_lockfile(size);
        group.bench_with_input(BenchmarkId::new("toml", size), &lock, |b, lock| {
            b.iter(|| {
                let s = toml::to_string_pretty(black_box(lock)).unwrap();
                black_box(s);
            });
        });
    }

    group.finish();
}

fn bench_lockfile_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfile_deserialize");

    for size in [50, 200, 500] {
        let lock = build_lockfile(size);
        let toml_str = toml::to_string_pretty(&lock).unwrap();
        group.bench_with_input(BenchmarkId::new("toml", size), &toml_str, |b, s| {
            b.iter(|| {
                let l: Lockfile = toml::from_str(black_box(s)).unwrap();
                black_box(l);
            });
        });
    }

    group.finish();
}

fn bench_lockfile_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfile_round_trip");

    for size in [50, 200, 500] {
        let lock = build_lockfile(size);
        group.bench_with_input(BenchmarkId::new("toml", size), &lock, |b, lock| {
            b.iter(|| {
                let s = toml::to_string_pretty(black_box(lock)).unwrap();
                let l: Lockfile = toml::from_str(&s).unwrap();
                black_box(l);
            });
        });
    }

    group.finish();
}

fn bench_lockfile_write_atomic(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfile_write_atomic");

    let dir = tempfile::tempdir().unwrap();

    for size in [50, 200, 500] {
        let lock = build_lockfile(size);
        let path = dir.path().join(format!("rv-{}.lock", size));
        group.bench_with_input(BenchmarkId::new("file", size), &lock, |b, lock| {
            b.iter(|| {
                lock.write_atomic(black_box(&path)).unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_lockfile_serialize,
    bench_lockfile_deserialize,
    bench_lockfile_round_trip,
    bench_lockfile_write_atomic,
);
criterion_main!(benches);
