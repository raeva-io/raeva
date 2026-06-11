use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use rv_version::{Coord, Version, VersionRange, VersionReq};

// Representative Maven versions from real-world projects (Spring, Hibernate, Netty,
// JUnit, Quarkus, etc.) covering all qualifier types Maven handles.
const VERSIONS: &[&str] = &[
    // Simple numeric
    "1.0.0",
    "2.13.3",
    "3.12.0",
    "4.5.56",
    "0.8.6",
    "5.10.0",
    "6.1.14",
    "17.0.0",
    "1.0",
    "21",
    // Pre-release qualifiers
    "1.0.0-alpha-1",
    "1.0.0-beta.2",
    "1.0.0-rc1",
    "3.0.0-M1",
    "3.0.0-M2",
    "3.0.0-M3",
    // Enterprise qualifiers
    "2.0.0.Final",
    "5.6.15.Final",
    "3.0.0.CR1",
    "1.0.0.SP1",
    // Snapshots
    "2.13.3-SNAPSHOT",
    "999-SNAPSHOT",
    "1.0.0-20240115.123456-42",
    // Complex multi-segment
    "1.2.3.4.5",
    "3.0.0-jre",
    "2.0.0-jakarta",
    "4.13.2",
    // Versions from real Spring Boot BOM
    "6.2.2",
    "3.4.2",
    "2.8.0",
    "5.11.4",
    "1.5.8",
    "42.7.5",
    "2.17.2",
    "4.0.5",
    "0.9.0",
    "5.4.0",
    "3.25.5",
    "12.0.16",
    "8.0.2.Final",
    "10.1.34",
    "1.20",
    "2.0.16",
    "1.14.4",
    "3.1.0-M1",
    "2.0.0-alpha-11",
    "3.0.0-beta1",
];

const COORDS: &[&str] = &[
    "org.springframework:spring-core:6.2.2",
    "com.google.guava:guava:33.4.0-jre",
    "io.netty:netty-all:4.1.117.Final",
    "org.apache.commons:commons-lang3:3.17.0",
    "com.fasterxml.jackson.core:jackson-databind:2.18.2",
    "org.junit.jupiter:junit-jupiter:5.11.4",
    "ch.qos.logback:logback-classic:1.5.16",
    "org.hibernate.orm:hibernate-core:6.6.5.Final",
    "io.quarkus:quarkus-core:3.17.7",
    "org.apache.maven:maven-model:4.0.0-rc-3",
    "com.google.guava:guava:33.4.0-jre:jar:sources",
    "org.apache.logging.log4j:log4j-core:2.24.3",
];

const VERSION_RANGES: &[&str] = &[
    "[1.0,2.0)",
    "[1.0,2.0]",
    "(1.0,2.0)",
    "[1.0,)",
    "(,2.0]",
    "[1.5]",
    "[1.0,2.0),[3.0,)",
    "(,1.0],[2.0,3.0]",
    "[1.0.0,2.0.0),[3.0.0.Final,)",
    "[1.0.0-SNAPSHOT,2.0.0-RELEASE)",
];

// ---------------------------------------------------------------------------
// Parse benchmarks
// ---------------------------------------------------------------------------

fn bench_version_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_parse");

    group.bench_function(
        BenchmarkId::new("batch", format!("{} versions", VERSIONS.len())),
        |b| {
            b.iter(|| {
                for v in VERSIONS {
                    let _ = Version::parse(black_box(v)).unwrap();
                }
            })
        },
    );

    // Benchmark individual categories to show performance characteristics
    group.bench_function("simple_numeric (1.0.0)", |b| {
        b.iter(|| Version::parse(black_box("1.0.0")).unwrap())
    });

    group.bench_function("enterprise_qualifier (5.6.15.Final)", |b| {
        b.iter(|| Version::parse(black_box("5.6.15.Final")).unwrap())
    });

    group.bench_function("snapshot (2.13.3-SNAPSHOT)", |b| {
        b.iter(|| Version::parse(black_box("2.13.3-SNAPSHOT")).unwrap())
    });

    group.bench_function("complex_multi_segment (1.2.3.4.5)", |b| {
        b.iter(|| Version::parse(black_box("1.2.3.4.5")).unwrap())
    });

    group.bench_function("timestamp_snapshot (1.0.0-20240115.123456-42)", |b| {
        b.iter(|| Version::parse(black_box("1.0.0-20240115.123456-42")).unwrap())
    });

    group.finish();
}

fn bench_coord_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("coord_parse");

    group.bench_function(
        BenchmarkId::new("batch", format!("{} coords", COORDS.len())),
        |b| {
            b.iter(|| {
                for coord in COORDS {
                    let _ = Coord::parse(black_box(coord)).unwrap();
                }
            })
        },
    );

    group.bench_function("simple_3_part (g:a:v)", |b| {
        b.iter(|| Coord::parse(black_box("org.springframework:spring-core:6.2.2")).unwrap())
    });

    group.bench_function("5_part (g:a:v:p:c)", |b| {
        b.iter(|| Coord::parse(black_box("com.google.guava:guava:33.4.0-jre:jar:sources")).unwrap())
    });

    group.finish();
}

fn bench_version_range_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_range_parse");

    group.bench_function(
        BenchmarkId::new("batch", format!("{} ranges", VERSION_RANGES.len())),
        |b| {
            b.iter(|| {
                for range in VERSION_RANGES {
                    let _ = VersionReq::parse(black_box(range)).unwrap();
                }
            })
        },
    );

    group.bench_function("simple_range [1.0,2.0)", |b| {
        b.iter(|| VersionReq::parse(black_box("[1.0,2.0)")).unwrap())
    });

    group.bench_function("union_range [1.0,2.0),[3.0,)", |b| {
        b.iter(|| VersionReq::parse(black_box("[1.0,2.0),[3.0,)")).unwrap())
    });

    group.bench_function("exact_range [1.5]", |b| {
        b.iter(|| VersionReq::parse(black_box("[1.5]")).unwrap())
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Compare benchmarks
// ---------------------------------------------------------------------------

fn bench_version_compare(c: &mut Criterion) {
    let parsed: Vec<Version> = VERSIONS
        .iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();

    let n = parsed.len();

    let mut group = c.benchmark_group("version_compare");

    group.bench_function(
        BenchmarkId::new("all_pairs", format!("{} comparisons", n * n)),
        |b| {
            b.iter(|| {
                for a in &parsed {
                    for b_ver in &parsed {
                        let _ = black_box(a.cmp(b_ver));
                    }
                }
            })
        },
    );

    // Benchmark worst-case: comparing versions that share long common prefixes
    let similar_a = Version::parse("3.0.0-M1").unwrap();
    let similar_b = Version::parse("3.0.0-M2").unwrap();
    group.bench_function("similar_versions (3.0.0-M1 vs 3.0.0-M2)", |b| {
        b.iter(|| black_box(similar_a.cmp(&similar_b)))
    });

    // Benchmark equal versions
    let eq_a = Version::parse("5.6.15.Final").unwrap();
    let eq_b = Version::parse("5.6.15.Final").unwrap();
    group.bench_function("equal_versions (5.6.15.Final)", |b| {
        b.iter(|| black_box(eq_a.cmp(&eq_b)))
    });

    // Benchmark versions that differ early
    let diff_a = Version::parse("1.0.0").unwrap();
    let diff_b = Version::parse("6.1.14").unwrap();
    group.bench_function("different_major (1.0.0 vs 6.1.14)", |b| {
        b.iter(|| black_box(diff_a.cmp(&diff_b)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Sort benchmarks
// ---------------------------------------------------------------------------

fn bench_version_sort(c: &mut Criterion) {
    let parsed: Vec<Version> = VERSIONS
        .iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();

    let mut group = c.benchmark_group("version_sort");

    group.bench_function(
        BenchmarkId::new("full_set", format!("{} versions", parsed.len())),
        |b| {
            b.iter_batched(
                || parsed.clone(),
                |mut versions| {
                    versions.sort();
                    black_box(versions);
                },
                BatchSize::SmallInput,
            )
        },
    );

    // Benchmark sorting already-sorted input (best case for timsort)
    let mut sorted = parsed.clone();
    sorted.sort();
    group.bench_function("pre_sorted", |b| {
        b.iter_batched(
            || sorted.clone(),
            |mut versions| {
                versions.sort();
                black_box(versions);
            },
            BatchSize::SmallInput,
        )
    });

    // Benchmark sorting reverse-sorted input (worst case)
    let mut reversed = sorted.clone();
    reversed.reverse();
    group.bench_function("reverse_sorted", |b| {
        b.iter_batched(
            || reversed.clone(),
            |mut versions| {
                versions.sort();
                black_box(versions);
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Range matching benchmarks
// ---------------------------------------------------------------------------

fn bench_version_range_match(c: &mut Criterion) {
    let parsed_versions: Vec<Version> = VERSIONS
        .iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();

    let range = VersionRange::parse("[1.0,5.0)").unwrap();
    let union_req = VersionReq::parse("[1.0,2.0),[3.0,5.0),[6.0,)").unwrap();

    let mut group = c.benchmark_group("version_range_match");

    group.bench_function(
        BenchmarkId::new(
            "single_range_vs_all",
            format!("{} versions", parsed_versions.len()),
        ),
        |b| {
            b.iter(|| {
                for v in &parsed_versions {
                    let _ = black_box(range.matches(v));
                }
            })
        },
    );

    group.bench_function(
        BenchmarkId::new(
            "union_range_vs_all",
            format!("{} versions", parsed_versions.len()),
        ),
        |b| {
            b.iter(|| {
                for v in &parsed_versions {
                    let _ = black_box(union_req.matches(v));
                }
            })
        },
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Range intersection benchmarks
// ---------------------------------------------------------------------------

fn bench_version_range_intersect(c: &mut Criterion) {
    let r1 = VersionRange::parse("[1.0,3.0)").unwrap();
    let r2 = VersionRange::parse("[2.0,5.0)").unwrap();
    let r3 = VersionRange::parse("[4.0,6.0)").unwrap();

    let req1 = VersionReq::parse("[1.0,2.0),[4.0,5.0)").unwrap();
    let req2 = VersionReq::parse("[1.5,4.5)").unwrap();

    let mut group = c.benchmark_group("version_range_intersect");

    group.bench_function("overlapping_ranges", |b| {
        b.iter(|| black_box(r1.intersect(&r2)))
    });

    group.bench_function("non_overlapping_ranges", |b| {
        b.iter(|| black_box(r1.intersect(&r3)))
    });

    group.bench_function("union_req_intersect", |b| {
        b.iter(|| black_box(req1.intersect(&req2)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_version_parse,
    bench_coord_parse,
    bench_version_range_parse,
    bench_version_compare,
    bench_version_sort,
    bench_version_range_match,
    bench_version_range_intersect,
);
criterion_main!(benches);
