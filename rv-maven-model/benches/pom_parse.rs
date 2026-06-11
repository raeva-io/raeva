use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::fs;
use std::path::{Path, PathBuf};

use rv_maven_model::{ParentResolver, Pom, PomError, Project, PropertyMap};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-fixtures")
}

fn fixture_path(rel: &str) -> PathBuf {
    fixture_dir().join(rel)
}

fn load_fixture(rel: &str) -> String {
    let path = fixture_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Resolver that returns None for all lookups (no parent, no BOM imports).
struct NoopResolver;

impl ParentResolver for NoopResolver {
    fn resolve_parent(&self, _parent: &rv_maven_model::Parent) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }

    fn strict_parent_resolution(&self) -> bool {
        false
    }

    fn strict_bom_resolution(&self) -> bool {
        false
    }
}

/// Collects all .xml fixture files with their relative paths and line counts.
fn collect_fixtures() -> Vec<(String, String, usize)> {
    let base = fixture_dir();
    let mut fixtures = Vec::new();
    for entry in walkdir(&base) {
        let rel = entry
            .strip_prefix(&base)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let content = fs::read_to_string(&entry).unwrap();
        let lines = content.lines().count();
        fixtures.push((rel, content, lines));
    }
    fixtures.sort_by_key(|(_, _, lines)| *lines);
    fixtures
}

/// Simple recursive directory walk for .xml files.
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                result.extend(walkdir(&path));
            } else if path.extension().is_some_and(|ext| ext == "xml") {
                result.push(path);
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Individual POM parsing (different complexity levels)
// ---------------------------------------------------------------------------

fn bench_pom_parse_by_complexity(c: &mut Criterion) {
    let simple_xml = load_fixture("simple-single-module/commons-lang3-pom.xml");
    let profiles_xml = load_fixture("profile-based/netty-parent-pom.xml");
    let bom_xml = load_fixture("bom-usage/spring-boot-dependencies-pom.xml");
    let quarkus_xml = load_fixture("complex-deps/quarkus-bom-pom.xml");

    let mut group = c.benchmark_group("pom_parse_complexity");

    group.bench_function(
        BenchmarkId::new("simple", "commons-lang3 (1070 lines)"),
        |b| b.iter(|| Pom::parse(black_box(&simple_xml)).unwrap()),
    );

    group.bench_function(
        BenchmarkId::new("profiles", "netty-parent (2117 lines, 34 profiles)"),
        |b| b.iter(|| Pom::parse(black_box(&profiles_xml)).unwrap()),
    );

    group.bench_function(
        BenchmarkId::new("bom", "spring-boot-deps (2743 lines)"),
        |b| b.iter(|| Pom::parse(black_box(&bom_xml)).unwrap()),
    );

    group.bench_function(
        BenchmarkId::new("mega_bom", "quarkus-bom (12778 lines)"),
        |b| b.iter(|| Pom::parse(black_box(&quarkus_xml)).unwrap()),
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Parse all fixture POMs (batch throughput)
// ---------------------------------------------------------------------------

fn bench_pom_parse_all_fixtures(c: &mut Criterion) {
    let fixtures = collect_fixtures();
    let _total_lines: usize = fixtures.iter().map(|(_, _, lines)| lines).sum();
    let _total_bytes: usize = fixtures.iter().map(|(_, content, _)| content.len()).sum();

    let mut group = c.benchmark_group("pom_parse_batch");

    // Filter to only fixtures that parse successfully (some have unresolved
    // property references in scope fields that cause deserialization errors).
    let parseable: Vec<_> = fixtures
        .iter()
        .filter(|(_, content, _)| Pom::parse(content).is_ok())
        .collect();
    let parseable_lines: usize = parseable.iter().map(|(_, _, l)| *l).sum();
    let parseable_bytes: usize = parseable.iter().map(|(_, c, _)| c.len()).sum();

    group.bench_function(
        BenchmarkId::new(
            "all_fixtures",
            format!(
                "{} POMs, {} lines, {} KB",
                parseable.len(),
                parseable_lines,
                parseable_bytes / 1024
            ),
        ),
        |b| {
            b.iter(|| {
                for (_, content, _) in &parseable {
                    let _ = Pom::parse(black_box(content)).unwrap();
                }
            })
        },
    );

    // Separate small vs large POMs
    let small: Vec<_> = parseable.iter().filter(|(_, _, l)| *l < 500).collect();
    let large: Vec<_> = parseable.iter().filter(|(_, _, l)| *l >= 2000).collect();

    if !small.is_empty() {
        group.bench_function(
            BenchmarkId::new("small_poms", format!("{} POMs (<500 lines)", small.len())),
            |b| {
                b.iter(|| {
                    for (_, content, _) in &small {
                        let _ = Pom::parse(black_box(content)).unwrap();
                    }
                })
            },
        );
    }

    if !large.is_empty() {
        group.bench_function(
            BenchmarkId::new("large_poms", format!("{} POMs (>=2000 lines)", large.len())),
            |b| {
                b.iter(|| {
                    for (_, content, _) in &large {
                        let _ = Pom::parse(black_box(content)).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Parse + effective model computation
// ---------------------------------------------------------------------------

fn bench_parse_and_resolve(c: &mut Criterion) {
    let simple_xml = load_fixture("simple-single-module/commons-lang3-pom.xml");
    let profiles_xml = load_fixture("profile-based/netty-parent-pom.xml");
    let bom_xml = load_fixture("bom-usage/spring-boot-dependencies-pom.xml");
    let quarkus_xml = load_fixture("complex-deps/quarkus-bom-pom.xml");

    let mut group = c.benchmark_group("pom_parse_and_resolve");

    group.bench_function(BenchmarkId::new("simple", "commons-lang3"), |b| {
        b.iter(|| {
            let pom = Pom::parse(black_box(&simple_xml)).unwrap();
            Project::from_pom(pom, NoopResolver).unwrap()
        })
    });

    group.bench_function(
        BenchmarkId::new("profiles", "netty-parent (34 profiles)"),
        |b| {
            b.iter(|| {
                let pom = Pom::parse(black_box(&profiles_xml)).unwrap();
                Project::from_pom(pom, NoopResolver).unwrap()
            })
        },
    );

    group.bench_function(BenchmarkId::new("bom", "spring-boot-deps"), |b| {
        b.iter(|| {
            let pom = Pom::parse(black_box(&bom_xml)).unwrap();
            Project::from_pom(pom, NoopResolver).unwrap()
        })
    });

    group.bench_function(BenchmarkId::new("mega_bom", "quarkus-bom"), |b| {
        b.iter(|| {
            let pom = Pom::parse(black_box(&quarkus_xml)).unwrap();
            Project::from_pom(pom, NoopResolver).unwrap()
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Property interpolation
// ---------------------------------------------------------------------------

fn bench_property_interpolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("property_interpolation");

    // Simple: single property substitution
    let mut simple_props = PropertyMap::new();
    simple_props.insert("spring.version", "6.2.2");

    group.bench_function("single_substitution", |b| {
        b.iter(|| {
            simple_props
                .interpolate_str_no_project(black_box(
                    "org.springframework:spring-core:${spring.version}",
                ))
                .unwrap()
        })
    });

    // Multiple substitutions in one string
    let mut multi_props = PropertyMap::new();
    multi_props.insert("group", "org.springframework");
    multi_props.insert("artifact", "spring-core");
    multi_props.insert("version", "6.2.2");

    group.bench_function("three_substitutions", |b| {
        b.iter(|| {
            multi_props
                .interpolate_str_no_project(black_box("${group}:${artifact}:${version}"))
                .unwrap()
        })
    });

    // Chained properties: a -> b -> c
    let mut chain_props = PropertyMap::new();
    chain_props.insert("spring", "6.2.2");
    chain_props.insert("spring.core.version", "${spring}");
    chain_props.insert("dep.version", "${spring.core.version}");

    group.bench_function("chained_3_deep", |b| {
        b.iter(|| {
            chain_props
                .interpolate_str_no_project(black_box("${dep.version}"))
                .unwrap()
        })
    });

    // No substitution needed (fast path)
    let empty_props = PropertyMap::new();
    group.bench_function("no_substitution_needed", |b| {
        b.iter(|| {
            empty_props
                .interpolate_str_no_project(black_box("org.springframework:spring-core:6.2.2"))
                .unwrap()
        })
    });

    // Realistic: Spring Boot BOM-style with many properties
    let mut bom_props = PropertyMap::new();
    bom_props.insert("spring-framework.version", "6.2.2");
    bom_props.insert("spring-security.version", "6.4.2");
    bom_props.insert("jackson.version", "2.18.2");
    bom_props.insert("slf4j.version", "2.0.16");
    bom_props.insert("logback.version", "1.5.16");
    bom_props.insert("junit-jupiter.version", "5.11.4");
    bom_props.insert("mockito.version", "5.15.2");
    bom_props.insert("hibernate.version", "6.6.5.Final");
    bom_props.insert("netty.version", "4.1.117.Final");
    bom_props.insert("tomcat.version", "10.1.34");

    // Simulate resolving 10 dependency versions
    let dep_strings: Vec<String> = vec![
        "org.springframework:spring-core:${spring-framework.version}",
        "org.springframework.security:spring-security-core:${spring-security.version}",
        "com.fasterxml.jackson.core:jackson-databind:${jackson.version}",
        "org.slf4j:slf4j-api:${slf4j.version}",
        "ch.qos.logback:logback-classic:${logback.version}",
        "org.junit.jupiter:junit-jupiter:${junit-jupiter.version}",
        "org.mockito:mockito-core:${mockito.version}",
        "org.hibernate.orm:hibernate-core:${hibernate.version}",
        "io.netty:netty-all:${netty.version}",
        "org.apache.tomcat.embed:tomcat-embed-core:${tomcat.version}",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    group.bench_function("bom_style_10_deps", |b| {
        b.iter(|| {
            for dep in &dep_strings {
                let _ = bom_props
                    .interpolate_str_no_project(black_box(dep))
                    .unwrap();
            }
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// POM parse isolated: just XML deserialization throughput
// ---------------------------------------------------------------------------

fn bench_pom_xml_throughput(c: &mut Criterion) {
    // Measure raw XML parsing throughput in MB/s
    let quarkus_xml = load_fixture("complex-deps/quarkus-bom-pom.xml");
    let quarkus_bytes = quarkus_xml.len();

    let mut group = c.benchmark_group("pom_xml_throughput");
    group.throughput(criterion::Throughput::Bytes(quarkus_bytes as u64));

    group.bench_function("quarkus_bom", |b| {
        b.iter(|| Pom::parse(black_box(&quarkus_xml)).unwrap())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pom_parse_by_complexity,
    bench_pom_parse_all_fixtures,
    bench_parse_and_resolve,
    bench_property_interpolation,
    bench_pom_xml_throughput,
);
criterion_main!(benches);
