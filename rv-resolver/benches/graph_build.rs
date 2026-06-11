use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use rv_maven_model::Scope;
use rv_resolver::{Edge, Graph, Node, Tree};
use rv_version::Coord;

/// Build a synthetic dependency graph with the given number of direct
/// dependencies and transitive depth.
fn build_graph(direct_deps: usize, depth: usize) -> Graph {
    let root_coord = Coord::parse("com.example:root:1.0.0").unwrap();
    let root = Node {
        coord: root_coord,
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::with_capacity(root, direct_deps * depth + 1);

    let root_idx = graph.root();

    for i in 0..direct_deps {
        let coord = Coord::parse(&format!("com.example:lib-{i}:1.0.0")).unwrap();
        let node = Node {
            coord,
            scope: Scope::Compile,
            repo_url: None,
            checksum: None,
            local: false,
            system_path: None,
        };
        let idx = graph.insert_node(node);
        graph.add_edge(
            root_idx,
            idx,
            Edge {
                scope: Scope::Compile,
                optional: false,
                exclusions: Vec::new(),
                requested: Some("1.0.0".to_string()),
            },
        );

        // Add transitive chain
        let mut parent_idx = idx;
        for j in 1..depth {
            let coord = Coord::parse(&format!("com.example:lib-{i}-transitive-{j}:1.0.0")).unwrap();
            let node = Node {
                coord,
                scope: Scope::Compile,
                repo_url: None,
                checksum: None,
                local: false,
                system_path: None,
            };
            let child_idx = graph.insert_node(node);
            graph.add_edge(
                parent_idx,
                child_idx,
                Edge {
                    scope: Scope::Compile,
                    optional: false,
                    exclusions: Vec::new(),
                    requested: Some("1.0.0".to_string()),
                },
            );
            parent_idx = child_idx;
        }
    }

    graph
}

/// Build a realistic Spring Boot-like dependency graph with shared transitive
/// dependencies (diamond pattern) to measure deduplication via insert_node.
fn build_diamond_graph() -> Graph {
    let root_coord = Coord::parse("com.example:app:1.0.0").unwrap();
    let root = Node {
        coord: root_coord,
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::with_capacity(root, 200);
    let root_idx = graph.root();

    // Simulate Spring Boot: many starters sharing spring-core, slf4j, etc.
    let shared_deps = [
        "org.springframework:spring-core:6.2.2",
        "org.springframework:spring-beans:6.2.2",
        "org.springframework:spring-context:6.2.2",
        "org.slf4j:slf4j-api:2.0.16",
        "com.fasterxml.jackson.core:jackson-core:2.18.2",
        "com.fasterxml.jackson.core:jackson-annotations:2.18.2",
        "com.fasterxml.jackson.core:jackson-databind:2.18.2",
    ];

    // Pre-insert shared deps
    let shared_indices: Vec<_> = shared_deps
        .iter()
        .map(|s| {
            let coord = Coord::parse(s).unwrap();
            let node = Node {
                coord,
                scope: Scope::Compile,
                repo_url: None,
                checksum: None,
                local: false,
                system_path: None,
            };
            graph.insert_node(node)
        })
        .collect();

    // Create 20 direct deps, each pulling in 3-5 shared deps
    for i in 0..20 {
        let coord = Coord::parse(&format!("com.example:module-{i}:1.0.0")).unwrap();
        let node = Node {
            coord,
            scope: Scope::Compile,
            repo_url: None,
            checksum: None,
            local: false,
            system_path: None,
        };
        let idx = graph.insert_node(node);
        graph.add_edge(
            root_idx,
            idx,
            Edge {
                scope: Scope::Compile,
                optional: false,
                exclusions: Vec::new(),
                requested: Some("1.0.0".to_string()),
            },
        );

        // Each module depends on a subset of shared deps
        let start = i % shared_indices.len();
        let count = 3 + (i % 3);
        for j in 0..count {
            let shared_idx = shared_indices[(start + j) % shared_indices.len()];
            graph.add_edge(
                idx,
                shared_idx,
                Edge {
                    scope: Scope::Compile,
                    optional: false,
                    exclusions: Vec::new(),
                    requested: None,
                },
            );
        }
    }

    graph
}

// ---------------------------------------------------------------------------
// Graph construction benchmarks
// ---------------------------------------------------------------------------

fn bench_graph_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_build");

    for &(direct, depth) in &[(10, 3), (50, 5), (100, 5), (200, 3)] {
        let total = 1 + direct * depth;
        group.bench_function(
            BenchmarkId::new(
                "linear",
                format!("{direct} direct x {depth} deep = {total} nodes"),
            ),
            |b| b.iter(|| black_box(build_graph(direct, depth))),
        );
    }

    group.bench_function(
        "diamond (Spring Boot-like, 20 modules + shared deps)",
        |b| b.iter(|| black_box(build_diamond_graph())),
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Graph node deduplication benchmarks
//
// insert_node should return existing index for duplicate coords.
// This measures the cost of the IndexMap lookup path.
// ---------------------------------------------------------------------------

fn bench_graph_insert_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_insert_dedup");

    // Build a graph, then try inserting duplicate nodes
    let graph = build_graph(100, 1);

    // Prepare duplicate nodes
    let dup_nodes: Vec<Node> = (0..100)
        .map(|i| Node {
            coord: Coord::parse(&format!("com.example:lib-{i}:1.0.0")).unwrap(),
            scope: Scope::Compile,
            repo_url: None,
            checksum: None,
            local: false,
            system_path: None,
        })
        .collect();

    group.bench_function("100_duplicate_inserts", |b| {
        b.iter(|| {
            let mut g = graph.clone();
            for node in &dup_nodes {
                let _ = black_box(g.insert_node(node.clone()));
            }
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Tree rendering benchmarks
// ---------------------------------------------------------------------------

fn bench_tree_render(c: &mut Criterion) {
    let small_graph = build_graph(10, 3);
    let medium_graph = build_graph(50, 5);
    let diamond_graph = build_diamond_graph();

    let mut group = c.benchmark_group("tree_render");

    group.bench_function(
        BenchmarkId::new("small", format!("{} nodes", small_graph.node_count())),
        |b| b.iter(|| black_box(Tree::from_graph(&small_graph).render())),
    );

    group.bench_function(
        BenchmarkId::new("medium", format!("{} nodes", medium_graph.node_count())),
        |b| b.iter(|| black_box(Tree::from_graph(&medium_graph).render())),
    );

    group.bench_function(
        BenchmarkId::new("diamond", format!("{} nodes", diamond_graph.node_count())),
        |b| b.iter(|| black_box(Tree::from_graph(&diamond_graph).render())),
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_graph_build,
    bench_graph_insert_dedup,
    bench_tree_render,
);
criterion_main!(benches);
