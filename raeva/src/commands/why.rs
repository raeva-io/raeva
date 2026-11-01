//! Dependency explanation command.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::io;

use clap::Args;
use rv_lock::{LockModule, LockModulePackage};
use rv_maven_types::PartialCoord;
use serde::Serialize;

use crate::commands::module_selector::{LockModuleExt, ModuleSelector};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

const SHOWN_PATHS: usize = 10;
const MAX_DEP_PATHS: usize = 10_000;
/// Partial paths the search may take from its queue before it gives up,
/// so a dense graph cannot keep it busy.
const MAX_SEARCH_STEPS: usize = 1_000_000;
/// Partial paths the search may hold, so a dense graph cannot exhaust
/// memory.
const MAX_SEARCH_NODES: usize = 2_000_000;

#[derive(Debug, Args)]
#[command(
    after_long_help = crate::commands::util::help_examples(&[
        ("why org.slf4j:slf4j-api", ""),
        ("why commons-logging", ""),
        ("why org.slf4j:slf4j-api --module app/pom.xml", ""),
        ("why org.slf4j:slf4j-api --module com.acme:app", ""),
        ("why org.slf4j:slf4j-api --all", ""),
    ])
)]
pub(crate) struct WhyArgs {
    #[arg(
        value_name = "COORD",
        value_parser = parse_coord,
        help = "Dependency coordinate (artifact, group:artifact, or group:artifact:version)"
    )]
    pub coord: PartialCoord,
    #[command(flatten)]
    module: ModuleSelector,
    #[arg(
        long,
        help = "Show every path, up to 10000, instead of the 10 shortest"
    )]
    pub all: bool,
}

fn parse_coord(value: &str) -> std::result::Result<PartialCoord, String> {
    PartialCoord::parse(value).map_err(|err| err.to_string())
}

#[derive(Debug, Serialize)]
struct WhyModuleOutput {
    module: String,
    gav: String,
    #[serde(skip)]
    label: String,
    found: bool,
    truncated: bool,
    paths: Vec<Vec<String>>,
    #[serde(skip)]
    display_paths: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct WhyOutput {
    target: String,
    platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jdk: Option<String>,
    found: bool,
    truncated: bool,
    modules: Vec<WhyModuleOutput>,
}

pub(crate) fn run(args: &WhyArgs, session: &Session) -> Result<Report> {
    let config = session.lock_config()?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock, config.host().java_version())?;
    let selection = args.module.select(platform)?;
    let mut modules = Vec::with_capacity(selection.modules().len());
    let limit = if args.all { MAX_DEP_PATHS } else { SHOWN_PATHS };
    for module in selection.modules() {
        modules.push(explain_module(module, &args.coord, limit)?);
    }

    let found = modules.iter().any(|module| module.found);
    let truncated = modules.iter().any(|module| module.truncated);
    let report = Report::data(WhyReport {
        output: WhyOutput {
            target: args.coord.to_string(),
            platform: platform.platform.os_arch(),
            jdk: platform.platform.jdk().map(str::to_string),
            found,
            truncated,
            modules,
        },
        show_headers: selection.is_aggregate(),
        all: args.all,
    });
    // A coordinate that is not in the graph exits 1, like `grep` with no
    // match, so scripts can test membership with the exit status.
    if found {
        Ok(report)
    } else {
        Ok(report.failed(CliError::NoDependencyPath {
            target: args.coord.to_string(),
        }))
    }
}

struct WhyReport {
    output: WhyOutput,
    show_headers: bool,
    all: bool,
}

impl CommandOutput for WhyReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(&self.output)
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.heading(format!("why {}", self.output.target))?;
        let mut rendered_section = false;
        for module in self.output.modules.iter().filter(|module| module.found) {
            if self.show_headers {
                if rendered_section {
                    human.blank_line()?;
                }
                human.line(format!("Module: {}", module.label))?;
            }
            rendered_section = true;
            // Numbered, so where one wrapped path ends and the next begins
            // shows; a direct dependency says so.
            for (index, path) in module.display_paths.iter().enumerate() {
                let number = format!("{}. ", index + 1);
                let width = human.width().saturating_sub(number.len());
                for (line_index, line) in wrap_path(path, width).into_iter().enumerate() {
                    // A label such as `(workspace)` takes the note inside.
                    let line = match (line_index, path.len()) {
                        (0, 1) => match [" (workspace)", " (system)"]
                            .into_iter()
                            .find_map(|label| line.strip_suffix(label).map(|rest| (rest, label)))
                        {
                            Some((rest, label)) => {
                                format!("{rest}{}, direct dependency)", label.trim_end_matches(')'))
                            }
                            None => format!("{line} (direct dependency)"),
                        },
                        _ => line,
                    };
                    match line_index {
                        0 => human.line(format!("{number}{line}"))?,
                        _ => human.line(format!("{}{line}", " ".repeat(number.len())))?,
                    }
                }
            }
            if module.truncated {
                human.note(if self.all {
                    format!("Showing the {MAX_DEP_PATHS} shortest paths; more exist.")
                } else {
                    format!(
                        "Showing the {SHOWN_PATHS} shortest paths; add --all to list up to \
                         {MAX_DEP_PATHS}."
                    )
                })?;
            }
        }
        Ok(())
    }
}

fn wrap_path(path: &[String], width: usize) -> Vec<String> {
    const INDENT: &str = "    ";
    let mut lines = Vec::new();
    let mut line = String::new();
    for (index, step) in path.iter().enumerate() {
        let piece = if index == 0 {
            step.clone()
        } else {
            format!(" -> {step}")
        };
        if !line.is_empty()
            && line.chars().count() + piece.chars().count() > width
            && line.trim() != ""
        {
            lines.push(std::mem::take(&mut line));
            line.push_str(INDENT);
            line.push_str(piece.trim_start());
        } else {
            line.push_str(&piece);
        }
    }
    lines.push(line);
    lines
}

fn explain_module(
    module: &LockModule,
    target: &PartialCoord,
    limit: usize,
) -> Result<WhyModuleOutput> {
    let (graph, roots) = build_graph(module)?;
    let targets: Vec<usize> = module
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| matches_target(package, target))
        .map(|(index, _)| index)
        .collect();
    let (paths, truncated) = collect_paths(&graph, &roots, &targets, limit);
    let labels = |label: fn(&LockModulePackage) -> String| -> Vec<Vec<String>> {
        paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|index| label(&module.packages[*index]))
                    .collect()
            })
            .collect()
    };
    let display_paths = labels(display_label);
    let paths = labels(|package| package.coordinate.to_string());
    Ok(WhyModuleOutput {
        module: module.path.clone(),
        gav: module.gav(),
        label: module.display_label(),
        found: !paths.is_empty(),
        truncated,
        paths,
        display_paths,
    })
}

pub(super) fn display_label(package: &LockModulePackage) -> String {
    let coordinate = crate::commands::util::display_coordinate(&package.coordinate);
    if package.workspace_module.is_some() {
        format!("{coordinate} (workspace)")
    } else if package.system_path.is_some() {
        format!("{coordinate} (system)")
    } else {
        coordinate
    }
}

/// Up to `limit` paths from a root to a target, shortest first, and whether
/// there are more. A path ends at the first target it reaches and visits no
/// package twice.
///
/// The search extends partial paths in order of their length plus the
/// distance from their end to the nearest target, which never overstates
/// what is left, so complete paths come out shortest first and every
/// partial path taken from the queue can still reach a target. Among equal
/// estimates the longer partial path goes first, so the first path comes
/// out after at most one step per package on it; [`MAX_SEARCH_STEPS`] and
/// [`MAX_SEARCH_NODES`] apply only after that, and a target a root reaches
/// is always reported as found.
pub(super) fn collect_paths(
    children: &[Vec<usize>],
    roots: &[usize],
    targets: &[usize],
    limit: usize,
) -> (Vec<Vec<usize>>, bool) {
    struct Step {
        node: usize,
        parent: Option<usize>,
        len: usize,
    }
    fn path_of(steps: &[Step], mut at: usize) -> Vec<usize> {
        let mut path = Vec::with_capacity(steps[at].len);
        loop {
            path.push(steps[at].node);
            match steps[at].parent {
                Some(parent) => at = parent,
                None => break,
            }
        }
        path.reverse();
        path
    }
    fn contains(steps: &[Step], mut at: usize, node: usize) -> bool {
        loop {
            if steps[at].node == node {
                return true;
            }
            match steps[at].parent {
                Some(parent) => at = parent,
                None => return false,
            }
        }
    }

    let count = children.len();
    let mut parents = vec![Vec::new(); count];
    for (from, outgoing) in children.iter().enumerate() {
        for &to in outgoing {
            parents[to].push(from);
        }
    }
    let mut is_target = vec![false; count];
    let mut distance = vec![usize::MAX; count];
    let mut queue = VecDeque::new();
    for &target in targets {
        if target < count && !is_target[target] {
            is_target[target] = true;
            distance[target] = 0;
            queue.push_back(target);
        }
    }
    while let Some(node) = queue.pop_front() {
        for &parent in &parents[node] {
            if distance[parent] == usize::MAX {
                distance[parent] = distance[node] + 1;
                queue.push_back(parent);
            }
        }
    }

    let mut steps: Vec<Step> = Vec::new();
    let mut heap = BinaryHeap::new();
    for &root in roots {
        if distance[root] != usize::MAX {
            heap.push(Reverse((distance[root], Reverse(1_usize), steps.len())));
            steps.push(Step {
                node: root,
                parent: None,
                len: 1,
            });
        }
    }
    let mut paths = Vec::new();
    let mut taken = 0;
    while let Some(Reverse((_, _, at))) = heap.pop() {
        taken += 1;
        let last = steps[at].node;
        if is_target[last] {
            if paths.len() == limit {
                return (paths, true);
            }
            paths.push(path_of(&steps, at));
            continue;
        }
        if !paths.is_empty() && (taken > MAX_SEARCH_STEPS || steps.len() > MAX_SEARCH_NODES) {
            return (paths, true);
        }
        let next: Vec<usize> = (children[last].iter().copied())
            .filter(|&child| distance[child] != usize::MAX && !contains(&steps, at, child))
            .collect();
        let len = steps[at].len + 1;
        for child in next {
            heap.push(Reverse((
                len - 1 + distance[child],
                Reverse(len),
                steps.len(),
            )));
            steps.push(Step {
                node: child,
                parent: Some(at),
                len,
            });
        }
    }
    (paths, false)
}

/// Each package's dependencies, sorted, and the roots in coordinate order.
pub(super) fn build_graph(module: &LockModule) -> Result<(Vec<Vec<usize>>, Vec<usize>)> {
    let count = module.packages.len();
    let mut children = vec![Vec::new(); count];
    let mut incoming = vec![0_usize; count];
    for edge in &module.edges {
        crate::commands::util::check_edge(module, edge)?;
        children[edge.from].push(edge.to);
        incoming[edge.to] += 1;
    }
    for outgoing in &mut children {
        outgoing.sort_unstable();
        outgoing.dedup();
    }
    let mut roots = crate::commands::util::module_roots(module, &incoming);
    roots.sort_by(|left, right| {
        (module.packages[*left].coordinate).cmp(&module.packages[*right].coordinate)
    });
    Ok((children, roots))
}

fn matches_target(package: &LockModulePackage, target: &PartialCoord) -> bool {
    let coordinate = &package.coordinate;
    coordinate.artifact_id() == target.artifact_id.as_str()
        && (target.group_id.as_ref()).is_none_or(|group| coordinate.group_id() == group.as_str())
        && (target.version.as_ref()).is_none_or(|version| {
            rv_maven_types::Version::parse(coordinate.version())
                .is_ok_and(|locked| locked == *version)
        })
        && (target.packaging.as_ref()).is_none_or(|packaging| coordinate.extension() == *packaging)
        && (target.classifier.as_ref())
            .is_none_or(|classifier| coordinate.classifier() == Some(classifier.as_str()))
}

#[cfg(test)]
mod tests {
    use super::{MAX_DEP_PATHS, collect_paths, matches_target};

    /// Paths are numbered, a wrapped one is indented past its number, and a
    /// direct dependency says so.
    #[test]
    fn paths_are_numbered_and_a_direct_one_is_marked() {
        use crate::output::CommandOutput;
        let long = |n: usize| format!("org.example.group{n}:artifact-with-a-long-name:1.0");
        let module = super::WhyModuleOutput {
            module: "pom.xml".to_string(),
            gav: "g:app:1".to_string(),
            label: "pom.xml (g:app:1)".to_string(),
            found: true,
            truncated: false,
            paths: Vec::new(),
            display_paths: vec![
                vec![long(1)],
                vec![long(1), long(2), long(3)],
                vec!["g:core:1 (workspace)".to_string()],
                vec!["g:lib:1.0(custom)".to_string()],
            ],
        };
        let report = super::WhyReport {
            output: super::WhyOutput {
                target: "a".to_string(),
                platform: "linux-x86_64".to_string(),
                jdk: None,
                found: true,
                truncated: false,
                modules: vec![module],
            },
            show_headers: false,
            all: false,
        };
        let (stdout, _) = crate::output::testing::render(false, |human| report.render_human(human));
        assert_eq!(
            stdout,
            format!(
                "1. {} (direct dependency)\n2. {}\n       -> {}\n       -> {}\n\
                 3. g:core:1 (workspace, direct dependency)\n\
                 4. g:lib:1.0(custom) (direct dependency)\n",
                long(1),
                long(1),
                long(2),
                long(3)
            ),
            "{stdout}"
        );
    }

    /// `serde(skip)` fields never appear. A new payload field must fail here
    /// until the tree/why section names it.
    #[test]
    fn the_docs_name_every_why_field() {
        let keys = rv_test_support::fixtures::serde_serialize_fields(include_str!("why.rs"));
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section =
            rv_test_support::fixtures::markdown_section(&docs, "## `raeva tree` and `raeva why`");
        rv_test_support::fixtures::assert_markdown_names(
            section,
            "docs/json-output.md tree/why section",
            &keys,
        );
    }

    #[test]
    fn collect_paths_caps_at_limit_and_flags_truncation() {
        let fan = 60;
        // The root is 0, the target 1, and every other package is between.
        let mut graph = vec![(2..fan + 2).collect(), Vec::new()];
        graph.extend((0..fan).map(|_| vec![1]));
        let (paths, truncated) = collect_paths(&graph, &[0], &[1], 10);
        assert!(truncated);
        assert_eq!(paths.len(), 10);
        let (paths, truncated) = collect_paths(&graph, &[0], &[1], fan);
        assert!(!truncated);
        assert_eq!(paths.len(), fan);
    }

    /// Layers in which every package depends on every package of the next
    /// have billions of paths; the search stops at the limit without
    /// exploring them.
    #[test]
    fn collect_paths_in_a_dense_graph_stops_with_paths_found() {
        // The root, then 12 layers of 12 packages each, then the target.
        let layer = |index: usize| (1 + 12 * index..13 + 12 * index).collect::<Vec<_>>();
        let target = 1 + 12 * 12;
        let mut graph = vec![layer(0)];
        for index in 1..12 {
            graph.extend((0..12).map(|_| layer(index)));
        }
        graph.extend((0..12).map(|_| vec![target]));
        graph.push(Vec::new());
        let (paths, truncated) = collect_paths(&graph, &[0], &[target], MAX_DEP_PATHS);
        assert!(truncated);
        assert_eq!(paths.len(), MAX_DEP_PATHS);
        assert!(paths.iter().all(|path| path.len() == 14));
    }

    #[test]
    fn why_matches_equal_versions_spelled_differently() {
        use rv_lock::LockModulePackage;
        use rv_maven_types::{ArtifactCoord, PartialCoord};

        let package = LockModulePackage::new(
            ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
            None,
        );
        let target = PartialCoord::parse("com.example:lib:1.0.0").unwrap();
        assert!(
            matches_target(&package, &target),
            "1.0 and 1.0.0 are the same Maven version; why should find the lock row"
        );
    }
}
