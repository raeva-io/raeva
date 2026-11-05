mod warnings;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Component, Path, PathBuf};

use clap::Args;
use futures::stream::{self, StreamExt};

use rv_config::maven_config::LOCAL_REPOSITORY_PROPERTY;
use rv_export::{
    AuthorizedClassifier, ExportOptions, ExportPlan, Exporter, LinkStrategy, ProjectPom, Reactor,
};
use rv_lock::Platform;
use rv_repo::{ArtifactRequest, RepoClient, RepoError, Repository};

use crate::commands::lock_inputs::{LocalProject, local_project};
use crate::commands::util::count_dependencies;
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Output, Report, Warning, WarningCode};
use crate::session::Session;

use self::warnings::{report_failure, report_warnings};

pub(crate) use rv_export::ExportError;

#[derive(Debug, Args)]
// The `Commands` variant's doc comment sets `about` and clears
// `long_about`, so the details go in `after_long_help`.
#[command(after_long_help = format!(
    "{}{}",
    "Copies the locked dependencies, their POMs, parents and imported BOMs from \
     raeva's store into a Maven local repository, so `mvn -o` finds them.

The destination is --m2-path, else -Dmaven.repo.local given to raeva, else \
local_repository in the user config.toml, else <localRepository> in \
~/.m2/settings.xml, else ~/.m2/repository. local_repository in raeva.toml and \
-Dmaven.repo.local in .mvn/maven.config are ignored here, with a warning. \
${user.home} and ${env.NAME} in a configured path are expanded, and a relative \
path is resolved against the current directory, as Maven does.

For a locked offline build, export to an empty directory of its own outside \
the project, as `raeva --help` shows. Its version lists then name only the \
locked versions, so `mvn -o` resolves what raeva.lock pins, also with a \
-Dmaven.repo.local.tail. Into the local repository other builds share, it adds \
the locked versions, removes nothing, and warns that `mvn -o` there is not a \
locked build.

Build plugins and extensions are not exported: fill another repository with \
one online Maven run and pass it as the tail. Reactor modules are not \
exported either: run `mvn -o` at the reactor root, or with -pl <module> -am.

",
    crate::commands::util::help_examples(&[
        ("export-m2 --m2-path \"$(mktemp -d)/deps\"", "Export to a new repository of its own"),
        ("export-m2 --dry-run", "Show what would be exported"),
    ])
))]
pub(crate) struct ExportM2Args {
    #[arg(long, help = "Show what would be exported without writing")]
    pub dry_run: bool,
    #[arg(long, help = "Overwrite existing files in the target repository")]
    pub overwrite: bool,
    #[arg(
        long,
        value_name = "STRATEGY",
        default_value = "copy",
        value_parser = parse_link_strategy,
        help = "How to place each file: copy, hardlink, or symlink. A link \
                shares the file in raeva's store, so a Maven write to it \
                corrupts the store"
    )]
    pub link: LinkStrategy,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write to this local repository instead of the configured one"
    )]
    pub m2_path: Option<PathBuf>,
    #[arg(long, help = "Also fetch/export -sources classifier JARs")]
    pub with_sources: bool,
    #[arg(long, help = "Also fetch/export -javadoc classifier JARs")]
    pub with_javadocs: bool,
}

pub(crate) async fn run(args: &ExportM2Args, session: &Session) -> Result<Report> {
    // Reject whitespace-only paths in addition to empty ones. Clap
    // rejects an empty `PathBuf` at parse time, but `   ` slips through
    // and produces "could not create directory" errors deep in the
    // exporter. We don't apply canonicalization here; the exporter
    // already takes care of building the path tree under the requested
    // location.
    if args
        .m2_path
        .as_deref()
        .is_some_and(|path| path.to_str().is_some_and(|text| text.trim().is_empty()))
    {
        return Err(CliError::Usage(
            "--m2-path must not be empty or whitespace-only".to_string(),
        ));
    }

    let start = std::time::Instant::now();
    let config = session.config_async().await?;
    let lock_config = config.clone();
    let (lock, models, resolved) = session
        .blocking("lockfile load", move |session| {
            session.fresh_lockfile(&lock_config)
        })
        .await?;
    // Opened after the freshness check, so a stale lock creates nothing
    // under raeva home.
    let store_dir = config.paths.store_dir.clone();
    let store = session
        .blocking("store open", move |_| {
            Ok(rv_store::Store::open(&store_dir)?)
        })
        .await?;
    let output = session.output();
    // The export is for a Maven build on this machine, which may need native
    // files only this platform's resolution names.
    let host = Platform::current()?.os_arch();
    if !(lock.platforms.iter()).any(|entry| entry.platform.os_arch() == host) {
        let mut recorded: Vec<String> = (lock.platforms.iter())
            .map(|entry| entry.platform.os_arch())
            .collect();
        recorded.sort();
        recorded.dedup();
        return Err(CliError::PlatformMissing {
            platform: host,
            recorded,
            frozen: false,
        });
    }

    let defined = defined_local_repository(&config)?;
    if args.m2_path.is_none() && defined.is_none() {
        warn_project_local_repository(&config);
    }
    let home = dirs::home_dir();
    let default_repository = || {
        (home.clone().unwrap_or_default())
            .join(".m2")
            .join("repository")
    };
    let m2_path = export_destination(
        args.m2_path.as_deref(),
        defined.as_deref(),
        config.user_local_repository(),
        home.as_deref(),
    )?
    .unwrap_or_else(default_repository);
    // The one `mvn` writes when told nothing else. An expression export-m2
    // cannot expand there makes no destination shared.
    let maven_repository =
        export_destination(None, None, config.maven_local_repository(), home.as_deref())
            .map(|path| path.unwrap_or_else(default_repository))
            .ok();
    let shared = maven_repository
        .as_deref()
        .is_some_and(|maven| same_directory(&m2_path, maven));
    if shared {
        output.warn(
            Warning::new(
                WarningCode::ExportSharedRepository,
                "the destination is the Maven local repository other builds share, so \
                 export-m2 leaves its other metadata in place and `mvn -o` there is not a \
                 locked build",
            )
            .with_context(serde_json::json!({ "m2_path": m2_path.display().to_string() })),
        );
    }
    let options = ExportOptions {
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        link_strategy: args.link,
        m2_path,
        shared,
    };

    let m2_display_path = options.m2_path.display().to_string();
    // The root project's own pom.xml drives its parent/imported-BOM closure,
    // which must be exported too (Maven reads the root pom from disk but needs
    // its ancestry in ~/.m2 to build offline). Only the primary export walks
    // it; the sources/javadocs passes below pass None.
    let projects: HashMap<Platform, LocalProject> = (lock.platforms.iter())
        .zip(&models)
        .map(|(platform, model)| {
            let project = local_project(&config, model, &platform.modules);
            (platform.platform.clone(), project)
        })
        .collect();
    let declared: HashMap<Platform, Vec<Repository>> = projects
        .iter()
        .map(|(platform, project)| (platform.clone(), project.declared_repositories.clone()))
        .collect();
    // Configured repos (private repos, mirrors) come from config; POM-declared
    // repos that backed resolution come from the lockfile (export-m2 can't see
    // the observed repo set otherwise). Config wins on conflict. Stored files
    // stand in for a row only when a repository the project declares, or the
    // freshness check's resolution trusted, served them.
    let mut resolved = resolved;
    if resolved.is_empty() {
        // Offline: export takes the files the store holds and fetches none.
        let client = RepoClient::new(&config)
            .await?
            .with_offline(true)
            .with_pinned_snapshots(true)
            .with_lock_pins(&lock);
        let platforms: Vec<_> = (lock.platforms.iter())
            .map(|entry| entry.platform.clone())
            .collect();
        resolved = declared.values().flatten().cloned().collect();
        let store = std::sync::Arc::new(store.clone());
        crate::commands::sync::count_stored(
            &config,
            store,
            &client,
            &lock,
            &platforms,
            &mut resolved,
            Some(&models),
        )
        .await?;
    }
    let mut searched = declared.clone();
    for repos in searched.values_mut() {
        repos.extend(resolved.iter().cloned());
    }
    let plan = ExportPlan::from_lock(&config, &lock, &searched)?;
    let classifiers = [
        ("sources", args.with_sources),
        ("javadoc", args.with_javadocs),
    ];
    let candidates = if args.with_sources || args.with_javadocs {
        let (candidates, warnings) = plan.authorize_classifiers(&config, &declared);
        report_warnings(output, &warnings);
        candidates
    } else {
        Vec::new()
    };
    let optional: Vec<_> = candidates
        .iter()
        .flat_map(|authorized| {
            classifiers
                .into_iter()
                .filter(|(_, wanted)| *wanted)
                .map(|(classifier, _)| authorized.candidate.artifact(classifier))
        })
        .collect();
    let exporter = Exporter::new(options, &store, plan)
        .with_optional_classifiers(&optional)
        .with_support_pom_limit(
            std::env::var(rv_export::MAX_SUPPORT_POM_NODES_ENV)
                .ok()
                .as_deref(),
        );
    output.step("Exporting artifacts...");
    let reactor = reactor(&projects, session.project_root());
    let stats = exporter
        .export(&reactor)
        .await
        .map_err(|failure| report_failure(output, failure))?;
    report_warnings(output, &stats.warnings);

    let client = if args.dry_run || !(args.with_sources || args.with_javadocs) {
        None
    } else {
        let client = RepoClient::new(&config).await?;
        Some(
            client
                .with_offline(session.offline())
                .with_progress(output.progress())
                .with_lock_pins(&lock),
        )
    };
    let mut classifier_counts = [0usize; 2];
    let mut unchanged = stats.skipped_count;
    for (count, (classifier, wanted)) in classifier_counts.iter_mut().zip(classifiers) {
        if !wanted {
            continue;
        }
        *count = match &client {
            // `--dry-run` must not touch the network, so it counts the
            // classifier jars the store already holds.
            None => count_classifiers_in_store(&store, &candidates, classifier).await?,
            Some(client) => {
                let items = fetch_classifier_items(
                    &store,
                    config.network.fetch_concurrency(),
                    client,
                    &declared,
                    candidates.clone(),
                    classifier,
                )
                .await?;
                let (exported, skipped) = export_items(output, &exporter, &items).await?;
                unchanged += skipped;
                exported
            }
        };
    }
    let [sources_exported, javadocs_exported] = classifier_counts;

    Ok(Report::data(ExportM2Report {
        exported: stats.exported_count + sources_exported + javadocs_exported,
        dependencies: count_dependencies(&lock),
        files: stats.exported_count,
        unchanged,
        dry_run: args.dry_run,
        sources: args.with_sources.then_some(sources_exported),
        javadocs: args.with_javadocs.then_some(javadocs_exported),
        m2_path: m2_display_path,
        shared,
        elapsed: start.elapsed(),
    }))
}

struct ExportM2Report {
    exported: usize,
    dependencies: usize,
    files: usize,
    unchanged: usize,
    dry_run: bool,
    sources: Option<usize>,
    javadocs: Option<usize>,
    m2_path: String,
    shared: bool,
    elapsed: std::time::Duration,
}

impl CommandOutput for ExportM2Report {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "exported": self.exported,
            "sources": self.sources.unwrap_or(0),
            "javadocs": self.javadocs.unwrap_or(0),
            "m2_path": self.m2_path,
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        use crate::commands::util::plural;
        let mut what = vec![
            plural(self.dependencies, "dependency", "dependencies"),
            plural(self.files, "file", "files"),
        ];
        if let Some(sources) = self.sources {
            what.push(plural(sources, "sources jar", "sources jars"));
        }
        if let Some(javadocs) = self.javadocs {
            what.push(plural(javadocs, "javadoc jar", "javadoc jars"));
        }
        let verb = if self.dry_run {
            "Would export"
        } else {
            "Exported"
        };
        let mut line = format!(
            "{verb} {} to {} in {:.1}s",
            what.join(", "),
            self.m2_path,
            self.elapsed.as_secs_f32()
        );
        if self.unchanged > 0 {
            line.push_str(&format!(
                "; {} already there",
                plural(self.unchanged, "file was", "files were")
            ));
        }
        human.success(line)?;
        if self.shared {
            human.note(
                "For a locked offline build, export to an empty directory outside the checkout \
                 and fill another with Maven's plugins; 'raeva --help' shows the commands",
            )?;
        }
        Ok(())
    }
}

/// The local repository to export into: `--m2-path`, then the command
/// line's `-Dmaven.repo.local`, then the user's configured local repository,
/// or `None` for the default `~/.m2/repository`.
///
/// Only the destination is expanded. `Config::local_repository` keeps the
/// configured text.
fn export_destination(
    explicit: Option<&Path>,
    defined: Option<&str>,
    configured: Option<&Path>,
    user_home: Option<&Path>,
) -> Result<Option<PathBuf>> {
    if let Some(explicit) = explicit {
        return Ok(Some(explicit.to_path_buf()));
    }
    if let Some(defined) = defined {
        // `MavenCli` has expanded it already, leaving what it cannot as
        // written, and takes a relative path from the directory it runs in.
        if defined.contains("${") {
            return Err(CliError::LocalRepository {
                path: defined.to_string(),
                reason: "it contains an expression export-m2 cannot expand",
            });
        }
        return std::path::absolute(defined)
            .map(Some)
            .map_err(CliError::io_at(Path::new(defined)));
    }
    let Some(configured) = configured else {
        return Ok(None);
    };
    let path = match configured.to_str() {
        // Maven trims the element and treats an empty one as unset.
        Some(text) if text.trim().is_empty() => return Ok(None),
        Some(text) => {
            let expanded = rv_config::expand_local_repository(text.trim(), user_home);
            if expanded.contains("${") {
                return Err(CliError::LocalRepository {
                    path: text.to_string(),
                    reason: "it contains an expression export-m2 cannot expand; only \
                             ${user.home} and ${env.NAME} with a set variable are supported",
                });
            }
            PathBuf::from(expanded)
        }
        None => configured.to_path_buf(),
    };
    // Maven resolves a relative local repository against the directory it
    // runs in (Maven 3 through java.io.File, Maven 4 with toAbsolutePath), so
    // `mvn` run from the same directory reads what this writes.
    let path = std::path::absolute(&path).map_err(CliError::io_at(&path))?;
    Ok(Some(path))
}

/// The command line's `-Dmaven.repo.local`, expanded as `MavenCli` expands
/// it. `.mvn/maven.config` is not read for it: a cloned project must not
/// choose where export-m2 writes.
fn defined_local_repository(config: &rv_config::Config) -> Result<Option<String>> {
    let environment = config.host().host_environment();
    let options = rv_config::maven_config::parse_for(
        None,
        config.command_line(),
        &environment,
        &config.project_root,
    )
    .map_err(|err| CliError::Usage(format!("invalid -D option: {err}")))?;
    match options.properties.get(LOCAL_REPOSITORY_PROPERTY) {
        Some(path) if path.trim().is_empty() => Err(CliError::Usage(format!(
            "-D{LOCAL_REPOSITORY_PROPERTY} must not be empty or whitespace-only"
        ))),
        path => Ok(path.cloned()),
    }
}

/// Warn about a local repository the project's raeva.toml or
/// `.mvn/maven.config` sets, which export-m2 does not follow. The values are
/// not printed: they may hold `${env.*}` text.
fn warn_project_local_repository(config: &rv_config::Config) {
    if config.project_sets_local_repository() {
        tracing::warn!(
            sec_code = "PROJECT_LOCAL_REPOSITORY_IGNORED",
            "export-m2 ignores local_repository in the project's raeva.toml; set it in \
             config.toml or settings.xml, or pass --m2-path"
        );
    }
    // The load has refused a maven.config Maven refuses.
    let maven_config = config.project_root.join(".mvn").join("maven.config");
    let sets_it = rv_config::read_optional_project_input_string(&maven_config)
        .ok()
        .flatten()
        .and_then(|content| {
            let environment = config.host().host_environment();
            let none = rv_config::maven_config::CommandLine::default();
            rv_config::maven_config::parse_for(
                Some(&content),
                &none,
                &environment,
                &config.project_root,
            )
            .ok()
        })
        .is_some_and(|options| options.properties.contains_key(LOCAL_REPOSITORY_PROPERTY));
    if sets_it {
        tracing::warn!(
            sec_code = "PROJECT_LOCAL_REPOSITORY_IGNORED",
            "export-m2 ignores -Dmaven.repo.local in .mvn/maven.config; pass it to raeva or \
             use --m2-path"
        );
    }
}

/// Whether `a` and `b` name one directory, by their canonical paths. A
/// directory that does not exist yet is created as a plain one, so `..`
/// after it drops its name; a name that `..` leads back to an existing
/// directory is resolved again, links included.
fn same_directory(a: &Path, b: &Path) -> bool {
    fn canonical(path: &Path) -> Option<PathBuf> {
        let path = std::path::absolute(path).ok()?;
        let mut existing = path.as_path();
        let mut missing = Vec::new();
        let mut canonical = loop {
            if let Ok(canonical) = dunce::canonicalize(existing) {
                break canonical;
            }
            missing.push(existing.components().next_back()?);
            existing = existing.parent()?;
        };
        for component in missing.into_iter().rev() {
            match component {
                Component::ParentDir => {
                    canonical.pop();
                }
                Component::CurDir => {}
                other => {
                    canonical.push(other);
                    if let Ok(resolved) = dunce::canonicalize(&canonical) {
                        canonical = resolved;
                    }
                }
            }
        }
        Some(canonical)
    }
    canonical(a).is_some_and(|a| canonical(b).is_some_and(|b| a == b))
}

/// The project POMs whose parent and imported-BOM closure export walks: the
/// module POMs the current local model discovers for each locked platform,
/// with the modules' coordinates. Module paths recorded in raeva.lock are never
/// read, since an edited lock could otherwise name a file outside the
/// project.
fn reactor(projects: &HashMap<Platform, LocalProject>, project_root: &Path) -> Reactor {
    // Each target platform may activate a different module set. Export walks
    // the union so a parent or BOM support POM needed only by a
    // platform-specific module is not dropped when that platform is not first.
    let mut project_poms = BTreeMap::new();
    let mut modules = BTreeSet::new();
    // In platform order, so a module whose coordinates differ by platform
    // is read the same way on every run.
    let mut platforms: Vec<_> = projects.iter().collect();
    platforms.sort_by_key(|(platform, _)| platform.to_string());
    for (_, project) in platforms {
        for pom in &project.module_poms {
            if pom.path.is_file() {
                project_poms
                    .entry(pom.path.clone())
                    .or_insert_with(|| pom.clone());
            }
        }
        modules.extend(project.modules.iter().cloned());
    }

    if project_poms.is_empty() {
        let root_pom = project_root.join("pom.xml");
        if root_pom.is_file() {
            project_poms.insert(
                root_pom.clone(),
                ProjectPom {
                    path: root_pom,
                    local_parent: false,
                },
            );
        }
    }

    Reactor {
        poms: project_poms.into_values().collect(),
        modules,
    }
}

async fn count_classifiers_in_store(
    store: &rv_store::Store,
    candidates: &[AuthorizedClassifier],
    classifier: &str,
) -> Result<usize> {
    let mut available = 0usize;
    for AuthorizedClassifier { candidate, .. } in candidates {
        let key = candidate.artifact(classifier).coord();
        if store.lookup_artifact(&key).await?.is_some() {
            available += 1;
        }
    }
    Ok(available)
}

/// Export fetched classifier jars, returning how many of their files were
/// exported and how many were already there. The POMs the main export
/// wrote count in neither.
async fn export_items(
    output: &Output,
    exporter: &Exporter<'_>,
    items: &[rv_lock::LockArtifact],
) -> Result<(usize, usize)> {
    if items.is_empty() {
        return Ok((0, 0));
    }
    let stats = exporter
        .export_items(items)
        .await
        .map_err(|failure| report_failure(output, failure))?;
    report_warnings(output, &stats.warnings);
    Ok((stats.exported_count, stats.skipped_classified_count))
}

async fn fetch_classifier_items(
    store: &rv_store::Store,
    concurrency: usize,
    client: &RepoClient,
    declared: &HashMap<Platform, Vec<Repository>>,
    candidates: Vec<AuthorizedClassifier>,
    classifier: &str,
) -> Result<Vec<rv_lock::LockArtifact>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    // The grants a resolution takes for the project's own POM repositories,
    // from the same current declarations and never from raeva.lock: without
    // them an on-premises repository a POM names is refused by the address
    // screen here although `raeva sync` reached it.
    client.policy().admit(
        declared.values().flatten().cloned(),
        rv_repo::Declaration::LocalPom,
    );

    // The items and a failure follow the candidates' order, while a slow
    // download holds only its own slot.
    let mut results: Vec<(usize, Result<Option<rv_lock::LockArtifact>>)> = stream::iter(
        candidates.into_iter().enumerate(),
    )
    .map(
        |(
            index,
            AuthorizedClassifier {
                candidate,
                repository: repo,
                ..
            },
        )| async move {
            let mut artifact = candidate.artifact(classifier);
            let key = artifact.coord();
            let request = ArtifactRequest::from(&key);
            let group = key.group_id();
            let artifact_id = key.artifact_id();
            let version = key.version();

            // A jar an earlier export fetched from this repository
            // is reused while its file is intact, so a repeated or
            // `--offline` export does not need the network.
            match stored_classifier(store, client, &repo, &key).await {
                Ok(Some(blob)) => {
                    artifact.checksums = vec![rv_maven_types::Digest::Sha256(blob)];
                    return (index, Ok(Some(artifact)));
                }
                Ok(None) => {}
                Err(err) => return (index, Err(err.into())),
            }

            // Sources and javadoc jars are best-effort: one that does not
            // exist, or whose repository publishes no checksum sidecar, is
            // skipped. Every other error stays fatal.
            let outcome = match client
                .fetch_artifact_to_store_and_index(&repo, &request, store, &key)
                .await
            {
                Ok(blob) => {
                    artifact.checksums = vec![rv_maven_types::Digest::Sha256(blob)];
                    Ok(Some(artifact))
                }
                Err(RepoError::NotFound(_)) => Ok(None),
                Err(RepoError::OfflineNotCached(_)) => {
                    tracing::warn!(
                        sec_code = "CLASSIFIER_NOT_STORED",
                        classifier = %classifier,
                        group = %group,
                        artifact = %artifact_id,
                        version = %version,
                        "skipping {classifier} jar for {group}:{artifact_id}:{version}: \
                         the store does not hold it intact, and --offline reads only the store"
                    );
                    Ok(None)
                }
                Err(RepoError::MissingChecksum(_)) => {
                    tracing::warn!(
                        sec_code = "CLASSIFIER_CHECKSUM_MISSING",
                        classifier = %classifier,
                        group = %group,
                        artifact = %artifact_id,
                        version = %version,
                        "skipping {classifier} jar for {group}:{artifact_id}:{version}: \
                         repository publishes no checksum sidecar"
                    );
                    Ok(None)
                }
                Err(err) => Err(CliError::Download {
                    failures: vec![format!(
                        "{group}:{artifact_id}:{version} ({classifier}): {err}"
                    )],
                    first: err,
                }),
            };
            (index, outcome)
        },
    )
    .buffer_unordered(concurrency)
    .collect()
    .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    (results.into_iter())
        .filter_map(|(_, result)| result.transpose())
        .collect()
}

/// The blob `client` would accept for `key` from `repo` that the store holds
/// intact.
async fn stored_classifier(
    store: &rv_store::Store,
    client: &RepoClient,
    repo: &Repository,
    key: &rv_maven_types::ArtifactCoord,
) -> std::result::Result<Option<rv_store::BlobId>, rv_store::StoreError> {
    let Some(blob) = client.stored_artifact(store, repo, key).await? else {
        return Ok(None);
    };
    let intact = store.verify_blobs(std::slice::from_ref(&blob), 1).await?;
    Ok(intact.contains(&blob).then_some(blob))
}

fn parse_link_strategy(value: &str) -> std::result::Result<LinkStrategy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "hardlink" => Ok(LinkStrategy::Hardlink),
        "symlink" => Ok(LinkStrategy::Symlink),
        "copy" => Ok(LinkStrategy::Copy),
        other => Err(format!("unknown link strategy: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportM2Args, export_destination, same_directory};
    use crate::error::CliError;
    use clap::Parser;

    use std::path::Path;

    /// Wrap `ExportM2Args` in a dummy parser so we can exercise the same
    /// clap derive that the production CLI uses.
    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: ExportM2Args,
    }

    #[tokio::test]
    async fn classifier_export_keeps_the_downloaded_blob_when_the_index_changes() {
        use super::*;
        use rv_lock::{LockArtifact, LockPlatform, Lockfile};
        use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav};
        let dir = tempfile::tempdir().unwrap();
        let repository = dir.path().join("repository/test/lib/1");
        std::fs::create_dir_all(&repository).unwrap();
        for classifier in ["sources", "javadoc"] {
            std::fs::write(
                repository.join(format!("lib-1-{classifier}.jar")),
                b"downloaded classifier",
            )
            .unwrap();
        }
        let url = url::Url::from_directory_path(dir.path().join("repository"))
            .unwrap()
            .to_string();
        let config = rv_config::Config::for_testing_with_repos(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
            vec![rv_config::RepoConfig::new(Some("repo"), &url)],
        );
        let store = rv_store::Store::open(&config.paths.store_dir).unwrap();
        let pom = store.put_bytes(b"<project/>").await.unwrap();
        let pom_key = ArtifactCoord::new("test", "lib", "1", "pom", None);
        let served = (pom_key, pom.clone(), url.clone(), url.clone());
        store.record_served(vec![served]).await.unwrap();
        let mut row = LockArtifact::new(
            ArtifactCoord::new("test", "lib", "1", "jar", None),
            "./repository/",
        );
        row.pom_sha256 = Some(pom);
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform::single_module(
            Platform::current().unwrap(),
            Gav::new("test", "app", "1"),
            "jar",
            vec![row],
        ));
        let client = RepoClient::new(&config).await.unwrap();
        let declared = HashMap::new();
        let plan = ExportPlan::from_lock(&config, &lock, &declared).unwrap();
        let (candidates, warnings) = plan.authorize_classifiers(&config, &declared);
        assert!(warnings.is_empty(), "{warnings:?}");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: dir.path().join("m2"),
            shared: false,
        };
        let exporter = Exporter::new(options, &store, plan);
        for classifier in ["sources", "javadoc"] {
            let items = fetch_classifier_items(
                &store,
                config.network.fetch_concurrency(),
                &client,
                &declared,
                candidates.clone(),
                classifier,
            )
            .await
            .unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(
                items[0].pin(),
                Some(&Digest::Sha256(BlobId::from_bytes(
                    b"downloaded classifier"
                )))
            );
            let other = store
                .put_bytes(b"another repository's classifier")
                .await
                .unwrap();
            store.add_artifact(&items[0].coord(), &other).await.unwrap();
            exporter.export_items(&items).await.unwrap();
            assert_eq!(
                std::fs::read(
                    dir.path()
                        .join(format!("m2/test/lib/1/lib-1-{classifier}.jar"))
                )
                .unwrap(),
                b"downloaded classifier"
            );
        }
    }

    /// A classifier jar an earlier export stored is reused without asking
    /// the repository again, and fetched again once its file is damaged.
    #[tokio::test]
    async fn a_stored_intact_classifier_jar_is_not_fetched_again() {
        use super::*;
        use rv_lock::{LockArtifact, LockPlatform, Lockfile};
        use rv_maven_types::{ArtifactCoord, BlobId, Gav};
        let dir = tempfile::tempdir().unwrap();
        let repository = dir.path().join("repository/test/lib/1");
        std::fs::create_dir_all(&repository).unwrap();
        let jar = repository.join("lib-1-sources.jar");
        std::fs::write(&jar, b"sources").unwrap();
        // Bytes a checksum verified, as a remote repository's are.
        let sidecar = repository.join("lib-1-sources.jar.sha256");
        std::fs::write(&sidecar, BlobId::from_bytes(b"sources").as_str()).unwrap();
        let url = url::Url::from_directory_path(dir.path().join("repository"))
            .unwrap()
            .to_string();
        let config = rv_config::Config::for_testing_with_repos(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
            vec![rv_config::RepoConfig::new(Some("repo"), &url)],
        );
        let store = rv_store::Store::open(&config.paths.store_dir).unwrap();
        let mut row = LockArtifact::new(
            ArtifactCoord::new("test", "lib", "1", "jar", None),
            "./repository/",
        );
        row.pom_sha256 = Some(store.put_bytes(b"<project/>").await.unwrap());
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform::single_module(
            Platform::current().unwrap(),
            Gav::new("test", "app", "1"),
            "jar",
            vec![row],
        ));
        let declared = HashMap::new();
        let plan = ExportPlan::from_lock(&config, &lock, &declared).unwrap();
        let (candidates, _) = plan.authorize_classifiers(&config, &declared);
        let fetch = || async {
            // A new client, as a new run makes, remembers no earlier fetch.
            let client = RepoClient::new(&config).await.unwrap();
            let concurrency = config.network.fetch_concurrency();
            let items = fetch_classifier_items(
                &store,
                concurrency,
                &client,
                &declared,
                candidates.clone(),
                "sources",
            );
            items.await.unwrap()
        };
        assert_eq!(fetch().await.len(), 1);
        std::fs::remove_file(&jar).unwrap();
        std::fs::remove_file(&sidecar).unwrap();
        let items = fetch().await;
        assert_eq!(items.len(), 1, "the stored jar is reused");
        let stored = store.get_path(&BlobId::from_bytes(b"sources"));
        let mut permissions = std::fs::metadata(&stored).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&stored, permissions).unwrap();
        std::fs::write(&stored, b"damaged").unwrap();
        assert!(fetch().await.is_empty(), "a damaged jar is fetched again");
    }

    #[test]
    fn export_destination_rejects_unexpanded_expressions() {
        for configured in ["${user.dir}/m2", "${user.home}/m2"] {
            let err = export_destination(None, None, Some(Path::new(configured)), None)
                .expect_err(configured);
            assert!(
                matches!(&err, CliError::LocalRepository { path, .. } if path == configured),
                "{err}"
            );
            assert_eq!(
                err.diagnose(&crate::error::HintEnv::discover()).status,
                crate::error::ExitStatus::Config
            );
            assert!(err.to_string().contains("--m2-path"), "{err}");
        }
    }
    #[test]
    fn export_destination_ranks_the_define_below_the_option() {
        let explicit = Path::new("/explicit");
        let configured = Path::new("/configured");
        let destination = |explicit, defined| {
            export_destination(explicit, defined, Some(configured), None)
                .unwrap()
                .unwrap()
        };
        assert_eq!(destination(Some(explicit), Some("/defined")), explicit);
        assert_eq!(
            destination(None, Some("/defined")),
            std::path::absolute("/defined").unwrap()
        );
        assert_eq!(
            destination(None, Some("relative")),
            std::env::current_dir().unwrap().join("relative")
        );
        assert_eq!(
            destination(None, None),
            std::path::absolute(configured).unwrap()
        );
        let err = export_destination(None, Some("${unset}/m2"), None, None).unwrap_err();
        assert!(matches!(err, CliError::LocalRepository { .. }), "{err}");
    }

    #[test]
    fn same_directory_compares_canonical_paths() {
        let dir = tempfile::tempdir().unwrap();
        let repository = dir.path().join("repository");
        // Neither exists yet: compared as written, `..` and `.` folded.
        assert!(same_directory(
            &repository,
            &dir.path().join("missing/../repository/.")
        ));
        assert!(!same_directory(&repository, &dir.path().join("other")));
        assert!(!same_directory(&repository, dir.path()));
        std::fs::create_dir(&repository).unwrap();
        assert!(same_directory(
            &repository,
            &dir.path().join("./repository/")
        ));
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&repository, &link).unwrap();
            assert!(same_directory(&link, &repository));
            assert!(same_directory(&link.join("."), &repository));
            assert!(same_directory(
                &dir.path().join("missing/../link"),
                &repository
            ));
        }
    }
}
