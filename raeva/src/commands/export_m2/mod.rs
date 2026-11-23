mod warnings;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

use crate::commands::lock_inputs::{LocalProject, ReactorModel, local_project};
use crate::commands::util::count_dependencies;
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report, Warning, WarningCode};
use crate::session::Session;

use self::warnings::{report_failure, report_warnings};

pub(crate) use rv_export::ExportError;

#[derive(Debug, Args)]
// The `Commands` variant's doc comment sets `about` and clears
// `long_about`, so the details go in `after_long_help`.
#[command(after_long_help = format!(
    "{}{}",
    "Copies the locked dependencies and plugins, their POMs, parents and imported BOMs from \
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

Build plugins and extensions are exported only when [plugins] lock = true in \
raeva.toml locks them, and what they download while they run only when \
[plugins] trace pins it. Otherwise fill another repository with one online \
Maven run and pass it as the tail. Reactor modules are not \
exported either: run `mvn -o` at the reactor root, or with -pl <module> -am.

--plan-json prints what an export into an empty directory writes, as JSON, \
and writes nothing: each file a repository serves, with its SHA-256 and the \
URL of the repository raeva.lock records for it, not a mirror's, and the text \
of each file the export writes itself. It covers every platform in raeva.lock \
and takes the digests from raeva's store, so run raeva sync first. The format \
is unstable.

",
    crate::commands::util::help_examples(&[
        ("export-m2 --m2-path \"$(mktemp -d)/deps\"", "Export to a new repository of its own"),
        ("export-m2 --dry-run", "Show what would be exported"),
        ("export-m2 --plan-json > plan.json", "Describe the repository for another tool to build"),
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
                corrupts the store. A hard link that cannot be made is a \
                copy. Maven 3.10 by default reads no symbolic link below \
                its repository, so a Maven 3.10 lock refuses symlink"
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
    #[arg(
        long,
        conflicts_with_all = ["dry_run", "overwrite", "link", "m2_path"],
        help = "Print what an export into an empty repository writes, as JSON, and write nothing"
    )]
    pub plan_json: bool,
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

    run_with(args, session, session.config_async().await?, false).await
}

/// [`run`] with `config`, whose lock path may name another lock than the
/// project's. `trace` is the export a traced build runs on, which holds the
/// tables of the platform it traces on whatever JDK runs it.
pub(crate) async fn run_with(
    args: &ExportM2Args,
    session: &Session,
    config: rv_config::Config,
    trace: bool,
) -> Result<Report> {
    // Maven 3.10 takes a local repository file only where its real path is
    // the one it asked for, so it reads none of a symbolic link export.
    if args.link == LinkStrategy::Symlink
        && config.lock.maven.mode == rv_maven_types::MavenMode::Maven310
    {
        return Err(CliError::Usage(
            "--link symlink writes a repository Maven 3.10 does not read: it rejects a file \
             that is a symbolic link (aether.lrm.enhanced.verifyRealPath). Use --link copy, \
             or --link hardlink"
                .to_string(),
        ));
    }
    let start = std::time::Instant::now();
    let lock_config = config.clone();
    let (lock, models, resolved) = session
        .blocking("lockfile load", move |session| {
            session.fresh_lockfile(&lock_config, true)
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
    // files only this platform's resolution names. A plan is for any.
    let host = Platform::current()?.os_arch();
    if !args.plan_json && !(lock.platforms.iter()).any(|entry| entry.platform.os_arch() == host) {
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
    if !args.plan_json
        && !trace
        && let Some((reason, hint)) = crate::commands::sync::unlisted_host_jdk(&config)
    {
        return Err(CliError::lockfile_mismatch_with(reason, hint));
    }

    let options = if args.plan_json {
        ExportOptions {
            dry_run: true,
            overwrite: false,
            link_strategy: args.link,
            m2_path: PathBuf::new(),
            shared: false,
        }
    } else {
        destination_options(args, &config, output)?
    };

    // Every locked platform's files are exported, so the repositories and
    // mirrors are those the settings profiles active on any of them declare,
    // as the freshness check read them.
    let platforms = (lock.platforms.iter()).map(|entry| &entry.platform);
    let config = config.for_platforms(platforms.map(|p| (p.os(), p.arch(), p.jdk())));
    let m2_display_path = options.m2_path.display().to_string();
    let shared = options.shared;
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
        let client = (crate::commands::sync::Mode::check(true).client(&config))
            .await?
            .with_lock_pins(&lock);
        let platforms: Vec<_> = (lock.platforms.iter())
            .map(|entry| entry.platform.clone())
            .collect();
        resolved = declared.values().flatten().cloned().collect();
        // The plugin rows come from the POMs' plugin repositories.
        if lock.platforms.iter().any(|entry| entry.plugins.is_some()) {
            let plugins = models
                .iter()
                .flat_map(ReactorModel::declared_plugin_repositories);
            let admission =
                rv_repo::RepositoryPolicy::screen(&config, plugins, rv_repo::Declaration::LocalPom);
            resolved.extend(admission.admitted);
        }
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
    let plugin_tables: Vec<(&rv_lock::Platform, &rv_lock::PluginTables)> = (lock.platforms.iter())
        .filter_map(|entry| Some((&entry.platform, entry.plugins.as_ref()?)))
        .collect();
    let plan = if plugin_tables.is_empty() {
        // Without plugin tables no version a plugin took is recorded.
        let mut unversioned = BTreeSet::new();
        if lineages_may_name(&lock, &store, &models) {
            let client = (crate::commands::sync::Mode::check(true).client(&config))
                .await?
                .with_lock_pins(&lock);
            let resolver = rv_resolver::Resolver::new(
                std::sync::Arc::new(config.clone()),
                std::sync::Arc::new(store.clone()),
                client,
            )
            .with_locked_versions(&lock);
            for (entry, model) in lock.platforms.iter().zip(&models) {
                match (resolver.unversioned_plugins(&model.workspace, &entry.platform)).await {
                    Ok(found) => unversioned.extend(found),
                    // A home that holds the locked files may not serve every
                    // read of the plugin models.
                    Err(error) => output.warn(warnings::plugins_unchecked(&entry.platform, &error)),
                }
            }
        }
        ExportPlan::from_lock(&config, &lock, &searched)?.with_unversioned_plugins(unversioned)
    } else {
        // The plugin files' origins are named by the ids the plugin tables
        // record, which the lock's own ids do not hold.
        let mut merged = lock.clone();
        let mut prefixes = Vec::new();
        let origins = rv_lock::LockOrigins::for_root(&config.project_root);
        for (platform, tables) in &plugin_tables {
            for (origin, ids) in &tables.repo_ids {
                (merged.repo_ids.entry(origin.clone()).or_default()).extend(ids.iter().cloned());
            }
            if let Some(repos) = searched.get_mut(*platform) {
                let scoped =
                    config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
                let pom = (models.iter())
                    .filter(|model| model.platform == **platform)
                    .flat_map(ReactorModel::declared_plugin_repositories);
                let pom =
                    rv_repo::RepositoryPolicy::screen(&config, pom, rv_repo::Declaration::LocalPom);
                let configured: Vec<_> = (scoped.profile_plugin_repositories().iter())
                    .chain(scoped.plugin_repositories())
                    .map(Repository::from)
                    .chain(pom.admitted)
                    .collect();
                repos.extend(plugin_repositories(tables, &origins, &configured));
            }
            prefixes.extend(tables.prefixes.iter().map(|row| {
                (
                    row.group.clone(),
                    row.repo_url.clone(),
                    row.prefix.clone(),
                    row.artifact.clone(),
                )
            }));
        }
        ExportPlan::from_lock(&config, &merged, &searched)?.with_plugin_prefixes(prefixes)
    };
    let classifiers = [
        ("sources", args.with_sources),
        ("javadoc", args.with_javadocs),
    ];
    // The plugin rows come from the plugin repositories the configuration
    // and the POMs declare, Maven's `central` among them.
    let mut trusted = declared.clone();
    if !plugin_tables.is_empty() {
        for model in &models {
            let Some(repos) = trusted.get_mut(&model.platform) else {
                continue;
            };
            let platform = &model.platform;
            let scoped = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
            let configured = (scoped.profile_plugin_repositories().iter())
                .chain(scoped.plugin_repositories())
                .map(Repository::from);
            let declared = model.declared_plugin_repositories();
            let admission = rv_repo::RepositoryPolicy::screen(
                &config,
                declared,
                rv_repo::Declaration::LocalPom,
            );
            repos.extend(configured.chain(admission.admitted));
        }
    }
    let candidates = if args.with_sources || args.with_javadocs {
        let (candidates, warnings) = plan.authorize_classifiers(&config, &trusted);
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
    // Classifier jars are fetched before anything is written, so that the
    // export judges their destinations with all the others.
    let mut items = Vec::new();
    if args.with_sources || args.with_javadocs {
        // A plan and `--dry-run` must not touch the network, so they judge
        // the classifier jars the store already holds and warn about the
        // others.
        let offline = args.plan_json || args.dry_run || session.offline();
        let client = (crate::commands::sync::Mode::plain(offline).client(&config))
            .await?
            .with_progress(output.progress())
            .with_lock_pins(&lock);
        for (classifier, wanted) in classifiers {
            if wanted {
                items.extend(
                    fetch_classifier_items(
                        &config,
                        &store,
                        config.network.fetch_concurrency(),
                        &client,
                        &trusted,
                        candidates.clone(),
                        classifier,
                    )
                    .await?,
                );
            }
        }
    }
    let reactor = reactor(&projects, session.project_root());
    if args.plan_json {
        let layout = exporter
            .layout(&reactor, &items)
            .await
            .map_err(|failure| report_failure(output, failure))?;
        report_warnings(output, &layout.warnings);
        return Ok(Report::document(plan_document(&layout)?));
    }
    output.step("Exporting artifacts...");
    let stats = exporter
        .export(&reactor, &items)
        .await
        .map_err(|failure| report_failure(output, failure))?;
    report_warnings(output, &stats.warnings);
    let optional =
        |classifier: &str| (stats.optional_exported.get(classifier).copied()).unwrap_or_default();
    let (sources_exported, javadocs_exported) = (optional("sources"), optional("javadoc"));

    Ok(Report::data(ExportM2Report {
        exported: stats.exported_count,
        dependencies: count_dependencies(&lock.platforms),
        files: stats.exported_count - sources_exported - javadocs_exported,
        unchanged: stats.skipped_count,
        dry_run: args.dry_run,
        sources: args.with_sources.then_some(sources_exported),
        javadocs: args.with_javadocs.then_some(javadocs_exported),
        m2_path: m2_display_path,
        shared,
        elapsed: start.elapsed(),
    }))
}

/// Where and how `args` export: the destination, and whether it is the
/// local repository other builds share, which is reported.
fn destination_options(
    args: &ExportM2Args,
    config: &rv_config::Config,
    output: &crate::output::Output,
) -> Result<ExportOptions> {
    let defined = defined_local_repository(config)?;
    if args.m2_path.is_none() && defined.is_none() {
        warn_project_local_repository(config);
    }
    let home = config.maven_user_home().map(Path::to_path_buf);
    // Without a home Maven's `~/.m2` is `?/.m2` where it runs, inside the
    // checkout, which no export should fill.
    let default_repository = || match &home {
        Some(home) if !rv_config::is_unknown_user_home(home) => {
            Ok(home.join(".m2").join("repository"))
        }
        _ => Err(CliError::LocalRepository {
            path: "~/.m2/repository".to_string(),
            reason: "Maven's JVM finds no user home, as for a user without a passwd home and \
                     without HOME, so it would be below the working directory",
        }),
    };
    let m2_path = match export_destination(
        args.m2_path.as_deref(),
        defined.as_deref(),
        config.user_local_repository(),
        home.as_deref(),
        config.host(),
    )? {
        Some(path) => path,
        None => default_repository()?,
    };
    // The one `mvn` writes when told nothing else. An expression export-m2
    // cannot expand there makes no destination shared.
    let configured = config.maven_local_repository();
    let maven_repository =
        export_destination(None, None, configured, home.as_deref(), config.host())
            .ok()
            .and_then(|path| path.map_or_else(|| default_repository().ok(), Some));
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
    Ok(ExportOptions {
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        link_strategy: args.link,
        m2_path,
        shared,
    })
}

/// The `--plan-json` document of `layout`.
fn plan_document(layout: &rv_export::RepositoryLayout) -> Result<String> {
    let files: Vec<_> = (layout.files.iter())
        .map(|file| {
            let mut entry = serde_json::json!({ "path": file.path, "sha256": file.sha256 });
            if let Some(url) = &file.url {
                entry["url"] = url.clone().into();
            }
            entry
        })
        .collect();
    let generated: Vec<_> = (layout.generated.iter())
        .map(|(path, content)| serde_json::json!({ "path": path, "content": content }))
        .collect();
    let plan = serde_json::json!({ "version": 1, "files": files, "generated": generated });
    Ok(serde_json::to_string_pretty(&plan)?)
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
                "For a locked offline build, export to an empty directory outside the checkout; \
                 'raeva --help' shows the commands",
            )?;
        }
        Ok(())
    }
}

/// Whether a POM of a module's lineage declares, without a version, a
/// build plugin or extension that may name an artifact the export writes
/// metadata for and raeva.lock records no `<release>` of: only then can the
/// plugin models hold one. A POM this cannot read, or a name with an
/// expression, counts.
fn lineages_may_name(
    lock: &rv_lock::Lockfile,
    store: &rv_store::Store,
    models: &[ReactorModel],
) -> bool {
    let entries = lock.platforms.iter();
    let released: HashSet<(&str, &str)> = (entries.clone())
        .flat_map(|entry| {
            entry
                .modules
                .iter()
                .flat_map(|module| &module.metadata_versions)
        })
        .filter(|read| read.kind == rv_lock::MetadataVersionKind::Release)
        .map(|read| (read.group.as_str(), read.artifact.as_str()))
        .collect();
    let artifacts = entries.flat_map(|entry| &entry.artifacts).map(|row| {
        let coordinate = &row.coordinate;
        (
            coordinate.group_id().to_string(),
            coordinate.artifact_id().to_string(),
        )
    });
    let support = lock.support_poms();
    let poms = support.keys().filter_map(|coordinate| {
        let mut parts = coordinate.split(':');
        Some((parts.next()?.to_string(), parts.next()?.to_string()))
    });
    let candidates: HashSet<(String, String)> = (artifacts.chain(poms))
        .filter(|(group, artifact)| !released.contains(&(group.as_str(), artifact.as_str())))
        .collect();
    let names = |pom: &rv_maven_model::Pom| match pom.unversioned_plugins() {
        Ok(Some(keys)) => keys
            .into_iter()
            .any(|key| key.0.contains('$') || key.1.contains('$') || candidates.contains(&key)),
        _ => true,
    };
    let parse = |bytes: Vec<u8>| {
        rv_maven_model::Pom::parse_with_plugins(&rv_maven_model::decode_pom(&bytes).ok()?).ok()
    };
    let read = |path: &Path| parse(std::fs::read(path).ok()?);
    let mut seen = HashSet::new();
    for module in models.iter().flat_map(|model| model.workspace.modules()) {
        if names(module.pom()) {
            return true;
        }
        let mut parent = module.pom().parent.clone();
        for path in module.local_parents() {
            // An ancestor seen before was read up to the top.
            if !seen.insert(path.display().to_string()) {
                parent = None;
                break;
            }
            let Some(pom) = read(path) else { return true };
            if names(&pom) {
                return true;
            }
            parent = pom.parent;
        }
        while let Some(next) = parent.take() {
            let coordinate = format!("{}:{}:{}", next.group_id, next.artifact_id, next.version);
            if !seen.insert(coordinate.clone()) {
                break;
            }
            let pin = support.get(&coordinate);
            let stored = pin.and_then(|pin| store.read_blob(&pin.sha256).ok().flatten());
            let Some(pom) = stored.and_then(parse) else {
                return true;
            };
            if names(&pom) {
                return true;
            }
            parent = pom.parent;
        }
    }
    false
}

/// The repositories plugin resolution read from: those of each set, and
/// those a plugin's POMs declare, under each id they were named by, and for
/// the empty origin the declarations in `configured` it stands for. A
/// declaration in `configured`, the settings' and the project POMs', of a
/// recorded origin under the same id stands for it as written, so a mirror
/// pattern reads it as the sync did: Maven 3.10 reads a `symlink+file:` URL
/// as the directory the lock records, which `external:*` matches only as
/// written.
fn plugin_repositories(
    tables: &rv_lock::PluginTables,
    origins: &rv_lock::LockOrigins,
    configured: &[Repository],
) -> Vec<Repository> {
    let urls: std::collections::BTreeSet<&str> = (tables.sets.iter())
        .flat_map(|set| set.repo_urls.iter().map(String::as_str))
        .chain(tables.repo_ids.keys().map(String::as_str))
        .collect();
    // The empty origin names a declaration whose URL the lock cannot
    // record, which only a mirror serves.
    let unrecorded = (configured.iter())
        .filter(|repo| urls.contains("") && origins.key(&repo.url).as_deref() == Some(""))
        .cloned();
    (urls.iter())
        .filter_map(|&recorded| {
            let url = match origins.project_url(recorded) {
                Some(directory) => directory,
                None if rv_lock::is_http_origin(recorded) || recorded.starts_with("file:") => {
                    recorded.to_string()
                }
                None => return None,
            };
            Some((recorded, url))
        })
        .flat_map(|(recorded, url)| {
            let ids: Vec<Option<String>> = match tables.repo_ids.get(recorded) {
                Some(ids) if !ids.is_empty() => ids.iter().cloned().map(Some).collect(),
                _ => vec![None],
            };
            let key = origins.key(&url);
            ids.into_iter().map(move |id| {
                let written = (configured.iter())
                    .find(|repo| repo.id == id && key.is_some() && origins.key(&repo.url) == key);
                match written {
                    Some(repo) => repo.clone(),
                    None => Repository::new(id, url.clone(), true, false),
                }
            })
        })
        .chain(unrecorded)
        .collect()
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
    host: &rv_maven_model::HostSnapshot,
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
            let expanded = rv_config::expand_local_repository(text.trim(), user_home, host);
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
    if config.project_settings_local_repository() {
        tracing::warn!(
            sec_code = "PROJECT_LOCAL_REPOSITORY_IGNORED",
            "export-m2 ignores <localRepository> in the settings file .mvn/maven.config names; \
             set it in config.toml, or pass --m2-path"
        );
    }
    // The load has refused a maven.config Maven refuses.
    let maven_config = config.mvn_dir().join("maven.config");
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
                    local_parents: Vec::new(),
                },
            );
        }
    }

    Reactor {
        poms: project_poms.into_values().collect(),
        modules,
    }
}

/// The classifier jars of `candidates` from the store, fetching the ones it
/// does not hold intact through `client`.
async fn fetch_classifier_items(
    config: &rv_config::Config,
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

    // Each candidate through the filters and credential scope of the
    // platform that recorded it.
    let mut clients: HashMap<Platform, RepoClient> = HashMap::new();
    let candidates: Vec<_> = (candidates.into_iter())
        .map(|authorized| {
            let platform = &authorized.candidate.platform;
            let client = (clients.entry(platform.clone())).or_insert_with(|| {
                let scoped =
                    config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
                client.for_platform(&scoped)
            });
            (authorized, client.clone())
        })
        .collect();

    // The items and a failure follow the candidates' order, while a slow
    // download holds only its own slot.
    let mut results: Vec<(usize, Result<Option<rv_lock::LockArtifact>>)> = stream::iter(
        candidates.into_iter().enumerate(),
    )
    .map(
        |(
            index,
            (
                AuthorizedClassifier {
                    candidate,
                    repository: repo,
                    ..
                },
                client,
            ),
        )| async move {
            let client = &client;
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
                         the store does not hold it intact, and an offline or dry run reads \
                         only the store"
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
        let jar = store.put_bytes(b"jar").await.unwrap();
        let jar_key = ArtifactCoord::new("test", "lib", "1", "jar", None);
        let served = [(pom_key, pom.clone()), (jar_key.clone(), jar.clone())]
            .map(|(key, blob)| (key, blob, url.clone(), url.clone()));
        store.record_served(served.into()).await.unwrap();
        let mut row = LockArtifact::new(jar_key, "./repository/");
        row.pom_sha256 = Some(pom);
        row.checksums = vec![Digest::Sha256(jar)];
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
                &config,
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
            exporter.export(&Reactor::default(), &items).await.unwrap();
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
                &config,
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
        let host = rv_maven_model::HostSnapshot::default();
        for configured in ["${user.dir}/m2", "${user.home}/m2"] {
            let err = export_destination(None, None, Some(Path::new(configured)), None, &host)
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
        let host = rv_maven_model::HostSnapshot::default();
        let explicit = Path::new("/explicit");
        let configured = Path::new("/configured");
        let destination = |explicit, defined| {
            export_destination(explicit, defined, Some(configured), None, &host)
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
        let err = export_destination(None, Some("${unset}/m2"), None, None, &host).unwrap_err();
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

    /// A repository a plugin's POM declares is trusted as the sets' are,
    /// under every id it was named by, and one in the project as its
    /// directory.
    #[test]
    fn plugin_repositories_take_each_recorded_id() {
        let mut tables =
            rv_lock::PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"inputs")).tables;
        let mut set = rv_lock::PluginSet::new("sha256:ab", rv_lock::PluginRole::Plugin);
        set.repo_urls = vec!["https://plugins.example/".to_string()];
        tables.sets.push(set);
        tables.repo_ids.insert(
            "https://declared.example/".to_string(),
            ["a".to_string(), "b".to_string()].into(),
        );
        let root = tempfile::TempDir::new().unwrap();
        let origins = rv_lock::LockOrigins::for_root(root.path());
        tables
            .repo_ids
            .insert("./repo/".to_string(), ["local".to_string()].into());
        tables
            .repo_ids
            .insert("ftp://other.example/".to_string(), ["c".to_string()].into());
        let repositories: Vec<String> = super::plugin_repositories(&tables, &origins, &[])
            .into_iter()
            .map(|repository| format!("{} {}", repository.id.unwrap_or_default(), repository.url))
            .collect();
        assert_eq!(
            repositories,
            [
                &format!("local {}", origins.project_url("./repo/").unwrap()),
                "a https://declared.example/",
                "b https://declared.example/",
                " https://plugins.example/",
            ]
        );
    }
}
