mod error;
mod export;
mod link;
mod metadata;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use clap::Args;
use futures::stream::{self, StreamExt};

use rv_config::{ArtifactKey, LockPackage, LockPlatform, Lockfile};
use rv_repo::{ArtifactRequest, RepoClient, RepoError, Repository, normalize_repo_url};

use self::export::{ExportOptions, Exporter};
use self::link::LinkStrategy;
use crate::commands::CommandContext;
use crate::error::{CliError, Result};
use crate::output::{Spinner, heading, is_json_mode, json_result, quiet_enabled, success};

pub(crate) use self::error::ExportError;

#[derive(Debug, Args)]
#[command(
    about = "Export locked dependencies to ~/.m2/repository",
    long_about = "Export the locked dependency artifacts (and their POM ancestry / imported \
                  BOMs) into ~/.m2/repository so `mvn -o` resolves dependencies offline.\n\n\
                  Maven build plugins (compiler, surefire, ...) are NOT in scope and are not \
                  exported; a `mvn -o` build still needs its plugins already present in the \
                  local repository (e.g. from a prior online build)."
)]
pub struct ExportM2Args {
    #[arg(long, help = "Show what would be exported without writing")]
    pub dry_run: bool,
    #[arg(long, help = "Overwrite existing files in the target repository")]
    pub overwrite: bool,
    #[arg(
        long,
        value_name = "STRATEGY",
        default_value = "copy",
        value_parser = parse_link_strategy,
        help = "Link strategy: copy (default), hardlink, or symlink. \
                Hardlink and symlink share an inode with the CAS blob, so \
                in-place Maven writes can corrupt the store; opt in only \
                if you understand the trade-off."
    )]
    pub link: LinkStrategy,
    #[arg(
        long,
        value_name = "PATH",
        help = "Override the target ~/.m2/repository path"
    )]
    pub m2_path: Option<PathBuf>,
    #[arg(long, help = "Also fetch/export -sources classifier JARs")]
    pub with_sources: bool,
    #[arg(long, help = "Also fetch/export -javadoc classifier JARs")]
    pub with_javadocs: bool,
}

pub async fn run(args: &ExportM2Args, project_root: &Path) -> Result<()> {
    // Reject whitespace-only paths in addition to empty ones. Clap
    // rejects an empty `PathBuf` at parse time, but `   ` slips through
    // and produces "could not create directory" errors deep in the
    // exporter. We don't apply canonicalization here; the exporter
    // already takes care of building the path tree under the requested
    // location.
    if args
        .m2_path
        .as_deref()
        .map(|p| {
            p.as_os_str().is_empty() || p.to_str().map(|s| s.trim().is_empty()).unwrap_or(false)
        })
        .unwrap_or(false)
    {
        return Err(CliError::Message(
            "--m2-path must not be empty or whitespace-only".to_string(),
        ));
    }

    let ctx = CommandContext::load_async(project_root).await?;

    let default_opts = ExportOptions::default();
    let options = ExportOptions {
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        link_strategy: args.link,
        m2_path: args.m2_path.clone().unwrap_or(default_opts.m2_path),
    };

    let m2_display_path = options.m2_path.display().to_string();
    // Configured repos (private repos, mirrors) come from config; POM-declared
    // repos that backed resolution come from the lockfile (export-m2 can't see
    // the observed repo set otherwise). Config wins on conflict.
    let mut repo_ids = lock_repo_ids(&ctx.lock);
    repo_ids.extend(repo_id_map(&ctx.config));
    let exporter = Exporter::new(options, &ctx.store)
        .with_repo_ids(repo_ids)
        .with_support_repo_ids(lock_support_repo_ids(&ctx.lock));
    let spinner = Spinner::start("export-m2: exporting artifacts");
    // The root project's own pom.xml drives its parent/imported-BOM closure,
    // which must be exported too (Maven reads the root pom from disk but needs
    // its ancestry in ~/.m2 to build offline). Only the primary export walks
    // it; the sources/javadocs passes below pass None.
    let root_pom = project_root.join("pom.xml");
    let root_pom = root_pom.is_file().then_some(root_pom.as_path());
    let stats = exporter.export_lock(&ctx.lock, root_pom).await?;

    let mut sources_exported = 0usize;
    let mut javadocs_exported = 0usize;

    if args.dry_run {
        // `--dry-run --with-sources/--with-javadocs` must not touch the
        // network. Report what a dry-run could actually export *right now*:
        // the classifier jars already materialized in the content store.
        // Counting the full candidate set over-reported (most artifacts have
        // no -sources/-javadoc jar), and a HEAD probe per candidate would be
        // exactly the network cost dry-run exists to avoid.
        if args.with_sources {
            sources_exported = count_available_classifiers(&ctx, "sources").await?;
        }
        if args.with_javadocs {
            javadocs_exported = count_available_classifiers(&ctx, "javadoc").await?;
        }
    } else if args.with_sources || args.with_javadocs {
        let client = RepoClient::new(&ctx.config).await?;
        let concurrency = ctx.config.network.concurrency.max(1);

        if args.with_sources {
            let sources_lock = fetch_classifier_lock(&ctx, &client, "sources", concurrency).await?;
            if !sources_lock.platforms.is_empty() {
                sources_exported = exporter
                    .export_lock(&sources_lock, None)
                    .await?
                    .exported_count;
            }
        }

        if args.with_javadocs {
            let javadocs_lock =
                fetch_classifier_lock(&ctx, &client, "javadoc", concurrency).await?;
            if !javadocs_lock.platforms.is_empty() {
                javadocs_exported = exporter
                    .export_lock(&javadocs_lock, None)
                    .await?
                    .exported_count;
            }
        }
    }

    spinner.finish(success("done"));

    let total_exported = stats.exported_count + sources_exported + javadocs_exported;

    if is_json_mode() {
        json_result(
            true,
            serde_json::json!({
                "exported": total_exported,
                "sources": sources_exported,
                "javadocs": javadocs_exported,
                "m2_path": m2_display_path,
            }),
        );
    } else if !quiet_enabled() {
        // Decorative summary -> stderr. The structured machine output for this
        // command is the side effect on disk (files under m2_path); there is
        // no tabular stdout payload to keep clean.
        eprintln!("{}", heading("export-m2 summary"));
        eprintln!(
            "Exported {} artifacts to {}",
            total_exported, m2_display_path
        );
        // Only mention sources/javadocs when the corresponding flag was
        // requested, so a plain export doesn't carry an irrelevant
        // "use --with-sources to include" footer on every run.
        if args.with_sources {
            eprintln!("Sources: {} exported", sources_exported);
        }
        if args.with_javadocs {
            eprintln!("Javadocs: {} exported", javadocs_exported);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClassifierCandidate {
    group_id: String,
    artifact_id: String,
    version: String,
    repo_url: String,
    snapshot_timestamp: Option<String>,
}

fn classifier_candidates(lock: &Lockfile) -> Vec<ClassifierCandidate> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for platform in &lock.platforms {
        for package in &platform.packages {
            if package.system_path.is_some()
                || package.packaging == "pom"
                || package.classifier.is_some()
                || package.repo_url.trim().is_empty()
            {
                continue;
            }

            let candidate = ClassifierCandidate {
                group_id: package.group_id.clone(),
                artifact_id: package.artifact_id.clone(),
                version: package.version.clone(),
                repo_url: package.repo_url.clone(),
                snapshot_timestamp: package.snapshot_timestamp.clone(),
            };

            if seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
    }

    candidates
}

/// Count classifier artifacts (`-sources` / `-javadoc`) that are already in
/// the content store and could therefore be exported offline right now. Used
/// by the `--dry-run` path so the reported counts reflect actual
/// availability instead of the full candidate set.
async fn count_available_classifiers(ctx: &CommandContext, classifier: &str) -> Result<usize> {
    count_classifiers_in_store(&ctx.store, &ctx.lock, classifier).await
}

/// Inner helper for [`count_available_classifiers`], split out so it can be
/// unit-tested against a bare `Store` + `Lockfile` without standing up a full
/// `CommandContext`.
async fn count_classifiers_in_store(
    store: &rv_store::Store,
    lock: &Lockfile,
    classifier: &str,
) -> Result<usize> {
    let candidates = classifier_candidates(lock);
    let mut available = 0usize;
    for candidate in candidates {
        let key = ArtifactKey::new(
            &candidate.group_id,
            &candidate.artifact_id,
            &candidate.version,
            "jar",
            Some(classifier.to_string()),
        );
        if store.lookup_artifact(&key).await?.is_some() {
            available += 1;
        }
    }
    Ok(available)
}

async fn fetch_classifier_lock(
    ctx: &CommandContext,
    client: &RepoClient,
    classifier: &str,
    concurrency: usize,
) -> Result<Lockfile> {
    // Fan the per-candidate fetches out with
    // `stream::iter(...).buffer_unordered` rather than awaiting each in
    // turn, so a 200-artifact project doesn't pay 200 serial round-trips
    // per classifier in wall time. Network concurrency is bounded by the
    // user's configured `network.concurrency`, matching the pattern
    // in `rv-repo::sync::download_artifacts_parallel`.
    let candidates = classifier_candidates(&ctx.lock);
    if candidates.is_empty() {
        return Ok(Lockfile::new());
    }

    let results: Vec<Result<Option<LockPackage>>> = stream::iter(candidates.into_iter())
        .map(|candidate| {
            let client = client.clone();
            let store = ctx.store.clone();
            let config = ctx.config.clone();
            let classifier = classifier.to_string();
            async move {
                let repo = repository_for_candidate(&config, &candidate);
                let request = ArtifactRequest::new(
                    &candidate.group_id,
                    &candidate.artifact_id,
                    &candidate.version,
                )
                .with_packaging("jar")
                .with_classifier(classifier.clone());

                let key = ArtifactKey::new(
                    &candidate.group_id,
                    &candidate.artifact_id,
                    &candidate.version,
                    "jar",
                    Some(classifier.clone()),
                );

                match client
                    .fetch_artifact_to_store_and_index(&repo, &request, &store, &key)
                    .await
                {
                    Ok(_) => Ok(Some(LockPackage {
                        group_id: candidate.group_id,
                        artifact_id: candidate.artifact_id,
                        version: candidate.version,
                        snapshot_timestamp: candidate.snapshot_timestamp,
                        packaging: "jar".to_string(),
                        classifier: Some(classifier),
                        repo_url: candidate.repo_url,
                        checksum: None,
                        system_path: None,
                        direct_scope: None,
                        extra: std::collections::BTreeMap::new(),
                    })),
                    Err(err) if classifier_fetch_is_skippable(&err) => {
                        // Sources/javadoc sidecars are best-effort: a jar
                        // that exists but publishes no checksum sidecar must
                        // not abort the whole export, same as one that does
                        // not exist at all.
                        if matches!(err, RepoError::MissingChecksum(_)) {
                            tracing::warn!(
                                classifier = %classifier,
                                group = %candidate.group_id,
                                artifact = %candidate.artifact_id,
                                version = %candidate.version,
                                "skipping {} jar for {}:{}:{}: repository publishes no checksum sidecar",
                                classifier,
                                candidate.group_id,
                                candidate.artifact_id,
                                candidate.version
                            );
                        } else {
                            tracing::debug!(
                                classifier = %classifier,
                                group = %candidate.group_id,
                                artifact = %candidate.artifact_id,
                                version = %candidate.version,
                                "classifier artifact not found; skipping"
                            );
                        }
                        Ok(None)
                    }
                    Err(err) => Err(CliError::Message(format!(
                        "failed to fetch {} classifier for {}:{}:{}: {}",
                        classifier,
                        candidate.group_id,
                        candidate.artifact_id,
                        candidate.version,
                        err
                    ))),
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut packages = Vec::new();
    for result in results {
        if let Some(pkg) = result? {
            packages.push(pkg);
        }
    }

    if packages.is_empty() {
        return Ok(Lockfile::new());
    }

    let platform = ctx
        .lock
        .platforms
        .first()
        .map(|entry| entry.platform.clone())
        .or_else(|| rv_config::Platform::current().ok())
        .ok_or_else(|| CliError::Message("unable to determine platform for export".to_string()))?;

    let mut lock = Lockfile::new();
    lock.platforms.push(LockPlatform {
        platform,
        packages,
        edges: Vec::new(),
        extra: std::collections::BTreeMap::new(),
    });
    Ok(lock)
}

/// Build the normalized-URL -> repository-id map the exporter uses to label
/// `_remote.repositories` entries. URLs are normalized with the same helper
/// the lockfile's `repo_url` is compared through, so a package's `repo_url`
/// looks up its configured id directly. Repositories without an explicit id
/// are skipped (the exporter falls back to `central`).
fn repo_id_map(config: &rv_config::Config) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for repo in config.repositories() {
        if let Some(id) = repo.id.as_deref() {
            map.insert(normalize_repo_url(&repo.url), id.to_string());
        }
    }
    map
}

/// Parse the `url\tid` lines `rv sync` records under the lockfile's
/// [`crate::commands::sync::LOCK_REPO_IDS_KEY`] metadata key into a
/// normalized-URL -> repository-id map. These are the repositories (including
/// POM-declared ones) that backed resolution; without them export-m2 would
/// label POM-declared repos' markers as `central`.
fn lock_repo_ids(lock: &Lockfile) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(encoded) = lock.metadata.get(crate::commands::sync::LOCK_REPO_IDS_KEY) {
        for line in encoded.lines() {
            if let Some((url, id)) = line.split_once('\t') {
                map.insert(url.to_string(), id.to_string());
            }
        }
    }
    map
}

/// Parse the `g:a:v\tid` lines `rv sync` records under
/// [`crate::commands::sync::LOCK_SUPPORT_REPO_IDS_KEY`] into a
/// support-POM-coord -> repository-id map, giving each parent/imported BOM the
/// id of the repository that actually served it (which may differ from the
/// child's repo).
fn lock_support_repo_ids(lock: &Lockfile) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(encoded) = lock
        .metadata
        .get(crate::commands::sync::LOCK_SUPPORT_REPO_IDS_KEY)
    {
        for line in encoded.lines() {
            if let Some((coord, id)) = line.split_once('\t') {
                map.insert(coord.to_string(), id.to_string());
            }
        }
    }
    map
}

/// True when a classifier (`-sources`/`-javadoc`) fetch failure should skip
/// the artifact instead of aborting the export. Sources and javadocs are
/// best-effort extras: a missing jar (`NotFound`) and a jar whose repository
/// publishes no checksum sidecar (`MissingChecksum`) are both expected in the
/// wild and must not fail the run. Every other error (network, auth,
/// checksum mismatch) stays fatal.
fn classifier_fetch_is_skippable(err: &RepoError) -> bool {
    matches!(err, RepoError::NotFound(_) | RepoError::MissingChecksum(_))
}

fn repository_for_candidate(
    config: &rv_config::Config,
    candidate: &ClassifierCandidate,
) -> Repository {
    let wanted = normalize_repo_url(&candidate.repo_url);
    for repo in config.repositories() {
        if normalize_repo_url(&repo.url) == wanted {
            return Repository::from(repo);
        }
    }
    Repository::new(None, wanted, true, true)
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
    use super::{ExportM2Args, LinkStrategy, classifier_candidates, lock_repo_ids};
    use clap::Parser;
    use rv_config::{LockPackage, LockPlatform, Lockfile, Platform};

    /// #5: export-m2 must recover POM-declared repo ids from the lockfile
    /// metadata that `rv sync` writes, so markers aren't mislabelled `central`.
    #[test]
    fn lock_repo_ids_round_trips_from_metadata() {
        let mut lock = Lockfile::new();
        lock.metadata.insert(
            crate::commands::sync::LOCK_REPO_IDS_KEY.to_string(),
            "https://repo1.maven.org/maven2/\tcentral\nhttps://nexus.corp/repo/\tcorp".to_string(),
        );
        let ids = lock_repo_ids(&lock);
        assert_eq!(
            ids.get("https://nexus.corp/repo/").map(String::as_str),
            Some("corp")
        );
        assert_eq!(
            ids.get("https://repo1.maven.org/maven2/")
                .map(String::as_str),
            Some("central")
        );
        // A lock without the metadata key yields an empty map (no panic).
        assert!(lock_repo_ids(&Lockfile::new()).is_empty());
    }

    /// Wrap `ExportM2Args` in a dummy parser so we can exercise the same
    /// clap derive that the production CLI uses.
    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: ExportM2Args,
    }

    #[test]
    fn default_link_strategy_is_copy_not_hardlink() {
        // No `--link` flag supplied: default should be Copy. Hardlink-by-default
        // would re-expose the CAS inode to in-place Maven writes.
        let parsed = Wrapper::try_parse_from(["rv"]).expect("parse");
        assert_eq!(parsed.args.link, LinkStrategy::Copy);
    }

    #[test]
    fn link_hardlink_is_still_opt_in() {
        let parsed = Wrapper::try_parse_from(["rv", "--link", "hardlink"]).expect("parse");
        assert_eq!(parsed.args.link, LinkStrategy::Hardlink);
    }

    fn package(
        group: &str,
        artifact: &str,
        version: &str,
        packaging: &str,
        classifier: Option<&str>,
        system_path: Option<&str>,
    ) -> LockPackage {
        LockPackage {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: version.to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: classifier.map(str::to_string),
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: None,
            system_path: system_path.map(str::to_string),
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn empty_m2_path_is_rejected() {
        // Bypass clap (which rejects an empty PathBuf at parse time) and
        // construct the args directly to validate the runtime guard in `run`.
        let tmp = tempfile::tempdir().expect("tempdir");
        let args = ExportM2Args {
            dry_run: false,
            overwrite: false,
            link: LinkStrategy::Copy,
            m2_path: Some(std::path::PathBuf::new()),
            with_sources: false,
            with_javadocs: false,
        };
        let err = super::run(&args, tmp.path())
            .await
            .expect_err("expected empty --m2-path to be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("--m2-path must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    /// `--with-sources`/`--with-javadocs` error mapping: NotFound and
    /// MissingChecksum skip the sidecar, everything else stays fatal.
    #[test]
    fn classifier_fetch_skips_not_found_and_missing_checksum_only() {
        use super::classifier_fetch_is_skippable;
        use rv_repo::RepoError;

        assert!(classifier_fetch_is_skippable(&RepoError::NotFound(
            "demo-1.0-sources.jar".to_string()
        )));
        assert!(classifier_fetch_is_skippable(&RepoError::MissingChecksum(
            "com/example/demo/1.0/demo-1.0-sources.jar".to_string()
        )));
        // Integrity violations and auth failures must abort the export.
        assert!(!classifier_fetch_is_skippable(
            &RepoError::ChecksumMismatch {
                path: "demo-1.0-sources.jar".to_string(),
                expected: "aa".to_string(),
                actual: "bb".to_string(),
            }
        ));
        assert!(!classifier_fetch_is_skippable(&RepoError::AuthError(
            "401 Unauthorized".to_string()
        )));
    }

    #[test]
    fn classifier_candidates_dedupes_and_skips_non_portable_entries() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform {
            platform,
            packages: vec![
                package("com.example", "demo", "1.0.0", "jar", None, None),
                package("com.example", "demo", "1.0.0", "jar", None, None),
                package("com.example", "demo", "1.0.0", "pom", None, None),
                package("com.example", "demo", "1.0.0", "jar", Some("tests"), None),
                package(
                    "com.example",
                    "local",
                    "1.0.0",
                    "jar",
                    None,
                    Some("/tmp/local.jar"),
                ),
            ],
            edges: Vec::new(),
            extra: std::collections::BTreeMap::new(),
        });

        let candidates = classifier_candidates(&lock);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].group_id, "com.example");
        assert_eq!(candidates[0].artifact_id, "demo");
        assert_eq!(candidates[0].version, "1.0.0");
    }

    /// #37: `--dry-run --with-sources` must report only classifier jars that
    /// are actually available (present in the store), not every candidate.
    #[tokio::test]
    async fn dry_run_counts_only_classifiers_present_in_store() {
        use rv_store::{ArtifactKey, Store};

        let store_dir = tempfile::tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        // Two candidate jars, but only `demo` has a -sources jar in the store.
        let sources_blob = store.put_bytes(b"sources").await.expect("sources");
        store
            .add_artifact(
                &ArtifactKey::new(
                    "com.example",
                    "demo",
                    "1.0.0",
                    "jar",
                    Some("sources".to_string()),
                ),
                &sources_blob,
            )
            .await
            .expect("add sources");

        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform {
            platform,
            packages: vec![
                package("com.example", "demo", "1.0.0", "jar", None, None),
                package("com.example", "other", "2.0.0", "jar", None, None),
            ],
            edges: Vec::new(),
            extra: std::collections::BTreeMap::new(),
        });

        // Candidate set is 2, but only one -sources jar is actually available.
        assert_eq!(classifier_candidates(&lock).len(), 2);
        let sources = super::count_classifiers_in_store(&store, &lock, "sources")
            .await
            .expect("count sources");
        assert_eq!(sources, 1, "only the materialized -sources jar counts");

        // No -javadoc jars materialized -> zero, not the candidate count.
        let javadocs = super::count_classifiers_in_store(&store, &lock, "javadoc")
            .await
            .expect("count javadoc");
        assert_eq!(javadocs, 0);
    }
}
