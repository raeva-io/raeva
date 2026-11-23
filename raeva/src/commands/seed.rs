//! `raeva seed`: carry the store's copies of the locked files between CI
//! jobs, checked against raeva.lock's pins when they come back.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use clap::{Args, Subcommand};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt;

use rv_config::{Config, UpdatePolicy};
use rv_lock::{LockOrigins, Lockfile, PinnedFiles, Platform};
use rv_maven_types::{ArtifactCoord, BlobId, Digest};
use rv_store::metadata_cache::{CacheError, CacheTable, Expiry, MetadataCache, now_epoch_seconds};
use rv_store::{Expect, PinCheck, PutError, Store};

use crate::commands::read_lockfile;
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

/// Bumped when the manifest, the key material or what a row's expiry
/// means changes.
const FORMAT: u32 = 3;
const MANIFEST: &str = "seed.json";
const BLOBS: &str = "blobs";
const METADATA: &str = "metadata";
/// No POM or version listing comes near this size.
const ROW_LIMIT: u64 = 16 << 20;
/// No lock pins so many files that its manifest comes near this.
const MANIFEST_LIMIT: u64 = 64 << 20;
/// The bytes of all the rows one restore writes into the metadata cache; a
/// large build's seed holds some tens of MiB.
const METADATA_LIMIT: u64 = 2 << 30;

#[derive(Debug, Args)]
#[command(after_long_help = format!(
    "{}{}",
    "A seed is a directory with the files raeva.lock pins, as the store holds them, \
which repository served each one, and the metadata cache rows a resolution reads. \
A CI cache keyed on `raeva seed key` carries \
it from one job to the next. The key covers the pins, the raeva version, this \
machine's platform, and the repositories and mirrors the configuration declares.

`raeva seed restore` refuses a seed saved for another key, and hashes every file \
and pinned POM against its pin as the store takes it: one that does not match \
refuses the whole seed, and the cache takes no row of it. Make the Maven repository afterwards with `raeva export-m2`.

",
    crate::commands::util::help_examples(&[
        ("seed key", "Print the key of this lock's seed"),
        ("seed save \"$RUNNER_TEMP/seed\"", "Save the seed after `raeva sync --frozen`"),
        ("seed restore \"$RUNNER_TEMP/seed\"", "Fill an empty store from a seed"),
    ])
))]
pub(crate) struct SeedArgs {
    #[command(subcommand)]
    pub command: SeedCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SeedCommand {
    /// Print the cache key of this lock's seed
    Key,
    /// Copy the locked files from the store into a new seed directory
    Save {
        /// The seed directory, missing or empty
        dir: PathBuf,
    },
    /// Fill the store from a seed, checking every file against its pin
    Restore {
        /// The seed directory `raeva seed save` wrote
        dir: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    format: u32,
    key: String,
    files: Vec<SeedFile>,
    /// The metadata cache rows a resolution reads: POMs, version listings
    /// and the answers repositories gave for files they lack.
    metadata: Vec<SeedRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SeedRow {
    table: RowTable,
    scope: String,
    path: String,
    sha256: String,
    fetched_at: i64,
    expires_at: i64,
    checksum_checked: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RowTable {
    Pom,
    VersionList,
    Miss,
}

impl RowTable {
    const ALL: [RowTable; 3] = [RowTable::Pom, RowTable::VersionList, RowTable::Miss];

    fn table(self) -> CacheTable {
        match self {
            RowTable::Pom => CacheTable::Pom,
            RowTable::VersionList => CacheTable::VersionList,
            RowTable::Miss => CacheTable::Miss,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SeedFile {
    coordinate: String,
    sha256: String,
    /// The (repository, endpoint) pairs the store records as having served
    /// these bytes for the coordinate, one inside the project as raeva.lock
    /// records it, so the seed restores in another checkout.
    served: Vec<(String, String)>,
}

pub(crate) async fn run(args: &SeedArgs, session: &Session) -> Result<Report> {
    let config = session
        .blocking("config load", Session::lock_config)
        .await?;
    let lock = read_lockfile(&config)?;
    let mut files = lock.pinned_files();
    add_plugin_origins(&lock, &mut files);
    add_extension_jars(&lock, &mut files);
    let key = seed_key(&config, &lock, &files)?;
    match &args.command {
        SeedCommand::Key => Ok(Report::data(KeyReport { key })),
        SeedCommand::Save { dir } => save(&config, &lock, &files, key, dir).await,
        SeedCommand::Restore { dir } => restore(&config, &lock, &files, key, dir).await,
    }
}

/// Of the routes `served` names for each of `files`, those a restore takes:
/// one the file's origins record, or one `sync --frozen` would take the
/// stored file through. That is the frozen check's rule with the
/// repositories it fetches pinned files from: the configuration's and the
/// project POMs', and, when they leave a file without a route, those an
/// offline resolution trusts once `before_resolving` has run, remote
/// parents' and dependency POMs' included. Save and restore take the same
/// ones, so a seed that saves restores. Also returns why that resolution
/// failed, if it ran and did.
async fn admitted(
    config: &Config,
    store: &Store,
    lock: &Lockfile,
    files: &PinnedFiles<'_>,
    served: &[Vec<(String, String)>],
    before_resolving: impl AsyncFnOnce() -> Result<()>,
) -> Result<(Vec<Vec<(String, String)>>, Option<CliError>)> {
    use crate::commands::sync;
    let platforms: Vec<Platform> = (lock.platforms.iter())
        .map(|entry| entry.platform.clone())
        .collect();
    let config = config.for_platforms(
        (platforms.iter()).map(|platform| (platform.os(), platform.arch(), platform.jdk())),
    );
    let models = crate::commands::lock_inputs::discover_reactor_models(&config, &platforms).ok();
    let client = (sync::Mode::check(true).client(&config).await?).with_lock_pins(lock);
    let store = Arc::new(store.clone());
    let declared = models.iter().flatten();
    let declared =
        declared.flat_map(crate::commands::lock_inputs::ReactorModel::declared_repositories);
    let mut trusted = (client.policy())
        .admit(declared, rv_repo::Declaration::LocalPom)
        .admitted;
    let lock_origins = LockOrigins::for_root(&config.project_root);
    let configs = sync::platform_configs(&config, &platforms);
    let clients = sync::platform_clients(&configs, &client);
    let inputs: Vec<_> = (files.iter().zip(served))
        .map(|(((key, pin), _), served)| (key, pin, served.as_slice()))
        .collect();
    let support_poms = only_support_poms(lock);
    let judge = |trusted: &[rv_repo::Repository], imports: &[(String, rv_repo::Repository)]| {
        let contexts = sync::restore_contexts(&configs, &platforms, &clients, trusted);
        let mut found = rv_repo::admitted_routes(&store, lock, &contexts, &inputs);
        // The frozen check takes the repository the lock records for a
        // support POM when an imported BOM's build read the POM through it,
        // though only BOMs declare it; no other file may come from there.
        for (at, (input, origins)) in inputs.iter().zip(files.values()).enumerate() {
            let Some(coord) = support_poms.get(input.0) else {
                continue;
            };
            let recorded = |repository: &rv_repo::Repository| {
                (configs.iter()).any(|config| {
                    let only = std::slice::from_ref(repository);
                    let selector =
                        rv_repo::LockRepositorySelector::new(config, &lock_origins, only);
                    (origins.iter()).any(|origin| {
                        (selector.select(origin, None).declared())
                            .is_some_and(|declared| declared.url == repository.url)
                    })
                })
            };
            let searched =
                (imports.iter()).filter(|(read, repository)| read == coord && recorded(repository));
            let widened: Vec<_> = (trusted.iter().cloned())
                .chain(searched.map(|(_, repository)| repository.clone()))
                .collect();
            if widened.len() > trusted.len() {
                let contexts = sync::restore_contexts(&configs, &platforms, &clients, &widened);
                let input = std::slice::from_ref(input);
                found[at] = rv_repo::admitted_routes(&store, lock, &contexts, input).remove(0);
            }
        }
        (files.values().zip(served).zip(found))
            .map(|((origins, served), found)| {
                let recorded = recorded_routes(&lock_origins, origins, served);
                (served.iter())
                    .filter(|route| recorded.contains(route) || found.contains(route))
                    .cloned()
                    .collect()
            })
            .collect::<Vec<_>>()
    };
    let routes = judge(&trusted, &[]);
    let Some(models) = models.filter(|_| routes.iter().any(Vec::is_empty)) else {
        return Ok((routes, None));
    };
    before_resolving().await?;
    let learned = sync::resolution_trust(&config, store.clone(), &client, lock, &models).await;
    trusted.extend(learned.repositories);
    Ok((judge(&trusted, &learned.imports), learned.failed))
}

/// The `g:a:v` of each file `lock` pins only as a support POM, by the key
/// of its file: one an artifact row also pins is the row's file too.
fn only_support_poms(lock: &Lockfile) -> HashMap<ArtifactCoord, String> {
    let rows: HashSet<ArtifactCoord> = (lock.platforms.iter())
        .flat_map(|platform| &platform.artifacts)
        .flat_map(|row| [row.coord(), ArtifactCoord::of(row.pom_gav(), "pom", None)])
        .collect();
    (lock.platforms.iter())
        .flat_map(|platform| &platform.support_poms)
        .filter_map(|(coord, pin)| {
            let key = ArtifactCoord::of(pin.file_gav(coord)?, "pom", None);
            (!rows.contains(&key)).then(|| (key, coord.clone()))
        })
        .collect()
}

/// Add to each file a plugin set reads the repositories that set resolves
/// from: its offline resolution takes the file as one of them served it,
/// which need not be the repository the file's row records.
fn add_plugin_origins<'a>(lock: &'a Lockfile, files: &mut PinnedFiles<'a>) {
    let mut read: BTreeMap<(ArtifactCoord, Digest), BTreeSet<&str>> = BTreeMap::new();
    for platform in &lock.platforms {
        let Some(tables) = &platform.plugins else {
            continue;
        };
        // As `sync --frozen` fetches them: a row's file and its POM for a
        // set whose class path holds the row, a support POM for a set that
        // reads it.
        for file in platform.pinned_files() {
            let reads = |set: &&rv_lock::PluginSet| match file.row {
                rv_lock::PinnedRow::File(row) | rv_lock::PinnedRow::Pom(row) => {
                    set.artifacts.contains(&row.coordinate)
                }
                rv_lock::PinnedRow::Support(coordinate, _) => {
                    set.poms.iter().any(|pom| pom == coordinate)
                }
            };
            let mut sets = tables.sets.iter().filter(reads).peekable();
            if sets.peek().is_none() {
                continue;
            }
            // A set records the repositories it started from; one a POM of
            // its closure declared is among those the tables name ids for.
            let urls = sets.flat_map(|set| &set.repo_urls);
            let urls = urls.chain(tables.repo_ids.keys()).map(String::as_str);
            read.entry((file.key, file.pin)).or_default().extend(urls);
        }
    }
    for (file, origins) in files.iter_mut() {
        origins.extend(read.get(file).into_iter().flatten());
    }
}

/// The origin of a file whose repository raeva.lock does not record: a
/// seed takes it as any repository served it, as the pin vouches for it.
const ANY_REPOSITORY: &str = "*";

/// Add the build extension jars the modules pin, which a resolution reads
/// offline as one of the module's plugin repositories served it. The lock
/// records no repository for one that no plugin table pins, as Maven takes
/// it from the plugin repositories of the configuration and the POMs, the
/// super POM's among them; a dependency row's repository is not one of
/// those. A plain `-SNAPSHOT` jar has no pin, as its file can be
/// redeployed.
fn add_extension_jars<'a>(lock: &'a Lockfile, files: &mut PinnedFiles<'a>) {
    for platform in &lock.platforms {
        let tabled: HashSet<&ArtifactCoord> = (platform.plugins.iter())
            .flat_map(|tables| &tables.sets)
            .flat_map(|set| &set.artifacts)
            .collect();
        let rows: HashMap<_, _> = (platform.artifacts.iter())
            .map(|row| (row.coord(), &row.coordinate))
            .collect();
        let jars = (platform.modules.iter())
            .flat_map(|module| &module.extensions)
            .filter(|jar| !rv_maven_types::resolves_through_snapshot_metadata(jar.gav.version()));
        for jar in jars {
            let key = jar.coord();
            let in_table = rows.get(&key).is_some_and(|row| tabled.contains(row));
            let origins = files.entry((key, Digest::Sha256(jar.sha256.clone())));
            let origins = origins.or_default();
            if !in_table {
                origins.insert(ANY_REPOSITORY);
            }
        }
    }
}

/// The key names everything a seed's use depends on: the pins, which
/// raeva reads and exports them, for which platform, and the repositories
/// and mirrors that decide which endpoint a locked file comes from, on any
/// platform the lock records, as the frozen check evaluates them.
fn seed_key(config: &Config, lock: &Lockfile, files: &PinnedFiles<'_>) -> Result<String> {
    fn of(platform: &Platform) -> (&str, &str, Option<&str>) {
        (platform.os(), platform.arch(), platform.jdk())
    }
    let each: Vec<Config> = (lock.platforms.iter())
        .map(|entry| config.for_platforms([of(&entry.platform)]))
        .collect();
    let config = config.for_platforms((lock.platforms.iter()).map(|entry| of(&entry.platform)));
    // As `sync --frozen`, which would refuse the settings this key names.
    config.settings_activation()?;
    let target = Platform::current()?.os_arch();
    let version = env!("CARGO_PKG_VERSION");
    let pins: Vec<_> = (files.iter())
        .map(|((key, pin), origins)| (key.to_string(), pin.to_string(), origins))
        .collect();
    // A URL that holds a secret is named as the seed names it, so a later
    // job's own token keeps the key, which is no digest of a token.
    let names = Mirrors::of(&config);
    let mirrors: Vec<_> = (config.mirrors().iter())
        .map(|mirror| {
            (
                &mirror.id,
                names.urls.get(&rv_repo::normalize_repo_url(&mirror.url)),
                &mirror.mirror_of,
                &mirror.mirror_of_layouts,
                mirror.blocked,
            )
        })
        .collect();
    let repositories = |repos: &[rv_config::RepoConfig]| -> Vec<rv_config::RepoConfig> {
        (repos.iter())
            .map(|repo| {
                let mut repo = repo.clone();
                if rv_config::url_holds_secret(&repo.url) {
                    repo.url.clear();
                }
                repo
            })
            .collect()
    };
    let material = serde_json::json!({
        "format": FORMAT,
        "raeva": version,
        "target": target,
        "config": lock.config_hash,
        "pins": pins,
        // Each platform's own profiles: merged, one id would keep only the
        // last profile's repository.
        "repositories": (each.iter())
            .map(|config| {
                [
                    repositories(config.repositories()),
                    repositories(config.profile_plugin_repositories()),
                    repositories(config.plugin_repositories()),
                ]
            })
            .collect::<Vec<_>>(),
        "mirrors": mirrors,
    });
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&material)?));
    Ok(format!(
        "raeva-seed-{FORMAT}-{version}-{target}-{}",
        &digest[..32]
    ))
}

fn not_held(details: String, hint: &str) -> CliError {
    CliError::LockfileMismatch {
        details,
        hint: Some(hint.to_string()),
    }
}

/// Names the first few `files`, and how many more there are.
fn listed(files: &[String]) -> String {
    let mut text = files.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if files.len() > 3 {
        text.push_str(&format!(" and {} more", files.len() - 3));
    }
    text
}

async fn save(
    config: &Config,
    lock: &Lockfile,
    files: &PinnedFiles<'_>,
    key: String,
    dir: &Path,
) -> Result<Report> {
    match fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(CliError::Usage(format!(
                    "{} is not empty; a seed is saved into a new directory",
                    dir.display()
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) if err.kind() == io::ErrorKind::NotADirectory => {
            return Err(CliError::Usage(format!(
                "{} is not a directory; a seed is saved into a new directory",
                dir.display()
            )));
        }
        Err(err) => return Err(CliError::io_at(dir)(err)),
    }
    // A seed holds what a passing `sync --frozen` fetched, so the inputs it
    // refuses fail here as there.
    crate::commands::sync::check_frozen_inputs(config)?;
    let store = Store::open(&config.paths.store_dir)?;
    let lock_origins = LockOrigins::for_root(&config.project_root);
    let mirrors = Mirrors::of(config);
    let checks = stream::iter(files.keys())
        .map(|(key, pin)| {
            let store = &store;
            async move {
                let blob = match pin.as_sha256() {
                    Some(blob) => Some(blob.clone()),
                    None => store.lookup_artifact(key).await?,
                };
                let Some(blob) = blob else {
                    return Ok::<_, CliError>(None);
                };
                if store.check_pin_async(&blob, pin).await? != PinCheck::Match {
                    return Ok(None);
                }
                let served = store.served_by(key, &blob).await?;
                Ok(Some((blob, served)))
            }
        })
        .buffered(config.network.fetch_concurrency())
        .collect::<Vec<_>>()
        .await;
    let checks: Vec<_> = checks.into_iter().collect::<Result<_>>()?;
    let served: Vec<_> = (checks.iter())
        .map(|check| {
            check
                .as_ref()
                .map_or_else(Vec::new, |(_, served)| served.clone())
        })
        .collect();
    let (routes, failed) = admitted(config, &store, lock, files, &served, async || Ok(())).await?;
    let relative = |origin: &str, url: &String| {
        let saved = mirrors.saved(origin, url)?;
        Some(match saved == *url {
            true => (lock_origins.declared(url))
                .filter(|declared| lock_origins.project_url(declared).is_some())
                .unwrap_or(saved),
            false => saved,
        })
    };
    let mut seeded = Vec::new();
    let (mut lacking, mut unadmitted, mut unnamed) = (Vec::new(), Vec::new(), Vec::new());
    let mut lacked = HashSet::new();
    for ((key, _), (check, routes)) in files.keys().zip(checks.into_iter().zip(routes)) {
        let named: Vec<_> = (routes.iter())
            .filter_map(|(repo, endpoint)| Some((relative(repo, repo)?, relative(repo, endpoint)?)))
            .collect();
        match check {
            None => {
                lacking.push(key.to_string());
                lacked.insert(key);
            }
            Some(_) if routes.is_empty() => unadmitted.push(key.to_string()),
            Some(_) if named.is_empty() => unnamed.push(key.to_string()),
            Some((blob, _)) => seeded.push((key, blob, named)),
        }
    }
    if !lacking.is_empty() {
        // A `--frozen --platforms` check restores only its platforms, so
        // name those whose files a seed still lacks.
        let platforms: Vec<String> = (lock.platforms.iter())
            .filter(|entry| (entry.pinned_files()).any(|file| lacked.contains(&file.key)))
            .map(|entry| entry.platform.to_string())
            .collect();
        let hint = match platforms.as_slice() {
            platforms if platforms.is_empty() || platforms.len() == lock.platforms.len() => {
                "Run 'raeva sync --frozen' first, then 'raeva seed save' again".to_string()
            }
            platforms => format!(
                "A seed holds the files of every platform raeva.lock records; run 'raeva sync \
                 --frozen' without --platforms, which restores those of {} too, then 'raeva \
                 seed save' again",
                platforms.join(", ")
            ),
        };
        return Err(not_held(
            format!(
                "the store does not hold every file raeva.lock pins: {}",
                listed(&lacking)
            ),
            &hint,
        ));
    }
    if !unadmitted.is_empty() {
        // Why the resolution that decides the trust failed says more than
        // the files it left without a route.
        if let Some(failed) = failed {
            return Err(failed);
        }
        return Err(not_held(
            format!(
                "the store holds files raeva.lock pins only from repositories 'raeva sync \
                 --frozen' does not take them from here: {}",
                listed(&unadmitted)
            ),
            "Save the seed with the configuration and options of the 'raeva sync --frozen' \
             that passed",
        ));
    }
    if !unnamed.is_empty() {
        return Err(not_held(
            format!(
                "files raeva.lock pins came only through a mirror whose URL holds a secret and \
                 whose id is missing or shared with another such mirror, which a seed cannot \
                 name: {}",
                listed(&unnamed)
            ),
            "Give that mirror an <id> of its own in settings.xml",
        ));
    }
    let blobs = dir.join(BLOBS);
    fs::create_dir_all(&blobs).map_err(CliError::io_at(&blobs))?;
    let mut copied = BTreeSet::new();
    let mut bytes = 0;
    for (_, blob, _) in &seeded {
        if copied.insert(blob.clone()) {
            let target = blobs.join(blob.as_str());
            let source = store.get_path(blob);
            let mut from = (store.open_blob(blob)?).ok_or_else(|| {
                CliError::io_at(&source)(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the store holds no regular file there",
                ))
            })?;
            let mut to = fs::File::create(&target).map_err(CliError::io_at(&target))?;
            bytes += io::copy(&mut from, &mut to).map_err(CliError::io_at(&target))?;
        }
    }
    let metadata = save_metadata(config, mirrors, &dir.join(METADATA)).await?;
    let manifest = Manifest {
        format: FORMAT,
        key: key.clone(),
        metadata,
        files: (seeded.into_iter())
            .map(|(key, blob, served)| SeedFile {
                coordinate: key.to_string(),
                sha256: blob.to_string(),
                served,
            })
            .collect(),
    };
    // Written last: a directory without it is not a seed.
    crate::commands::write_atomic(&dir.join(MANIFEST), &serde_json::to_vec(&manifest)?)?;
    Ok(Report::data(SeedReport {
        action: "Saved",
        key,
        files: manifest.files.len(),
        blobs: copied.len(),
        bytes,
        metadata: manifest.metadata.len(),
        dir: dir.display().to_string(),
    }))
}

/// Copy the metadata cache's rows into `dir`, one file per distinct content,
/// and list them. A row whose scope could carry a credential, or names an
/// endpoint `mirrors` does not, stays behind.
async fn save_metadata(config: &Config, mirrors: Mirrors, dir: &Path) -> Result<Vec<SeedRow>> {
    let path = config.paths.metadata_db_path();
    let cache = MetadataCache::new(&path).map_err(rv_repo::RepoError::from)?;
    let dir = dir.to_path_buf();
    let task = tokio::task::spawn_blocking(move || -> Result<Vec<SeedRow>> {
        fs::create_dir_all(&dir).map_err(CliError::io_at(&dir))?;
        let mut rows = Vec::new();
        let mut written = BTreeSet::new();
        for table in RowTable::ALL {
            let entries = cache
                .rows(table.table())
                .map_err(rv_repo::RepoError::from)?;
            for (scope, path, entry) in entries {
                let origin = rv_repo::cache_scope_repository(&scope);
                // A row an earlier raeva wrote may hold a repository's text.
                if rv_config::stored_repository(origin) != origin {
                    continue;
                }
                let scope = rv_repo::map_scope_urls(&scope, |url| mirrors.saved(origin, url));
                let Some(scope) = scope.filter(|scope| rv_repo::shareable_cache_scope(scope))
                else {
                    continue;
                };
                if !valid_row_path(&path) {
                    continue;
                }
                let sha256 = entry.sha256.to_string();
                if written.insert(sha256.clone()) {
                    let target = dir.join(&sha256);
                    fs::write(&target, &entry.content).map_err(CliError::io_at(&target))?;
                }
                rows.push(SeedRow {
                    table,
                    scope,
                    path,
                    sha256,
                    fetched_at: entry.fetched_at,
                    expires_at: entry.expires_at,
                    checksum_checked: entry.checksum_checked,
                });
            }
        }
        Ok(rows)
    });
    task.await
        .map_err(|err| CliError::task_failed("seed metadata", err))?
}

/// Whether `path` is a relative repository path that names no directory
/// outside the repository.
fn valid_row_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn read_manifest(dir: &Path) -> Result<Option<Manifest>> {
    let path = dir.join(MANIFEST);
    let file = match rv_store::open_unfollowed_regular(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotADirectory => return Ok(None),
        Err(err) => return Err(CliError::io_at(&path)(err)),
    };
    if (file.metadata().map_err(CliError::io_at(&path))?).len() > MANIFEST_LIMIT {
        return Ok(None);
    }
    let mut text = Vec::new();
    (file.take(MANIFEST_LIMIT))
        .read_to_end(&mut text)
        .map_err(CliError::io_at(&path))?;
    // A manifest this raeva cannot read is a seed of another format.
    Ok(serde_json::from_slice(&text).ok())
}

/// The (repository, endpoint) routes among `served` whose repository is one
/// the lock records for the file, `origins`: only those vouch for it, as a
/// sync that downloaded it would have recorded.
/// What a seed names a mirror whose URL holds a secret by, before its id.
const MIRROR: &str = "mirror:";

/// `id` with each byte other than a letter, digit, `.`, `_` or `-` written
/// as `%XX`, so a name holds no `/` or `%` of the id and each id has one.
fn mirror_name(id: &str) -> String {
    let mut name = String::with_capacity(id.len());
    for byte in id.bytes() {
        match byte.is_ascii_alphanumeric() || b"._-".contains(&byte) {
            true => name.push(char::from(byte)),
            false => name.push_str(&format!("%{byte:02X}")),
        }
    }
    name
}

/// The mirrors of the configuration, by the URL their requests go to. A seed
/// names a mirror whose URL holds a secret by its id, which the
/// configuration that restores the seed resolves, and leaves out an
/// endpoint that is neither its repository's own URL nor a configured
/// mirror's, such as one an earlier token spelled.
#[derive(Clone, Default)]
struct Mirrors {
    /// Each mirror's URL and what a seed names it: the URL itself, its
    /// [`MIRROR`] reference, or `None` for one with a secret and no id of
    /// its own.
    urls: HashMap<String, Option<String>>,
}

impl Mirrors {
    fn of(config: &Config) -> Self {
        let secret = |mirror: &rv_config::MirrorConfig| rv_config::url_holds_secret(&mirror.url);
        let mut ids: HashMap<&str, usize> = HashMap::new();
        for mirror in config.mirrors().iter().filter(|mirror| secret(mirror)) {
            *ids.entry(mirror.id.as_deref().unwrap_or_default())
                .or_default() += 1;
        }
        let named = |id: &str| !id.is_empty() && ids.get(id) == Some(&1);
        let mut urls: HashMap<String, Option<String>> = HashMap::new();
        for mirror in config.mirrors() {
            let url = rv_repo::normalize_repo_url(&mirror.url);
            let name = match secret(mirror) {
                false => Some(url.clone()),
                true => (mirror.id.as_deref())
                    .filter(|id| named(id))
                    .map(|id| format!("{MIRROR}{}/", mirror_name(id))),
            };
            // The first mirror of a URL with a name keeps it.
            let known = urls.entry(url).or_default();
            if known.is_none() {
                *known = name;
            }
        }
        Self { urls }
    }

    /// What a seed names `url`, which a request for the repository at
    /// `origin` went to; `None` to leave it out.
    fn saved(&self, origin: &str, url: &str) -> Option<String> {
        // As the mirrors are keyed, so `file:/x` is the mirror `file:///x`.
        let normalized = rv_repo::normalize_repo_url(url);
        match self.urls.get(&normalized) {
            Some(name) => name.clone(),
            None => (url == origin || !normalized.contains("://")).then(|| url.to_string()),
        }
    }

    /// The URL a seed's `name` stands for here; `None` for a mirror this
    /// configuration does not name so.
    fn restored(&self, name: &str) -> Option<String> {
        if !name.starts_with(MIRROR) {
            return Some(name.to_string());
        }
        (self.urls.iter())
            .find(|(_, saved)| saved.as_deref() == Some(name))
            .map(|(url, _)| url.clone())
    }
}

fn recorded_routes(
    lock_origins: &LockOrigins,
    origins: &BTreeSet<&str>,
    served: &[(String, String)],
) -> Vec<(String, String)> {
    // A repository no lock records may hold a secret in its URL.
    let any = |repo: &str| {
        let unrecorded = rv_config::stored_repository(repo) == rv_config::UNRECORDED_REPOSITORY;
        origins.contains(ANY_REPOSITORY) && (unrecorded || !rv_config::url_holds_secret(repo))
    };
    (served.iter())
        .filter(|(repo, _)| {
            any(repo) || (origins.iter()).any(|origin| lock_origins.matches(origin, repo))
        })
        .cloned()
        .collect()
}

/// Why a seed file is not restored.
enum Refused {
    Missing,
    Mismatch,
}

async fn restore(
    config: &Config,
    lock: &Lockfile,
    files: &PinnedFiles<'_>,
    key: String,
    dir: &Path,
) -> Result<Report> {
    crate::commands::sync::check_frozen_inputs(config)?;
    let manifest = read_manifest(dir)?;
    let Some(manifest) = manifest.filter(|manifest| manifest.format == FORMAT) else {
        return Err(not_held(
            format!(
                "{} holds no seed this raeva reads ({MANIFEST} is missing or of another format)",
                dir.display()
            ),
            "Save a seed with 'raeva seed save' after 'raeva sync --frozen'",
        ));
    };
    if manifest.key != key {
        return Err(not_held(
            format!(
                "the seed in {} is for another lock or configuration: its key is {}, and this \
                 lock's is {key}",
                dir.display(),
                rv_maven_types::bounded(&manifest.key)
            ),
            "Restore the seed saved under this lock's key, or save one with 'raeva seed save' \
             after 'raeva sync --frozen'",
        ));
    }
    let entries: BTreeMap<&str, &SeedFile> = (manifest.files.iter())
        .map(|file| (file.coordinate.as_str(), file))
        .collect();
    let blobs = dir.join(BLOBS);
    // A blob path is opened without following its last component only, so
    // the directory above it must be the seed's own.
    if !fs::symlink_metadata(&blobs).is_ok_and(|meta| meta.is_dir()) {
        return Err(not_held(
            format!("the seed in {} has no {BLOBS} directory", dir.display()),
            "Delete the seed and save it again with 'raeva seed save' after 'raeva sync --frozen'",
        ));
    }
    let store = Store::open(&config.paths.store_dir)?;
    let lock_origins = LockOrigins::for_root(&config.project_root);
    let mirrors = Mirrors::of(config);
    let outcomes = stream::iter(files.keys())
        .map(|(key, pin)| {
            let (store, blobs, lock_origins) = (&store, &blobs, &lock_origins);
            let mirrors = &mirrors;
            let entry = entries.get(key.to_string().as_str()).copied();
            async move {
                let Some(entry) = entry else {
                    return Ok::<_, CliError>(Err(Refused::Missing));
                };
                // A project-relative origin this checkout cannot place
                // names no URL, not even an unrecorded one.
                let absolute = |url: &String| match rv_lock::is_project_relative_origin(url) {
                    true => lock_origins.project_url(url),
                    false => mirrors.restored(url),
                };
                let served: Vec<_> = (entry.served.iter())
                    .filter_map(|(repo, endpoint)| Some((absolute(repo)?, absolute(endpoint)?)))
                    .collect();
                let restored = restore_file(store, blobs, key, pin, entry).await?;
                Ok(restored.map(|(blob, size)| (blob, size, served)))
            }
        })
        .buffered(config.network.fetch_concurrency())
        .collect::<Vec<_>>()
        .await;
    let (mut missing, mut mismatched) = (Vec::new(), Vec::new());
    let mut restored = Vec::new();
    for ((key, _), outcome) in files.keys().zip(outcomes) {
        match outcome? {
            Ok((blob, size, served)) => restored.push((key, blob, size, served)),
            Err(Refused::Missing) => missing.push(key.to_string()),
            Err(Refused::Mismatch) => mismatched.push(key.to_string()),
        }
    }
    if !mismatched.is_empty() {
        return Err(not_held(
            format!(
                "the seed in {} holds other bytes than raeva.lock pins for {}",
                dir.display(),
                listed(&mismatched)
            ),
            "Delete the seed: someone changed it after it was saved. 'raeva sync --frozen' \
             downloads the files",
        ));
    }
    let lacks = |missing: &[String]| {
        not_held(
            format!(
                "the seed in {} lacks files raeva.lock pins, or the repository the lock records \
                 as serving them: {}",
                dir.display(),
                listed(missing)
            ),
            "Delete the seed and save it again with 'raeva seed save' after 'raeva sync --frozen'",
        )
    };
    if !missing.is_empty() {
        return Err(lacks(&missing));
    }
    let metadata = check_metadata(lock, lock_origins, mirrors, dir, manifest.metadata).await?;
    let rows = metadata.len();
    // An offline resolution reads the rows: they go in first when it runs.
    let mut metadata = Some(metadata);
    let served: Vec<_> = restored
        .iter()
        .map(|(_, _, _, served)| served.clone())
        .collect();
    let write_rows = async || write_metadata(config, metadata.take().unwrap_or_default()).await;
    let (routes, _) = admitted(config, &store, lock, files, &served, write_rows).await?;
    let missing: Vec<_> = (restored.iter().zip(&routes))
        .filter(|(_, routes)| routes.is_empty())
        .map(|((key, ..), _)| key.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(lacks(&missing));
    }
    // The evidence is recorded only once every file matched its pin, so a
    // refused seed leaves blobs no restore takes without a download.
    let (mut served, mut origins) = (Vec::new(), Vec::new());
    for ((key, blob, ..), routes) in restored.iter().zip(&routes) {
        for (repo_url, endpoint_url) in routes {
            served.push((
                (*key).clone(),
                blob.clone(),
                repo_url.clone(),
                endpoint_url.clone(),
            ));
            // As a restore from the lock records them: the pin, not the
            // route, vouches for the bytes, so a resolving sync takes them
            // only while raeva.lock pins them.
            let origin = rv_store::Origin {
                repo_url: repo_url.clone(),
                endpoint_url: endpoint_url.clone(),
                checksum_verified: false,
                served: false,
            };
            origins.push(((*key).clone(), blob.clone(), origin));
        }
    }
    store.record_served(served).await?;
    let unrecorded = store.unrecorded_origins(origins).await?;
    (store.record_origins(unrecorded.into_iter().flatten().collect())).await?;
    if let Some(metadata) = metadata {
        write_metadata(config, metadata).await?;
    }
    let blobs: BTreeSet<_> = restored.iter().map(|(_, blob, _, _)| blob).collect();
    let bytes = (restored.iter())
        .map(|(_, blob, size, _)| (blob, *size))
        .collect::<BTreeMap<_, _>>()
        .values()
        .sum();
    Ok(Report::data(SeedReport {
        action: "Restored",
        key,
        files: restored.len(),
        blobs: blobs.len(),
        bytes,
        metadata: rows,
        dir: dir.display().to_string(),
    }))
}

/// A metadata row read back from a seed, ready for the cache.
struct CheckedRow {
    table: CacheTable,
    scope: String,
    path: String,
    /// Shared by the rows of one digest, which a seed may repeat.
    content: Arc<[u8]>,
    fetched_at: i64,
    expires_at: i64,
    checksum_checked: bool,
}

/// Read every metadata row of the seed in `dir` and check it: a scope
/// without a credential, a repository path, bytes that hash to the row's
/// digest, and, for a POM raeva.lock pins, the pinned bytes. One row that
/// fails refuses the seed. A home that other projects share can cache
/// other bytes under a pinned path from a repository the lock does not
/// record for it; such a row is not the pinned POM and stays behind.
///
/// A row raeva.lock does not pin, such as a version listing or the POM of a
/// version the resolution rejected, is taken as the default-branch run that
/// saved the seed cached it. It only steers the resolution `sync --frozen`
/// runs again, whose result must still equal raeva.lock, every file of it
/// matching its pin, with the lock's versions as the caps on each range.
async fn check_metadata(
    lock: &Lockfile,
    lock_origins: LockOrigins,
    mirrors: Mirrors,
    dir: &Path,
    rows: Vec<SeedRow>,
) -> Result<Vec<CheckedRow>> {
    let mut pins = lock.pinned_paths();
    // The plugin pass reads its POMs from the repositories of the plugin
    // tables, which a row of the dependencies need not record.
    for files in lock
        .platforms
        .iter()
        .filter_map(|platform| platform.plugin_files())
    {
        let tables = &files.tables;
        let sets = tables.sets.iter().flat_map(|set| &set.repo_urls);
        let urls: BTreeSet<_> = sets.chain(tables.repo_ids.keys()).collect();
        for file in files.pinned_files() {
            if let Some((_, origins)) = pins.get_mut(&file.path()) {
                origins.extend(urls.iter().map(|url| url.to_string()));
            }
        }
    }
    let dir = dir.join(METADATA);
    let seed = dir.parent().map(Path::to_path_buf).unwrap_or_default();
    let task = tokio::task::spawn_blocking(move || -> Result<Vec<CheckedRow>> {
        let refused = |what: &str, path: &str| {
            not_held(
                format!(
                    "the seed in {} holds {what} for {}",
                    seed.display(),
                    rv_maven_types::bounded(path)
                ),
                "Delete the seed: someone changed it after it was saved. 'raeva sync --frozen' \
                 downloads the files",
            )
        };
        if !rows.is_empty() && !fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
            return Err(refused("no metadata directory", METADATA));
        }
        let mut contents: HashMap<String, Arc<[u8]>> = HashMap::new();
        let mut checked = Vec::with_capacity(rows.len());
        let mut written: u64 = 0;
        for row in rows {
            if !rv_repo::shareable_cache_scope(&row.scope) || !valid_row_path(&row.path) {
                return Err(refused("a metadata row it cannot use", &row.path));
            }
            let Ok(sha256) = rv_maven_types::Sha256::from_str(&row.sha256) else {
                return Err(refused("a metadata row it cannot use", &row.path));
            };
            let content = match contents.get(sha256.as_str()) {
                Some(content) => Arc::clone(content),
                None => {
                    let path = dir.join(sha256.as_str());
                    let file = rv_store::open_unfollowed_regular(&path)
                        .map_err(CliError::io_at(&path))?
                        .ok_or_else(|| refused("no copy of the metadata", &row.path))?;
                    let mut content = Vec::new();
                    (file.take(ROW_LIMIT + 1))
                        .read_to_end(&mut content)
                        .map_err(CliError::io_at(&path))?;
                    if content.len() as u64 > ROW_LIMIT
                        || rv_maven_types::Sha256::from_bytes(&content) != sha256
                    {
                        return Err(refused("other metadata than it lists", &row.path));
                    }
                    let content: Arc<[u8]> = content.into();
                    contents.insert(sha256.as_str().to_string(), Arc::clone(&content));
                    content
                }
            };
            if let (RowTable::Pom, Some((pin, origins))) = (row.table, pins.get(&row.path))
                && Digest::of_bytes(pin.algorithm(), &content) != *pin
            {
                let repo = rv_repo::cache_scope_repository(&row.scope);
                if origins.is_empty()
                    || (origins.iter()).any(|origin| lock_origins.matches(origin, repo))
                {
                    return Err(refused("other bytes than raeva.lock pins", &row.path));
                }
                continue;
            }
            // A row of a mirror this configuration does not name stays behind.
            let Some(scope) = rv_repo::map_scope_urls(&row.scope, |url| mirrors.restored(url))
            else {
                continue;
            };
            written += content.len() as u64;
            if written > METADATA_LIMIT {
                return Err(refused("over 2 GiB of metadata rows", "metadata.db"));
            }
            checked.push(CheckedRow {
                table: row.table.table(),
                scope,
                path: row.path,
                content,
                fetched_at: row.fetched_at,
                expires_at: row.expires_at,
                checksum_checked: row.checksum_checked,
            });
        }
        Ok(checked)
    });
    task.await
        .map_err(|err| CliError::task_failed("seed metadata", err))?
}

/// Write `rows` into the metadata cache, keeping a row the cache already
/// holds. Each row expires when it did in the cache it was saved from, or
/// once the update policy its scope records runs out from now if that is
/// sooner, as a clock that ran ahead leaves it. A `daily` row keeps when it
/// was fetched, so it is due by this run's zone as it would be in the cache
/// it was saved from.
async fn write_metadata(config: &Config, rows: Vec<CheckedRow>) -> Result<()> {
    let path = config.paths.metadata_db_path();
    let cache = MetadataCache::new(&path).map_err(rv_repo::RepoError::from)?;
    let task = tokio::task::spawn_blocking(move || -> std::result::Result<(), CacheError> {
        let now = now_epoch_seconds();
        for row in rows {
            if cache.get(row.table, &row.scope, &row.path)?.is_some() {
                continue;
            }
            let policy = rv_repo::cache_scope_update_policy(&row.scope);
            if row.expires_at < 0 && policy.is_none_or(|policy| policy == UpdatePolicy::Daily) {
                cache.insert_fetched_at(
                    row.table,
                    &row.scope,
                    &row.path,
                    &row.content,
                    Expiry::Daily,
                    row.fetched_at,
                    row.checksum_checked,
                )?;
                continue;
            }
            let ttl = row.expires_at.saturating_sub(now);
            let ttl = policy.map_or(ttl, |policy| ttl.min(policy.ttl_secs()));
            cache.insert(
                row.table,
                &row.scope,
                &row.path,
                &row.content,
                Expiry::After(ttl),
                row.checksum_checked,
            )?;
        }
        Ok(())
    });
    (task.await)
        .map_err(|err| CliError::task_failed("seed metadata", err))?
        .map_err(rv_repo::RepoError::from)?;
    Ok(())
}

/// Put the seed's copy of `key` into the store, which takes it only when it
/// matches `pin`.
async fn restore_file(
    store: &Store,
    blobs: &Path,
    key: &ArtifactCoord,
    pin: &Digest,
    entry: &SeedFile,
) -> Result<std::result::Result<(BlobId, u64), Refused>> {
    let Ok(blob) = BlobId::from_str(&entry.sha256) else {
        return Ok(Err(Refused::Mismatch));
    };
    if pin.as_sha256().is_some_and(|pinned| *pinned != blob) {
        return Ok(Err(Refused::Mismatch));
    }
    let path = blobs.join(blob.as_str());
    let open = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || rv_store::open_unfollowed_regular(&path))
    };
    let file = open
        .await
        .map_err(|err| CliError::task_failed("seed read", err))?
        .map_err(CliError::io_at(&path))?;
    let Some(file) = file else {
        return Ok(Err(Refused::Missing));
    };
    let chunks = stream::try_unfold(tokio::fs::File::from_std(file), |mut file| async move {
        let mut chunk = vec![0; 1 << 20];
        let read = file.read(&mut chunk).await?;
        chunk.truncate(read);
        Ok::<_, io::Error>((read > 0).then(|| (chunk.into(), file)))
    });
    let expect = Expect {
        sidecar: None,
        pin: Some(pin),
    };
    match store.put_stream_verified(chunks, expect, Some(key)).await {
        Ok(verified) if verified.blob == blob => Ok(Ok((verified.blob, verified.size))),
        Ok(_) | Err(PutError::Mismatch { .. }) => Ok(Err(Refused::Mismatch)),
        Err(PutError::Stream(err)) => Err(CliError::io_at(&path)(err)),
        Err(PutError::Store(err)) => Err(err.into()),
    }
}

struct KeyReport {
    key: String,
}

impl CommandOutput for KeyReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({ "key": self.key }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.line(&self.key)
    }
}

struct SeedReport {
    action: &'static str,
    key: String,
    files: usize,
    blobs: usize,
    bytes: u64,
    metadata: usize,
    dir: String,
}

impl CommandOutput for SeedReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "key": self.key,
            "files": self.files,
            "blobs": self.blobs,
            "bytes": self.bytes,
            "metadata": self.metadata,
            "path": self.dir,
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        let preposition = if self.action == "Saved" { "to" } else { "from" };
        human.done(
            self.action,
            format!(
                "{} locked files ({} blobs, {} bytes) and {} metadata cache rows {preposition} {}",
                self.files, self.blobs, self.bytes, self.metadata, self.dir
            ),
        )?;
        human.line(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::{RowTable, SeedRow, check_metadata, valid_row_path};

    /// The rows of one digest share its bytes, so a seed that repeats a
    /// row holds one copy of them.
    #[tokio::test]
    async fn rows_of_one_digest_share_their_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"<metadata/>";
        let sha256 = rv_maven_types::Sha256::from_bytes(content);
        std::fs::create_dir(dir.path().join(super::METADATA)).unwrap();
        std::fs::write(dir.path().join("metadata").join(sha256.as_str()), content).unwrap();
        let row = || SeedRow {
            table: RowTable::VersionList,
            scope: "https://repo.example/\u{1f}https://repo.example/\u{1f}id=r".to_string(),
            path: "g/a/maven-metadata.xml".to_string(),
            sha256: sha256.as_str().to_string(),
            fetched_at: 0,
            expires_at: 0,
            checksum_checked: false,
        };
        let lock = rv_lock::Lockfile::new();
        let origins = rv_lock::LockOrigins::for_root(dir.path());
        let mirrors = super::Mirrors::default();
        let rows = check_metadata(&lock, origins, mirrors, dir.path(), vec![row(), row()]);
        let rows = rows.await;
        let rows = rows.unwrap();
        assert!(Arc::ptr_eq(&rows[0].content, &rows[1].content));
    }

    /// Rows that share one file still count once each toward what a
    /// restore writes, so a seed that repeats a large row is refused.
    #[tokio::test]
    async fn a_seed_that_writes_too_much_metadata_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![b'x'; super::ROW_LIMIT as usize];
        let sha256 = rv_maven_types::Sha256::from_bytes(&content);
        std::fs::create_dir(dir.path().join(super::METADATA)).unwrap();
        std::fs::write(dir.path().join("metadata").join(sha256.as_str()), &content).unwrap();
        let rows = (0..=super::METADATA_LIMIT / super::ROW_LIMIT)
            .map(|at| SeedRow {
                table: RowTable::VersionList,
                scope: "https://repo.example/\u{1f}https://repo.example/\u{1f}id=r".to_string(),
                path: format!("g/a{at}/maven-metadata.xml"),
                sha256: sha256.as_str().to_string(),
                fetched_at: 0,
                expires_at: 0,
                checksum_checked: false,
            })
            .collect();
        let lock = rv_lock::Lockfile::new();
        let origins = rv_lock::LockOrigins::for_root(dir.path());
        let mirrors = super::Mirrors::default();
        let checked = check_metadata(&lock, origins, mirrors, dir.path(), rows).await;
        assert!(checked.is_err());
    }

    /// A mirror keeps its name beside a mirror of the same URL with none.
    #[test]
    fn a_named_mirror_keeps_its_name_beside_another_of_its_url() {
        let url = "https://user:secret@mirror.example/";
        let mirror = |id: Option<&str>, of: &str| {
            let mut mirror = rv_config::MirrorConfig::new(id, url);
            mirror.mirror_of = vec![of.to_string()];
            mirror
        };
        let dir = tempfile::tempdir().unwrap();
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let config = rv_config::Config::for_testing(dir.path().to_path_buf(), paths)
            .with_mirrors(vec![mirror(Some("m"), "central"), mirror(None, "other")]);
        let mirrors = super::Mirrors::of(&config);
        let name = &mirrors.urls[&rv_repo::normalize_repo_url(url)];
        assert_eq!(
            name.as_deref(),
            Some(format!("{}m/", super::MIRROR).as_str())
        );
    }

    /// Two mirrors whose URLs hold a secret and that share an id, or one
    /// without an id, have no name, so a seed carries nothing through them.
    #[test]
    fn a_secret_mirror_without_an_id_of_its_own_has_no_name() {
        let urls = [
            "https://user:a@one.example/",
            "https://user:b@two.example/",
            "https://user:c@three.example/",
        ];
        let dir = tempfile::tempdir().unwrap();
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let mirrors = [(Some("m"), urls[0]), (Some("m"), urls[1]), (None, urls[2])]
            .map(|(id, url)| rv_config::MirrorConfig::new(id, url));
        let config = rv_config::Config::for_testing(dir.path().to_path_buf(), paths)
            .with_mirrors(mirrors.to_vec());
        let mirrors = super::Mirrors::of(&config);
        for url in urls {
            assert_eq!(mirrors.saved("https://repo.example/", url), None, "{url}");
        }
    }

    /// Every id has a name of its own, without a `/`, and an id of letters,
    /// digits, `.`, `_` and `-` is its own name.
    #[test]
    fn each_mirror_id_has_one_name() {
        let ids = [
            "nexus",
            "corp:nexus",
            "corp%3Anexus",
            "corp+nexus",
            "nexus~1",
            "a/b",
        ];
        let names: BTreeSet<_> = ids.iter().map(|id| super::mirror_name(id)).collect();
        assert_eq!(names.len(), ids.len(), "{names:?}");
        assert!(names.iter().all(|name| !name.contains('/')), "{names:?}");
        assert_eq!(super::mirror_name("my-repo_1.0"), "my-repo_1.0");
        assert_eq!(super::mirror_name("corp:nexus"), "corp%3Anexus");
    }

    #[test]
    fn a_row_path_stays_inside_the_repository() {
        assert!(valid_row_path("org/example/lib/1.0/lib-1.0.pom"));
        assert!(valid_row_path("org/example/lib/maven-metadata.xml"));
        for path in ["", "/etc/passwd", "a/../b", "a//b", "./a", "a\\b", "a/b\n"] {
            assert!(!valid_row_path(path), "{path:?}");
        }
    }
}
