//! The repository list a model build reads its parents and imported BOMs
//! through, as Maven's model resolver holds it.
//!
//! Maven keeps the list by effective id: a repository a mirror serves is
//! listed under the mirror's id. `addRepository` with a declared id it has
//! not seen only aggregates the declaration, keeping an entry already listed
//! under its effective id; with one it has seen and `replace`, it first
//! drops the entries whose effective id is the declared id. Maven 3.10's
//! dependency resolver skips that replacement for an id of the request's
//! entries. The project's resolver, which builds the BOMs a project
//! imports, keeps the request's entries behind its POM's, so a removed one
//! comes back there.

use foldhash::HashSet;
use rv_maven_types::MavenMode;
use rv_repo::Repository;

/// Who reads a repository of the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Reach {
    Read,
    /// Neither raeva nor Maven: a blocked mirror's, a URL that holds an
    /// expression no mirror serves, or a layout Maven reaches only through
    /// a mirror and none serves.
    Neither,
    /// Maven only, as raeva refuses it.
    Maven,
}

/// A repository a build's model resolver was handed.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Added {
    pub(super) repo: Repository,
    /// An interpolated declaration, which replaces the entries of its id.
    pub(super) replace: bool,
    /// A refused declaration takes its place in the list without being
    /// searched.
    pub(super) reach: Reach,
    /// The super POM's `central`, which every effective model ends with.
    pub(super) implied: bool,
}

/// The declarations one build's model resolvers were handed, in order: the
/// build's own, then those of each imported BOM being built, whose
/// resolver is a copy of its importer's.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct ModelBuild {
    /// A project's resolver rather than a dependency's.
    pub(super) project: bool,
    pub(super) added: Vec<Added>,
}

/// An entry of the list.
#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub(super) repo: Repository,
    key: String,
    pub(super) reach: Reach,
    /// Placed by a declaration only Maven reads in place of an entry raeva
    /// reads.
    pub(super) displaced: bool,
    /// The request's own Central entry, mirrored or not.
    central: bool,
}

/// Where the list starts.
pub(super) struct Start {
    pub(super) request: Vec<Repository>,
    /// The project resolver's request entries, kept behind its POM's.
    pub(super) external: Vec<Repository>,
    /// The ids the resolver has seen: none for a dependency's, the
    /// project's declarations for a project's.
    pub(super) seen: HashSet<Option<String>>,
}

/// The super POM's `central`.
pub(super) fn super_central() -> Repository {
    Repository::new(
        Some("central".to_string()),
        "https://repo.maven.apache.org/maven2",
        true,
        false,
    )
}

/// The id Maven lists `repo` under: its mirror's, else its own, an absent
/// id as the empty one.
fn effective_id(config: &rv_config::Config, repo: &Repository) -> String {
    match rv_repo::listing_mirror(config, repo) {
        Some((id, _)) => id,
        None => repo.id.clone().unwrap_or_default(),
    }
}

/// Whether Maven reads `repo` neither: a blocked mirror takes it.
pub(super) fn blocked(config: &rv_config::Config, repo: &Repository) -> bool {
    rv_repo::listing_mirror(config, repo).is_some_and(|(_, blocked)| blocked)
}

/// Where a request through `repo` goes, Central's two names as one.
fn endpoint(config: &rv_config::Config, repo: &Repository) -> String {
    let url = rv_repo::mirrored_repository(config, repo).url;
    if super::backend::is_central(&url) {
        String::new()
    } else {
        url
    }
}

/// The list after `build`'s declarations.
pub(super) fn replay(
    config: &rv_config::Config,
    mode: MavenMode,
    start: Start,
    build: &ModelBuild,
) -> Vec<Entry> {
    let entry = |repo: Repository| Entry {
        key: effective_id(config, &repo),
        central: is_request_central(&repo),
        repo,
        reach: Reach::Read,
        displaced: false,
    };
    let request = start.request;
    let mut list: Vec<Entry> = request.iter().cloned().map(entry).collect();
    let request_ids: HashSet<String> = list.iter().map(|entry| entry.key.clone()).collect();
    let mut seen = start.seen;
    for added in &build.added {
        let id = added.repo.id.clone();
        let mut displaced = false;
        if !seen.insert(id.clone()) {
            if !added.replace {
                continue;
            }
            if !build.project
                && mode == MavenMode::Maven310
                && id.as_ref().is_some_and(|id| request_ids.contains(id))
            {
                continue;
            }
            if let Some(id) = &id {
                displaced =
                    (list.iter()).any(|known| known.reach == Reach::Read && known.key == *id);
                list.retain(|known| known.key != *id);
            }
        }
        let key = effective_id(config, &added.repo);
        if list.iter().any(|known| known.key == key) {
            continue;
        }
        // One that reaches a request entry's endpoint and layout reads the
        // same files there, under the URL the request records, with its own
        // policies.
        let reach = match added.implied {
            true => Reach::Maven,
            false => added.reach,
        };
        let same = |known: &&Repository| {
            known.layout() == added.repo.layout()
                && endpoint(config, known) == endpoint(config, &added.repo)
        };
        let (repo, reach, central) = match request
            .iter()
            .find(same)
            .filter(|_| reach != Reach::Neither)
        {
            Some(known) => {
                let mut repo = known.clone();
                repo.releases_enabled = added.repo.releases_enabled;
                repo.snapshots_enabled = added.repo.snapshots_enabled;
                (repo, Reach::Read, is_request_central(known))
            }
            None => (added.repo.clone(), reach, false),
        };
        list.push(Entry {
            key,
            repo,
            reach,
            displaced: displaced && reach == Reach::Maven,
            central,
        });
    }
    for repo in start.external {
        let external = entry(repo);
        if !list.iter().any(|known| known.key == external.key) {
            list.push(external);
        }
    }
    list
}

/// Whether `repo`, a request entry, is the request's Central.
fn is_request_central(repo: &Repository) -> bool {
    repo.id.as_deref() == Some("central") && super::backend::is_central(&repo.url)
}

/// Where Maven searches a POM of one exact version, as far as raeva reads.
pub(super) struct Search<'a> {
    /// The entries raeva reads that come before `unread`, or all of them.
    pub(super) before: Vec<Repository>,
    /// The first entry only Maven reads that could serve the version and
    /// either took the place of an entry raeva reads or comes before one.
    pub(super) unread: Option<&'a Entry>,
    /// For a release past an `unread` that took no entry's place: the
    /// entries raeva reads before the request's Central, and Central.
    /// A release on Central is immutable, so an entry only Maven reads
    /// ahead of it holds the same file or none, and a POM found first on
    /// Central is Maven's. One found on another entry first is not known
    /// to be, nor is one after an entry that took another's place.
    pub(super) central: Option<(Vec<Repository>, Repository)>,
}

/// Where Maven searches `entries` for a POM of `version`, an exact one.
pub(super) fn search<'a>(entries: &'a [Entry], version: &str) -> Search<'a> {
    let serves = |entry: &Entry| entry.repo.allows_version(version);
    let read = |entry: &Entry| entry.reach == Reach::Read;
    let cut = (entries.iter().enumerate()).find(|(at, entry)| {
        entry.reach == Reach::Maven
            && serves(entry)
            && (entry.displaced
                || entries[at + 1..]
                    .iter()
                    .any(|after| read(after) && serves(after)))
    });
    let end = cut.map_or(entries.len(), |(at, _)| at);
    let before = (entries[..end].iter())
        .filter(|entry| read(entry))
        .map(|entry| entry.repo.clone())
        .collect();
    let central = cut
        .filter(|(_, unread)| !unread.displaced && !rv_maven_types::is_snapshot_version(version))
        .and_then(|(at, _)| {
            let mut others = Vec::new();
            for entry in entries[at + 1..].iter().filter(|entry| serves(entry)) {
                match entry.reach {
                    Reach::Read if entry.central => return Some((others, entry.repo.clone())),
                    Reach::Read => others.push(entry.repo.clone()),
                    Reach::Maven if entry.displaced => return None,
                    Reach::Maven | Reach::Neither => {}
                }
            }
            None
        });
    Search {
        before,
        unread: cut.map(|(_, entry)| entry),
        central,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> rv_config::Config {
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        rv_config::Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new())
    }

    fn repo(id: Option<&str>, url: &str) -> Repository {
        Repository::new(id.map(str::to_string), url, true, false)
    }

    fn urls(build: &ModelBuild, request: &[Repository], mode: MavenMode) -> Vec<String> {
        let start = Start {
            request: request.to_vec(),
            external: Vec::new(),
            seen: HashSet::default(),
        };
        (replay(&config(), mode, start, build).into_iter())
            .map(|entry| entry.repo.url)
            .collect()
    }

    fn add(build: &mut ModelBuild, repos: Vec<Repository>, replace: bool) {
        build.added.extend(repos.into_iter().map(|repo| Added {
            repo,
            replace,
            reach: Reach::Read,
            implied: false,
        }));
    }

    /// A release past an entry only Maven reads may come from the request's
    /// Central, after the other entries raeva reads before it; a snapshot,
    /// or a release past an entry that took another's place, may not.
    #[test]
    fn a_release_past_an_unread_entry_may_come_from_central() {
        let central = repo(Some("central"), "https://repo1.maven.org/maven2");
        let corp = repo(Some("corp"), "https://corp.example/");
        let both = |mut repo: Repository| {
            repo.snapshots_enabled = true;
            repo
        };
        let copy = Added {
            repo: both(repo(Some("copy"), "https://copy.example/")),
            replace: false,
            reach: Reach::Maven,
            implied: false,
        };
        let mut build = ModelBuild::default();
        build.added.push(copy);
        let start = |request: &[Repository]| Start {
            request: request.to_vec(),
            external: Vec::new(),
            seen: HashSet::default(),
        };
        let mode = MavenMode::Maven39;
        // The request's entries come first, so the unread one is last and
        // nothing is cut; moved ahead of them, it is.
        let mut entries = replay(
            &config(),
            mode,
            start(&[corp.clone(), central.clone()]),
            &build,
        );
        assert!(search(&entries, "1").unread.is_none());
        entries.rotate_right(1);
        let release = search(&entries, "1");
        assert!(release.before.is_empty());
        assert_eq!(
            release.unread.map(|entry| entry.repo.url.as_str()),
            Some("https://copy.example/")
        );
        let (others, found) = release.central.expect("central");
        assert_eq!(others, [corp]);
        assert_eq!(found.url, central.url);
        let mut snapshots = entries.clone();
        for entry in &mut snapshots {
            entry.repo.snapshots_enabled = true;
        }
        assert!(search(&snapshots, "1-SNAPSHOT").central.is_none());
        entries[0].displaced = true;
        assert!(search(&entries, "1").central.is_none());
    }

    /// One entry per id, an absent id counting as the empty one: a lineage
    /// declaration keeps the first, an interpolated one of an id seen before
    /// replaces it unless its id is absent.
    #[test]
    fn a_builds_repositories_are_kept_one_per_id() {
        let mut build = ModelBuild::default();
        add(
            &mut build,
            vec![
                repo(None, "https://first.example/"),
                repo(Some("a"), "https://a.example/"),
                repo(None, "https://second.example/"),
                repo(Some(""), "https://empty.example/"),
            ],
            false,
        );
        let mode = MavenMode::Maven39;
        assert_eq!(
            urls(&build, &[], mode),
            ["https://first.example/", "https://a.example/"]
        );
        add(
            &mut build,
            vec![
                repo(Some("a"), "https://a2.example/"),
                repo(None, "https://third.example/"),
            ],
            true,
        );
        assert_eq!(
            urls(&build, &[], mode),
            ["https://first.example/", "https://a2.example/"]
        );
        add(
            &mut build,
            vec![repo(Some(""), "https://empty2.example/")],
            true,
        );
        assert_eq!(
            urls(&build, &[], mode),
            ["https://a2.example/", "https://empty2.example/"]
        );
    }

    /// A dependency's interpolated declaration of a request id replaces the
    /// request's entry in Maven 3.9.12 and is dropped in 3.10.0.
    #[test]
    fn a_request_id_is_replaced_in_maven_39_only() {
        let request = [
            repo(Some("corp"), "https://corp.example/"),
            repo(Some("other"), "https://other.example/"),
        ];
        let mut build = ModelBuild::default();
        add(
            &mut build,
            vec![repo(Some("corp"), "https://corp.example/")],
            false,
        );
        add(
            &mut build,
            vec![repo(Some("corp"), "https://corp.example/")],
            true,
        );
        assert_eq!(
            urls(&build, &request, MavenMode::Maven39),
            ["https://other.example/", "https://corp.example/"]
        );
        assert_eq!(
            urls(&build, &request, MavenMode::Maven310),
            ["https://corp.example/", "https://other.example/"]
        );
    }
}
