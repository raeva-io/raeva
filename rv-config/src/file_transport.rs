//! The settings.xml URLs Maven reads as a directory although they are no
//! absolute `file:` URL; see [`rv_maven_model::file_transport`].

use std::path::Path;

use rv_maven_types::MavenMode;

use crate::maven_settings::MavenSettings;

/// The settings.xml repositories, plugin repositories and mirrors of
/// `settings` with each URL Maven reads as a directory in `mode` written as
/// that directory's `file:` URL, a relative one under `base`, the directory
/// `mvn` runs in. Each keeps the URL as written for mirror matching and
/// repository filters, where Maven still reads it.
pub(crate) fn read_directories(settings: &mut MavenSettings, mode: MavenMode, base: &Path) {
    let read = |url: &str| rv_maven_model::file_transport::directory_url(url, mode, base);
    let repositories = (settings.profiles.iter_mut().flatten()).flat_map(|profile| {
        (profile.repositories.iter_mut()).chain(&mut profile.plugin_repositories)
    });
    for repository in repositories {
        if let Some(url) = read(&repository.url) {
            repository.declared_url = Some(std::mem::replace(&mut repository.url, url));
        }
    }
    for mirror in settings.mirrors.iter_mut().flatten() {
        if let Some(url) = read(&mirror.url) {
            crate::redact::register_moved_url(&mirror.url, &url);
            mirror.declared_url = Some(std::mem::replace(&mut mirror.url, url));
        }
    }
}
