//! The repository URLs Maven reads as a directory although they are no
//! absolute `file:` URL. Maven 3.9.12 and 3.10.0 read a relative `file:`
//! path, such as `file:repo`, under the directory `mvn` runs in. Maven
//! 3.10.0's file transporter also takes `symlink+` and `hardlink+` before a
//! `file:` URL, which only change how a deploy writes, and a URL without a
//! scheme or whose scheme is one uppercase letter, such as `C:/repo`, which
//! Resolver 2's `RepositoryUriUtils.toUri` reads as a path. `bundle:` names a zip file,
//! which Maven cannot read as a repository either.

use std::path::{Component, Path, PathBuf};

use rv_maven_types::MavenMode;

/// The `file:` URL of the directory Maven reads for `url` in `mode`, with a
/// relative path taken under `base`, the directory `mvn` runs in; `None`
/// for a URL Maven reads as written or does not read.
pub fn directory_url(url: &str, mode: MavenMode, base: &Path) -> Option<String> {
    let maven_310 = mode == MavenMode::Maven310;
    let (linked, rest) =
        match (url.strip_prefix("symlink+")).or_else(|| url.strip_prefix("hardlink+")) {
            Some(rest) if maven_310 => (true, rest),
            _ => (false, url),
        };
    let protocol = protocol(rest);
    let mut letters = protocol.chars();
    // One UTF-16 unit, as Java counts the scheme's length.
    let drive = (letters.next()).is_some_and(|letter| {
        letter.is_alphabetic() && letter.is_uppercase() && letter.len_utf16() == 1
    }) && letters.next().is_none();
    // Resolver 2 reads a URL without a scheme as a path too.
    if !(protocol == "file" || (maven_310 && (drive || protocol.is_empty()))) {
        return None;
    }
    let path = basedir(rest)?;
    let path = Path::new(without_separators_before_drive(&path));
    // A plain `file:` URL of an absolute path is read as written.
    if protocol == "file" && !linked && path.has_root() {
        return None;
    }
    Some(crate::directory_uri(&under(path, base)))
}

/// Why `url` may not serve as a repository, as a clause after "its URL",
/// when it is a `file:` URL that names a host other than `localhost`, such
/// as `file://server/share/repo` or `file://server/C:/repo`. Maven drops the
/// host and reads `/share/repo` on the drive it runs on, where raeva would
/// read the share or nothing. The host is read from the text, as Maven
/// reads it, not from a parsed URL. Tabs and line breaks are dropped first,
/// as the URL parser drops them. A host that holds a `${...}` raeva left as
/// written is refused for that input, such as `${user.dir}`, which Maven
/// expands to a path.
pub fn host_refusal(url: &str) -> Option<String> {
    let url: String = (url.chars())
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let url = url.trim_matches(|c: char| c <= ' ');
    if !url.get(..5)?.eq_ignore_ascii_case("file:") {
        return None;
    }
    let slash = |c: char| matches!(c, '/' | '\\');
    let authority = url[5..].strip_prefix(slash)?.strip_prefix(slash)?;
    let host = &authority[..authority
        .find(['/', '\\', '?', '#'])
        .unwrap_or(authority.len())];
    if let Some(start) = host.find("${") {
        let name = &authority[start + 2..];
        let name = &name[..name.find('}').unwrap_or(name.len())];
        return Some(unread_input_refusal(name));
    }
    // `localhost` in any case or encoding, and a drive such as `C:`, parse
    // to no host.
    let local = host.is_empty()
        || url::Url::parse(&format!("file://{host}/")).is_ok_and(|url| {
            url.host_str()
                .is_none_or(|host| host.is_empty() || host == "localhost")
        });
    (!local).then(|| {
        "is a file: URL with a host, which Maven reads as a path on this machine without the \
         host, and raeva does not read; give a local path or a file:/// URL"
            .to_string()
    })
}

/// The clause after "its URL" for a `${name}` that stayed as written.
fn unread_input_refusal(name: &str) -> String {
    let shown = rv_maven_types::bounded(name);
    let set = match name.strip_prefix("env.") {
        Some(variable) => format!(
            "set {} and list it in [security] allow_env_substitution in config.toml",
            rv_maven_types::bounded(variable)
        ),
        None => format!("define it in .mvn/maven.config or with -D{shown}=<value>"),
    };
    format!(
        "takes ${{{shown}}}, which raeva does not read; {set}, or give a local path or a \
         file:/// URL"
    )
}

/// Refuse a repository of `repositories`, as `kind` names them, whose URL,
/// as written or as the directory Maven reads, [`host_refusal`] refuses.
/// The URL is not shown, and the id only when `named`: an interpolated one
/// may hold a secret.
pub(crate) fn reject_hosts(
    kind: &str,
    repositories: &[crate::Repository],
    named: bool,
) -> Result<(), crate::PomError> {
    for repo in repositories {
        let urls = std::iter::once(&repo.url).chain(&repo.declared_url);
        let Some(refusal) = urls.into_iter().find_map(|url| host_refusal(url)) else {
            continue;
        };
        let entry = match repo.id.as_deref() {
            Some(id) if named => format!("{kind} '{}'", rv_maven_types::bounded(id)),
            None if named => format!("a {kind} without an id"),
            _ => format!("a {kind} the project or a parent POM declares"),
        };
        return Err(crate::PomError::InvalidProject(format!(
            "the URL of {entry} {refusal}"
        )));
    }
    Ok(())
}

/// `path` as `new File(path)` reads it in `base`: a relative one under it,
/// and on Windows one from the root on its drive, and `C:repo` under `base`
/// on its drive and under the drive's current directory on another.
fn under(path: &Path, base: &Path) -> PathBuf {
    let mut parts = path.components();
    match (base.components().next(), parts.next()) {
        _ if path.is_absolute() => path.to_path_buf(),
        (Some(Component::Prefix(at)), Some(Component::Prefix(named))) => {
            match drive(at).is_some() && drive(at) == drive(named) {
                true => base.join(parts.as_path()),
                false => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
            }
        }
        (Some(Component::Prefix(prefix)), _) if path.has_root() => {
            PathBuf::from(prefix.as_os_str()).join(path)
        }
        _ => base.join(path),
    }
}

fn drive(prefix: std::path::PrefixComponent<'_>) -> Option<u8> {
    match prefix.kind() {
        std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter) => {
            Some(letter.to_ascii_uppercase())
        }
        _ => None,
    }
}

/// On Windows, `path` from its drive on, as `new File` reads `/C:/repo`
/// as `C:\repo`.
fn without_separators_before_drive(path: &str) -> &str {
    let rest = path.trim_start_matches(['/', '\\']);
    let mut chars = rest.chars();
    let drive = (chars.next()).is_some_and(|letter| letter.is_ascii_alphabetic())
        && chars.next() == Some(':');
    match cfg!(windows) && drive {
        true => rest,
        false => path,
    }
}

/// Java's `String.trim`.
fn trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `RepositoryUriUtils.protocol`: the trimmed text before the first `:`.
fn protocol(url: &str) -> &str {
    url.find(':').map_or("", |at| trim(&url[..at]))
}

/// `RepositoryUriUtils.basedir`: the path `url` names, `None` where Maven
/// fails to read it, which skips the repository.
fn basedir(url: &str) -> Option<String> {
    let protocol = protocol(url);
    let rest: String = match protocol.is_empty() {
        true => url.to_string(),
        false => url.chars().skip(protocol.chars().count() + 1).collect(),
    };
    let mut path = decode(&rest)?;
    if let Some(after) = path.strip_prefix("//") {
        let mut host = after.to_string();
        if names_drive(&host) {
            host = with_drive(&host);
        } else {
            let slash = host.find('/');
            if let Some(at) = slash {
                host = host[at + 1..].to_string();
            }
            if names_drive(&host) {
                host = with_drive(&host);
            } else if slash.is_some() {
                host = format!("/{host}");
            }
        }
        path = host;
    }
    if path.chars().nth(1) == Some('|') {
        path = with_drive(&path);
    }
    Some(trim(&path).to_string())
}

fn names_drive(path: &str) -> bool {
    matches!(path.chars().nth(1), Some('|' | ':'))
}

fn with_drive(path: &str) -> String {
    let mut chars = path.chars();
    let letter = chars.next().unwrap_or_default();
    format!("{letter}:{}", chars.skip(1).collect::<String>())
}

/// `RepositoryUriUtils.decode`: each `%` and two hex digits read as the
/// character of that code, `None` where they are no number.
fn decode(text: &str) -> Option<String> {
    let mut chars: Vec<char> = text.chars().collect();
    let mut from = 0;
    while let Some(at) = (chars.iter().skip(from)).position(|&c| c == '%') {
        let at = at + from;
        from = at + 1;
        if at + 2 >= chars.len() {
            continue;
        }
        let hex: String = chars[at + 1..at + 3].iter().collect();
        let code = u8::from_str_radix(&hex, 16).ok()?;
        chars.splice(at..at + 3, [char::from(code)]);
    }
    Some(chars.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::{basedir, directory_url, host_refusal};
    use rv_maven_types::MavenMode;
    use std::path::Path;

    /// `RepositoryUriUtils.basedir` as Resolver 2.0.24 reads each form.
    #[test]
    fn basedir_reads_the_path_as_resolver_does() {
        for (url, path) in [
            ("C:/repo", "/repo"),
            ("C:\\repo", "\\repo"),
            ("C:repo", "repo"),
            ("C://host/share/repo", "/share/repo"),
            ("C:///D:/repo", "D:/repo"),
            ("C://D|/repo", "D:/repo"),
            ("C:/my%20repo", "/my repo"),
            ("C:/a%2", "/a%2"),
            ("file:///srv/repo", "/srv/repo"),
        ] {
            assert_eq!(basedir(url).as_deref(), Some(path), "{url}");
        }
        assert_eq!(basedir("C:/a%zz"), None);
    }

    #[test]
    fn a_file_url_with_a_host_is_refused() {
        for url in [
            "file://server/share/repo/",
            "FILE://server/share/",
            " file://127.0.0.1/repo/",
            "file://[::1]/repo/",
            "file://server/C:/repo/",
            "file://server",
            "fi\tle://server/share/",
            "file:\\\\server\\share\\",
            "file://${repo.host}/repo/",
        ] {
            assert!(host_refusal(url).is_some(), "{url}");
        }
        for (url, name) in [
            ("file://${user.dir}/repo/", "${user.dir}, which"),
            ("file://${env.REPO_DIR}/repo/", "${env.REPO_DIR}, which"),
            ("file://${undefined}${other}/repo/", "${undefined}, which"),
            ("file://x${repo.host}/repo/", "${repo.host}, which"),
        ] {
            let refusal = host_refusal(url).unwrap_or_default();
            assert!(
                refusal.starts_with(&format!("takes {name}")),
                "{url}: {refusal}"
            );
            assert!(!refusal.contains("with a host"), "{url}: {refusal}");
        }
        assert!(
            host_refusal("file://server/repo/")
                .unwrap()
                .contains("file: URL with a host")
        );
        assert_eq!(host_refusal("file:///${user.dir}/repo/"), None);
        for url in [
            "file:///srv/repo/",
            "file://localhost/srv/repo/",
            "file://LOCALHOST/srv/repo/",
            "file://local%68ost/srv/repo/",
            "file://C:/repo/",
            "file://C:\\Users\\me/repo/",
            "file://C|/repo/",
            "file:////server/share/",
            "file:",
            "file:/srv/repo/",
            "https://server/repo/",
            "symlink+file://server/share/",
        ] {
            assert_eq!(host_refusal(url), None, "{url}");
        }
    }

    #[test]
    fn maven_reads_these_urls_as_directories() {
        let base = std::env::current_dir().unwrap().join("project");
        let read = |url: &str, mode| directory_url(url, mode, &base);
        let under = |dir: &str| Some(crate::directory_uri(&base.join(dir)));
        let (maven_39, maven_310) = (MavenMode::Maven39, MavenMode::Maven310);
        for mode in [maven_39, maven_310] {
            assert_eq!(read("file:repo", mode), under("repo"), "{mode:?}");
            assert_eq!(read("file:./repo", mode), under("./repo"), "{mode:?}");
            for url in [
                "file:///srv/repo",
                "file:/srv/repo",
                "https://repo.example/",
                "symlink+https://repo.example/",
                "bundle:file:///srv/repo.zip",
                "c:/repo",
                "CD:/repo",
                // One letter, but two UTF-16 units to Java.
                "\u{1D400}:/srv/repo",
            ] {
                assert_eq!(read(url, mode), None, "{url} {mode:?}");
            }
        }
        for url in ["symlink+file:///srv/repo", "C:/srv/repo", "C:repo", "repo"] {
            assert_eq!(read(url, maven_39), None, "{url}");
        }
        assert_eq!(read("C:repo", maven_310), under("repo"));
        assert_eq!(read("repo", maven_310), under("repo"));
        assert_eq!(read("symlink+file:repo", maven_310), under("repo"));
        let srv = Some(crate::directory_uri(Path::new(if cfg!(windows) {
            "C:\\srv\\repo"
        } else {
            "/srv/repo"
        })));
        #[cfg(unix)]
        {
            assert_eq!(read("symlink+file:///srv/repo", maven_310), srv);
            assert_eq!(read("hardlink+file:/srv/repo", maven_310), srv);
            assert_eq!(read("C:/srv/repo", maven_310), srv);
            assert_eq!(read("/srv/repo", maven_310), srv);
            assert_eq!(read("hardlink+C:/srv/repo", maven_310), srv);
            assert_eq!(read("C:\\srv\\repo", maven_310), under("\\srv\\repo"));
            let nested = read("file:repo\\nested", maven_39).unwrap();
            assert!(nested.ends_with("/project/repo%5Cnested/"), "{nested}");
        }
        #[cfg(windows)]
        {
            // As `new File("/srv/repo")`, on the drive `mvn` runs on,
            // whatever letter the URL names.
            let drive = base.to_str().unwrap().chars().next().unwrap();
            let on_drive = Some(crate::directory_uri(Path::new(&format!(
                "{drive}:\\srv\\repo"
            ))));
            for url in ["C:/srv/repo", "C:\\srv\\repo", "Z:/srv/repo"] {
                assert_eq!(read(url, maven_310), on_drive, "{url}");
            }
            // The forms Maven 3.10.0 read on a Windows host.
            for url in [
                "symlink+file:///C:/x07/fix/r2",
                "hardlink+file:///C:/x07/fix/r2",
                "symlink+file:/C:/x07/fix/r2",
                "hardlink+file:\\C:\\x07\\fix\\r2",
            ] {
                let plain = Some(crate::directory_uri(Path::new("C:\\x07\\fix\\r2")));
                assert_eq!(read(url, maven_310), plain, "{url}");
            }
            assert_eq!(read("file:///C:/x07/fix/r2", maven_310), None);
            // `/C:` and `/C:repo` on the drive `mvn` runs on: its directory.
            let base_dir = Some(crate::directory_uri(&base));
            assert_eq!(
                read(&format!("symlink+file:/{drive}:"), maven_310),
                base_dir
            );
            for url in [
                format!("symlink+file:/{drive}:repo"),
                format!("file:{drive}:repo"),
            ] {
                assert_eq!(read(&url, maven_310), under("repo"), "{url}");
            }
            let _ = srv;
        }
    }
}
