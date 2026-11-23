//! The first pass over raeva's raw inputs, which registers every secret
//! they hold ([`crate::register_secret`]) before anything reads them for
//! what they mean: a parse or validation error or a warning may quote any
//! of them. It reads the command line, the JVM option
//! variables, the mavenrc files, `.mvn/jvm.config` and `.mvn/maven.config`,
//! the option files those name, `raeva.toml`, `config.toml`, and the
//! settings files raeva may read, and tolerates any of them malformed.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use rv_maven_model::mavenrc::Shell;

use crate::redact::{option_secrets, register_named_secret, register_secret, secret_named};

/// The variables whose `-D` options `mvn`, `mvn.cmd`, a Maven Wrapper
/// script or a JVM reads.
const JVM_OPTION_VARIABLES: [&str; 9] = [
    "MAVEN_OPTS",
    "MAVEN_DEBUG_OPTS",
    "MAVEN_ARGS",
    "MAVEN_CONFIG",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "OPENJ9_JAVA_OPTIONS",
    "IBM_JAVA_OPTIONS",
];

/// The largest option file raeva reads, which bounds what it holds in memory.
const MAX_OPTION_FILE: u64 = 64 * 1024 * 1024;

/// The elements of a settings file whose text is a credential.
const CREDENTIALS: [&str; 4] = ["password", "passphrase", "privateKey", "master"];

/// Register the secrets of raeva's command line `args`, without the
/// program name, and of every input it names or raeva reads.
pub fn prime_secrets(args: &[String]) {
    register_argument_secrets(args);
    let value = |names: &[&str]| -> Vec<&str> {
        let mut values = Vec::new();
        for (at, arg) in args.iter().enumerate() {
            for name in names {
                if arg == name {
                    values.extend(args.get(at + 1).map(String::as_str));
                } else if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
                    values.push(value);
                } else if name.len() == 2
                    && let Some(value) = arg.strip_prefix(name).filter(|v| !v.is_empty())
                {
                    values.push(value);
                }
            }
        }
        values
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    let roots = value(&["-C", "--project-root"]);
    let root = roots.last().map_or(cwd.clone(), |root| cwd.join(root));
    let settings: Vec<PathBuf> = (value(&["-s", "--settings"]).into_iter())
        .map(|path| cwd.join(path))
        .collect();
    let defines = defines(args);
    if let Ok(paths) = crate::paths::ResolvedPaths::discover() {
        rv_maven_model::mavenrc::use_script_home(paths.cache_dir);
    }
    // The mavenrc files read as everything after reads them, or, where
    // they fail, which the configuration then refuses, read as text below.
    let shell = Shell::capture_anywhere(&root).unwrap_or_else(|_| Shell::process());
    let (homes, named) = prime_project(&root, &defines, &shell);
    let settings: Vec<PathBuf> = settings.into_iter().chain(named).collect();
    // The JVM option variables' `-D` values are system properties too, which
    // a settings credential may take a part of.
    let mut properties = jvm_defines(&shell);
    properties.extend(defines);
    prime_settings(homes, &properties, &settings, &shell);
}

/// The `-D` values (`name=value`) of the JVM option variables in `shell`,
/// words as the JVM reads them.
fn jvm_defines(shell: &Shell) -> Vec<String> {
    let mut defines = Vec::new();
    for name in [
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "MAVEN_OPTS",
        "MAVEN_DEBUG_OPTS",
        "_JAVA_OPTIONS",
    ] {
        let value = match name {
            "MAVEN_OPTS" | "MAVEN_DEBUG_OPTS" => shell.shell_value(name),
            _ => shell.exported(name),
        };
        let words = value.and_then(|value| crate::jvm_options::jvm_words(&value));
        for word in words.unwrap_or_default() {
            if let Some(define) = word.strip_prefix(b"-D") {
                defines.push(String::from_utf8_lossy(define).into_owned());
            }
        }
    }
    defines
}

/// Register the secrets of the JVM options and project files a
/// configuration for `project_root` reads, with the command line's `-D`
/// values `defines` (`name=value`). Returns the Maven user homes they name,
/// and the settings files their `-s` options name.
pub(crate) fn prime_project(
    project_root: &Path,
    defines: &[String],
    shell: &Shell,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut homes: Vec<PathBuf> = Vec::new();
    let mut settings: Vec<PathBuf> = Vec::new();
    let mut root = project_root.to_path_buf();
    let mut texts: Vec<String> = Vec::new();
    // The JVM reads a relative option file from where `mvn` runs, as the
    // reader does.
    let working_dir = std::env::current_dir().unwrap_or_else(|_| project_root.to_path_buf());
    // What the mavenrc files leave in a variable named like a secret.
    let unexported = (shell.unexported()).map(|(name, value)| (OsStr::new(name), value));
    for (name, value) in shell.exported_env().chain(unexported) {
        let name = name.to_string_lossy();
        if secret_named(&name) && shell.changing(&name).is_some() {
            register_named_secret(&value.to_string_lossy());
        }
    }
    texts.extend(option_variables(shell));
    texts
        .extend((rv_maven_model::mavenrc_paths().iter()).filter_map(|path| read_option_file(path)));
    // The `.mvn` the configuration reads, which fails where this does.
    if let Ok(mvn) = crate::config::launcher_mvn_dir(project_root, shell) {
        root = mvn.parent().map_or(root, Path::to_path_buf);
        texts.extend(read_option_file(&mvn.join("jvm.config")));
        texts.extend(read_option_file(&mvn.join("maven.config")));
    }
    for dir in project_root.ancestors() {
        if let Some(text) = read_option_file(&dir.join("raeva.toml")) {
            register_toml_secrets(&text);
        }
    }
    if let Ok(paths) = crate::paths::ResolvedPaths::discover()
        && let Some(text) = read_option_file(&paths.config_file_path())
    {
        register_toml_secrets(&text);
    }
    // The option files these name, and those an argument file names in
    // turn, such as a VM options file.
    let mut seen = std::collections::HashSet::new();
    let mut next = 0;
    for _ in 0..3 {
        let named: Vec<PathBuf> = (texts[next..].iter())
            .flat_map(|text| {
                (option_files(&readings(text, shell)).into_iter())
                    .map(|file| working_dir.join(file))
            })
            .collect();
        next = texts.len();
        for file in named.into_iter().filter(|file| seen.insert(file.clone())) {
            texts.extend(read_option_file(&file));
        }
    }
    for text in &texts {
        for value in option_secrets(text, &|name| exported(shell, name)) {
            register_named_secret(&value);
        }
        let words = readings(text, shell);
        register_argument_secrets(&words);
        homes.extend(user_homes(&words));
        settings.extend(settings_files(&words, &root));
    }
    let defines: Vec<String> = defines.iter().map(|define| format!("-D{define}")).collect();
    homes.extend(user_homes(&defines));
    (homes, settings)
}

/// The settings files the `-s` options of `words` name, in `.mvn/maven.config`
/// or `MAVEN_ARGS`, relative ones and Maven's root directory expressions taken
/// from `root`.
fn settings_files(words: &[String], root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut words = words.iter();
    while let Some(word) = words.next() {
        let value = match word.as_str() {
            "-s" | "--settings" => words.next().cloned(),
            _ => (word
                .strip_prefix("--settings=")
                .or_else(|| word.strip_prefix("-s")))
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        };
        if let Some(value) = value {
            let root_text = root.to_string_lossy();
            let value = value
                .replace("${session.rootDirectory}", &root_text)
                .replace("${maven.multiModuleProjectDirectory}", &root_text);
            files.push(root.join(value));
        }
    }
    files
}

/// Register the credentials of the settings files raeva may read: `-s`
/// files `settings`, and those of the Maven user homes `homes`, `HOME`,
/// `USERPROFILE` and the Maven installation, with the command line's `-D`
/// values `defines` (`name=value`) for their `${...}`.
pub(crate) fn prime_settings(
    mut homes: Vec<PathBuf>,
    defines: &[String],
    settings: &[PathBuf],
    shell: &Shell,
) {
    homes.extend(std::env::var_os("HOME").map(PathBuf::from));
    homes.extend(std::env::var_os("USERPROFILE").map(PathBuf::from));
    let lookup = |name: &str| {
        (defines.iter())
            .rev()
            .find_map(|define| define.strip_prefix(name)?.strip_prefix('='))
            .map(str::to_string)
            .or_else(|| exported(shell, name.strip_prefix("env.").unwrap_or(name)))
    };
    let mut security: Vec<PathBuf> = homes
        .iter()
        .map(|home| home.join(".m2/settings-security.xml"))
        .collect();
    security.extend(lookup("settings.security").map(PathBuf::from));
    let masters: Vec<String> = (security.iter())
        .filter_map(|path| read_option_file(path))
        .flat_map(|text| register_credential_text(&text, &[], &lookup))
        .collect();
    let mut files: Vec<PathBuf> = settings.to_vec();
    files.extend(homes.iter().map(|home| home.join(".m2/settings.xml")));
    for home in ["MAVEN_HOME", "M2_HOME"]
        .iter()
        .filter_map(std::env::var_os)
    {
        files.push(PathBuf::from(home).join("conf/settings.xml"));
    }
    for file in files {
        if let Some(text) = read_option_file(&file) {
            register_credential_text(&text, &masters, &lookup);
        }
    }
}

/// The `name=value` of each `-D` option of `args`.
fn defines(args: &[String]) -> Vec<String> {
    let mut defines = Vec::new();
    for (at, arg) in args.iter().enumerate() {
        if arg == "-D" || arg == "--define" {
            defines.extend(args.get(at + 1).cloned());
        } else if let Some(define) = arg.strip_prefix("--define=").or(arg.strip_prefix("-D")) {
            defines.push(define.to_string());
        }
    }
    defines
}

/// Register the secret-named `-D` values of `args`, words as a program
/// gets them: each whole, a quote in it included, and each word of one with
/// white space, as a program that splits its arguments again shows it.
pub(crate) fn register_argument_secrets(args: &[String]) {
    for define in defines(args) {
        let Some((name, value)) = define.split_once('=') else {
            continue;
        };
        if secret_named(&name.replace(['"', '\''], "")) {
            register_named_secret(value);
            register_named_secret(value.trim_matches(['"', '\'']));
            if value.trim().contains(char::is_whitespace) {
                value.split_whitespace().for_each(register_named_secret);
            }
        }
    }
}

/// Register the `-D` values of `text`, a TOML file such as `raeva.toml`
/// whose `[plugins] trace` holds a build's arguments: its strings, in
/// order, read as arguments, or, when it does not parse, the text between
/// each pair of quotes.
fn register_toml_secrets(text: &str) {
    fn strings(value: &toml::Value, out: &mut Vec<String>) {
        match value {
            toml::Value::String(text) => out.push(text.clone()),
            toml::Value::Array(values) => values.iter().for_each(|value| strings(value, out)),
            toml::Value::Table(table) => table.values().for_each(|value| strings(value, out)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    match text.parse::<toml::Table>() {
        Ok(table) => table.values().for_each(|value| strings(value, &mut found)),
        Err(_) => {
            let mut rest = text;
            while let Some(at) = rest.find(['"', '\'']) {
                let quote = rest.as_bytes()[at] as char;
                let after = &rest[at + 1..];
                let Some(end) = after.find(quote) else {
                    break;
                };
                found.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
        }
    }
    register_argument_secrets(&found);
}

/// The argument files (`@file`) and VM options files (`-XX:VMOptionsFile=`)
/// `words` name.
fn option_files(words: &[String]) -> Vec<String> {
    (words.iter())
        .filter_map(|word| {
            let file = (word.strip_prefix('@').filter(|file| !file.starts_with('@')))
                .or_else(|| word.strip_prefix("-XX:VMOptionsFile="))?;
            (!file.is_empty()).then(|| file.to_string())
        })
        .collect()
}

/// The words of `text`, JVM options or a shell or batch script that sets
/// them, in each reading a program that takes them may give: split at white
/// space with the quotes kept, as `mvn` splits `$MAVEN_OPTS` and
/// `.mvn/jvm.config`; with the quotes removed, as HotSpot reads
/// `JAVA_TOOL_OPTIONS` and a VM options file; with a shell's escapes too;
/// as the java launcher reads an argument file and `JDK_JAVA_OPTIONS`; and
/// a shell or batch assignment's value split again, with its variables
/// expanded from the assignments of `text` and the environment.
fn readings(text: &str, shell: &Shell) -> Vec<String> {
    let mut words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    words.extend(quoted_words(text, false));
    words.extend(quoted_words(text, true));
    words.extend(argument_file_words(text));
    let split: Vec<String> = (words.iter())
        .filter(|word| word.contains(char::is_whitespace))
        .flat_map(|word| word.split_whitespace().map(str::to_string))
        .collect();
    words.extend(split);
    let expanded: Vec<String> = (words.iter())
        .filter(|word| word.contains(['$', '%']))
        .map(|word| expand_variables(word, text, shell))
        .collect();
    words.extend(expanded);
    let mut seen = std::collections::HashSet::new();
    words.retain(|word| seen.insert(word.clone()));
    words
}

/// The words of `text` split at white space outside quotes, with the quotes
/// removed, and with `shell`, a backslash escaping the next character as
/// `sh` reads it.
fn quoted_words(text: &str, shell: bool) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some('"') | None, '\\') if shell => {
                if let Some(next) = chars.next() {
                    let kept = quote.is_none() || matches!(next, '"' | '\\' | '$' | '`');
                    if !kept {
                        word.push('\\');
                    }
                    word.push(next);
                }
            }
            (Some(_), c) => word.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                started = false;
            }
            (None, c) => word.push(c),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

/// The words of `text` as the java launcher reads an argument file: split
/// at white space outside quotes and at each line end, with the quotes
/// removed, the escapes `\n`, `\r`, `\t`, `\f` and of any other character in
/// quotes decoded, a backslash before a line end in quotes joining the next
/// line without its leading white space, and a `#` outside quotes starting a
/// comment to the line end.
fn argument_file_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = text.chars().peekable();
    let end = |word: &mut String, started: &mut bool, words: &mut Vec<String>| {
        if *started || !word.is_empty() {
            words.push(std::mem::take(word));
        }
        *started = false;
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (_, '\n' | '\r') => {
                quote = None;
                end(&mut word, &mut started, &mut words);
            }
            (Some(open), c) if c == open => quote = None,
            (Some(_), '\\') => match chars.next() {
                Some('n') => word.push('\n'),
                Some('r') => word.push('\r'),
                Some('t') => word.push('\t'),
                Some('f') => word.push('\u{c}'),
                Some('\n' | '\r') => while chars.next_if(|c| c.is_whitespace()).is_some() {},
                Some(other) => word.push(other),
                None => {}
            },
            (Some(_), c) => word.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, '#') => {
                end(&mut word, &mut started, &mut words);
                while chars.next_if(|c| !matches!(c, '\n' | '\r')).is_some() {}
            }
            (None, c) if c.is_whitespace() => end(&mut word, &mut started, &mut words),
            (None, c) => word.push(c),
        }
    }
    end(&mut word, &mut started, &mut words);
    words
}

/// `word` with each `$NAME`, `${NAME}` and `%NAME%` replaced by its value
/// as `shell`, the mavenrc files as `mvn` sources them, gives it, or where
/// it cannot tell, as an assignment in `text` (`NAME=value`, `export
/// NAME=value`, `set NAME=value` or `set "NAME=value"`) or the environment
/// answers it.
fn expand_variables(word: &str, text: &str, shell: &Shell) -> String {
    // As `mvn` holds it, where raeva reads the mavenrc files that may set
    // it; else as `text` last assigns it, or this process has it.
    let value = |name: &str| {
        (shell.shell_value(name).map(lossy))
            .or_else(|| assigned(text, name).into_iter().next_back())
            .or_else(|| std::env::var(name).ok())
    };
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut rest = word;
    while let Some(at) = rest.find(['$', '%']) {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, used) = if rest[at..].starts_with('%') {
            match after.find('%') {
                Some(end) if end > 0 && after[..end].chars().all(is_name) => {
                    (&after[..end], end + 1)
                }
                _ => ("", 0),
            }
        } else if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => (&braced[..end], end + 2),
                None => ("", 0),
            }
        } else {
            let end = after.find(|c| !is_name(c)).unwrap_or(after.len());
            (&after[..end], end)
        };
        match value(name).filter(|_| !name.is_empty()) {
            Some(value) => out.push_str(&value),
            None => out.push_str(&rest[at..at + 1 + used]),
        }
        rest = &after[used..];
    }
    out.push_str(rest);
    out
}

/// The values of [`JVM_OPTION_VARIABLES`] as `mvn` holds them once it has
/// sourced the mavenrc files `shell` read, and as this process has them.
fn option_variables(shell: &Shell) -> Vec<String> {
    let mut texts = Vec::new();
    for name in JVM_OPTION_VARIABLES {
        let after = shell.shell_value(name).map(lossy);
        let before = std::env::var(name)
            .ok()
            .filter(|text| after.as_ref() != Some(text));
        texts.extend(after.into_iter().chain(before));
    }
    texts
}

/// `value`, a variable's bytes, as text.
fn lossy(value: Vec<u8>) -> String {
    String::from_utf8_lossy(&value).into_owned()
}

/// The variable `name` in the environment of the JVM `mvn` starts.
fn exported(shell: &Shell, name: &str) -> Option<String> {
    shell.exported(name).map(lossy)
}

/// The values `text`, a shell or batch script, assigns the variable `name`,
/// in order: `NAME=value` and `export NAME=value` to the first unquoted
/// white space or `;`, a quoted value whole, `set NAME=value` to the line
/// end, and `set "NAME=value"` to the last quote.
fn assigned(text: &str, name: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim_start().trim_start_matches('@');
        let batch = (line.get(..4))
            .filter(|set| set.eq_ignore_ascii_case("set "))
            .map(|_| line[4..].trim_start());
        if let Some(rest) = batch {
            let (rest, quoted) = match rest.strip_prefix('"') {
                Some(rest) => (&rest[..rest.rfind('"').unwrap_or(rest.len())], true),
                None => (rest, false),
            };
            if let Some((assigned, value)) = rest.split_once('=')
                && assigned.eq_ignore_ascii_case(name)
            {
                let value = if quoted { value } else { value.trim_end() };
                values.push(value.to_string());
            }
            continue;
        }
        for word in quoted_words(line, true) {
            let word = word.strip_prefix("export ").unwrap_or(&word);
            if let Some(value) = word
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
            {
                values.push(value.to_string());
            }
        }
    }
    values
}

/// The `-Duser.home` values of `words`: Maven user homes whose settings
/// raeva may read.
fn user_homes(words: &[String]) -> Vec<PathBuf> {
    (words.iter())
        .filter_map(|word| word.strip_prefix("-Duser.home=").map(PathBuf::from))
        .collect()
}

/// The text of `path` when it is a regular file of at most 64 MiB: a FIFO
/// or device would block or stream, and raeva only looks.
pub(crate) fn read_option_file(path: &Path) -> Option<String> {
    read_option_bytes(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// [`read_option_file`] as bytes.
pub(crate) fn read_option_bytes(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_OPTION_FILE {
        return None;
    }
    let mut bytes = Vec::new();
    (std::fs::File::open(path).ok()?)
        .take(MAX_OPTION_FILE)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Register the credentials of `xml`, a settings or settings-security file
/// that may not parse: the text of each credential element and of each
/// `Authorization` header value, as written, with its entities decoded, with
/// its `${...}` expanded by `lookup`, and decrypted with each of `masters`
/// or `settings.security`. Returns the master passwords it holds, decrypted.
pub(crate) fn register_credential_text(
    xml: &str,
    masters: &[String],
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut found = Vec::new();
    let mut texts: Vec<(&str, String)> = (CREDENTIALS.iter())
        .flat_map(|name| {
            element_texts(xml, name)
                .into_iter()
                .map(move |text| (*name, text))
        })
        .collect();
    // An `Authorization` header's value follows its name.
    for (at, _) in xml.match_indices("Authorization") {
        if let Some(text) = element_texts(&xml[at..], "value").into_iter().next() {
            texts.push(("value", text));
        }
    }
    for (element, text) in texts {
        let decoded = decode_entities(&text);
        let mut spellings = vec![text.clone(), decoded.clone()];
        let (expanded, read) = expand(&decoded, lookup);
        spellings.extend(read);
        spellings.push(expanded);
        let mut plain = Vec::new();
        for spelling in &spellings {
            register_secret(spelling);
            if crate::encryption::is_encrypted(spelling) {
                let keys = (masters.iter().map(String::as_str)).chain(["settings.security"]);
                for key in keys {
                    plain.extend(crate::encryption::decrypt_maven_password(spelling, key));
                }
            }
        }
        for value in &plain {
            register_secret(value);
        }
        if element == "master" {
            found.extend(
                spellings
                    .into_iter()
                    .filter(|s| !crate::encryption::is_encrypted(s)),
            );
            found.extend(plain);
        }
    }
    found
}

/// The text of each `<name>` element of `xml`, with a namespace prefix,
/// white space or attributes in its tag too, and a CDATA section's content.
fn element_texts(xml: &str, name: &str) -> Vec<String> {
    let mut texts = Vec::new();
    for (at, _) in xml.match_indices(name) {
        let before = &xml[..at];
        let prefix =
            before.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || "_.-:".contains(c));
        if !prefix.ends_with('<') || before[prefix.len()..].contains(['<', '>']) {
            continue;
        }
        let tag = &xml[at + name.len()..];
        if !tag.starts_with(|c: char| c.is_whitespace() || c == '>') {
            continue;
        }
        let Some(end) = tag.find('>') else {
            continue;
        };
        if tag[..end].ends_with('/') {
            continue;
        }
        let content = &tag[end + 1..];
        let text = match content.strip_prefix("<![CDATA[") {
            Some(cdata) => &cdata[..cdata.find("]]>").unwrap_or(cdata.len())],
            None => &content[..content.find('<').unwrap_or(content.len())],
        };
        texts.push(text.trim().to_string());
    }
    texts
}

/// `text` with the XML entities Maven's reader knows decoded.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let Some(end) = after.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = after;
            continue;
        };
        let entity = &after[..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => (entity.strip_prefix("#x").or(entity.strip_prefix("#X")))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#')?.parse().ok())
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `text` with each `${name}` `lookup` answers replaced, and the values it
/// read.
fn expand(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut read = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[at..]);
            return (out, read);
        };
        let name = rv_maven_types::expression_key(&after[..end]);
        match lookup(name) {
            Some(value) => {
                out.push_str(&value);
                read.push(value);
            }
            None => out.push_str(&rest[at..at + 3 + end]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    (out, read)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shell of this process, which reads a mavenrc file's
    /// assignments from its text.
    fn sourcing(_text: &str, _batch: bool) -> Shell {
        Shell::process()
    }

    /// [`readings`] of `text` as a mavenrc file.
    fn reads(text: &str) -> Vec<String> {
        readings(text, &sourcing(text, false))
    }

    /// The options a mavenrc file leaves, as the shell that sourced it
    /// holds them, unexported too.
    #[test]
    fn options_are_read_as_the_shell_leaves_them() {
        let opts = "-Dapi.token=zqSECRETzq -Duser.home=zqSECRETzq/x";
        let shell = Shell::for_testing(&["/etc/mavenrc"], &[], &[], &[("MAVEN_OPTS", opts)]);
        let words: Vec<String> = (option_variables(&shell).iter())
            .flat_map(|text| readings(text, &shell))
            .collect();
        for word in ["-Dapi.token=zqSECRETzq", "-Duser.home=zqSECRETzq/x"] {
            assert!(words.iter().any(|w| w == word), "{word}: {words:?}");
        }
    }

    #[test]
    fn words_drop_quotes_and_keep_a_quoted_space() {
        assert_eq!(
            quoted_words("-XX:VMOptionsFile=\"/a b\" @'c d' e", false),
            ["-XX:VMOptionsFile=/a b", "@c d", "e"]
        );
        let words = readings("@x @@y -XX:VMOptionsFile=\"/a b\"", &sourcing("", false));
        let files = option_files(&words);
        assert!(files.contains(&"x".to_string()) && files.contains(&"/a b".to_string()));
        assert!(!files.iter().any(|file| file.starts_with('@')), "{files:?}");
    }

    #[test]
    fn readings_take_each_program_s_quoting() {
        let has = |text: &str, word: &str| reads(text).iter().any(|w| w == word);
        // `mvn` keeps the quotes of `$MAVEN_OPTS`.
        assert!(has("-Da.token=zqP'Wzq", "-Da.token=zqP'Wzq"));
        assert!(has("-Da.token=zq\"DQ\"zq", "-Da.token=zq\"DQ\"zq"));
        // The java launcher's argument file.
        let file = concat!(
            "-Db.token=zq\"ARG CAT\"zq\n",
            "-Dc.token=\"zqT\\tzq\"\n",
            "-Dd.token=\"zqE\\\"zq\"\n",
            "-De.token=zqH#zq\n",
            "-Df.token=\"zqL1\\\n   L2zq\"\n",
        );
        for word in [
            "-Db.token=zqARG CATzq",
            "-Dc.token=zqT\tzq",
            "-Dd.token=zqE\"zq",
            "-De.token=zqH",
            "-Df.token=zqL1L2zq",
        ] {
            assert!(has(file, word), "{word}: {:?}", reads(file));
        }
        // A shell's escape, and an assignment's value split again.
        let rc = "V=zqM1zq\nMAVEN_OPTS=\"$MAVEN_OPTS -Dm.token=$V -Dn.token=zqM5\\\"Qzq\"";
        assert!(has(rc, "-Dm.token=zqM1zq"), "{:?}", reads(rc));
        assert!(has(rc, "-Dn.token=zqM5\"Qzq"), "{:?}", reads(rc));
        // A batch file's.
        let bat =
            "set V=zqWzq\nset \"Q=zqQzq\"\nset MAVEN_OPTS=%MAVEN_OPTS% -Dw.token=%V% -Dq.token=%Q%";
        for batch in [false, true] {
            let words = readings(bat, &sourcing(bat, batch));
            assert!(words.iter().any(|w| w == "-Dw.token=zqWzq"), "{words:?}");
            assert!(words.iter().any(|w| w == "-Dq.token=zqQzq"), "{words:?}");
        }
        // `$HOME` in an argument file's path, left as written where `HOME`
        // is unset, as on Windows.
        let home = std::env::var("HOME").unwrap_or_else(|_| "$HOME".to_string());
        assert!(has(
            "MAVEN_OPTS=\"$MAVEN_OPTS @$HOME/jvm.opts\"",
            &format!("@{home}/jvm.opts")
        ));
    }

    #[test]
    fn credential_text_is_read_from_any_tag_spelling() {
        let xml = "<s:password a='1'>zqAzq</zqAzq><passphrase >zqB&#10;zqB</passphrase>\
                   <privateKey><![CDATA[zqC]]></privateKey><password/><masterx>no</masterx>";
        assert_eq!(element_texts(xml, "password"), ["zqAzq"]);
        assert_eq!(element_texts(xml, "passphrase"), ["zqB&#10;zqB"]);
        assert_eq!(element_texts(xml, "privateKey"), ["zqC"]);
        assert!(element_texts(xml, "master").is_empty());
        assert_eq!(
            decode_entities("zqB&#10;zqB&amp;&#x41;&bad"),
            "zqB\nzqB&A&bad"
        );
        let lookup = |name: &str| (name == "env.V").then(|| "zqVzq".to_string());
        assert_eq!(
            expand("a${env.V}b${W}", &lookup),
            ("azqVzqb${W}".to_string(), vec!["zqVzq".to_string()])
        );
    }

    #[test]
    fn an_option_file_that_is_not_a_regular_file_is_not_read() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(read_option_file(dir.path()), None);
        let file = dir.path().join("f");
        std::fs::write(&file, "-Dx=y").unwrap();
        assert_eq!(read_option_file(&file).as_deref(), Some("-Dx=y"));
    }
}
