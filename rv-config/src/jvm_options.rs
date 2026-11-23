//! The `-D` options Maven's JVM takes from every channel `mvn`, `mvn.cmd`
//! and the java launcher read, in the order the JVM reads them, and the
//! names raeva cannot read exactly there.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::ConfigError;
use crate::user_home::Host;

/// The JVM variables HotSpot reads (`JAVA_TOOL_OPTIONS` before its command
/// line, `_JAVA_OPTIONS` after it) and the one the java launcher reads
/// before it (`JDK_JAVA_OPTIONS`, JDK 9 and later).
pub(crate) const JVM_VARIABLES: [&str; 3] =
    ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"];

/// The variables only OpenJ9 reads.
const OPENJ9_VARIABLES: [&str; 2] = ["OPENJ9_JAVA_OPTIONS", "IBM_JAVA_OPTIONS"];

/// The channel `.mvn/jvm.config` is named as.
pub(crate) const JVM_CONFIG: &str = ".mvn/jvm.config";

/// How a channel's text becomes the JVM's options.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Split {
    /// `mvn`'s unquoted `$MAVEN_OPTS`: words at `IFS`, which the shell may
    /// glob, each a command-line argument.
    Shell,
    /// `.mvn/jvm.config` as `mvn` passes it.
    JvmConfig,
    /// A variable HotSpot reads, split at C white space.
    Jvm,
    /// `JDK_JAVA_OPTIONS`, split as HotSpot splits its variables, which
    /// may name argument files.
    Launcher,
}

impl Split {
    /// Whether the java launcher expands an `@file` word there.
    fn argument_files(self) -> bool {
        self != Self::Jvm
    }
}

/// The `-D` value a channel gave a name, the last the JVM read.
#[derive(Debug, Clone)]
pub(crate) struct Define {
    /// The value as the JVM gets it, which may not be UTF-8.
    pub(crate) value: Vec<u8>,
    /// The channel it came from, such as `MAVEN_OPTS`.
    pub(crate) channel: &'static str,
}

/// What Maven's JVM takes from its option channels.
#[derive(Debug, Default)]
pub(crate) struct JvmOptions {
    defines: HashMap<String, Define>,
    /// The `-D` values of `.mvn/jvm.config` and the option files it names,
    /// each as the JVM reads it there whatever a later channel sets, a
    /// value the shell may glob as written.
    jvm_config: HashMap<String, String>,
    /// The names a later channel may set in a way raeva does not read,
    /// with the channel and why, `{name}` standing for the name.
    unread: HashMap<String, (String, String)>,
}

impl JvmOptions {
    /// The last `-D` value of `name` the JVM read.
    pub(crate) fn define(&self, name: &str) -> Option<&Define> {
        self.defines.get(name)
    }

    /// Why raeva cannot tell the value of `name`: the channel, and a reason
    /// with `{name}` for the name.
    pub(crate) fn unread(&self, name: &str) -> Option<String> {
        let (channel, why) = self.unread.get(name)?;
        Some(format!("{channel} {}", why.replace("{name}", name)))
    }

    /// Each name with its last UTF-8 value and channel; a value that is not
    /// UTF-8 is among [`Self::unread_names`].
    pub(crate) fn properties(&self) -> impl Iterator<Item = (&str, &str, &'static str)> {
        (self.defines.iter())
            .filter(|(name, _)| !self.unread.contains_key(*name))
            .filter_map(|(name, define)| {
                let value = std::str::from_utf8(&define.value).ok()?;
                Some((name.as_str(), value, define.channel))
            })
    }

    /// The last `-D` value of each name `.mvn/jvm.config` gives.
    pub(crate) fn jvm_config(&self) -> &HashMap<String, String> {
        &self.jvm_config
    }

    /// The names whose value raeva cannot tell.
    pub(crate) fn unread_names(&self) -> impl Iterator<Item = &str> {
        let not_utf8 = (self.defines.iter())
            .filter(|(_, define)| std::str::from_utf8(&define.value).is_err())
            .map(|(name, _)| name.as_str());
        self.unread.keys().map(String::as_str).chain(not_utf8)
    }

    fn take(&mut self, token: &[u8], channel: &'static str) {
        let Some((name, value)) = self.note_jvm_config(token, channel) else {
            return;
        };
        self.unread.remove(name);
        let value = value.to_vec();
        self.defines
            .insert(name.to_string(), Define { value, channel });
    }

    /// The name and value of the `-D` option `token`, noted as
    /// `.mvn/jvm.config`'s when `channel` is.
    fn note_jvm_config<'a>(
        &mut self,
        token: &'a [u8],
        channel: &'static str,
    ) -> Option<(&'a str, &'a [u8])> {
        let define = token
            .strip_prefix(b"-D")
            .filter(|define| !define.is_empty())?;
        let (name, value) = match define.iter().position(|&byte| byte == b'=') {
            Some(at) => (&define[..at], &define[at + 1..]),
            None => (define, &b""[..]),
        };
        let name = std::str::from_utf8(name).ok()?;
        if channel == JVM_CONFIG {
            let value = String::from_utf8_lossy(value).into_owned();
            self.jvm_config.insert(name.to_string(), value);
        }
        Some((name, value))
    }

    /// Mark the names `text` may set as unread, for `channel` and `why`.
    fn taint(&mut self, text: &[u8], channel: &str, why: &str) {
        for name in mentioned(&String::from_utf8_lossy(text)) {
            self.unread
                .insert(name, (channel.to_string(), why.to_string()));
        }
    }

    /// Refuse a `-D` of `.mvn/jvm.config` that only some JDKs let stand
    /// where the lock cannot tell which JDK runs `mvn`
    /// ([`rv_maven_model::jvm_config_by_jdk`]), `jdks` being the `[lock]
    /// jdks` entries, and mark one of another channel unread, which fails
    /// only what reads it: `mvn` takes no value from the project there.
    pub(crate) fn refuse_jdk_dependent(&mut self, jdks: &[String]) -> Result<(), ConfigError> {
        let mut found: Vec<(String, &'static str, String)> = (self.properties())
            .filter_map(|(name, value, channel)| {
                let why = rv_maven_model::jvm_config_by_jdk(name, value, jdks, channel)?;
                Some((name.to_string(), channel, why))
            })
            .collect();
        found.sort();
        for (name, channel, why) in found {
            if channel == JVM_CONFIG {
                return Err(ConfigError::UnreadHostProperty(why));
            }
            let why = why.strip_prefix(channel).unwrap_or(&why).trim_start();
            self.unread
                .insert(name, (channel.to_string(), why.to_string()));
        }
        Ok(())
    }
}

/// The names a JVM option of this run may set in a way raeva does not
/// read, with why, which a message about a property left undefined names.
static UNREAD: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// Why a JVM option of this run may set `name` in a way raeva does not
/// read, when one may.
pub fn unread_jvm_option(name: &str) -> Option<String> {
    let unread = UNREAD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (unread.iter())
        .find(|(unread, _)| unread == name)
        .map(|(_, why)| why.clone())
}

impl JvmOptions {
    /// Record [`Self::unread`] for [`unread_jvm_option`].
    pub(crate) fn register_unread(&self) {
        let mut unread = UNREAD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *unread = (self.unread.keys())
            .filter_map(|name| Some((name.clone(), self.unread(name)?)))
            .collect();
    }
}

/// Read every channel of `host` and `jvm_config`, `.mvn/jvm.config` as
/// `mvn` passes it, in the order the JVM reads them: `JAVA_TOOL_OPTIONS`,
/// `JDK_JAVA_OPTIONS` (JDK 9 and later), the command line (`jvm_config`,
/// `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS`), then `_JAVA_OPTIONS`, the last value
/// of a name winning. The argument files the launcher expands there and in
/// `JDK_JAVA_OPTIONS`, and the VM options files HotSpot reads from any of
/// them, are read in place, from where `mvn` runs.
///
/// What raeva cannot read exactly marks the names it may set unread: a
/// quoted value in a JVM variable or an option file, any JVM variable on
/// OpenJ9, `JDK_JAVA_OPTIONS` for a JDK raeva does not know, a word of
/// `MAVEN_OPTS` the shell may glob, and on Windows a `"` or `^` there.
///
/// # Errors
///
/// [`ConfigError::UnreadHostProperty`] for an option file that cannot be
/// read, which the JVM refuses too, or one that names a VM options file.
pub(crate) fn read(jvm_config: Option<&str>, host: &Host<'_>) -> Result<JvmOptions, ConfigError> {
    crate::user_home::refuse_changed_ifs(&host.shell)?;
    let mut options = JvmOptions::default();
    let shell = |name| host.shell.shell_value(name);
    let exported = |name| host.shell.exported(name);
    let jdk_options = match host.jdk {
        // JDK 8's launcher does not read it.
        jdk if jdk.hotspot_before(9) => None,
        _ => exported("JDK_JAVA_OPTIONS"),
    };
    let channels: [(&'static str, Option<Vec<u8>>, Split); 6] = [
        (
            "JAVA_TOOL_OPTIONS",
            exported("JAVA_TOOL_OPTIONS"),
            Split::Jvm,
        ),
        ("JDK_JAVA_OPTIONS", jdk_options, Split::Launcher),
        (
            JVM_CONFIG,
            jvm_config.map(|text| text.as_bytes().to_vec()),
            Split::JvmConfig,
        ),
        ("MAVEN_OPTS", shell("MAVEN_OPTS"), Split::Shell),
        ("MAVEN_DEBUG_OPTS", shell("MAVEN_DEBUG_OPTS"), Split::Shell),
        ("_JAVA_OPTIONS", exported("_JAVA_OPTIONS"), Split::Jvm),
    ];
    for (channel, text, split) in channels {
        let Some(text) = text else {
            continue;
        };
        read_channel(&mut options, channel, &text, split, host)?;
    }
    // OpenJ9 reads its own variables and parses the others its own way.
    if host.jdk.openj9 {
        let variables = JVM_VARIABLES.into_iter().chain(OPENJ9_VARIABLES);
        for channel in variables {
            if let Some(text) = exported(channel) {
                refuse_skipped_option_files(channel, &text)?;
                let why = "sets {name} for an OpenJ9 JVM, which raeva does not model";
                options.taint(&text, channel, why);
            }
        }
    }
    Ok(options)
}

fn read_channel(
    options: &mut JvmOptions,
    channel: &'static str,
    text: &[u8],
    split: Split,
    host: &Host<'_>,
) -> Result<(), ConfigError> {
    let lossy = String::from_utf8_lossy(text);
    let stop = match split {
        Split::Launcher if !host.jdk.hotspot_from(9) => Some(
            "sets {name}, which only JDK 9 and later read, and raeva cannot tell which JDK mvn \
             runs",
        ),
        Split::Shell if cfg!(windows) && lossy.contains('"') => Some(
            "quotes a value beside {name}, which java's own command line parsing reads and raeva \
             does not",
        ),
        Split::Shell if cfg!(windows) && lossy.contains('^') => {
            Some("has a ^ beside {name}, which cmd removes from mvn.cmd's java command line")
        }
        _ => None,
    };
    if let Some(why) = stop {
        refuse_skipped_option_files(channel, text)?;
        options.taint(text, channel, why);
        return Ok(());
    }
    let words: Vec<Vec<u8>> = match split {
        Split::Shell => (text.split(|&byte| is_ifs(byte)))
            .map(<[u8]>::to_vec)
            .collect(),
        Split::JvmConfig => (text.split(|&byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r')))
            .map(<[u8]>::to_vec)
            .collect(),
        Split::Jvm | Split::Launcher => jvm_words(text).ok_or_else(|| {
            unread_option(
                &format!("{channel} has a quote it does not close"),
                "which the JVM refuses to start with",
            )
        })?,
    };
    let mut argument_files = split.argument_files();
    for word in words.iter().filter(|word| !word.is_empty()) {
        // `mvn` passes `.mvn/jvm.config` on in its unquoted `$MAVEN_OPTS`.
        if matches!(split, Split::Shell | Split::JvmConfig) && !cfg!(windows) {
            let lossy = String::from_utf8_lossy(word);
            if crate::user_home::shell_may_expand(&lossy, host.working_dir) {
                refuse_glob(channel, &lossy)?;
                options.note_jvm_config(word, channel);
                let why = "sets {name} to a pattern the shell may expand";
                options.taint(word, channel, why);
                continue;
            }
        }
        if word == b"--disable-@files" {
            argument_files = false;
        }
        let file = match word.strip_prefix(b"-XX:VMOptionsFile=") {
            Some(file) => Some((file, true)),
            None if argument_files && !word.starts_with(b"@@") => {
                (word.strip_prefix(b"@").filter(|file| !file.is_empty())).map(|file| (file, false))
            }
            None => None,
        };
        match file {
            Some((file, vm)) => {
                read_file(options, channel, &String::from_utf8_lossy(file), vm, host)?;
            }
            None => options.take(word, channel),
        }
    }
    Ok(())
}

/// The refusal of an option text raeva does not read, `what` and `why`.
fn unread_option(what: &str, why: &str) -> ConfigError {
    ConfigError::UnreadHostProperty(format!(
        "{what} {why}, so raeva cannot tell what mvn's JVM takes from it; fix the option, or \
         pass the -D values on the command line of both raeva and mvn, such as \
         -Duser.home=<dir>"
    ))
}

/// Refuse `text` of `channel`, which raeva does not read, when it may name
/// an option file, whose options could set any name, `user.home` too.
fn refuse_skipped_option_files(channel: &str, text: &[u8]) -> Result<(), ConfigError> {
    let bare: Vec<u8> = (text.iter().copied())
        .filter(|byte| !matches!(byte, b'"' | b'\'' | b'\\' | b'^'))
        .collect();
    let names_file = (bare.split(u8::is_ascii_whitespace_or_vt))
        .any(|word| word.starts_with(b"@") || word.starts_with(b"-XX:VMOptionsFile="));
    let opens = String::from_utf8_lossy(&bare).contains("ptionsfile");
    match names_file || opens {
        true => Err(unread_option(
            &format!("{channel} names an option file"),
            "beside an option raeva does not read",
        )),
        false => Ok(()),
    }
}

/// Refuse `word`, a pattern of `channel` the shell may expand, unless each
/// word it can expand to sets the one name it starts with or no option
/// raeva reads: what it matches starts with the text before its first
/// pattern character.
fn refuse_glob(channel: &str, word: &str) -> Result<(), ConfigError> {
    let at = word.find(['*', '?', '[']).unwrap_or(word.len());
    let prefix = &word[..at];
    let named = prefix
        .strip_prefix("-D")
        .is_some_and(|define| define.contains('='));
    let other = !prefix.starts_with("-D")
        && !prefix.starts_with('@')
        && !"-D".starts_with(prefix)
        && !"-XX:VMOptionsFile=".starts_with(prefix)
        && !prefix.starts_with("-XX:VMOptionsFile=");
    match named || other {
        true => Ok(()),
        false => Err(unread_option(
            &format!("{channel} has {word}"),
            "a pattern the shell may expand to options",
        )),
    }
}

/// The words HotSpot and the java launcher read from a variable or a VM
/// options file: split at C white space, a `'` or `"` quoting up to the
/// next one, which both drop, with no escapes; `None` for a quote left
/// open, which the JVM refuses.
pub fn jvm_words(text: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut words = Vec::new();
    let mut word: Option<Vec<u8>> = None;
    let mut bytes = text.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte.is_ascii_whitespace_or_vt() {
            words.extend(word.take());
            continue;
        }
        let word = word.get_or_insert_default();
        match byte {
            b'"' | b'\'' => loop {
                match bytes.next()? {
                    close if close == byte => break,
                    quoted => word.push(quoted),
                }
            },
            byte => word.push(byte),
        }
    }
    words.extend(word.take());
    Some(words)
}

/// The words the java launcher reads from an argument file: split at
/// space, tab and form feed outside quotes and at every line end, a `'` or
/// `"` quoting up to the next one, which it drops; in quotes `\n`, `\r`,
/// `\t` and `\f` stand for those characters, a backslash before any other
/// for it, and one before a line end joins the next line without its
/// leading white space; a `#` outside quotes ends the word and comments out
/// the rest of the line.
pub fn argument_file_words(text: &[u8]) -> Vec<Vec<u8>> {
    let blank = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c);
    let mut words = Vec::new();
    let mut word: Option<Vec<u8>> = None;
    let mut quote = None;
    let mut bytes = text.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        match (quote, byte) {
            (_, b'\n' | b'\r') => {
                quote = None;
                words.extend(word.take());
            }
            (Some(open), byte) if byte == open => quote = None,
            (Some(_), b'\\') => {
                let escaped = match bytes.next() {
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    Some(b'f') => 0x0c,
                    Some(b'\n' | b'\r') => {
                        while bytes.next_if(blank).is_some() {}
                        continue;
                    }
                    Some(other) => other,
                    None => continue,
                };
                word.get_or_insert_default().push(escaped);
            }
            (Some(_), byte) => word.get_or_insert_default().push(byte),
            (None, b'"' | b'\'') => {
                quote = Some(byte);
                word.get_or_insert_default();
            }
            (None, b'#') => {
                words.extend(word.take());
                while bytes
                    .next_if(|byte| !matches!(byte, b'\n' | b'\r'))
                    .is_some()
                {}
            }
            (None, b' ' | b'\t' | 0x0c) => words.extend(word.take()),
            (None, byte) => word.get_or_insert_default().push(byte),
        }
    }
    words.extend(word.take());
    words
}

/// The option files the configuration read, with the channel that named
/// each and the bytes it held, or `None` where it found none.
type OptionFiles = Vec<(&'static str, PathBuf, Option<Vec<u8>>)>;
static OPTION_FILES: std::sync::Mutex<OptionFiles> = std::sync::Mutex::new(Vec::new());

/// Note that the configuration read `text` from the option file `path`,
/// which `channel` names, or found none there.
pub(crate) fn record_option_file(
    channel: &'static str,
    path: &std::path::Path,
    text: Option<&[u8]>,
) {
    (OPTION_FILES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
    .push((channel, path.to_path_buf(), text.map(<[u8]>::to_vec)));
}

static WORKING_DIR_READ: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

/// Note that the configuration took a path `what` names from the
/// directory raeva runs in, as `mvn` does from its own.
pub(crate) fn record_working_dir_read(what: &'static str) {
    (WORKING_DIR_READ
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
    .get_or_insert(what);
}

/// What named the first path the configuration took from the directory
/// raeva runs in, such as `JDK_JAVA_OPTIONS` for a relative argument file.
pub fn working_dir_read() -> Option<&'static str> {
    *WORKING_DIR_READ
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The channel, such as `JDK_JAVA_OPTIONS`, that names an option file the
/// configuration read which no longer holds what it read then, or which
/// exists where it found none, as when the mavenrc files write it anew
/// each time they run.
pub fn changed_option_file() -> Option<&'static str> {
    (OPTION_FILES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
    .iter()
    .find(|(_, path, text)| crate::prime::read_option_bytes(path) != *text)
    .map(|(channel, _, _)| *channel)
}

/// Read the option file `file` a word of `channel` names, an argument file
/// or a VM options file when `vm`, in place.
fn read_file(
    options: &mut JvmOptions,
    channel: &'static str,
    file: &str,
    vm: bool,
    host: &Host<'_>,
) -> Result<(), ConfigError> {
    let what = format!("{channel}'s {file}");
    if std::path::Path::new(file).is_relative() {
        record_working_dir_read(channel);
    }
    let path = host.working_dir.join(file);
    // A FIFO or device, which raeva may not read without blocking or
    // taking what the JVM reads.
    if std::fs::metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
        return Err(unread_option(&what, "is not a regular file"));
    }
    let Some(text) = crate::prime::read_option_bytes(&path) else {
        return Err(unread_option(&what, "cannot be read"));
    };
    record_option_file(channel, &path, Some(&text));
    let words = match vm {
        true => jvm_words(&text).ok_or_else(|| {
            unread_option(
                &what,
                "has a quote it does not close, which the JVM refuses",
            )
        })?,
        false => argument_file_words(&text),
    };
    for word in &words {
        match word.strip_prefix(b"-XX:VMOptionsFile=") {
            // HotSpot refuses one a VM options file names.
            Some(_) if vm => {
                return Err(unread_option(
                    &what,
                    "names a VM options file, which the JVM refuses",
                ));
            }
            Some(file) => read_file(options, channel, &String::from_utf8_lossy(file), true, host)?,
            None => options.take(word, channel),
        }
    }
    Ok(())
}

/// White space that the shell's default `IFS` splits at.
fn is_ifs(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n')
}

trait CWhiteSpace {
    /// C's `isspace`, at which HotSpot and the java launcher split their
    /// variables: ASCII white space and the vertical tab.
    fn is_ascii_whitespace_or_vt(&self) -> bool;
}

impl CWhiteSpace for u8 {
    fn is_ascii_whitespace_or_vt(&self) -> bool {
        self.is_ascii_whitespace() || *self == 0x0b
    }
}

/// The `-D` names `text` may set, quotes and backslashes dropped, and
/// `user.home` wherever it may name it.
fn mentioned(text: &str) -> Vec<String> {
    let bare: String = (text.chars())
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    let mut names: Vec<String> = (bare.split("-D").skip(1))
        .map(|rest| {
            let end = rest.find(|c: char| c == '=' || c.is_whitespace());
            rest[..end.unwrap_or(rest.len())].to_string()
        })
        .filter(|name| !name.is_empty())
        .collect();
    if crate::user_home::mentions_user_home(text) {
        names.push("user.home".to_string());
    }
    names
}

#[cfg(test)]
mod tests;
