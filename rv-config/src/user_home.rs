//! The `-Duser.home` Maven's JVM takes, from the channels
//! [`crate::jvm_options`] reads, or a refusal where raeva cannot tell it.

use std::path::Path;

use crate::error::ConfigError;
use crate::paths::LauncherJdk;

pub(crate) use rv_maven_model::mavenrc::Shell;

const USER_HOME: &str = "user.home";

/// What decides Maven's `user.home` besides the project's files: the
/// variables `mvn` holds once it has sourced the mavenrc files, and the
/// JDK it runs.
pub(crate) struct Host<'a> {
    pub(crate) shell: Shell,
    pub(crate) jdk: LauncherJdk,
    /// Where a relative argument file is read from: where `mvn` runs.
    pub(crate) working_dir: &'a Path,
}

/// Why raeva does not take `name` as `file`, a mavenrc file, changes it,
/// where it reads the value of this process.
pub(crate) fn mavenrc_changes(file: &Path, name: &str) -> ConfigError {
    ConfigError::UnreadHostProperty(format!(
        "{}, which mvn sources, changes {name}, which raeva does not follow there, so raeva \
         cannot tell what mvn takes from it; set {name} in the environment instead, or run \
         both raeva and mvn with MAVEN_SKIP_RC=1",
        file.display()
    ))
}

/// Refuse an `IFS` the mavenrc files of `shell` leave other than the
/// shell's own, at which `mvn` splits its variables and `.mvn/jvm.config`.
pub(crate) fn refuse_changed_ifs(shell: &Shell) -> Result<(), ConfigError> {
    let Some(file) = shell.files().last() else {
        return Ok(());
    };
    match shell.shell_value("IFS") {
        Some(ifs) if !cfg!(windows) && ifs != b" \t\n" => Err(mavenrc_changes(file, "IFS")),
        _ => Ok(()),
    }
}

/// The `-Duser.home` Maven's JVM takes, the last that sets it among
/// `options` ([`crate::jvm_options::read`]). `MavenCli` then sets the `-D`
/// values of `defines`, `.mvn/maven.config`'s and then the command line's,
/// as system properties.
///
/// # Errors
///
/// [`ConfigError::UnreadHostProperty`], naming the channel: for a value
/// with an expression, which Maven expands against its properties where it
/// takes `user.home`, but for a JVM channel's `${MAVEN_PROJECTBASEDIR}`,
/// which names none; for a value that is not UTF-8; and, unless the
/// command line sets `user.home`, when a channel may set it in a way raeva
/// does not read exactly.
pub(crate) fn user_home_define(
    options: &crate::jvm_options::JvmOptions,
    defines: &crate::maven_config::CommandLine,
    command_line: &crate::maven_config::CommandLine,
) -> Result<Option<String>, ConfigError> {
    let user_home = |defines: &crate::maven_config::CommandLine| {
        (defines.defines.iter())
            .map(|define| crate::maven_config::define_property(define))
            .filter(|(name, _)| *name == USER_HOME)
            .map(|(_, value)| value.to_string())
            .next_back()
    };
    let expanded = |value: Option<String>| match value {
        Some(value) if value.contains("${") => Err(ConfigError::UnreadHostProperty(format!(
            "-Duser.home={} takes an expression, which Maven expands against its properties \
             where it takes user.home, and raeva does not; write the directory out",
            rv_maven_types::bounded(&value)
        ))),
        value => Ok(value),
    };
    // `MavenCli` sets the command line's, `MAVEN_ARGS`'s as the mavenrc
    // files leave it first, last, over every channel.
    if user_home(command_line).is_some() {
        return expanded(user_home(defines));
    }
    if let Some(why) = options.unread(USER_HOME) {
        return Err(ConfigError::UnreadHostProperty(format!(
            "{why}, so raeva cannot tell the Maven user home mvn's JVM takes, which decides \
             the settings.xml; pass -Duser.home=<dir> on the command line of both raeva and mvn"
        )));
    }
    if let Some(defined) = user_home(defines) {
        return expanded(Some(defined));
    }
    let Some(define) = options.define(USER_HOME) else {
        return Ok(None);
    };
    match std::str::from_utf8(&define.value) {
        // Maven expands an expression where a POM or settings.xml takes
        // `${user.home}`, so only one that names no property it knows, as
        // mvn 3.9 leaves `${MAVEN_PROJECTBASEDIR}`, reads as written.
        Ok(value) if value.replace(PROJECT_BASEDIR_EXPRESSION, "").contains("${") => {
            expanded(Some(value.to_string()))
        }
        Ok(value) => Ok(Some(value.to_string())),
        Err(_) => Err(ConfigError::UnreadHostProperty(format!(
            "{} sets user.home to bytes that are not UTF-8 text, which raeva does not read as \
             a path; pass -Duser.home=<dir> on the command line of both raeva and mvn",
            define.channel
        ))),
    }
}

const PROJECT_BASEDIR_EXPRESSION: &str = "${MAVEN_PROJECTBASEDIR}";

/// Whether `text` may name `user.home` to a shell, an argument file or the
/// JVM, which drop quotes and backslashes and join lines.
pub(crate) fn mentions_user_home(text: &str) -> bool {
    let bare: String = (text.chars())
        .filter(|c| !matches!(c, '"' | '\'' | '\\') && !c.is_whitespace())
        .collect();
    bare.contains(USER_HOME)
}

/// Whether `sh` may replace `token`, a word of `mvn`'s unquoted
/// `$MAVEN_OPTS`, with the paths it matches in `working_dir`. A pattern
/// that matches nothing stays as it is, and one can match only below the
/// directory its first pattern character is in, which for a
/// `-Duser.home=...` word is relative to `working_dir`.
pub(crate) fn shell_may_expand(token: &str, working_dir: &Path) -> bool {
    let Some(at) = token.find(['*', '?', '[']) else {
        return false;
    };
    let dir = token[..at].rfind('/').map_or("", |slash| &token[..=slash]);
    working_dir.join(dir).is_dir()
}

#[cfg(test)]
mod tests;
