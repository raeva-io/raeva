//! The system properties Maven's JVM holds, as measured in `jvm_names.tsv`,
//! and how raeva answers each. A name in no measurement is unset: no JVM
//! or `mvn` sets it, so a POM's or the user's value is the only one.

use rv_maven_types::MavenMode;

/// How raeva answers a system property every or some JVMs set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// The locked platform, JDK or Maven line gives the value, which
    /// [`super::host_property`] works out.
    Locked,
    /// Every JVM sets this value.
    Fixed(&'static str),
    /// Every JVM sets it, to a value of its host, vendor, locale or
    /// architecture.
    PerHost,
    /// Some JVMs set it and others do not, or set it empty.
    Uneven,
    /// Maven sets it after `MavenCli` copies the system properties, so no
    /// model sees it.
    Unseen,
}

/// The Maven lines whose run sets a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lines {
    Both,
    Maven39,
    Maven310,
}

use Class::*;
use Lines::*;

/// Each measured name, sorted. A value every measured JVM gave is
/// `PerHost` or `Uneven` where another JVM gives another: Oracle's
/// `java.runtime.name`, OpenJ9's `java.vm.name` and missing
/// `sun.management.compiler`, the locale's `user.language`, a 32-bit or
/// big-endian JVM's `sun.arch.data.model` and `sun.cpu.endian`, and
/// `user.country`, which no JVM sets under `LC_ALL=C`.
pub(crate) const JVM_NAMES: [(&str, Lines, Class); 80] = [
    ("apple.awt.application.name", Both, Uneven),
    ("awt.toolkit", Both, Uneven),
    ("classworlds.conf", Both, PerHost),
    ("file.encoding", Both, PerHost),
    ("file.encoding.pkg", Both, Uneven),
    ("file.separator", Both, Locked),
    ("ftp.nonProxyHosts", Both, Uneven),
    ("guice.disable.misplaced.annotation.check", Both, Unseen),
    ("guice_custom_class_loading", Both, Unseen),
    ("http.nonProxyHosts", Both, Uneven),
    ("jansi.mode", Maven39, Unseen),
    ("java.awt.graphicsenv", Both, Uneven),
    ("java.awt.printerjob", Both, Uneven),
    ("java.class.path", Both, PerHost),
    ("java.class.version", Both, PerHost),
    ("java.endorsed.dirs", Both, Uneven),
    ("java.ext.dirs", Both, Uneven),
    ("java.home", Both, Locked),
    ("java.io.tmpdir", Both, PerHost),
    ("java.library.path", Both, PerHost),
    ("java.runtime.name", Both, PerHost),
    ("java.runtime.version", Both, PerHost),
    ("java.specification.maintenance.version", Both, Uneven),
    (
        "java.specification.name",
        Both,
        Fixed("Java Platform API Specification"),
    ),
    (
        "java.specification.vendor",
        Both,
        Fixed("Oracle Corporation"),
    ),
    ("java.specification.version", Both, Locked),
    ("java.vendor", Both, PerHost),
    ("java.vendor.url", Both, PerHost),
    ("java.vendor.url.bug", Both, PerHost),
    ("java.vendor.version", Both, Uneven),
    ("java.version", Both, Locked),
    ("java.version.date", Both, Uneven),
    ("java.vm.compressedOopsMode", Both, Uneven),
    ("java.vm.info", Both, PerHost),
    ("java.vm.name", Both, PerHost),
    (
        "java.vm.specification.name",
        Both,
        Fixed("Java Virtual Machine Specification"),
    ),
    (
        "java.vm.specification.vendor",
        Both,
        Fixed("Oracle Corporation"),
    ),
    ("java.vm.specification.version", Both, PerHost),
    ("java.vm.vendor", Both, PerHost),
    ("java.vm.version", Both, PerHost),
    ("jdk.debug", Both, Uneven),
    ("library.jansi.path", Maven39, PerHost),
    ("library.jline.path", Maven310, PerHost),
    ("line.separator", Both, Locked),
    ("maven.build.version", Both, Locked),
    ("maven.conf", Both, PerHost),
    ("maven.home", Both, PerHost),
    ("maven.multiModuleProjectDirectory", Both, Locked),
    ("maven.version", Both, Locked),
    ("native.encoding", Both, Uneven),
    (
        "org.jline.terminal.exec.redirectPipeCreationMode",
        Maven310,
        Locked,
    ),
    ("os.arch", Both, Locked),
    ("os.name", Both, Locked),
    ("os.version", Both, PerHost),
    ("path.separator", Both, Locked),
    ("socksNonProxyHosts", Both, Uneven),
    ("stderr.encoding", Both, Uneven),
    ("stdin.encoding", Both, Uneven),
    ("stdout.encoding", Both, Uneven),
    ("sun.arch.data.model", Both, PerHost),
    ("sun.boot.class.path", Both, Uneven),
    ("sun.boot.library.path", Both, PerHost),
    ("sun.cpu.endian", Both, PerHost),
    ("sun.cpu.isalist", Both, Uneven),
    ("sun.io.unicode.encoding", Both, PerHost),
    ("sun.java.command", Both, PerHost),
    ("sun.java.launcher", Both, Fixed("SUN_STANDARD")),
    ("sun.jnu.encoding", Both, PerHost),
    ("sun.management.compiler", Both, Uneven),
    ("sun.os.patch.level", Both, Uneven),
    ("sun.stderr.encoding", Both, Uneven),
    ("sun.stdout.encoding", Both, Uneven),
    ("user.country", Both, Uneven),
    ("user.dir", Both, PerHost),
    ("user.home", Both, PerHost),
    ("user.language", Both, PerHost),
    ("user.name", Both, PerHost),
    ("user.script", Both, Uneven),
    ("user.timezone", Both, Unseen),
    ("user.variant", Both, Uneven),
];

/// How raeva answers `name` under the Maven line `mode`, `None` for a
/// name no JVM or `mvn` of that line sets where a model sees it.
pub(crate) fn class(name: &str, mode: MavenMode) -> Option<Class> {
    let (_, lines, class) = measured(name)?;
    let on_line = match lines {
        Both => true,
        Maven39 => mode == MavenMode::Maven39,
        Maven310 => mode == MavenMode::Maven310,
    };
    (on_line && class != Unseen).then_some(class)
}

/// Whether some JVM or `mvn` line sets `name` where a model sees it.
pub(crate) fn measured_name(name: &str) -> bool {
    measured(name).is_some_and(|(_, _, class)| class != Unseen)
}

/// The names [`class`] answers on some line.
pub(crate) fn names() -> impl Iterator<Item = &'static str> {
    (JVM_NAMES.iter())
        .filter(|(_, _, class)| *class != Unseen)
        .map(|(name, _, _)| *name)
}

/// Each name every JVM sets to one value, with that value.
pub(crate) fn fixed_values() -> impl Iterator<Item = (&'static str, &'static str)> {
    JVM_NAMES.iter().filter_map(|(name, _, class)| match class {
        Fixed(value) => Some((*name, *value)),
        _ => None,
    })
}

fn measured(name: &str) -> Option<(&'static str, Lines, Class)> {
    let index = JVM_NAMES.binary_search_by(|(known, _, _)| known.cmp(&name));
    index.ok().map(|index| JVM_NAMES[index])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Row<'a> {
        name: &'a str,
        lines: &'a str,
        every_jvm: bool,
        value: Option<&'a str>,
        notes: &'a str,
    }

    fn rows() -> Vec<Row<'static>> {
        (include_str!("jvm_names.tsv").lines())
            .filter(|line| !line.starts_with('#'))
            .map(|line| {
                let mut fields = line.split('\t');
                let mut field = || fields.next().unwrap_or_default();
                let (name, lines, jvms, value, notes) =
                    (field(), field(), field(), field(), field());
                Row {
                    name,
                    lines,
                    every_jvm: jvms == "all",
                    value: value.strip_prefix('='),
                    notes,
                }
            })
            .collect()
    }

    #[test]
    fn every_measured_name_has_a_class_the_measurement_allows() {
        let rows = rows();
        let measured: Vec<&str> = rows.iter().map(|row| row.name).collect();
        let classified: Vec<&str> = JVM_NAMES.iter().map(|(name, _, _)| *name).collect();
        assert_eq!(classified, measured, "jvm_names.tsv and JVM_NAMES differ");
        // Names one value every measured JVM gave does not hold for.
        let differ_elsewhere = [
            "java.runtime.name",
            "java.vm.name",
            "sun.arch.data.model",
            "sun.cpu.endian",
            "sun.management.compiler",
            "user.country",
            "user.language",
        ];
        for (row, (name, lines, class)) in rows.iter().zip(JVM_NAMES) {
            let expected_lines = match lines {
                Both => "3.9,3.10",
                Maven39 => "3.9",
                Maven310 => "3.10",
            };
            assert_eq!(row.lines, expected_lines, "{name}");
            let late = row.notes.split(' ').any(|note| note == "late");
            assert_eq!(class == Unseen, late, "{name}");
            let even = row.every_jvm && !row.notes.contains("empty:") && !late;
            match class {
                Fixed(value) => assert!(even && row.value == Some(value), "{name}"),
                Locked | PerHost => assert!(even, "{name}"),
                Uneven => assert!(!even || differ_elsewhere.contains(&name), "{name}"),
                Unseen => {}
            }
        }
    }
}
