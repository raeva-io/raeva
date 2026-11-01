//! The character rules for one Maven coordinate component.
//!
//! Every coordinate that reaches a repository URL, a local-repository path, a
//! trusted-checksums line or the terminal goes through
//! [`validate_coordinate_component`]: raeva.lock rows, export-m2 and
//! export-checksums paths, and repository requests.

use std::fmt;

/// Longest component accepted, in bytes. Most file systems cap one path
/// component at 255 bytes, and a component becomes a directory or a file
/// name in the Maven repository layout.
const MAX_COMPONENT_BYTES: usize = 255;

/// Which part of a coordinate a value is, which decides the rules it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoordinateField {
    /// A `groupId`, a dotted name whose segments become directories.
    Group,
    /// An `artifactId`.
    Artifact,
    /// A version, as written.
    Version,
    /// A classifier.
    Classifier,
    /// The file extension, recorded in raeva.lock as `packaging`.
    Extension,
}

impl CoordinateField {
    /// The name error messages use for the field. [`Self::Extension`] is
    /// `packaging`, its raeva.lock name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Group => "group",
            Self::Artifact => "artifact",
            Self::Version => "version",
            Self::Classifier => "classifier",
            Self::Extension => "packaging",
        }
    }
}

impl fmt::Display for CoordinateField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a coordinate component was refused. The value is kept for the
/// message, which prints it escaped and cut, so control characters never
/// reach a terminal through it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{field} {} {reason}", crate::text::quoted(value))]
pub struct InvalidCoordinateComponent {
    field: CoordinateField,
    value: String,
    reason: Reason,
}

impl InvalidCoordinateComponent {
    /// The field the refused value was checked as.
    pub fn field(&self) -> CoordinateField {
        self.field
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    Empty,
    TooLong,
    NotMavenId,
    NotPrintableAscii,
    NotTerminalSafe,
    Forbidden(char),
    DotDot,
    EmptyGroupSegment,
    TrailingDot,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty"),
            Self::TooLong => write!(f, "is longer than {MAX_COMPONENT_BYTES} bytes"),
            Self::NotMavenId => {
                f.write_str("may contain only ASCII letters, digits, '.', '-' and '_'")
            }
            Self::NotPrintableAscii => f.write_str(
                "may contain only printable ASCII characters (no spaces or control characters)",
            ),
            Self::NotTerminalSafe => {
                f.write_str("must not contain control or invisible characters")
            }
            Self::Forbidden(ch) => write!(f, "must not contain {ch:?}"),
            Self::DotDot => f.write_str("must not contain '..'"),
            Self::EmptyGroupSegment => f.write_str("must not start or end with '.'"),
            Self::TrailingDot => f.write_str("must not end with '.'"),
        }
    }
}

/// Characters refused in every component on top of the per-field charset.
///
/// `\ / : " < > | ? *` are the characters Maven 3.9's model validator bans in
/// versions and repository ids (`ILLEGAL_FS_CHARS`): path separators, the NTFS
/// alternate-data-stream separator and the characters Windows refuses in file
/// names. `# @ % ;` would change what a repository URL path means: a
/// fragment, a userinfo separator, a percent escape that a server can decode
/// into `/` or `..`, and the path parameters that servlet containers strip
/// from a segment, so that `a-1.0.jar;x` would fetch `a-1.0.jar`.
const FORBIDDEN: &[char] = &[
    '\\', '/', ':', '"', '<', '>', '|', '?', '*', '#', '@', '%', ';',
];

/// Check one coordinate component against Maven's coordinate rules and the
/// repository layout, and refuse anything that could leave the directory it
/// names or alter a URL, a file name, a line-oriented file or the terminal.
///
/// - Every field must be non-empty and at most 255 bytes.
/// - `group` and `artifact` follow Maven's id rule, which Maven 3.9 enforces
///   for the project and every declared dependency: ASCII letters, digits,
///   `.`, `-` and `_`. A group must not start or end with `.`, which would
///   make an empty directory name in the layout.
/// - `version`, `classifier` and `packaging` may hold printable ASCII only:
///   no control characters (ESC, BEL, CR, LF, tab), spaces or non-ASCII text.
/// - No field may contain `\ / : " < > | ? * # @ % ;` or `..`, or end with `.`,
///   which Windows strips from file names so that `1.0.` and `1.0` would name
///   one directory.
///
/// This is stricter than Maven for versions and classifiers, which Maven
/// leaves unchecked in dependency POMs, and never looser.
pub fn validate_coordinate_component(
    field: CoordinateField,
    value: &str,
) -> Result<(), InvalidCoordinateComponent> {
    check(field, value).map_err(|reason| InvalidCoordinateComponent {
        field,
        value: value.to_string(),
        reason,
    })
}

/// Check the version of a reactor module, which is never fetched, exported
/// or written into a trusted-checksums line. Maven 3.9 only warns about the
/// characters [`validate_coordinate_component`] bans in a project version,
/// so this keeps them and refuses only what is unsafe to print: an empty or
/// over-long value, control characters and invisible characters.
pub fn validate_reactor_version(value: &str) -> Result<(), InvalidCoordinateComponent> {
    let reason = if value.is_empty() {
        Some(Reason::Empty)
    } else if value.len() > MAX_COMPONENT_BYTES {
        Some(Reason::TooLong)
    } else if !is_terminal_safe(value) {
        Some(Reason::NotTerminalSafe)
    } else {
        None
    };
    match reason {
        Some(reason) => Err(InvalidCoordinateComponent {
            field: CoordinateField::Version,
            value: value.to_string(),
            reason,
        }),
        None => Ok(()),
    }
}

fn check(field: CoordinateField, value: &str) -> Result<(), Reason> {
    if value.is_empty() {
        return Err(Reason::Empty);
    }
    if value.len() > MAX_COMPONENT_BYTES {
        return Err(Reason::TooLong);
    }
    match field {
        CoordinateField::Group | CoordinateField::Artifact => {
            if !is_maven_id_text(value) {
                return Err(Reason::NotMavenId);
            }
        }
        CoordinateField::Version | CoordinateField::Classifier | CoordinateField::Extension => {
            if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(Reason::NotPrintableAscii);
            }
            if let Some(ch) = value.chars().find(|ch| FORBIDDEN.contains(ch)) {
                return Err(Reason::Forbidden(ch));
            }
        }
    }
    if value.contains("..") {
        return Err(Reason::DotDot);
    }
    if field == CoordinateField::Group && value.starts_with('.') {
        return Err(Reason::EmptyGroupSegment);
    }
    if value.ends_with('.') {
        return Err(if field == CoordinateField::Group {
            Reason::EmptyGroupSegment
        } else {
            Reason::TrailingDot
        });
    }
    Ok(())
}

/// Whether `value` holds only the characters of Maven's id pattern,
/// `[A-Za-z0-9_.-]`. An empty value does.
pub fn is_maven_id_text(value: &str) -> bool {
    (value.bytes()).all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// True when `text` holds no character that would steer a terminal or hide
/// text from a reader: control characters (C0, DEL and C1, which include ESC,
/// BEL, CR, LF and tab), the line and paragraph separators, the interlinear
/// annotation controls, and every default-ignorable code point, which
/// covers the bidirectional overrides and isolates, zero-width characters,
/// variation selectors, Hangul fillers, the byte-order mark and the tag
/// characters. For free-text lock fields such as profile ids and system
/// paths, which have no coordinate charset.
pub fn is_terminal_safe(text: &str) -> bool {
    !text.chars().any(is_unsafe_char)
}

pub(crate) fn is_unsafe_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

#[cfg(test)]
mod tests {
    use super::{CoordinateField, is_terminal_safe, validate_coordinate_component};

    const ALL: [CoordinateField; 5] = [
        CoordinateField::Group,
        CoordinateField::Artifact,
        CoordinateField::Version,
        CoordinateField::Classifier,
        CoordinateField::Extension,
    ];

    #[test]
    fn accepts_real_world_coordinates() {
        for (field, value) in [
            (CoordinateField::Group, "org.springframework.boot"),
            (CoordinateField::Group, "io.github.some_user"),
            (CoordinateField::Artifact, "scala-library_2.13"),
            (CoordinateField::Version, "1.0.0-SNAPSHOT"),
            (CoordinateField::Version, "1.0-20240101.010101-7"),
            (CoordinateField::Version, "2.0.0+build.5"),
            (CoordinateField::Version, "1.0~rc1"),
            (CoordinateField::Version, "1_0"),
            (CoordinateField::Classifier, "linux-x86_64"),
            (CoordinateField::Classifier, "tests"),
            (CoordinateField::Extension, "jar"),
            (CoordinateField::Extension, "tar.gz"),
            (CoordinateField::Extension, "maven-plugin"),
        ] {
            validate_coordinate_component(field, value)
                .unwrap_or_else(|err| panic!("{field} {value:?}: {err}"));
        }
    }

    #[test]
    fn every_field_refuses_terminal_and_path_tricks() {
        let hostile = [
            "",
            "a\u{1b}[31mred",
            "a\u{7}",
            "a\rb",
            "1.0\n0123  org/x/y/1/y-1.jar",
            "a\tb",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{9b}b",
            "..",
            "a..b",
            "a/b",
            "a\\b",
            "a:b",
            "a?b",
            "a#b",
            "a@b",
            "a%2fb",
            "jar;x",
            "a*b",
            "a|b",
            "a\"b",
            "a<b",
            "a>b",
            "a b",
            "a\u{202e}b",
            "caf\u{e9}",
            "a.",
            ".",
        ];
        for field in ALL {
            for value in hostile {
                let err = validate_coordinate_component(field, value)
                    .expect_err(&format!("{field} {value:?} must be refused"));
                assert!(
                    !err.to_string().chars().any(char::is_control),
                    "the message must not carry control characters: {err:?}"
                );
            }
        }
    }

    #[test]
    fn group_and_artifact_follow_the_maven_id_rule() {
        for value in ["a+b", "a~b", "a!b", "a$b", "a,b", "a=b", "a'b"] {
            for field in [CoordinateField::Group, CoordinateField::Artifact] {
                validate_coordinate_component(field, value)
                    .expect_err(&format!("{field} {value:?}"));
            }
            validate_coordinate_component(CoordinateField::Version, value)
                .unwrap_or_else(|err| panic!("version {value:?}: {err}"));
        }
        validate_coordinate_component(CoordinateField::Group, ".org").expect_err("leading dot");
        validate_coordinate_component(CoordinateField::Artifact, ".hidden")
            .expect("an artifact may start with a dot");
    }

    #[test]
    fn refuses_components_longer_than_a_file_name() {
        let long = "a".repeat(256);
        validate_coordinate_component(CoordinateField::Artifact, &long).expect_err("too long");
        validate_coordinate_component(CoordinateField::Artifact, &long[..255]).expect("255 bytes");
    }

    #[test]
    fn terminal_safe_text_refuses_controls_and_invisible_characters() {
        assert!(is_terminal_safe("C:/Program Files/Java/lib/tools.jar"));
        assert!(is_terminal_safe("profil\u{e9}"));
        for unsafe_text in [
            "a\u{1b}]0;x\u{7}",
            "a\nb",
            "a\tb",
            "a\u{7f}b",
            "a\u{9b}[31m",
            "a\u{202e}b",
            "a\u{200b}b",
            "a\u{34f}b",
            "a\u{3164}",
            "a\u{fe0f}",
            "a\u{e0041}",
        ] {
            assert!(!is_terminal_safe(unsafe_text), "{unsafe_text:?}");
        }
    }
}
