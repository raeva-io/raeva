//! A POM of the project as Maven's model reader reads it strictly.
//!
//! `DefaultModelBuilder` reads a POM from a file, as the project's own
//! POMs and the POMs at their `<relativePath>` are, with the strict
//! `MavenXpp3Reader` and fails the build with "Malformed POM" when it
//! refuses one. A POM from a repository is read leniently, which skips
//! what strict reading refuses. Strict reading refuses an element the
//! model class does not have at that place, an attribute it does not take,
//! text other than spaces, tabs and line breaks between elements, and a
//! root element other than `<project>`. `strict_model.txt` holds what each
//! class takes.

use std::sync::LazyLock;

use quick_xml::events::Event;
use quick_xml::events::attributes::Attribute;
use rv_maven_types::bounded;

use crate::PomError;

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Class(&'static str),
    /// The item's name, and its class when it is not text.
    List(&'static str, Option<&'static str>),
    Properties,
    Any,
}

struct Class {
    name: &'static str,
    attributes: Vec<&'static str>,
    elements: Vec<(&'static str, Kind)>,
}

static CLASSES: LazyLock<Vec<Class>> = LazyLock::new(|| {
    (include_str!("strict_model.txt").lines())
        .filter(|line| !line.starts_with('#'))
        .map(read_class)
        .collect()
});

fn read_class(line: &'static str) -> Class {
    let mut words = line.split(' ');
    let mut class = Class {
        name: words.next().unwrap_or_default(),
        attributes: Vec::new(),
        elements: Vec::new(),
    };
    for word in words {
        if let Some(attribute) = word.strip_prefix('@') {
            class.attributes.push(attribute);
            continue;
        }
        let (names, kind) = if let Some(names) = word.strip_suffix('~') {
            (names, Kind::Any)
        } else if let Some(names) = word.strip_suffix('*') {
            (names, Kind::Properties)
        } else if let Some((names, list)) = (word.strip_suffix(']')).and_then(|w| w.split_once('['))
        {
            match list.split_once(':') {
                Some((item, of)) => (names, Kind::List(item, Some(of))),
                None => (names, Kind::List(list, None)),
            }
        } else if let Some((names, of)) = word.split_once(':') {
            (names, Kind::Class(of))
        } else {
            (word, Kind::Text)
        };
        for name in names.split('|') {
            class.elements.push((name, kind));
        }
    }
    class
}

fn class(name: &str) -> Option<&'static Class> {
    CLASSES.iter().find(|class| class.name == name)
}

/// An open element and what it may hold.
enum Open {
    Class(&'static Class),
    List(&'static str, Option<&'static str>),
    Properties,
    Text(String),
    Any,
}

impl Open {
    fn child(&self, name: &str) -> Result<Open, String> {
        let unrecognised = || format!("Unrecognised tag: '{}'", bounded(name));
        let of = |kind: Option<&str>| match kind.and_then(class) {
            Some(class) => Open::Class(class),
            None => Open::Text(name.to_string()),
        };
        Ok(match self {
            Open::Class(class) => {
                match (class.elements.iter()).find(|(element, _)| *element == name) {
                    Some((_, Kind::Text)) => Open::Text(name.to_string()),
                    Some((_, Kind::Class(of))) => class_of(of),
                    Some((_, Kind::List(item, of))) => Open::List(item, *of),
                    Some((_, Kind::Properties)) => Open::Properties,
                    Some((_, Kind::Any)) => Open::Any,
                    None => return Err(unrecognised()),
                }
            }
            Open::List(item, kind) if name == *item => of(*kind),
            Open::List(..) => return Err(unrecognised()),
            Open::Properties => Open::Text(name.to_string()),
            Open::Text(text) => {
                return Err(format!(
                    "the element <{}> inside the text of <{}>",
                    bounded(name),
                    bounded(text)
                ));
            }
            Open::Any => Open::Any,
        })
    }

    /// Whether text other than spaces, tabs and line breaks may stand here.
    fn takes_text(&self) -> bool {
        matches!(self, Open::Text(_) | Open::Any)
    }
}

fn class_of(name: &str) -> Open {
    class(name).map_or(Open::Any, Open::Class)
}

/// MXParser's whitespace.
fn blank(text: &[u8]) -> bool {
    text.iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

/// Check the POM file `bytes` as Maven reads a POM of the project, naming
/// it by `path` when it is not the one being read. What the lenient reader
/// refuses too is left to [`crate::Pom::parse`].
pub fn check_project_pom(bytes: &[u8], path: Option<&str>) -> Result<(), PomError> {
    let Ok(xml) = crate::decode_pom(bytes) else {
        return Ok(());
    };
    match check(&xml) {
        Err(PomError::Strict {
            reason,
            line,
            column,
            ..
        }) => Err(PomError::Strict {
            path: path.map(str::to_string),
            reason,
            line,
            column,
        }),
        _ => Ok(()),
    }
}

fn check(xml: &str) -> Result<(), PomError> {
    let root = crate::document::root_element(xml)?;
    let offset = root.as_ptr() as usize - xml.as_ptr() as usize;
    let mut reader = quick_xml::Reader::from_str(root);
    let mut open: Vec<Open> = Vec::new();
    loop {
        let at = offset + usize::try_from(reader.buffer_position()).unwrap_or(0);
        let refuse = |reason: String| {
            let before = &xml[..at.min(xml.len())];
            let line_start = before.rfind('\n').map_or(0, |index| index + 1);
            PomError::Strict {
                path: None,
                reason,
                line: before.matches('\n').count() + 1,
                column: before[line_start..].chars().count() + 1,
            }
        };
        let (tag, empty) = match reader.read_event() {
            Err(_) | Ok(Event::Eof) => return Ok(()),
            Ok(Event::Start(tag)) => (tag, false),
            Ok(Event::Empty(tag)) => (tag, true),
            Ok(Event::End(_)) => {
                open.pop();
                continue;
            }
            Ok(Event::Text(text)) => match open.last() {
                Some(within) if !within.takes_text() && !blank(&text) => {
                    return Err(refuse("text between elements".to_string()));
                }
                _ => continue,
            },
            Ok(Event::CData(text)) => match open.last() {
                Some(within) if !within.takes_text() && !blank(&text) => {
                    return Err(refuse("text between elements".to_string()));
                }
                _ => continue,
            },
            Ok(Event::GeneralRef(reference)) => match open.last() {
                Some(within)
                    if !within.takes_text()
                        && !(reference.resolve_char_ref().ok().flatten())
                            .is_some_and(|c| c.is_ascii() && blank(&[c as u8])) =>
                {
                    return Err(refuse("text between elements".to_string()));
                }
                _ => continue,
            },
            Ok(_) => continue,
        };
        let name = String::from_utf8_lossy(tag.name().as_ref()).into_owned();
        let element = match open.last() {
            None if name == "project" => class_of("Model"),
            None => {
                return Err(refuse(format!(
                    "Expected root element 'project' but found '{}'",
                    bounded(&name)
                )));
            }
            Some(within) => within.child(&name).map_err(refuse)?,
        };
        if let Open::Class(class) = &element {
            let unknown = (tag.attributes().with_checks(false).flatten())
                .map(|Attribute { key, .. }| String::from_utf8_lossy(key.as_ref()).into_owned())
                .find(|key| !key.contains(':') && !class.attributes.contains(&key.as_str()));
            if let Some(key) = unknown {
                return Err(refuse(format!(
                    "Unknown attribute '{}' for tag '{}'",
                    bounded(&key),
                    bounded(&name)
                )));
            }
        }
        if !empty {
            open.push(element);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_the_model_names_is_in_it() {
        for class in CLASSES.iter() {
            for (name, kind) in &class.elements {
                let of = match kind {
                    Kind::Class(of) | Kind::List(_, Some(of)) => of,
                    _ => continue,
                };
                assert!(super::class(of).is_some(), "{}.{name}: {of}", class.name);
            }
        }
    }

    /// Each case as the strict and lenient `MavenXpp3Reader` of Maven
    /// 3.9.12 and 3.10.0 read it: `Some(reason)` where strict reading
    /// refuses the POM and lenient reading takes it.
    #[test]
    fn strict_reading_refuses_what_maven_refuses() {
        let cases = [
            (
                "<project><profiles><profiles><profile><id>p</id></profile></profiles>\
                 </profiles></project>",
                Some("Unrecognised tag: 'profiles' at line 1, column 20"),
            ),
            ("<project><foo/></project>", Some("Unrecognised tag: 'foo'")),
            (
                "<project><scope>test</scope></project>",
                Some("Unrecognised tag: 'scope'"),
            ),
            (
                "<project><ArtifactId>x</ArtifactId></project>",
                Some("'ArtifactId'"),
            ),
            (
                "<project><m:artifactId xmlns:m=\"u\">x</m:artifactId></project>",
                Some("Unrecognised tag: 'm:artifactId'"),
            ),
            (
                "<project><build><plugins><plugin><executions><execution><goals><goal>a</goal>\
                 <x>b</x></goals></execution></executions></plugin></plugins></build></project>",
                Some("Unrecognised tag: 'x'"),
            ),
            (
                "<project><dependencies><dependency foo=\"x\"/></dependencies></project>",
                Some("Unknown attribute 'foo' for tag 'dependency'"),
            ),
            (
                "<project foo=\"x\"/>",
                Some("Unknown attribute 'foo' for tag 'project'"),
            ),
            (
                "<project><dependencies><dependency xmlns=\"u\"/></dependencies></project>",
                Some("Unknown attribute 'xmlns' for tag 'dependency'"),
            ),
            (
                "<pom/>",
                Some("Expected root element 'project' but found 'pom'"),
            ),
            ("<m:project xmlns:m=\"u\"/>", Some("found 'm:project'")),
            (
                "<project>junk<groupId>g</groupId></project>",
                Some("text between"),
            ),
            (
                "<project><groupId>g</groupId>x</project>",
                Some("text between"),
            ),
            ("<project><![CDATA[x]]></project>", Some("text between")),
            ("<project>&#160;</project>", Some("text between")),
            ("<project>\u{c}</project>", Some("text between")),
            (
                "<project><profiles><profile><activation>x<jdk>1</jdk></activation></profile>\
                 </profiles></project>",
                Some("text between"),
            ),
            (
                "<project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"x\" \
                 xsi:schemaLocation=\"y\" xml:lang=\"en\"><modelVersion>4.0.0</modelVersion>\
                 </project>",
                None,
            ),
            (
                "<project>&#32;<![CDATA[ ]]> <!-- c --> <?pi x?>\n\t</project>",
                None,
            ),
            (
                "<project><dependencies foo=\"x\"/><groupId a=\"b\">g</groupId><modules>\
                 <module c=\"d\">m</module></modules><properties e=\"f\"><a b=\"c\">1</a><b/>\
                 </properties></project>",
                None,
            ),
            (
                "<project><scm child.scm.url.inherit.append.path=\"false\"/><distributionManagement>\
                 <site child.site.url.inherit.append.path=\"false\"/></distributionManagement>\
                 <organisation><name>x</name></organisation></project>",
                None,
            ),
            (
                "<project><build><plugins><plugin><configuration a=\"b\"><foo><bar/>text</foo>\
                 </configuration><goals><x/></goals></plugin></plugins></build><ciManagement>\
                 <notifiers><notifier><configuration><a>1</a></configuration></notifier>\
                 </notifiers></ciManagement><profiles/></project>",
                None,
            ),
        ];
        for (xml, expected) in cases {
            let result = check(xml).map_err(|error| error.to_string());
            match expected {
                Some(reason) => {
                    let error = result.expect_err(xml);
                    assert!(error.contains(reason), "{xml}: {error}");
                }
                None => assert!(result.is_ok(), "{xml}: {result:?}"),
            }
        }
    }
}
