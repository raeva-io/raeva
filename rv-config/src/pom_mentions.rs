//! Which system property names the project's own files define or read.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use quick_xml::de::EntityResolver;
use quick_xml::events::Event;

/// Which of `names` the project reads: a POM of `poms` defines it as a
/// property, in any profile, or holds it in a value, as does
/// `.mvn/extensions.xml` at `root` or one of `texts`. A POM's or that
/// file's values are its element texts and attribute values as Maven's
/// parser reads them, references resolved and an element's text joined
/// across comments and CDATA sections. Any place in a value counts, as
/// Maven evaluates expressions such as `${session.systemProperties(name)}`
/// that name it inside, but the name a `-D` option sets, which only
/// defines the property for another process.
///
/// # Errors
///
/// Why a file cannot be read as XML, when it cannot.
pub(crate) fn mentioned(
    root: &Path,
    poms: &[PathBuf],
    texts: &[&str],
    names: &[&str],
) -> Result<BTreeSet<String>, String> {
    let mut unseen: Vec<&str> = names.to_vec();
    let mut found = BTreeSet::new();
    let mut take = |reads: &dyn Fn(&str) -> bool| {
        unseen.retain(|name| {
            let read = reads(name);
            if read {
                found.insert((*name).to_string());
            }
            !read
        });
    };
    for text in texts {
        take(&|name| reads(text, name));
    }
    let extensions = root.join(".mvn").join("extensions.xml");
    let extensions = extensions.is_file().then_some(extensions);
    for (path, is_pom) in
        (poms.iter().map(|path| (path, true))).chain(extensions.iter().map(|path| (path, false)))
    {
        let text = read_xml(path)?;
        let shown = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
        if is_pom {
            let pom = rv_maven_model::Pom::parse(&text).map_err(|error| shown(&error))?;
            let properties = (std::iter::once(&pom.properties))
                .chain(pom.profiles.iter().map(|profile| &profile.properties));
            for properties in properties {
                take(&|name| properties.get(name).is_some());
            }
        }
        xml_values(&text, |value| take(&|name| reads(value, name)))
            .map_err(|error| shown(&error))?;
    }
    Ok(found)
}

/// Whether `text` holds `name` other than as the name a `-D` option sets:
/// `-Dname` followed by `=`, whitespace, a quote or the end of `text`.
fn reads(text: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(at) = text[from..].find(name).map(|at| from + at) {
        let after = &text[at + name.len()..];
        let set = text[..at].ends_with("-D")
            && (after.is_empty()
                || after.starts_with(|next: char| next.is_whitespace() || "='\"".contains(next)));
        if !set {
            return true;
        }
        match text[at..].chars().next() {
            Some(first) => from = at + first.len_utf8(),
            None => return false,
        }
    }
    false
}

fn read_xml(path: &Path) -> Result<String, String> {
    let bytes = crate::read_project_input(path).map_err(|error| error.to_string())?;
    let text = rv_maven_model::decode_pom(&bytes);
    text.map(|text| text.into_owned())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Each element's text and each attribute value of the XML document `text`
/// as Maven's parser reads them: references resolved, and an element's text
/// joined across the comments, processing instructions, CDATA sections and
/// child elements in it.
fn xml_values(text: &str, mut each: impl FnMut(&str)) -> Result<(), quick_xml::Error> {
    let entity = |name: &str| rv_maven_model::MavenEntities.resolve(name);
    let mut reader = quick_xml::Reader::from_str(text);
    let mut open: Vec<String> = Vec::new();
    loop {
        match reader.read_event()? {
            Event::Start(element) => {
                attribute_values(&element, &mut each)?;
                open.push(String::new());
            }
            Event::Empty(element) => attribute_values(&element, &mut each)?,
            Event::End(_) => {
                if let Some(value) = open.pop() {
                    each(&value);
                }
            }
            Event::Text(part) => {
                if let Some(value) = open.last_mut() {
                    value.push_str(&part.decode()?);
                }
            }
            Event::CData(part) => {
                if let Some(value) = open.last_mut() {
                    value.push_str(&part.decode()?);
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(value) = open.last_mut() {
                    match reference.resolve_char_ref()? {
                        Some(character) => value.push(character),
                        None => {
                            let name = reference.decode()?;
                            match entity(&name) {
                                Some(resolved) => value.push_str(resolved),
                                None => value.push_str(&format!("&{name};")),
                            }
                        }
                    }
                }
            }
            Event::Eof if open.is_empty() => return Ok(()),
            Event::Eof => {
                let missing = quick_xml::errors::IllFormedError::MissingEndTag(String::new());
                return Err(missing.into());
            }
            _ => {}
        }
    }
}

fn attribute_values(
    element: &quick_xml::events::BytesStart<'_>,
    each: &mut impl FnMut(&str),
) -> Result<(), quick_xml::Error> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::InvalidAttr)?;
        let value = attribute
            .normalized_value_with(quick_xml::XmlVersion::Implicit1_0, 1, |name| {
                rv_maven_model::MavenEntities.resolve(name)
            })
            .unwrap_or_else(|_| {
                String::from_utf8_lossy(&attribute.value)
                    .into_owned()
                    .into()
            });
        each(&value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A POM holds a name in any spelling Maven's parser reads as that
    /// name: through a character reference, in an attribute too, or split by
    /// a comment or CDATA section. A longer name, a profile's properties and
    /// activation and `.mvn/extensions.xml` and the other texts hold names
    /// too; another project's POM does not.
    #[test]
    fn every_spelling_of_a_read_counts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".mvn")).unwrap();
        std::fs::write(
            root.join("pom.xml"),
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <description>${jdk&#46;decimal} ${jdk&#x2e;hex} ${jdk.<!-- c -->comment} \
             ${jdk.<![CDATA[cdata]]>} ${jdk<![CDATA[.]]>split} ${jdk&#46;brace&#125; \
             ${jdk.longer.name}</description>\
             <build><plugins><plugin><configuration><arg value=\"${jdk&#46;attribute}\"/>\
             </configuration></plugin></plugins></build>\
             <profiles><profile><id>p</id><activation><property><name>!jdk.activation</name>\
             </property></activation><properties><jdk.profile>1</jdk.profile></properties>\
             </profile></profiles></project>",
        )
        .unwrap();
        std::fs::write(
            root.join(".mvn/extensions.xml"),
            "<extensions><extension><version>${jdk&#46;extension}</version></extension>\
             </extensions>",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(
            root.join("other/pom.xml"),
            "<project><description>${jdk.other}</description></project>",
        )
        .unwrap();
        let names = [
            "jdk.decimal",
            "jdk.hex",
            "jdk.comment",
            "jdk.cdata",
            "jdk.split",
            "jdk.brace",
            "jdk.attribute",
            "jdk.activation",
            "jdk.profile",
            "jdk.extension",
            "jdk.config",
            "jdk.longer",
            "jdk.other",
        ];
        let found = mentioned(
            root,
            &[root.join("pom.xml")],
            &["-Dlibrary.version=${jdk.config}"],
            &names,
        )
        .unwrap();
        let found: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(
            found,
            [
                "jdk.activation",
                "jdk.attribute",
                "jdk.brace",
                "jdk.cdata",
                "jdk.comment",
                "jdk.config",
                "jdk.decimal",
                "jdk.extension",
                "jdk.hex",
                "jdk.longer",
                "jdk.profile",
                "jdk.split",
            ]
        );
    }

    /// A name inside any expression Maven may evaluate counts, such as
    /// `${session.systemProperties(name)}` or a quoted map key, as does one
    /// in a `-D` value. A name the files do not hold or hold only in a
    /// comment does not.
    #[test]
    fn a_name_anywhere_in_the_text_counts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("pom.xml"),
            "<project><version>${session.systemProperties(jdk.system)}</version>\
             <description>${session.userProperties(jdk.user)} \
             ${session.request.systemProperties(jdk.request)} \
             ${project.properties(jdk.project)} ${session.systemProperties['jdk.quoted']} \
             ${session.request.userProperties(\"jdk.double\")} \
             ${session.systemProperties(jdk&#46;reference)}</description>\
             <!-- jdk.comment --></project>",
        )
        .unwrap();
        let names = [
            "jdk.system",
            "jdk.user",
            "jdk.request",
            "jdk.project",
            "jdk.quoted",
            "jdk.double",
            "jdk.reference",
            "jdk.comment",
            "jdk.value",
            "jdk.absent",
        ];
        let found = mentioned(
            root,
            &[root.join("pom.xml")],
            &["-Dx=${session.systemProperties(jdk.value)}"],
            &names,
        )
        .unwrap();
        let found: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(
            found,
            [
                "jdk.double",
                "jdk.project",
                "jdk.quoted",
                "jdk.reference",
                "jdk.request",
                "jdk.system",
                "jdk.user",
                "jdk.value",
            ]
        );
    }

    /// An element or attribute named after a name, such as a surefire
    /// `systemPropertyVariables` entry, and a `-D` option that sets it, such
    /// as one in an `argLine` or `.mvn/jvm.config`, only define the property
    /// for another process, and a comment is read by no one, so they do not
    /// count. Each place is judged alone: the same name read elsewhere, as
    /// `-Dname=${name}` does, a property definition, an activation, element
    /// text that a CDATA section spells as an element and a longer `-D` name
    /// count.
    #[test]
    fn a_definition_for_another_process_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("pom.xml"),
            "<project><build><plugins><plugin><configuration>\
             <systemPropertyVariables><java.awt.headless>true</java.awt.headless>\
             <jdk.empty/><jdk.spaced >1</jdk.spaced ></systemPropertyVariables>\
             <argLine>-Dfile.encoding=UTF-8 -Djdk.quoted=\"1\" -Djdk.bare</argLine>\
             <arg value=\"-Djdk.attribute\"/><arg>-Djdk.reference&#61;1</arg>\
             <!-- -Djdk.comment=1 ${jdk.comment} --><x jdk.attribute.name=\"1\"/><argLine>-Djdk.self=${jdk.self}</argLine>\
             <classifier>${user.language}</classifier><skip>${java.awt.headful}</skip>\
             <a><![CDATA[<jdk.cdata>]]></a><b>-Djdk.longer.name=1</b>\
             </configuration></plugin></plugins></build>\
             <properties><jdk.property>1</jdk.property></properties>\
             <profiles><profile><id>p</id><activation><property><name>jdk.activation</name>\
             </property></activation></profile></profiles></project>",
        )
        .unwrap();
        let names = [
            "java.awt.headless",
            "jdk.empty",
            "jdk.spaced",
            "file.encoding",
            "jdk.quoted",
            "jdk.bare",
            "jdk.attribute",
            "jdk.reference",
            "jdk.comment",
            "jdk.attribute.name",
            "jdk.text",
            "jdk.self",
            "user.language",
            "java.awt.headful",
            "jdk.cdata",
            "jdk.longer",
            "jdk.property",
            "jdk.activation",
            "jdk.both",
        ];
        let found = mentioned(
            root,
            &[root.join("pom.xml")],
            &["-Djdk.text=1", "-Djdk.both=${jdk.both}"],
            &names,
        )
        .unwrap();
        let found: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(
            found,
            [
                "java.awt.headful",
                "jdk.activation",
                "jdk.both",
                "jdk.cdata",
                "jdk.longer",
                "jdk.property",
                "jdk.self",
                "user.language",
            ]
        );
    }

    /// A POM or `.mvn/extensions.xml` that is not well-formed XML fails the
    /// read, as does a POM that cannot be read.
    #[test]
    fn a_file_that_does_not_parse_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let pom = root.join("pom.xml");
        let names = ["jdk.x"];
        assert!(mentioned(root, std::slice::from_ref(&pom), &[], &names).is_err());
        std::fs::write(&pom, "<project><description>${jdk.y}</project>").unwrap();
        assert!(mentioned(root, std::slice::from_ref(&pom), &[], &names).is_err());
        std::fs::write(&pom, "<project/>").unwrap();
        assert!(mentioned(root, std::slice::from_ref(&pom), &[], &names).is_ok());
        std::fs::create_dir_all(root.join(".mvn")).unwrap();
        std::fs::write(root.join(".mvn/extensions.xml"), "<extensions>").unwrap();
        assert!(mentioned(root, std::slice::from_ref(&pom), &[], &names).is_err());
    }
}
