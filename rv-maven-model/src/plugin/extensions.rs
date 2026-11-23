//! `.mvn/extensions.xml`, the core extensions Maven loads before it reads
//! any project.

use serde::Deserialize;

use crate::PomError;

/// An `<extension>` of `.mvn/extensions.xml`, trimmed and not interpolated.
/// Maven 3.9 expands `${...}` in its coordinates from the user and system
/// properties only, and resolves it from the plugin repositories of the
/// settings, since no project is read yet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CoreExtension {
    /// The `<groupId>`, empty when absent.
    #[serde(default)]
    pub group_id: String,
    /// The `<artifactId>`, empty when absent.
    #[serde(default)]
    pub artifact_id: String,
    /// The `<version>`, which Maven requires.
    pub version: Option<String>,
    /// The `<classLoadingStrategy>`, `self-first` when absent.
    #[serde(default = "default_strategy")]
    pub class_loading_strategy: String,
}

fn default_strategy() -> String {
    "self-first".to_string()
}

#[derive(Deserialize)]
struct CoreExtensionsXml {
    #[serde(default, rename = "extension")]
    extensions: Vec<CoreExtension>,
}

/// Parse the text of a `.mvn/extensions.xml`, with the limits and the
/// markup checks of [`crate::Pom::parse`].
pub fn parse_core_extensions(xml: &str) -> Result<Vec<CoreExtension>, PomError> {
    if xml.len() > crate::Pom::MAX_SIZE {
        return Err(PomError::InvalidModel(
            ".mvn/extensions.xml exceeds the 5MB limit".to_string(),
        ));
    }
    let root = crate::document::root_element(xml)?;
    let mut deserializer =
        quick_xml::de::Deserializer::from_str_with_resolver(root, crate::xml::MavenEntities);
    let mut parsed = CoreExtensionsXml::deserialize(&mut deserializer)?.extensions;
    for extension in &mut parsed {
        crate::pom::trim_str(&mut extension.group_id);
        crate::pom::trim_str(&mut extension.artifact_id);
        crate::pom::trim_opt(&mut extension.version);
        crate::pom::trim_str(&mut extension.class_loading_strategy);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_extensions_in_order() {
        let extensions = parse_core_extensions(
            "<?xml version='1.0' encoding='UTF-8'?>\n<!-- core -->\n<extensions \
             xmlns='http://maven.apache.org/EXTENSIONS/1.0.0'>\
             <extension><groupId> fr.jcgay.maven </groupId><artifactId>maven-profiler</artifactId>\
             <version>\n3.3\n</version></extension>\
             <extension><groupId>io.takari.maven</groupId><artifactId>takari-smart-builder\
             </artifactId><version>${smart.version}</version>\
             <classLoadingStrategy>plugin</classLoadingStrategy></extension></extensions>",
        )
        .unwrap();
        let coordinates: Vec<_> = (extensions.iter())
            .map(|extension| {
                format!(
                    "{}:{}:{}:{}",
                    extension.group_id,
                    extension.artifact_id,
                    extension.version.as_deref().unwrap_or("-"),
                    extension.class_loading_strategy
                )
            })
            .collect();
        assert_eq!(
            coordinates,
            [
                "fr.jcgay.maven:maven-profiler:3.3:self-first",
                "io.takari.maven:takari-smart-builder:${smart.version}:plugin"
            ]
        );
        assert!(parse_core_extensions("<extensions/>").unwrap().is_empty());
        assert!(parse_core_extensions("<extensions><extension>").is_err());
    }
}
