use crate::model::Lineage;
use crate::{ActivationContext, Gav, License, ModelPolicy, ModelSource, Pom};

/// Effective package metadata after parent inheritance and interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveMetadata {
    /// The effective coordinates.
    pub gav: Gav,
    /// Licenses from the model or its nearest parent that declares licenses.
    pub licenses: Vec<License>,
}

impl EffectiveMetadata {
    /// Build metadata from the parent lineage without resolving dependency BOMs.
    pub async fn build<S: ModelSource>(
        pom: Pom,
        source: &S,
        policy: ModelPolicy,
        ctx: &ActivationContext,
    ) -> Result<Self, S::Error> {
        let model = Lineage::build(pom, source, policy, ctx).await?.activate()?;
        let licenses = model
            .pom
            .licenses
            .into_iter()
            .map(|license| {
                Ok(License {
                    name: model
                        .properties
                        .interpolate_opt(license.name.as_deref(), &model.project)?,
                    url: model
                        .properties
                        .interpolate_opt(license.url.as_deref(), &model.project)?,
                })
            })
            .collect::<Result<Vec<_>, crate::PomError>>()?;
        Ok(Self {
            gav: Gav {
                group_id: model.project.group_id,
                artifact_id: model.project.artifact_id,
                version: model.project.version,
            },
            licenses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EffectiveMetadata;
    use crate::{ActivationContext, MemorySource, ModelPolicy, Pom, ready};

    fn build(extra: &str) -> EffectiveMetadata {
        let parent = Pom::parse("<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version><properties><kind>Parent</kind></properties><licenses><license><name> ${kind} ${project.artifactId} </name><url> https://example.org/${kind} </url></license><license><name>Second</name></license></licenses></project>").unwrap();
        let child = Pom::parse(&format!("<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId><properties><kind>Child</kind></properties>{extra}<dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>missing-bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>")).unwrap();
        let source = MemorySource::new().with_parent("g", "parent", "1", parent);
        let result = ready(EffectiveMetadata::build(
            child,
            &source,
            ModelPolicy::DEPENDENCY,
            &ActivationContext::default(),
        ))
        .unwrap();
        assert!(
            source
                .lookups()
                .iter()
                .all(|lookup| !lookup.starts_with("import "))
        );
        result
    }

    #[test]
    fn licenses_inherit_and_interpolate_in_the_child_context() {
        for extra in ["", "<licenses/>"] {
            let metadata = build(extra);
            assert_eq!(metadata.licenses.len(), 2);
            assert_eq!(metadata.licenses[0].name.as_deref(), Some("Child child"));
            assert_eq!(
                metadata.licenses[0].url.as_deref(),
                Some("https://example.org/Child")
            );
        }
    }

    #[test]
    fn declared_licenses_replace_the_parent_list() {
        let metadata = build("<licenses><license><name>Own ${kind}</name></license></licenses>");
        assert_eq!(metadata.licenses.len(), 1);
        assert_eq!(metadata.licenses[0].name.as_deref(), Some("Own Child"));
    }

    #[test]
    fn absent_licenses_stay_absent() {
        let pom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>",
        )
        .unwrap();
        let metadata = ready(EffectiveMetadata::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::DEPENDENCY,
            &ActivationContext::default(),
        ))
        .unwrap();
        assert!(metadata.licenses.is_empty());
    }
}
