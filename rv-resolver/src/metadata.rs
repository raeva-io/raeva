use std::sync::Arc;

use rv_config::Config;
use rv_lock::Platform;
use rv_maven_model::{
    ActivationContext, EffectiveMetadata, ImportCoord, ModelPolicy, ModelSource, Parent,
    ParentLookup, Pom, parent_has_expression,
};

use crate::parent_resolver::{LocalParents, anchor_parent_path, build_activation_context};
use crate::{Workspace, WorkspaceModule};

impl Workspace {
    /// Build module metadata from local parents and the supplied repository evidence.
    pub async fn module_metadata<S: ModelSource>(
        &self,
        module: &WorkspaceModule,
        config: &Config,
        platform: &Platform,
        evidence: &S,
    ) -> Result<EffectiveMetadata, S::Error> {
        let base_dir = self
            .root()
            .join(&module.pom_path)
            .parent()
            .unwrap()
            .to_path_buf();
        let local = LocalParents::new(base_dir.clone(), self.local_parent_boundary())
            .cached_in(Arc::clone(&self.parents));
        let mut activation = build_activation_context(Some(base_dir), config, Some(platform));
        let mut pom = module.pom().clone();
        self.apply_root_maven_config(&mut activation, &mut pom);
        EffectiveMetadata::build(
            pom,
            &MetadataSource {
                workspace: self,
                local,
                evidence,
                dependency: false,
            },
            ModelPolicy::PROJECT,
            &activation,
        )
        .await
    }

    /// Build dependency metadata with the same property context as dependency resolution.
    pub async fn dependency_metadata<S: ModelSource>(
        &self,
        pom: Pom,
        config: &Config,
        platform: &Platform,
        evidence: &S,
    ) -> Result<EffectiveMetadata, S::Error> {
        let mut activation = ActivationContext::new(config.model_environment(
            platform.os(),
            platform.arch(),
            platform.jdk(),
        ));
        (activation.system_properties, activation.expanded_properties) =
            self.root_user_properties(&activation);
        let boundary = self.local_parent_boundary();
        EffectiveMetadata::build(
            pom,
            &MetadataSource {
                workspace: self,
                local: LocalParents::new(boundary.clone(), boundary)
                    .cached_in(Arc::clone(&self.parents)),
                evidence,
                dependency: true,
            },
            ModelPolicy::DEPENDENCY,
            &activation,
        )
        .await
    }

    /// The raw POM of `module` standing in for a parent or BOM. Payload
    /// validation runs before inheritance, so it carries the module's
    /// effective group and artifact rather than raw `${revision}` text. Its
    /// `<relativePath>` is anchored on its own directory, and when no local
    /// file is its parent, a parent version holding an expression is the
    /// parent's reactor identity.
    pub(crate) fn stand_in_pom(&self, module: &WorkspaceModule) -> Pom {
        let mut pom = module.pom().clone();
        pom.group_id = Some(module.gav().group_id.clone());
        pom.artifact_id = Some(module.gav().artifact_id.clone());
        anchor_parent_path(&mut pom, &self.root().join(&module.pom_path));
        if module.local_parents().is_empty()
            && let Some(parent) = &mut pom.parent
            && parent.version.contains("${")
            && let Some(version) = self.unique_version(&parent.group_id, &parent.artifact_id)
        {
            parent.version = version;
        }
        pom
    }
}

struct MetadataSource<'a, S> {
    workspace: &'a Workspace,
    local: LocalParents,
    evidence: &'a S,
    dependency: bool,
}

impl<S> MetadataSource<'_, S> {
    /// A dependency model's parent that is a reactor module, as dependency
    /// resolution reads it.
    fn reactor_parent(&self, parent: &Parent) -> Option<Pom> {
        if !self.dependency {
            return None;
        }
        let module = self.workspace.get(&rv_maven_model::Gav {
            group_id: parent.group_id.clone(),
            artifact_id: parent.artifact_id.clone(),
            version: parent.version.clone(),
        })?;
        Some(self.workspace.stand_in_pom(module))
    }
}

impl<S: ModelSource> ModelSource for MetadataSource<'_, S> {
    type Error = S::Error;

    async fn parent(
        &self,
        parent: &mut Parent,
        lookup: ParentLookup,
    ) -> Result<Option<Pom>, Self::Error> {
        if let Some(pom) = self.local.load(parent) {
            return Ok(Some(pom));
        }
        if parent_has_expression(parent) {
            return Ok(None);
        }
        if let Some(pom) = self.reactor_parent(parent) {
            return Ok(Some(pom));
        }
        // The evidence leaves a range that selected a reactor module to it.
        match self.evidence.parent(parent, lookup).await? {
            Some(pom) => Ok(Some(pom)),
            None => Ok(self.reactor_parent(parent)),
        }
    }

    async fn import(&self, _bom: ImportCoord<'_>) -> Result<Option<Pom>, Self::Error> {
        unreachable!("metadata builds do not import BOMs")
    }
}
