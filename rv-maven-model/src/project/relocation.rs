//! Artifact relocation resolution for the effective project model.

use crate::PomError;
use crate::pom::Relocation;
use crate::properties::{ProjectInfo, PropertyMap};

pub(super) fn resolve_relocation(
    relocation: Option<Relocation>,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Option<Relocation>, PomError> {
    let Some(relocation) = relocation else {
        return Ok(None);
    };

    let group_id = resolve_relocation_field(&relocation.group_id, properties, project)?;
    let artifact_id = resolve_relocation_field(&relocation.artifact_id, properties, project)?;
    let version = resolve_relocation_field(&relocation.version, properties, project)?;
    let message = resolve_relocation_field(&relocation.message, properties, project)?;

    if group_id.is_none() && artifact_id.is_none() && version.is_none() && message.is_none() {
        return Ok(None);
    }

    Ok(Some(Relocation {
        group_id,
        artifact_id,
        version,
        message,
    }))
}

fn resolve_relocation_field(
    value: &Option<String>,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Option<String>, PomError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    let resolved = properties.interpolate_str(raw, project)?;
    if resolved.is_empty() {
        Ok(None)
    } else {
        Ok(Some(resolved))
    }
}
