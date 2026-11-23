//! Profile activation and interpolation for the effective project model.

use crate::properties::PropertyMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::activation::ConditionReads;
use crate::{Activation, PomError};

/// Interpolate the profile activations of one POM in a parent chain the way
/// Maven 3.9's `DefaultModelBuilder.getInterpolatedProfiles` does, before
/// inheritance: from that POM's own `<properties>`, then user properties,
/// then system properties. No `${project.*}` value is available, and a file
/// condition also sees `${basedir}` and `${project.basedir}` as the input
/// project's directory and, in the Maven 3.10 mode, `${project.rootDirectory}`
/// as its root.
pub(crate) fn interpolate_lineage_activations(
    pom: &mut crate::Pom,
    ctx: &crate::ActivationContext,
) -> Result<(), PomError> {
    if pom
        .profiles
        .iter()
        .all(|profile| profile.activation.is_none())
    {
        return Ok(());
    }
    // A `-D` value may hold a host value `.mvn/maven.config` expanded, so
    // condition text is checked against the same map with those values
    // changed: text that changes with them counts as the host's.
    // Comparison expansions discard their reads so probe values cannot
    // enter the lock's input recipes.
    let user_keys: Vec<&String> = ctx.expanded_properties.iter().collect();
    let needs_properties = pom
        .profiles
        .iter()
        .filter_map(|p| p.activation.as_ref())
        .any(|a| {
            a.property
                .iter()
                .flat_map(|p| [&p.name, &p.value])
                .chain(
                    a.os.iter()
                        .flat_map(|os| [&os.name, &os.family, &os.arch, &os.version]),
                )
                .chain([&a.jdk])
                .chain(a.file.iter().flat_map(|f| [&f.exists, &f.missing]))
                .flatten()
                .any(|value| value.contains("${"))
        });
    let condition_properties = |changed: bool| {
        if !needs_properties {
            return PropertyMap::new();
        }
        let mut map = activation_interpolation_map(ctx);
        if changed {
            for key in &user_keys {
                if let Some(value) = map.get(key).cloned() {
                    let value = format!("{value}\u{0}");
                    if map.is_external(key) {
                        map.insert_external(key.as_str(), value);
                    } else {
                        map.insert(key.as_str(), value);
                    }
                }
            }
        }
        map.extend(pom.declared_properties());
        map
    };
    let properties = condition_properties(false);
    let changed_user_values = (!user_keys.is_empty()).then(|| condition_properties(true));
    let file_properties = with_basedir(&properties, ctx);
    let changed_file_properties = changed_user_values
        .as_ref()
        .map(|map| with_basedir(map, ctx));
    let declared = pom.own_properties.as_ref().unwrap_or(&pom.properties);
    // A condition reads a settings.xml property where its expansion looks
    // the name up, through whatever prefix or nesting, and neither a `-D`
    // value, the POM's own property, nor a file path's project directory
    // answers first.
    let record_inputs = |text: &str, recorder: &crate::ModelEnvironment, file: bool| {
        if !text.contains("${") {
            return false;
        }
        let mut user_value = false;
        let map = if file { &file_properties } else { &properties };
        let (_, names) =
            map.interpolate_str_exact_names(text, &ctx.environment.selection(&Arc::default()));
        let directory = |name: &str| file && ctx.is_file_directory(name);
        for name in names {
            if declared.get(&name).is_none() && !directory(&name) {
                user_value |= (ctx.properties.contains_key(&name)
                    && !(name == "packaging" && ctx.packaging_injected))
                    || ctx.system_properties.contains_key(&name)
                    || [
                        "maven.multiModuleProjectDirectory",
                        "java.home",
                        "env.JAVA_HOME",
                    ]
                    .contains(&name.as_str());
                recorder.record_user_property(&name);
            }
            if ctx.settings_property_names.contains(&name)
                && !ctx.properties.contains_key(&name)
                && declared.get(&name).is_none()
                && !directory(&name)
            {
                recorder.record(crate::HostInput::SettingsProperty(name));
            }
        }
        user_value
    };
    for profile in &mut pom.profiles {
        let Some(mut activation) = profile.activation.take() else {
            continue;
        };
        // Whether interpolating each condition read `java.version`, which
        // a lookup the condition records may hide.
        let [java_jdk, java_property, java_os, java_file] =
            std::array::from_fn(|_| Arc::new(AtomicBool::new(false)));
        let file = activation.file.take();
        let os = activation.os.take();
        let property = activation.property.take();
        let written = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
        let (exists_written, missing_written) = file
            .as_ref()
            .map(|file| (written(&file.exists), written(&file.missing)))
            .unwrap_or_default();
        // The host values interpolation reads stay with the condition they
        // went into, and count only where it is tested.
        let jdk_reads = ctx.environment.selection(&java_jdk);
        let (probed, probe) = jdk_reads.probed();
        let with_changed_user_values = changed_user_values
            .as_ref()
            .map(|changed| {
                interpolate_activation(activation.clone(), |value| {
                    changed.interpolate_str_exact(value, &probed.detached())
                })
            })
            .transpose()?;
        let mut jdk_user_value = false;
        let mut interpolated = interpolate_activation(activation, |value| {
            jdk_user_value |= record_inputs(value, &probed, false);
            properties.interpolate_str_exact(value, &probed)
        })?;
        let property_reads = ctx.environment.selection(&java_property);
        let (property_probed, property_probe) = property_reads.probed();
        let property_name_reads = ctx.environment.selection(&java_property);
        let (property_name_probed, property_name_probe) = property_name_reads.probed();
        let mut property_user_value = false;
        let mut property_name_user_value = false;
        let mut property_activation = |map: &PropertyMap,
                                       record: bool|
         -> Result<
            Option<crate::activation::ActivationProperty>,
            PomError,
        > {
            let mut activated = property.clone();
            if let Some(property) = &mut activated {
                for (is_name, value) in [(true, &mut property.name), (false, &mut property.value)] {
                    let Some(value) = value else { continue };
                    let recorder = if is_name {
                        &property_name_probed
                    } else {
                        &property_probed
                    };
                    if record {
                        let user_value = record_inputs(value, recorder, false);
                        property_user_value |= user_value;
                        property_name_user_value |= is_name && user_value;
                    }
                    *value = if record {
                        map.interpolate_str_exact(value, recorder)?
                    } else {
                        map.interpolate_str_exact(value, &recorder.detached())?
                    };
                }
            }
            Ok(activated)
        };
        interpolated.property = property_activation(&properties, true)?;
        let changed_property = changed_user_values
            .as_ref()
            .map(|map| property_activation(map, false))
            .transpose()?;
        interpolated.property_name_from_input = property_name_user_value
            || property_name_probe.load(Ordering::Relaxed)
            || changed_property.as_ref().is_some_and(|other| {
                other.as_ref().and_then(|property| property.name.as_ref())
                    != interpolated
                        .property
                        .as_ref()
                        .and_then(|property| property.name.as_ref())
            });
        if interpolated.property_name_from_input {
            if let Some(expression) = property
                .as_ref()
                .and_then(|property| property.name.as_ref())
            {
                let (_, names) = properties
                    .replay_exact_names(expression, &ctx.environment.selection(&java_property));
                let default_packaging = ctx.default_packaging.clone();
                let properties = names
                    .into_iter()
                    .filter_map(|name| declared.get(&name).cloned().map(|value| (name, value)))
                    .collect();
                property_reads.record(crate::HostInput::UserPropertyLookup {
                    expression: expression.clone(),
                    properties,
                    from_host: property_name_probe.load(Ordering::Relaxed),
                    default_packaging,
                    source: ctx.property_source,
                });
            }
        } else {
            for input in property_name_reads.take_reads() {
                property_reads.record(input);
            }
        }
        interpolated.jdk_from_input = jdk_user_value
            || probe.load(Ordering::Relaxed)
            || with_changed_user_values.is_some_and(|other| other.jdk != interpolated.jdk);
        interpolated.property_from_input = property_user_value
            || property_name_probe.load(Ordering::Relaxed)
            || property_probe.load(Ordering::Relaxed)
            || changed_property.is_some_and(|other| other != interpolated.property);
        let os_reads = ctx.environment.selection(&java_os);
        interpolated.os = interpolate_activation(
            crate::Activation {
                os,
                ..crate::Activation::default()
            },
            |value| {
                record_inputs(value, &os_reads, false);
                properties.interpolate_str_exact(value, &os_reads)
            },
        )?
        .os;
        let mut file_reads = BTreeSet::new();
        if let Some(mut file) = file {
            // Maven tests `<exists>` when it is not empty, else `<missing>`;
            // only the tested path's provenance counts, but the reads that
            // emptied `<exists>` decided which one that is.
            let mut tested = false;
            let mut skipped = BTreeSet::new();
            for (value, written) in [
                (&mut file.exists, exists_written),
                (&mut file.missing, missing_written),
            ] {
                let Some(path) = value.as_mut() else {
                    continue;
                };
                let expression = path.clone();
                // Only the path Maven tests, or an empty one before it,
                // keeps its reads.
                let path_java = Arc::new(AtomicBool::new(false));
                let reads = ctx.environment.selection(&path_java);
                let (probed, probe) = reads.probed();
                let user_value = record_inputs(path, &probed, true);
                let expanded = file_properties.interpolate_str_exact(path, &probed)?;
                let changed = changed_file_properties
                    .as_ref()
                    .map(|changed| changed.interpolate_str_exact(path, &probed.detached()))
                    .transpose()?;
                let from_host = user_value
                    || probe.load(Ordering::Relaxed)
                    || changed.is_some_and(|changed| changed != expanded);
                *path = expanded;
                // Maven aligns a written condition to the project directory
                // once it is interpolated, so one that expands to nothing
                // names the directory itself.
                let unread = names_an_unread_property(path, ctx);
                if let Some(basedir) = ctx.base_dir.as_ref().filter(|_| written && !unread) {
                    *path = align_to_base_directory(path, basedir, &ctx.environment);
                }
                if !tested && path_java.load(Ordering::Relaxed) {
                    java_file.store(true, Ordering::Relaxed);
                }
                if !tested && path.is_empty() {
                    skipped.extend(reads.take_reads());
                } else if !tested {
                    tested = true;
                    interpolated.path_from_host = from_host;
                    file_reads = reads.take_reads();
                    if from_host {
                        let (_, names) = file_properties.replay_exact_names(
                            &expression,
                            &ctx.environment.selection(&java_file),
                        );
                        let default_packaging = ctx.default_packaging.clone();
                        let properties: std::collections::BTreeMap<_, _> = names
                            .into_iter()
                            .filter(|name| !ctx.is_file_directory(name))
                            .filter_map(|name| {
                                declared.get(&name).cloned().map(|value| (name, value))
                            })
                            .collect();
                        let public_name = |name: &str| {
                            let reads = |text: &str| {
                                crate::properties::expression_names(text)
                                    .into_iter()
                                    .any(|read| {
                                        ["", "project.properties.", "pom.properties."]
                                            .into_iter()
                                            .any(|prefix| read.strip_prefix(prefix) == Some(name))
                                    })
                            };
                            reads(&expression) || properties.values().any(|value| reads(value))
                        };
                        file_reads.retain(|input| match input {
                            crate::HostInput::UserProperty(name)
                            | crate::HostInput::UserOverride(name)
                            | crate::HostInput::SettingsProperty(name) => public_name(name),
                            crate::HostInput::Env(name) => public_name(&format!("env.{name}")),
                            crate::HostInput::InterpolationLookup { .. } => false,
                            _ => true,
                        });
                        file_reads.insert(crate::HostInput::FileLookup {
                            expression,
                            properties,
                            base_dir: ctx.base_dir.clone(),
                            default_packaging,
                            source: ctx.property_source,
                        });
                    }
                }
            }
            file_reads.extend(skipped);
            interpolated.file = Some(file);
        }
        interpolated.interpolation_reads = ConditionReads {
            os: os_reads.take_reads(),
            file: file_reads,
            jdk: jdk_reads.take_reads(),
            property: property_reads.take_reads(),
            java: [&java_os, &java_file, &java_jdk, &java_property]
                .map(|read| read.load(Ordering::Relaxed)),
        };
        profile.activation = Some(interpolated);
    }
    Ok(())
}

/// The `<file>` paths of a profile from outside the POM, such as a
/// settings.xml profile, as Maven's `ProfileActivationFilePathInterpolator`
/// expands them: `${basedir}` and `${project.basedir}`, then the user
/// properties, then the system properties, aligned to the project directory.
/// A path that cannot be interpolated stays as written.
pub(crate) fn interpolate_external_file(
    file: &mut crate::ActivationFile,
    ctx: &crate::ActivationContext,
) {
    let properties = with_basedir(&activation_interpolation_map(ctx), ctx);
    let environment = ctx.environment.detached();
    for value in [&mut file.exists, &mut file.missing].into_iter().flatten() {
        if value.is_empty() {
            continue;
        }
        let (interpolated, names) = properties.interpolate_str_exact_names(value, &environment);
        for name in names {
            if !ctx.is_file_directory(&name) {
                ctx.environment.record_user_property(&name);
            }
        }
        if let Ok(interpolated) = interpolated {
            *value = interpolated;
        }
        if let Some(basedir) = ctx
            .base_dir
            .as_ref()
            .filter(|_| !names_an_unread_property(value, ctx))
        {
            *value = align_to_base_directory(value, basedir, &ctx.environment);
        }
        // As `file_active` tests it.
        *value = crate::activation::without_trailing_separator(value).to_string();
    }
}

/// Whether `path` still names a property raeva does not answer on `ctx`.
/// Aligning it would let a `..` after the reference drop it from the path,
/// and the refusal it calls for with it.
fn names_an_unread_property(path: &str, ctx: &crate::ActivationContext) -> bool {
    (crate::properties::expression_names(path).into_iter()).any(|name| match name {
        "java.home" | "env.JAVA_HOME" => {
            ctx.environment.target_jdk().is_some() && ctx.environment.host_java_home().is_none()
        }
        name => {
            crate::activation::host_property(&ctx.environment, name)
                == Some(crate::activation::HostProperty::Unread)
                || (name.strip_prefix("env.")).is_some_and(|var| ctx.environment.hides_env(var))
        }
    })
}

/// System properties, then active settings.xml profile properties, then
/// user properties, as Maven interpolates profile activation and
/// settings.xml `<file>` paths before the model's own properties or
/// `${basedir}`.
fn activation_interpolation_map(ctx: &crate::ActivationContext) -> PropertyMap {
    ctx.activation_properties(&PropertyMap::new())
}

fn with_basedir(map: &PropertyMap, ctx: &crate::ActivationContext) -> PropertyMap {
    let mut map = map.clone();
    for (name, directory) in ctx.file_directories() {
        map.insert(name, directory);
    }
    ctx.insert_launcher_root(&mut map);
    map
}

/// Maven's `DefaultPathTranslator.alignToBaseDirectory`: either slash
/// becomes the host's separator, a path that starts at a root is made
/// absolute by [`crate::properties::java_absolute_path`], and a relative
/// path is joined to the project directory with its `.` and `..` segments
/// removed by name, as `URI.normalize` removes them, whether or not they
/// exist.
pub(crate) fn align_to_base_directory(
    path: &str,
    basedir: &std::path::Path,
    environment: &crate::ModelEnvironment,
) -> String {
    use std::path::{Component, Path, PathBuf};
    let path = crate::properties::with_host_separators(path);
    if let Some(absolute) =
        crate::properties::java_absolute_path(Path::new(&path), basedir, environment)
    {
        return absolute.to_string_lossy().into_owned();
    }
    let mut aligned = PathBuf::new();
    for component in basedir.join(&path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(aligned.components().next_back(), Some(Component::Normal(_))) {
                    aligned.pop();
                } else if !aligned.has_root() {
                    aligned.push("..");
                }
            }
            component => aligned.push(component),
        }
    }
    aligned.to_string_lossy().into_owned()
}

/// Interpolate activation fields before profile selection, including while
/// reading raw lineage POMs whose parents have not been resolved yet.
pub(crate) fn interpolate_activation(
    mut activation: Activation,
    mut interpolate: impl FnMut(&str) -> Result<String, PomError>,
) -> Result<Activation, PomError> {
    let property = activation.property.iter_mut();
    let os = activation.os.iter_mut();
    let file = activation.file.iter_mut();
    let fields = (property.flat_map(|property| [&mut property.name, &mut property.value]))
        .chain(os.flat_map(|os| [&mut os.name, &mut os.family, &mut os.arch, &mut os.version]))
        .chain([&mut activation.jdk])
        .chain(file.flat_map(|file| [&mut file.exists, &mut file.missing]));
    for value in fields.flatten() {
        *value = interpolate(value)?;
    }
    Ok(activation)
}

#[cfg(test)]
mod tests {
    use super::align_to_base_directory;
    use std::path::{MAIN_SEPARATOR_STR, Path};

    #[test]
    fn private_activation_names_retain_only_public_expressions() {
        use crate::{ActivationContext, HostInput, ModelEnvironment, Pom};
        for expression in ["${selector}", "${alias}"] {
            let mut pom = Pom::parse(&format!(
                "<project><properties><alias>${{selector}}</alias></properties>\
                 <profiles><profile><id>selected</id><activation><property>\
                 <name>{expression}</name><value>yes</value></property></activation>\
                 </profile></profiles></project>"
            ))
            .unwrap();
            let mut ctx = ActivationContext::new(ModelEnvironment::default());
            ctx.properties.extend([
                ("selector".to_string(), "private-key".to_string()),
                ("private-key".to_string(), "yes".to_string()),
            ]);
            super::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
            let (active, reads) = pom.profiles[0]
                .activation
                .as_ref()
                .unwrap()
                .evaluate("selected", &ctx)
                .unwrap();
            assert!(active);
            assert_eq!(reads.len(), 1);
            let HostInput::UserPropertyLookup {
                expression: retained,
                properties,
                from_host,
                ..
            } = reads.first().unwrap()
            else {
                panic!("expected an expression lookup");
            };
            assert_eq!(retained, expression);
            assert!(!from_host);
            assert!(!format!("{properties:?}").contains("private-key"));
            let selection =
                crate::activation::select_profiles(&pom.profiles, &crate::PropertyMap::new(), &ctx)
                    .unwrap();
            assert!(!selection.host_decides(&pom.profiles, 0));
        }
    }

    #[test]
    fn literal_user_property_file_paths_are_private() {
        use crate::{ActivationContext, HostInput, ModelEnvironment, Pom};
        let mut pom = Pom::parse(
            "<project><profiles><profile><id>file</id><activation><file>\
             <exists>${activation.path}</exists></file></activation></profile></profiles></project>",
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut ctx = ActivationContext::new(ModelEnvironment::default());
        ctx.base_dir = Some(directory.path().to_path_buf());
        ctx.properties
            .insert("activation.path".into(), "private-file".into());
        super::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
        let activation = pom.profiles[0].activation.as_ref().unwrap();
        assert!(activation.path_from_host);
        let (active, reads) = activation.evaluate("file", &ctx).unwrap();
        assert!(!active);
        assert_eq!(
            reads,
            [
                HostInput::UserProperty("activation.path".into()),
                HostInput::FileLookup {
                    expression: "${activation.path}".into(),
                    properties: Default::default(),
                    base_dir: ctx.base_dir.clone(),
                    default_packaging: None,
                    source: crate::PropertySource::User,
                },
            ]
            .into()
        );
    }

    /// Maven tests a `<file>` path that starts at a root without a drive,
    /// such as `\marker`, on the drive it was started on, as
    /// `java.io.File.getAbsolutePath` does, not on the project's drive.
    #[cfg(windows)]
    #[test]
    fn a_rooted_file_condition_is_on_the_working_drive() {
        use crate::{ActivationContext, Pom};
        let file = tempfile::NamedTempFile::new().unwrap();
        let marker = file.path().to_string_lossy().into_owned();
        let (drive, rooted) = marker.split_at(2);
        let other = if drive.eq_ignore_ascii_case("Q:") {
            "P:"
        } else {
            "Q:"
        };
        let working = file.path().parent().unwrap();
        let mut ctx = ActivationContext::new(
            (crate::HostSnapshot::for_testing(&[]).with_working_directory(working))
                .host_environment(),
        );
        ctx.base_dir = Some(format!(r"{other}\work\app").into());
        let mut pom = Pom::parse(&format!(
            "<project><profiles><profile><id>file</id><activation><file>\
             <exists>{rooted}</exists></file></activation></profile></profiles></project>"
        ))
        .unwrap();
        super::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
        let activation = pom.profiles[0].activation.as_ref().unwrap();
        let (active, _) = activation.evaluate("file", &ctx).unwrap();
        assert!(active, "{rooted} from {other}");
        assert!(ctx.file_condition_exists(rooted), "{rooted} from {other}");
    }

    /// Without a drive of its own, the working directory is a UNC path,
    /// under which `java.io.File` puts a rooted path whole.
    #[cfg(windows)]
    #[test]
    fn a_rooted_path_under_a_unc_working_directory() {
        let environment = |directory: &str| {
            crate::HostSnapshot::for_testing(&[])
                .with_working_directory(Path::new(directory))
                .host_environment()
        };
        let base = Path::new(r"R:\work\app");
        for (working, path, expected) in [
            (r"c:\x07", r"\marker", r"c:\marker"),
            (r"C:\", "/a/marker", r"C:\a\marker"),
            (
                r"\\server\share\dir",
                r"\marker",
                r"\\server\share\dir\marker",
            ),
            (r"C:\x07", r"D:\marker", r"D:\marker"),
        ] {
            let aligned = align_to_base_directory(path, base, &environment(working));
            assert_eq!(aligned, expected, "{path} in {working}");
        }
    }

    #[test]
    fn aligns_like_maven_path_translator() {
        let base = if cfg!(windows) {
            r"C:\work\app"
        } else {
            "/work/app"
        };
        let expected = |relative: &str| {
            Path::new(base)
                .join(relative.replace('/', MAIN_SEPARATOR_STR))
                .to_string_lossy()
                .into_owned()
        };
        let base = Path::new(base);
        let environment = crate::ModelEnvironment::default();
        assert_eq!(
            align_to_base_directory("absent/../marker", base, &environment),
            expected("marker")
        );
        assert_eq!(
            align_to_base_directory(r".\marker", base, &environment),
            expected("marker")
        );
        assert_eq!(
            align_to_base_directory("a/./b/../c", base, &environment),
            expected("a/c")
        );
        assert_eq!(
            align_to_base_directory("", base, &environment),
            base.to_string_lossy()
        );
    }
}
