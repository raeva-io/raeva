use std::collections::HashMap;

use super::*;

/// A class file of `name` extending `superclass`, `@Named(named)` when
/// given, with a no-argument constructor of `code` (built over the pool)
/// and a method for each of `methods`.
pub(crate) fn class_file(
    name: &str,
    superclass: &str,
    named: Option<&str>,
    methods: &[&str],
    code: impl FnOnce(&mut Pool) -> Vec<u8>,
) -> Vec<u8> {
    class_with(name, superclass, &[], named, |pool| {
        let mut all = vec![("<init>", "()V", Some(code(pool)))];
        all.extend((methods.iter()).map(|method| (*method, "()Ljava/lang/String;", None)));
        all
    })
}

/// A class file of `name` extending `superclass` and implementing
/// `interfaces`, `@Named(named)` when given, with `methods` (built over the
/// pool): name, descriptor and code, if any.
pub(crate) fn class_with<'a>(
    name: &str,
    superclass: &str,
    interfaces: &[&str],
    named: Option<&str>,
    methods: impl FnOnce(&mut Pool) -> Vec<(&'a str, &'a str, Option<Vec<u8>>)>,
) -> Vec<u8> {
    let mut pool = Pool::default();
    let this = pool.class(name);
    let parent = pool.class(superclass);
    let interfaces: Vec<u16> = interfaces.iter().map(|name| pool.class(name)).collect();
    let code_name = pool.utf8("Code");
    let methods: Vec<(u16, u16, Option<Vec<u8>>)> = (methods(&mut pool).into_iter())
        .map(|(method, descriptor, code)| (pool.utf8(method), pool.utf8(descriptor), code))
        .collect();
    let annotation = named.map(|value| {
        let attribute = pool.utf8("RuntimeVisibleAnnotations");
        let kind = pool.utf8("Ljavax/inject/Named;");
        let element = pool.utf8("value");
        let value = pool.utf8(value);
        (attribute, kind, element, value)
    });
    let mut out = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
    out.extend_from_slice(&(pool.count + 1).to_be_bytes());
    out.extend_from_slice(&pool.bytes);
    out.extend_from_slice(&[0, 0x21]);
    out.extend_from_slice(&this.to_be_bytes());
    out.extend_from_slice(&parent.to_be_bytes());
    out.extend_from_slice(&(interfaces.len() as u16).to_be_bytes());
    for interface in interfaces {
        out.extend_from_slice(&interface.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(methods.len() as u16).to_be_bytes());
    for (method, descriptor, code) in methods {
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&method.to_be_bytes());
        out.extend_from_slice(&descriptor.to_be_bytes());
        let Some(body) = code else {
            out.extend_from_slice(&[0, 0]);
            continue;
        };
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&code_name.to_be_bytes());
        out.extend_from_slice(&(12 + body.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0, 2, 0, 1]);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&[0, 0, 0, 0]);
    }
    match annotation {
        Some((attribute, kind, element, value)) => {
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&attribute.to_be_bytes());
            out.extend_from_slice(&11u32.to_be_bytes());
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&element.to_be_bytes());
            out.push(b's');
            out.extend_from_slice(&value.to_be_bytes());
        }
        None => out.extend_from_slice(&[0, 0]),
    }
    out
}

#[derive(Default)]
pub(crate) struct Pool {
    bytes: Vec<u8>,
    count: u16,
    utf8: HashMap<String, u16>,
}

impl Pool {
    fn push(&mut self, entry: &[u8]) -> u16 {
        self.bytes.extend_from_slice(entry);
        self.count += 1;
        self.count
    }

    pub(crate) fn utf8(&mut self, text: &str) -> u16 {
        if let Some(&index) = self.utf8.get(text) {
            return index;
        }
        let mut entry = vec![1];
        entry.extend_from_slice(&(text.len() as u16).to_be_bytes());
        entry.extend_from_slice(text.as_bytes());
        let index = self.push(&entry);
        self.utf8.insert(text.to_string(), index);
        index
    }

    pub(crate) fn class(&mut self, name: &str) -> u16 {
        let name = self.utf8(name);
        self.push(&[7, (name >> 8) as u8, name as u8])
    }

    /// `ldc` of the string `text`.
    pub(crate) fn ldc(&mut self, text: &str) -> Vec<u8> {
        let text = self.utf8(text);
        let index = self.push(&[8, (text >> 8) as u8, text as u8]);
        vec![0x13, (index >> 8) as u8, index as u8]
    }

    /// `op` (`invokespecial` or `invokevirtual`) of `owner.name descriptor`.
    pub(crate) fn call(&mut self, op: u8, owner: &str, name: &str, descriptor: &str) -> Vec<u8> {
        let owner = self.class(owner);
        let (name, descriptor) = (self.utf8(name), self.utf8(descriptor));
        let signature = self.push(&[
            12,
            (name >> 8) as u8,
            name as u8,
            (descriptor >> 8) as u8,
            descriptor as u8,
        ]);
        let method = self.push(&[
            10,
            (owner >> 8) as u8,
            owner as u8,
            (signature >> 8) as u8,
            signature as u8,
        ]);
        vec![op, (method >> 8) as u8, method as u8]
    }
}

pub(crate) const DEFAULT: &str = "org/apache/maven/artifact/handler/DefaultArtifactHandler";
const ALOAD_0: u8 = 0x2a;

/// maven-hpi-plugin 3.1841's `ExecutableWarArtifactHandler`, as javac
/// compiles it.
pub(crate) fn executable_war_class() -> Vec<u8> {
    let name = "org/jenkinsci/maven/plugins/hpi/extensions/ExecutableWarArtifactHandler";
    class_file(name, DEFAULT, Some("executable-war"), &[], |pool| {
        let mut code = vec![ALOAD_0];
        code.extend(pool.ldc("executable-war"));
        code.extend(pool.call(0xb7, DEFAULT, "<init>", "(Ljava/lang/String;)V"));
        code.push(ALOAD_0);
        code.extend(pool.ldc("war"));
        code.extend(pool.call(0xb6, name, "setExtension", "(Ljava/lang/String;)V"));
        code.push(ALOAD_0);
        code.extend(pool.ldc("java"));
        code.extend(pool.call(0xb6, name, "setLanguage", "(Ljava/lang/String;)V"));
        code.extend([ALOAD_0, 0x04]);
        code.extend(pool.call(0xb6, name, "setAddedToClasspath", "(Z)V"));
        code.push(0xb1);
        code
    })
}

fn reader(entries: Vec<(&str, Vec<u8>)>) -> impl Fn(&str) -> Option<Vec<u8>> {
    let entries: HashMap<String, Vec<u8>> = (entries.into_iter())
        .map(|(name, bytes)| (name.to_string(), bytes))
        .collect();
    move |name| entries.get(name).cloned()
}

/// The class files of a realm whose jars hold one copy of each, as `read`
/// gives them.
fn one_jar(read: &dyn Fn(&str) -> Option<Vec<u8>>) -> impl Fn(&str) -> ClassFiles + '_ {
    |name| {
        (read(name).into_iter())
            .map(|bytes| ("t:own:1".to_string(), bytes))
            .collect()
    }
}

fn summary(handlers: &[(String, Result<ArtifactHandler, String>)]) -> Vec<String> {
    (handlers.iter())
        .map(|(type_, handler)| match handler {
            Ok(handler) => format!(
                "{type_} {} {} {} {}",
                handler.extension,
                handler.classifier.as_deref().unwrap_or("-"),
                handler.includes_dependencies,
                handler.added_to_classpath
            ),
            Err(reason) => format!("{type_} unreadable: {reason}"),
        })
        .collect()
}

/// maven-hpi-plugin 3.38 and older define their handlers in
/// components.xml, over `DefaultArtifactHandler`.
#[test]
fn reads_the_handlers_of_a_components_xml() {
    let xml = "<component-set><components>\
        <component><role>org.apache.maven.lifecycle.mapping.LifecycleMapping</role>\
        <role-hint>hpi</role-hint></component>\
        <component><role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
        <role-hint>hpi</role-hint>\
        <implementation>org.apache.maven.artifact.handler.DefaultArtifactHandler</implementation>\
        <configuration><extension>hpi</extension><type>hudson-plugin</type>\
        <packaging>hpi</packaging><language>java</language>\
        <addedToClasspath>true</addedToClasspath></configuration></component>\
        <component><role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
        <role-hint>executable-war</role-hint>\
        <implementation>org.apache.maven.artifact.handler.DefaultArtifactHandler</implementation>\
        <configuration><type>executable-war</type><extension>war</extension>\
        </configuration></component>\
        <component><role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
        <role-hint>bundle-tests</role-hint>\
        <configuration><type>bundle-tests</type><classifier>tests</classifier>\
        <includesDependencies>TRUE</includesDependencies></configuration></component>\
        </components></component-set>";
    let read = reader(vec![(
        "META-INF/plexus/components.xml",
        xml.as_bytes().to_vec(),
    )]);
    assert_eq!(
        summary(&read_artifact_handlers(&read, &one_jar(&read)).unwrap()),
        [
            "hpi hpi - false true",
            "executable-war war - false false",
            "bundle-tests bundle-tests tests true false",
        ]
    );
}

/// maven-hpi-plugin 3.49 and later define them as Sisu `@Named` classes,
/// whose constructors raeva reads; a static initializer changes nothing.
#[test]
fn reads_a_sisu_named_handler_class() {
    let jm = "org/x/JmArtifactHandler";
    let base = "org/x/AbstractModuleHandler";
    let base_class = class_file(base, DEFAULT, None, &[], |pool| {
        let mut code = vec![ALOAD_0];
        code.extend(pool.ldc("jenkins-module"));
        code.extend(pool.call(0xb7, DEFAULT, "<init>", "(Ljava/lang/String;)V"));
        code.push(ALOAD_0);
        code.extend(pool.ldc("jm"));
        code.extend(pool.call(0xb6, base, "setExtension", "(Ljava/lang/String;)V"));
        code.push(0xb1);
        code
    });
    let jm_class = class_file(jm, base, Some("jm"), &["<clinit>"], |pool| {
        let mut code = vec![ALOAD_0];
        code.extend(pool.call(0xb7, base, "<init>", "()V"));
        code.push(0xb1);
        code
    });
    let index = "org.jenkinsci.maven.plugins.hpi.extensions.ExecutableWarArtifactHandler\n\
                 org.x.JmArtifactHandler\norg.x.NotAHandler\norg.x.Missing\n";
    let other = class_file(
        "org/x/NotAHandler",
        "java/lang/Object",
        Some("x"),
        &[],
        |_| vec![0xb1],
    );
    let read = reader(vec![
        (
            "META-INF/sisu/javax.inject.Named",
            index.as_bytes().to_vec(),
        ),
        (
            "org/jenkinsci/maven/plugins/hpi/extensions/ExecutableWarArtifactHandler.class",
            executable_war_class(),
        ),
        ("org/x/JmArtifactHandler.class", jm_class),
        ("org/x/AbstractModuleHandler.class", base_class),
        ("org/x/NotAHandler.class", other),
    ]);
    assert_eq!(
        summary(&read_artifact_handlers(&read, &one_jar(&read)).unwrap()),
        ["executable-war war - false true", "jm jm - false false"]
    );
}

/// Sisu reads its index as Java's `readLine` splits it, at `\n`, `\r` or
/// both, drops what follows a `#`, trims what Java's `trim` does and
/// takes each class once, at its first line. Each class is read once.
#[test]
fn reads_a_sisu_index_as_sisu_does() {
    let index = "# generated\r\n org.jenkinsci.maven.plugins.hpi.extensions.ExecutableWarArtifactHandler\
                 # a comment\rorg.jenkinsci.maven.plugins.hpi.extensions.ExecutableWarArtifactHandler\n\
                 \u{a0}org.jenkinsci.maven.plugins.hpi.extensions.ExecutableWarArtifactHandler\n"
        .repeat(1000);
    let entries = reader(vec![
        ("META-INF/sisu/javax.inject.Named", index.into_bytes()),
        (
            "org/jenkinsci/maven/plugins/hpi/extensions/ExecutableWarArtifactHandler.class",
            executable_war_class(),
        ),
    ]);
    let reads = std::cell::RefCell::new(HashMap::<String, usize>::new());
    let read = |name: &str| {
        *reads.borrow_mut().entry(name.to_string()).or_default() += 1;
        entries(name)
    };
    assert_eq!(
        summary(&read_artifact_handlers(&read, &one_jar(&read)).unwrap()),
        ["executable-war war - false true"]
    );
    let reads = reads.into_inner();
    assert!(reads.values().all(|&count| count == 1), "{reads:?}");
    let nbsp =
        "\u{a0}org/jenkinsci/maven/plugins/hpi/extensions/ExecutableWarArtifactHandler.class";
    assert_eq!(reads.get(nbsp), Some(&1), "{reads:?}");
}

/// A handler whose values come from code raeva does not read is refused
/// with a reason, never guessed.
#[test]
fn refuses_a_handler_it_cannot_read() {
    let name = "org/x/Odd";
    let overriding = class_file(name, DEFAULT, Some("odd"), &["getExtension"], |_| {
        vec![0xb1]
    });
    let branching = class_file(name, DEFAULT, Some("odd"), &[], |pool| {
        let mut code = vec![ALOAD_0];
        code.extend(pool.call(0xb7, DEFAULT, "<init>", "()V"));
        code.extend([0xa7, 0, 0, 0xb1]);
        code
    });
    // Loads that pile up 64 KiB strings stop at a handler's stack depth.
    let piling = class_file(name, DEFAULT, Some("odd"), &[], |pool| {
        let long = "x".repeat(0xFFFF);
        let mut code = Vec::new();
        for _ in 0..1000 {
            code.extend(pool.ldc(&long));
        }
        code.push(0xb1);
        code
    });
    // Every method may name one 64 KiB constant; reading them keeps no copy.
    let long = "x".repeat(0xFFFF);
    let naming = class_file(name, DEFAULT, Some("odd"), &[long.as_str(); 0xFFFE], |_| {
        vec![0xb1]
    });
    let reasons: Vec<String> = [overriding, branching, piling, naming]
        .into_iter()
        .map(|class| {
            let read = reader(vec![
                ("META-INF/sisu/javax.inject.Named", b"org.x.Odd".to_vec()),
                ("org/x/Odd.class", class),
            ]);
            summary(&read_artifact_handlers(&read, &one_jar(&read)).unwrap()).join("")
        })
        .collect();
    assert_eq!(
        reasons,
        [
            "odd unreadable: org.x.Odd declares methods besides constructors",
            "odd unreadable: org.x.Odd runs instruction 0xa7",
            "odd unreadable: org.x.Odd keeps more values on its stack than a handler does",
            "odd unreadable: org.x.Odd declares methods besides constructors",
        ]
    );
    // Truncated or lying bytes are no handler, not a panic.
    let bytes = executable_war_class();
    for len in 0..bytes.len() {
        let read = reader(vec![
            ("META-INF/sisu/javax.inject.Named", b"org.x.Odd".to_vec()),
            ("org/x/Odd.class", bytes[..len].to_vec()),
        ]);
        assert!(
            read_artifact_handlers(&read, &one_jar(&read))
                .unwrap()
                .is_empty(),
            "{len}"
        );
    }
}

const HANDLER: &str = "org/apache/maven/artifact/handler/ArtifactHandler";

/// A class like nbm-maven-plugin 14.5's `NbmArtifactHandler`, `@Named(named)`
/// over `superclass`, implementing `interfaces`, whose `getExtension`
/// returns `extension` and whose other getters return constants, with
/// `getDirectory` computed as javac compiles it.
fn implementing_class(
    name: &str,
    superclass: &str,
    interfaces: &[&str],
    named: &str,
    extension: Option<&str>,
) -> Vec<u8> {
    class_with(name, superclass, interfaces, Some(named), |pool| {
        let mut init = vec![ALOAD_0];
        init.extend(pool.call(0xb7, superclass, "<init>", "()V"));
        init.push(0xb1);
        let mut get_extension = match extension {
            Some(extension) => pool.ldc(extension),
            None => vec![ALOAD_0, 0xb4, 0, 1],
        };
        get_extension.push(0xb0);
        let mut packaging = pool.ldc(named);
        packaging.push(0xb0);
        let mut directory = vec![ALOAD_0];
        directory.extend(pool.call(0xb6, name, "getPackaging", "()Ljava/lang/String;"));
        directory.push(0xb0);
        let string = "()Ljava/lang/String;";
        vec![
            ("<init>", "()V", Some(init)),
            ("getExtension", string, Some(get_extension)),
            ("getClassifier", string, Some(vec![0x01, 0xb0])),
            ("getPackaging", string, Some(packaging)),
            ("isIncludesDependencies", "()Z", Some(vec![0x04, 0xac])),
            ("getLanguage", string, Some(vec![0x01, 0xb0])),
            ("isAddedToClasspath", "()Z", Some(vec![0x03, 0xac])),
            ("getDirectory", string, Some(directory)),
        ]
    })
}

/// A `@Named` class that implements `ArtifactHandler` itself, as
/// nbm-maven-plugin 14.5's `nbm` handler does, is read from the constants
/// its getters return, also through an interface of the realm that extends
/// `ArtifactHandler`. One that computes a getter, or implements the
/// interface below another superclass, is refused; a `@Named` class that
/// is no handler, as a Plexus archiver is, is no type.
#[test]
fn reads_a_handler_that_implements_the_interface() {
    let index = "org.x.Nbm\norg.x.Via\norg.x.Computed\norg.x.Below\norg.x.Archiver\n";
    let nbm = implementing_class(
        "org/x/Nbm",
        "java/lang/Object",
        &[HANDLER],
        "nbm",
        Some("jar"),
    );
    let via = implementing_class(
        "org/x/Via",
        "java/lang/Object",
        &["org/x/Typed"],
        "via",
        Some("v"),
    );
    let typed = class_with("org/x/Typed", "java/lang/Object", &[HANDLER], None, |_| {
        Vec::new()
    });
    let computed = implementing_class(
        "org/x/Computed",
        "java/lang/Object",
        &[HANDLER],
        "computed",
        None,
    );
    let below = implementing_class("org/x/Below", "org/x/Base", &[], "below", Some("b"));
    let base = class_with("org/x/Base", "java/lang/Object", &[HANDLER], None, |_| {
        Vec::new()
    });
    let archiver = class_with(
        "org/x/Archiver",
        "org/x/AbstractArchiver",
        &["org/codehaus/plexus/archiver/Archiver"],
        Some("nbm"),
        |_| Vec::new(),
    );
    let abstract_archiver = class_with(
        "org/x/AbstractArchiver",
        "java/lang/Object",
        &[],
        None,
        |_| Vec::new(),
    );
    let own = reader(vec![
        (
            "META-INF/sisu/javax.inject.Named",
            index.as_bytes().to_vec(),
        ),
        ("org/x/Nbm.class", nbm),
        ("org/x/Via.class", via),
        ("org/x/Computed.class", computed),
        ("org/x/Below.class", below),
        ("org/x/Archiver.class", archiver),
    ]);
    // The interfaces and superclasses are in another jar of the realm.
    let others = reader(vec![
        ("org/x/Typed.class", typed),
        ("org/x/Base.class", base),
        ("org/x/AbstractArchiver.class", abstract_archiver),
    ]);
    let realm = |name: &str| own(name).or_else(|| others(name));
    assert_eq!(
        summary(&read_artifact_handlers(&own, &one_jar(&realm)).unwrap()),
        [
            "nbm jar - true false",
            "via v - true false",
            "computed unreadable: org.x.Computed computes getExtension",
            "below unreadable: org.x.Below implements ArtifactHandler below a superclass raeva \
             does not read",
        ]
    );
}

/// A realm's jars that define a type alike give it once; jars that define
/// it differently make it unreadable, as raeva does not follow which one
/// Maven ranks first. Within one jar the first definition counts.
#[test]
fn a_realm_refuses_a_type_its_jars_define_differently() {
    let handler = |extension: &str| Ok(ArtifactHandler::plain(extension));
    let merged = merge_realm_handlers([
        (
            "t:own:1".to_string(),
            vec![
                ("same".to_string(), handler("zip")),
                ("twice".to_string(), handler("a")),
                ("twice".to_string(), handler("b")),
                ("other".to_string(), handler("x")),
            ],
        ),
        (
            "t:dep:1".to_string(),
            vec![
                ("same".to_string(), handler("zip")),
                ("other".to_string(), handler("y")),
                ("new".to_string(), handler("n")),
            ],
        ),
    ]);
    assert_eq!(
        summary(&merged),
        [
            "same zip - false true",
            "twice a - false true",
            "other unreadable: t:own:1 and t:dep:1 in one extension realm define it differently",
            "new n - false true",
        ]
    );
}

/// A jar of a realm: its coordinates and entries.
type RealmJar = (&'static str, Vec<(&'static str, Vec<u8>)>);

/// The class files of a realm of `jars` as the realm's reader gives them.
fn realm_of(jars: Vec<RealmJar>) -> impl Fn(&str) -> ClassFiles {
    move |name| {
        let mut copies: ClassFiles = Vec::new();
        for (coord, entries) in &jars {
            for (entry, bytes) in entries {
                if *entry == name && !copies.iter().any(|(_, known)| known == bytes) {
                    copies.push((coord.to_string(), bytes.clone()));
                }
            }
        }
        copies
    }
}

/// A class two jars of a realm define differently makes a handler that
/// reads it unreadable, as the realm loads the first jar's copy and raeva
/// does not follow the realm's order: a superclass, a `components.xml`
/// implementation, and a `@Named` class itself, under each name a copy
/// gives. Jars that define the class alike read as one.
#[test]
fn a_realm_refuses_a_handler_class_its_jars_define_differently() {
    let base = "org/x/Base";
    let base_class = |fat: u8| {
        class_file(base, DEFAULT, None, &[], |pool| {
            let mut code = vec![ALOAD_0];
            code.extend(pool.ldc("zip"));
            code.extend(pool.call(0xb7, DEFAULT, "<init>", "(Ljava/lang/String;)V"));
            code.extend([ALOAD_0, fat]);
            code.extend(pool.call(0xb6, base, "setIncludesDependencies", "(Z)V"));
            code.push(0xb1);
            code
        })
    };
    let handler_class = |named: &str| {
        class_file("org/x/Handler", base, Some(named), &[], |pool| {
            let mut code = vec![ALOAD_0];
            code.extend(pool.call(0xb7, base, "<init>", "()V"));
            code.push(0xb1);
            code
        })
    };
    let own = reader(vec![
        (
            "META-INF/sisu/javax.inject.Named",
            b"org.x.Handler\n".to_vec(),
        ),
        (
            "META-INF/plexus/components.xml",
            b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>plexus</role-hint><implementation>org.x.Base</implementation>\
              </component></components></component-set>"
                .to_vec(),
        ),
    ]);
    let read = |other_handler: Vec<u8>, z_base: Vec<u8>, a_base: Vec<u8>| {
        let realm = realm_of(vec![
            (
                "t:own:1",
                vec![("org/x/Handler.class", handler_class("zip"))],
            ),
            ("t:z-base:1", vec![("org/x/Base.class", z_base)]),
            (
                "t:a-base:1",
                vec![
                    ("org/x/Base.class", a_base),
                    ("org/x/Handler.class", other_handler),
                ],
            ),
        ]);
        summary(&read_artifact_handlers(&own, &realm).unwrap())
    };
    let base_differs = "t:z-base:1 and t:a-base:1 in one extension realm define class \
                        org.x.Base differently";
    assert_eq!(
        read(handler_class("zip"), base_class(0x04), base_class(0x03)),
        [
            format!("plexus unreadable: {base_differs}"),
            format!("zip unreadable: {base_differs}"),
        ]
    );
    assert_eq!(
        read(handler_class("zip"), base_class(0x04), base_class(0x04)),
        ["plexus zip - true false", "zip zip - true false"]
    );
    let handler_differs = "t:own:1 and t:a-base:1 in one extension realm define class \
                           org.x.Handler differently";
    assert_eq!(
        read(handler_class("tgz"), base_class(0x04), base_class(0x04)),
        [
            "plexus zip - true false".to_string(),
            format!("zip unreadable: {handler_differs}"),
            format!("tgz unreadable: {handler_differs}"),
        ]
    );
}

/// A core type keeps its core handler, and is unreadable where an
/// extension defines it otherwise; an extension adds the others, the first
/// definition counting, for every clone of the types.
#[test]
fn extensions_add_types_the_core_does_not_define() {
    let handler = |extension: &str, includes| {
        Ok(ArtifactHandler {
            extension: extension.to_string(),
            classifier: None,
            includes_dependencies: includes,
            added_to_classpath: true,
        })
    };
    let types = ArtifactTypes::pending(MavenMode::Maven39);
    let before = types.clone();
    assert_eq!(before.extension("executable-war"), "executable-war");
    types.define([
        ("war".to_string(), handler("zip", false)),
        ("executable-war".to_string(), handler("war", false)),
        ("executable-war".to_string(), handler("jar", true)),
        ("odd".to_string(), Err("why".to_string())),
        ("jar".to_string(), handler("jar", false)),
        ("ear".to_string(), Err("unread".to_string())),
        ("ear".to_string(), handler("ear", true)),
        (
            "test-jar".to_string(),
            Ok(ArtifactHandler {
                classifier: Some("tests".to_string()),
                ..handler("jar", false).unwrap()
            }),
        ),
    ]);
    let differs = "a build extension defines it other than Maven's core, and Maven may take \
                   either handler";
    assert_eq!(types.unreadable("war"), Some(differs));
    assert_eq!(types.unreadable("ear"), Some("unread"));
    assert_eq!(types.unreadable("jar"), None);
    assert_eq!(types.unreadable("test-jar"), None);
    assert_eq!(types.unreadable("pom"), None);
    assert_eq!(before.extension("executable-war"), "war");
    assert_eq!(types.extension("war"), "war");
    assert!(types.includes_dependencies("war"));
    assert_eq!(types.extension("executable-war"), "war");
    assert!(!types.includes_dependencies("executable-war"));
    assert!(types.added_to_classpath("executable-war"));
    assert_eq!(types.extension("odd"), "odd");
    assert_eq!(types.unreadable("odd"), Some("why"));
    assert_eq!(types.extension("zip"), "zip");
    assert_eq!(
        ArtifactTypes::core(MavenMode::Maven39).extension("fatjar"),
        "fatjar"
    );
    assert_eq!(
        ArtifactTypes::core(MavenMode::Maven310).extension("fatjar"),
        "jar"
    );
}
