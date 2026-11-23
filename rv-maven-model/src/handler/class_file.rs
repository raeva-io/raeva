//! Reads the values a handler class sets in its constructor. A class comes
//! from a repository's jar, so every read is bounded and a class outside
//! the shapes raeva reads is refused with a reason, never guessed: one
//! extends `DefaultArtifactHandler` (through classes of the extension's
//! realm), declares no method but constructors and a static initializer,
//! and its no-argument constructor passes constants to the superclass
//! constructor and the setters; the other implements `ArtifactHandler`
//! itself, as a direct subclass of `Object`, and each getter Maven's
//! resolver reads returns a constant.

use std::collections::HashSet;

use super::{ClassFiles, HandlerFields};

/// What the jars of an extension's realm hold for a class file.
type Read<'a> = &'a dyn Fn(&str) -> ClassFiles;

const DEFAULT_HANDLER: &str = "org/apache/maven/artifact/handler/DefaultArtifactHandler";
const HANDLER: &str = "org/apache/maven/artifact/handler/ArtifactHandler";
const OBJECT: &str = "java/lang/Object";
const NAMED: [&str; 2] = ["Ljavax/inject/Named;", "Ljakarta/inject/Named;"];
/// The deepest chain of superclasses inside the jar raeva follows.
const MAX_CHAIN: usize = 8;
/// The most superclasses and interfaces raeva reads to tell whether a
/// class is a handler.
const MAX_HIERARCHY: usize = 64;
/// The deepest nesting of annotation values raeva skips.
const MAX_NESTING: usize = 16;
/// The most values a constructor raeva reads keeps on its operand stack: a
/// setter call needs two. Each may be a string of 64 KiB, so a class of
/// repeated loads must not pile them up.
const MAX_STACK: usize = 8;
/// The getters `RepositoryUtils.newArtifactType` reads that decide a
/// dependency's file and collection, with their descriptors.
const GETTERS: [(&str, &str); 4] = [
    ("getExtension", "()Ljava/lang/String;"),
    ("getClassifier", "()Ljava/lang/String;"),
    ("isIncludesDependencies", "()Z"),
    ("isAddedToClasspath", "()Z"),
];

/// The Sisu names and constructed fields of the class `name` (`a.b.C`)
/// the index lists, none when it is no `@Named` handler. Of a class two
/// jars of the realm hold differently, each name a copy may give is
/// refused, as which copy the realm loads turns on the order of its jars.
pub(super) fn named_handler(
    read: Read<'_>,
    name: &str,
) -> Vec<(String, Result<HandlerFields, String>)> {
    let copies = read(&entry(name));
    let differing = differing(&entry(name), &copies);
    let mut handlers: Vec<(String, Result<HandlerFields, String>)> = Vec::new();
    for (_, bytes) in &copies {
        let Some((named, fields)) = named_copy(read, bytes) else {
            continue;
        };
        if let Err(reason) = &differing {
            if !handlers.iter().any(|(known, _)| *known == named) {
                handlers.push((named, Err(reason.clone())));
            }
        } else {
            handlers.push((named, fields));
        }
    }
    handlers
}

/// [`named_handler`] of one copy of the class.
fn named_copy(read: Read<'_>, bytes: &[u8]) -> Option<(String, Result<HandlerFields, String>)> {
    let class = ClassFile::parse(bytes).ok()?;
    let named = class.named.clone().filter(|named| !named.is_empty())?;
    let fields = match shape(read, &class) {
        Shape::NotHandler => return None,
        Shape::Extending => construct(read, &class, 0),
        Shape::Implementing => class.returned_fields(),
        Shape::Unread(what) => Err(format!("{} {what}", class.name.replace('/', "."))),
        Shape::Differing(reason) => Err(reason),
    };
    Some((named, fields))
}

/// The fields the no-argument constructor of the class `name` leaves.
pub(super) fn constructed_fields(read: Read<'_>, name: &str) -> Result<HandlerFields, String> {
    let bytes = load(read, &entry(name))?
        .ok_or_else(|| format!("{name} is in none of the extension's jars"))?;
    let class = ClassFile::parse(&bytes).map_err(|error| format!("{name}: {error}"))?;
    construct(read, &class, 0)
}

/// The class file at `entry` as the realm loads it, `None` when none of
/// its jars holds it.
fn load(read: Read<'_>, entry: &str) -> Result<Option<Vec<u8>>, String> {
    let mut copies = read(entry);
    differing(entry, &copies)?;
    Ok(copies.pop().map(|(_, bytes)| bytes))
}

/// Why raeva cannot tell which of `copies`, the files the realm's jars
/// hold at `entry`, the realm loads, when they differ.
fn differing(entry: &str, copies: &[(String, Vec<u8>)]) -> Result<(), String> {
    match copies {
        [(first, _), (second, _), ..] => Err(format!(
            "{first} and {second} in one extension realm define class {} differently",
            entry.trim_end_matches(".class").replace('/', ".")
        )),
        _ => Ok(()),
    }
}

fn entry(name: &str) -> String {
    format!("{}.class", name.replace('.', "/"))
}

/// What a class's hierarchy makes of it.
enum Shape {
    /// It is no `ArtifactHandler`.
    NotHandler,
    /// It descends from `DefaultArtifactHandler`.
    Extending,
    /// It implements `ArtifactHandler` as a direct subclass of `Object`.
    Implementing,
    /// It is, or may be, a handler of another shape.
    Unread(&'static str),
    /// Two jars of the realm define a class of its hierarchy differently.
    Differing(String),
}

/// The shape of `class`, from its superclasses and interfaces that `read`
/// finds. One it does not find is the JDK's or Maven core's, which
/// implement `ArtifactHandler` only in `DefaultArtifactHandler`.
fn shape(read: Read<'_>, class: &ClassFile) -> Shape {
    let load = |name: &str| {
        load(read, &format!("{name}.class"))
            .map(|bytes| bytes.and_then(|bytes| ClassFile::parse(&bytes).ok()))
    };
    let mut interfaces = class.interfaces.clone();
    let mut superclass = class.superclass.clone();
    let mut chain = 0;
    while let Some(name) = superclass {
        if name == DEFAULT_HANDLER {
            return Shape::Extending;
        }
        chain += 1;
        if chain > MAX_HIERARCHY {
            return Shape::Unread("has too deep a chain of superclasses");
        }
        let parent = match load(&name) {
            Ok(Some(parent)) => parent,
            Ok(None) => break,
            Err(reason) => return Shape::Differing(reason),
        };
        interfaces.extend(parent.interfaces);
        superclass = parent.superclass;
    }
    let mut seen = HashSet::new();
    let mut implements = false;
    while let Some(name) = interfaces.pop() {
        if name == HANDLER {
            implements = true;
            break;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        if seen.len() > MAX_HIERARCHY {
            return Shape::Unread("has too many interfaces");
        }
        match load(&name) {
            Ok(Some(interface)) => interfaces.extend(interface.interfaces),
            Ok(None) => {}
            Err(reason) => return Shape::Differing(reason),
        }
    }
    match class.superclass.as_deref() {
        _ if !implements => Shape::NotHandler,
        Some(OBJECT) => Shape::Implementing,
        _ => Shape::Unread("implements ArtifactHandler below a superclass raeva does not read"),
    }
}

/// Run the no-argument constructor of `class` over fresh fields.
fn construct(read: Read<'_>, class: &ClassFile, depth: usize) -> Result<HandlerFields, String> {
    let name = class.name.replace('/', ".");
    let refuse = |what: &str| Err(format!("{name} {what}"));
    if depth >= MAX_CHAIN {
        return refuse("has too deep a chain of superclasses");
    }
    // A static initializer sets no field of the handler.
    if class.other_methods {
        return refuse("declares methods besides constructors");
    }
    let Some(code) = &class.constructor else {
        return refuse("has no constructor without arguments");
    };
    let superclass = class.superclass.as_deref().unwrap_or("");
    let mut fields = HandlerFields::default();
    let mut stack: Vec<Value> = Vec::new();
    let mut at = 0;
    while let Some(&op) = code.get(at) {
        if stack.len() > MAX_STACK {
            return refuse("keeps more values on its stack than a handler does");
        }
        at += 1;
        match op {
            0x2a => stack.push(Value::This),
            0x01 => stack.push(Value::Null),
            0x03 | 0x04 => stack.push(Value::Flag(op == 0x04)),
            0x12 | 0x13 => {
                let index = if op == 0x12 {
                    code.get(at).map(|&byte| u16::from(byte))
                } else {
                    u16_at(code, at)
                };
                at += if op == 0x12 { 1 } else { 2 };
                match index.and_then(|index| class.string(index)) {
                    Some(text) => stack.push(Value::Text(text.to_string())),
                    None => return refuse("loads a constant other than a string"),
                }
            }
            0xb6 | 0xb7 => {
                let Some((owner, method, descriptor)) =
                    u16_at(code, at).and_then(|index| class.method_ref(index))
                else {
                    return refuse("calls a method raeva cannot name");
                };
                at += 2;
                let argument = match descriptor {
                    "()V" => None,
                    "(Ljava/lang/String;)V" | "(Z)V" => Some(stack.pop()),
                    _ => return refuse(&format!("calls {method}{descriptor}")),
                };
                if stack.pop() != Some(Value::This) {
                    return refuse("calls a method on another object");
                }
                let argument = argument.flatten();
                match (op, method, argument) {
                    (0xb7, "<init>", None) if owner == superclass => {
                        if superclass != DEFAULT_HANDLER {
                            let parent =
                                load(read, &format!("{superclass}.class"))?.ok_or_else(|| {
                                    format!("{superclass} is in none of the extension's jars")
                                })?;
                            let parent = ClassFile::parse(&parent)
                                .map_err(|error| format!("{superclass}: {error}"))?;
                            fields = construct(read, &parent, depth + 1)?;
                        }
                    }
                    (0xb7, "<init>", Some(value)) if owner == superclass => {
                        if superclass != DEFAULT_HANDLER {
                            return refuse("passes a type to a superclass raeva does not read");
                        }
                        fields.type_ = value.text()?;
                    }
                    (0xb6, "setExtension", Some(value)) => fields.extension = value.text()?,
                    (0xb6, "setLanguage", Some(Value::Text(_) | Value::Null)) => {}
                    (0xb6, "setAddedToClasspath", Some(Value::Flag(flag))) => {
                        fields.added_to_classpath = flag;
                    }
                    (0xb6, "setIncludesDependencies", Some(Value::Flag(flag))) => {
                        fields.includes_dependencies = flag;
                    }
                    _ => return refuse(&format!("calls {method}{descriptor}")),
                }
            }
            0xb1 if stack.is_empty() => return Ok(fields),
            _ => return refuse(&format!("runs instruction {op:#04x}")),
        }
    }
    refuse("has a constructor without a return")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    This,
    Null,
    Flag(bool),
    Text(String),
}

impl Value {
    fn text(self) -> Result<Option<String>, String> {
        match self {
            Self::Text(text) => Ok(Some(text)),
            Self::Null => Ok(None),
            _ => Err("passes a flag where a string goes".to_string()),
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let field = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([field[0], field[1]]))
}

/// The parts of a class file raeva reads.
struct ClassFile {
    /// `a/b/C`.
    name: String,
    superclass: Option<String>,
    /// The interfaces it names, `a/b/C`.
    interfaces: Vec<String>,
    /// The `@Named` value, empty for a bare `@Named`.
    named: Option<String>,
    /// The code of the first constructor without arguments.
    constructor: Option<Vec<u8>>,
    /// Whether it declares a method other than a constructor or a static
    /// initializer.
    other_methods: bool,
    /// The code of each of [`GETTERS`] it declares, in their order.
    getters: [Option<Vec<u8>>; GETTERS.len()],
    pool: Vec<Constant>,
}

#[derive(Debug, Clone)]
enum Constant {
    Unused,
    Utf8(String),
    Class(u16),
    Text(u16),
    MethodRef(u16, u16),
    NameAndType(u16, u16),
    Other,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self.at.checked_add(len).ok_or("truncated")?;
        let slice = self.bytes.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn attribute(&mut self) -> Result<(u16, &'a [u8]), &'static str> {
        let name = self.u16()?;
        let len = usize::try_from(self.u32()?).map_err(|_| "attribute size")?;
        Ok((name, self.take(len)?))
    }
}

impl ClassFile {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut reader = Reader { bytes, at: 0 };
        if reader.u32()? != 0xCAFE_BABE {
            return Err("is not a class file");
        }
        reader.take(4)?;
        let count = usize::from(reader.u16()?);
        let mut pool = vec![Constant::Unused];
        while pool.len() < count {
            let tag = reader.u8()?;
            let constant = match tag {
                1 => {
                    let len = usize::from(reader.u16()?);
                    Constant::Utf8(String::from_utf8_lossy(reader.take(len)?).into_owned())
                }
                7 => Constant::Class(reader.u16()?),
                8 => Constant::Text(reader.u16()?),
                10 => Constant::MethodRef(reader.u16()?, reader.u16()?),
                12 => Constant::NameAndType(reader.u16()?, reader.u16()?),
                3 | 4 | 9 | 11 | 17 | 18 => {
                    reader.take(4)?;
                    Constant::Other
                }
                5 | 6 => {
                    reader.take(8)?;
                    pool.push(Constant::Other);
                    Constant::Unused
                }
                15 => {
                    reader.take(3)?;
                    Constant::Other
                }
                16 | 19 | 20 => {
                    reader.take(2)?;
                    Constant::Other
                }
                _ => return Err("has an unknown constant"),
            };
            pool.push(constant);
        }
        let mut class = Self {
            name: String::new(),
            superclass: None,
            interfaces: Vec::new(),
            named: None,
            constructor: None,
            other_methods: false,
            getters: Default::default(),
            pool,
        };
        reader.take(2)?;
        let this = reader.u16()?;
        class.name = class.class_name(this).ok_or("has no name")?.to_string();
        let superclass = reader.u16()?;
        class.superclass = class.class_name(superclass).map(str::to_string);
        for _ in 0..reader.u16()? {
            let interface = reader.u16()?;
            let interface = class
                .class_name(interface)
                .ok_or("has a nameless interface")?;
            class.interfaces.push(interface.to_string());
        }
        for _ in 0..reader.u16()? {
            reader.take(6)?;
            for _ in 0..reader.u16()? {
                reader.attribute()?;
            }
        }
        for _ in 0..reader.u16()? {
            reader.take(2)?;
            let name = class.utf8(reader.u16()?).ok_or("has a nameless method")?;
            let descriptor = class
                .utf8(reader.u16()?)
                .ok_or("has a method without type")?;
            // Only the code of the constructor and the getters is kept: a
            // class may name one long constant from every method.
            let constructor = name == "<init>" && descriptor == "()V";
            let getter = (GETTERS.iter()).position(|getter| *getter == (name, descriptor));
            class.other_methods |= name != "<init>" && name != "<clinit>";
            let mut code = None;
            for _ in 0..reader.u16()? {
                let (attribute, body) = reader.attribute()?;
                if (constructor || getter.is_some())
                    && code.is_none()
                    && class.utf8(attribute) == Some("Code")
                {
                    let mut body = Reader { bytes: body, at: 0 };
                    body.take(4)?;
                    let len = usize::try_from(body.u32()?).map_err(|_| "code size")?;
                    code = Some(body.take(len)?.to_vec());
                }
            }
            match getter {
                Some(getter) => class.getters[getter] = class.getters[getter].take().or(code),
                None if constructor => class.constructor = class.constructor.take().or(code),
                None => {}
            }
        }
        for _ in 0..reader.u16()? {
            let (attribute, body) = reader.attribute()?;
            if class.utf8(attribute) == Some("RuntimeVisibleAnnotations") {
                class.named = class.named_value(body)?;
            }
        }
        Ok(class)
    }

    /// The fields a handler that implements `ArtifactHandler` itself
    /// gives through [`GETTERS`], each of which must return a constant.
    fn returned_fields(&self) -> Result<HandlerFields, String> {
        let name = self.name.replace('/', ".");
        let mut values = Vec::new();
        for ((getter, _), code) in GETTERS.iter().zip(&self.getters) {
            let value = match code.as_deref() {
                None => return Err(format!("{name} does not declare {getter}")),
                Some([0x01, 0xb0]) => Some(Value::Null),
                Some([0x03, 0xac]) => Some(Value::Flag(false)),
                Some([0x04, 0xac]) => Some(Value::Flag(true)),
                Some(&[0x12, index, 0xb0]) => self.text_value(u16::from(index)),
                Some(&[0x13, high, low, 0xb0]) => self.text_value(u16::from_be_bytes([high, low])),
                Some(_) => None,
            };
            values.push(value.ok_or_else(|| format!("{name} computes {getter}"))?);
        }
        let Ok(
            [
                extension,
                classifier,
                Value::Flag(includes),
                Value::Flag(added),
            ],
        ) = <[Value; GETTERS.len()]>::try_from(values)
        else {
            return Err(format!("{name} returns a getter's value of the wrong kind"));
        };
        let text = |value: Value| match value {
            Value::Text(text) => Ok(Some(text)),
            Value::Null => Ok(None),
            _ => Err(format!("{name} returns a getter's value of the wrong kind")),
        };
        let extension = text(extension)?.filter(|extension| !extension.is_empty());
        Ok(HandlerFields {
            type_: None,
            extension: Some(extension.ok_or_else(|| format!("{name} returns no extension"))?),
            classifier: text(classifier)?,
            includes_dependencies: includes,
            added_to_classpath: added,
        })
    }

    fn text_value(&self, index: u16) -> Option<Value> {
        Some(Value::Text(self.string(index)?.to_string()))
    }

    fn utf8(&self, index: u16) -> Option<&str> {
        match self.pool.get(usize::from(index))? {
            Constant::Utf8(text) => Some(text),
            _ => None,
        }
    }

    fn class_name(&self, index: u16) -> Option<&str> {
        match self.pool.get(usize::from(index))? {
            Constant::Class(name) => self.utf8(*name),
            _ => None,
        }
    }

    fn string(&self, index: u16) -> Option<&str> {
        match self.pool.get(usize::from(index))? {
            Constant::Text(text) => self.utf8(*text),
            _ => None,
        }
    }

    /// Owner, name and descriptor of a method reference.
    fn method_ref(&self, index: u16) -> Option<(&str, &str, &str)> {
        let Constant::MethodRef(owner, signature) = self.pool.get(usize::from(index))? else {
            return None;
        };
        let Constant::NameAndType(name, descriptor) = self.pool.get(usize::from(*signature))?
        else {
            return None;
        };
        Some((
            self.class_name(*owner)?,
            self.utf8(*name)?,
            self.utf8(*descriptor)?,
        ))
    }

    /// The value of a `@Named` among the annotations `body` holds.
    fn named_value(&self, body: &[u8]) -> Result<Option<String>, &'static str> {
        let mut reader = Reader { bytes: body, at: 0 };
        let mut named = None;
        for _ in 0..reader.u16()? {
            let annotation = reader.u16()?;
            let is_named = self
                .utf8(annotation)
                .is_some_and(|descriptor| NAMED.contains(&descriptor));
            let mut value = String::new();
            for _ in 0..reader.u16()? {
                let element = reader.u16()?;
                let text = skip_element(&mut reader, 0)?;
                if is_named && self.utf8(element) == Some("value") {
                    value = text
                        .and_then(|index| self.utf8(index))
                        .unwrap_or("")
                        .to_string();
                }
            }
            if is_named {
                named = Some(value);
            }
        }
        Ok(named)
    }
}

/// Skip one annotation element value, giving the constant index of a
/// string one.
fn skip_element(reader: &mut Reader<'_>, depth: usize) -> Result<Option<u16>, &'static str> {
    if depth > MAX_NESTING {
        return Err("nests annotations too deep");
    }
    match reader.u8()? {
        b's' => return Ok(Some(reader.u16()?)),
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b'c' => {
            reader.u16()?;
        }
        b'e' => {
            reader.take(4)?;
        }
        b'@' => {
            reader.u16()?;
            for _ in 0..reader.u16()? {
                reader.u16()?;
                skip_element(reader, depth + 1)?;
            }
        }
        b'[' => {
            for _ in 0..reader.u16()? {
                skip_element(reader, depth + 1)?;
            }
        }
        _ => return Err("has an unknown annotation value"),
    }
    Ok(None)
}
