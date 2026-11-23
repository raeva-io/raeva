//! Reads entries of a jar, as plugin locking needs the descriptors inside
//! plugin and extension jars (`META-INF/maven/plugin.xml`,
//! `META-INF/plexus/components.xml`, `META-INF/maven/extension.xml`). The
//! jar comes from a repository, so every offset and size is checked against
//! the file and the inflated size is bounded.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use rv_maven_model::{DefinedType, PomError};

use crate::error::ResolveError;

/// The largest descriptor read; Maven's own are well under a megabyte.
const MAX_ENTRY: usize = 16 * 1024 * 1024;
/// The end-of-central-directory record and the longest comment after it.
const MAX_TAIL: u64 = 22 + 0xFFFF;

#[derive(Debug, thiserror::Error)]
pub(crate) enum JarError {
    #[error("cannot read the jar: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a jar Maven can read: {0}")]
    Format(&'static str),
    /// A jar Java may read but which passes a bound raeva keeps on what an
    /// untrusted jar makes it read.
    #[error("{0} larger than raeva reads")]
    Limit(&'static str),
}

fn u16_at(bytes: &[u8], at: usize) -> Option<usize> {
    let field = bytes.get(at..at + 2)?;
    Some(usize::from(u16::from_le_bytes([field[0], field[1]])))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u64> {
    let field = bytes.get(at..at + 4)?;
    Some(u64::from(u32::from_le_bytes([
        field[0], field[1], field[2], field[3],
    ])))
}

/// The bytes of the entry `name` in the jar at `path`, `None` when the jar
/// has no such entry.
pub(crate) fn read_entry(path: &Path, name: &str) -> Result<Option<Vec<u8>>, JarError> {
    Jar::open(path)?.read(name)
}

/// Where one entry's bytes are, as the central directory records them; a
/// compressed size it leaves unrecorded is `None`. Java reads an entry
/// without the uncompressed size either header records, so it is not
/// kept, and records that agree on these read the same bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Entry {
    method: usize,
    compressed: Option<u64>,
    local: u64,
}

/// A jar with its central directory read, so each entry is found without
/// reading the directory again. Of two entries of one name, the last is
/// read, as Java reads it.
struct Jar {
    file: RefCell<File>,
    len: u64,
    entries: HashMap<Vec<u8>, Entry>,
    /// The first directory entry of each name, by the name without its
    /// slash, which Java finds when no entry has that name.
    directories: HashMap<Vec<u8>, Entry>,
}

impl Jar {
    /// Open the store file at `path`, which is not read when it is not a
    /// regular file, as a FIFO would block the read.
    fn open(path: &Path) -> Result<Self, JarError> {
        let mut file = rv_store::open_unfollowed_regular(path)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "not a regular file")
        })?;
        let len = file.metadata()?.len();
        let tail_len = len.min(MAX_TAIL);
        let tail_start = len - tail_len;
        file.seek(SeekFrom::Start(tail_start))?;
        let mut tail = vec![0; usize::try_from(tail_len).map_err(|_| JarError::Format("size"))?];
        file.read_exact(&mut tail)?;
        let format = |what| JarError::Format(what);
        let mut read_at = |at: u64, buf: &mut [u8]| -> Result<bool, JarError> {
            if at.checked_add(buf.len() as u64).is_none_or(|end| end > len) {
                return Ok(false);
            }
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(buf)?;
            Ok(true)
        };
        let mut signature_at = |at: u64, signature: &[u8; 4]| -> Result<bool, JarError> {
            let mut found = [0; 4];
            Ok(read_at(at, &mut found)? && found == *signature)
        };
        // As OpenJDK's `ZipFile.Source.findEND`: the last end record whose
        // comment runs to the end of the file, or failing that, one whose
        // central directory and first local header are where it says.
        let mut found = None;
        for at in (0..tail.len().saturating_sub(21)).rev() {
            if !tail[at..].starts_with(b"PK\x05\x06") {
                continue;
            }
            let count = u16_at(&tail, at + 10).ok_or(format("end record"))? as u64;
            let directory_size = u32_at(&tail, at + 12).ok_or(format("end record"))?;
            let directory_offset = u32_at(&tail, at + 16).ok_or(format("end record"))?;
            let comment_len = u16_at(&tail, at + 20).ok_or(format("end record"))? as u64;
            let end = tail_start + at as u64;
            if end + 22 + comment_len != len {
                let directory_start = end.checked_sub(directory_size);
                let base = directory_start.and_then(|start| start.checked_sub(directory_offset));
                let (Some(directory_start), Some(base)) = (directory_start, base) else {
                    continue;
                };
                if !(signature_at(directory_start, b"PK\x01\x02")?
                    && signature_at(base, b"PK\x03\x04")?)
                {
                    continue;
                }
            }
            // Java then reads the comment, which must be there.
            if end + 22 + comment_len > len {
                return Err(format("end record comment"));
            }
            found = Some((end, count, directory_size, directory_offset));
            break;
        }
        let (mut end, mut count, mut directory_size, mut directory_offset) =
            found.ok_or(format("no end of central directory"))?;
        // A ZIP64 end record, which may always be present, gives the sizes
        // when its locator sits before the end record and its values agree
        // with those the end record does not mark as too large. Java takes
        // the locator's offset as it stands, not shifted by a prefix.
        let mut locator = [0; 20];
        if end >= 20 && read_at(end - 20, &mut locator)? && locator.starts_with(b"PK\x06\x07") {
            let record_at = u64::from_le_bytes(locator[8..16].try_into().unwrap_or_default());
            let mut record = [0; 56];
            if read_at(record_at, &mut record)? && record.starts_with(b"PK\x06\x06") {
                let field = |at: usize| {
                    u64::from_le_bytes(record[at..at + 8].try_into().unwrap_or_default())
                };
                let (count64, size64, offset64) = (field(32), field(40), field(48));
                if (size64 == directory_size || directory_size == 0xFFFF_FFFF)
                    && (offset64 == directory_offset || directory_offset == 0xFFFF_FFFF)
                    && (count64 == count || count == 0xFFFF)
                {
                    (end, count, directory_size, directory_offset) =
                        (record_at, count64, size64, offset64);
                }
            }
        }
        // Java opens a jar whose end record starts the file as empty.
        if end == 0 {
            return Ok(Self {
                file: RefCell::new(file),
                len,
                entries: HashMap::new(),
                directories: HashMap::new(),
            });
        }
        let directory_start = end
            .checked_sub(directory_size)
            .ok_or(format("central directory out of bounds"))?;
        let base = directory_start
            .checked_sub(directory_offset)
            .ok_or(format("central directory out of bounds"))?;
        if directory_size > MAX_ENTRY as u64 {
            return Err(JarError::Limit("central directory"));
        }
        if count
            .checked_mul(46)
            .is_none_or(|least| least > directory_size)
        {
            return Err(format("end record entry count"));
        }
        file.seek(SeekFrom::Start(directory_start))?;
        let mut directory = vec![0; directory_size as usize];
        file.read_exact(&mut directory)?;
        let (mut entries, mut directories) = (HashMap::new(), HashMap::new());
        let mut at = 0;
        while at + 46 <= directory.len() {
            if !directory[at..].starts_with(b"PK\x01\x02") {
                return Err(format("central directory entry"));
            }
            // Java refuses the whole jar for an entry it cannot read.
            let flags = u16_at(&directory, at + 8).ok_or(format("entry"))?;
            let method = u16_at(&directory, at + 10).ok_or(format("entry"))?;
            if flags & 1 != 0 || !matches!(method, 0 | 8) {
                return Err(format("entry Java cannot read"));
            }
            let name_len = u16_at(&directory, at + 28).ok_or(format("entry"))?;
            let extra_len = u16_at(&directory, at + 30).ok_or(format("entry"))?;
            let comment_len = u16_at(&directory, at + 32).ok_or(format("entry"))?;
            let record_len = 46 + name_len + extra_len + comment_len;
            if record_len > 0xFFFF || at + record_len > directory.len() {
                return Err(format("central directory entry"));
            }
            let name = &directory[at + 46..at + 46 + name_len];
            let extra = &directory[at + 46 + name_len..at + 46 + name_len + extra_len];
            let comment = &directory[at + 46 + name_len + extra_len..at + record_len];
            if std::str::from_utf8(name).is_err() || std::str::from_utf8(comment).is_err() {
                return Err(format("entry name or comment"));
            }
            let ([_, compressed, offset], given) = zip64_values(&directory[at..], extra)?;
            let recorded = |value| (given || value != 0xFFFF_FFFF).then_some(value);
            let local = base
                .checked_add(offset)
                .ok_or(format("local header out of bounds"))?;
            let entry = Entry {
                method,
                compressed: recorded(compressed),
                local,
            };
            if let Some(directory) = name.strip_suffix(b"/") {
                directories.entry(directory.to_vec()).or_insert(entry);
            }
            entries.insert(name.to_vec(), entry);
            at += record_len;
        }
        if at != directory.len() {
            return Err(format("central directory entry"));
        }
        Ok(Self {
            file: RefCell::new(file),
            len,
            entries,
            directories,
        })
    }

    /// The entry `name`, or failing that the directory entry `name/` for a
    /// name that is not empty and does not end in a slash.
    fn entry(&self, name: &str) -> Option<&Entry> {
        let directory = || self.directories.get(name.as_bytes());
        (self.entries.get(name.as_bytes()))
            .or_else(|| directory().filter(|_| !name.is_empty() && !name.ends_with('/')))
    }

    /// The most bytes reading `entry` takes from the file.
    fn input(&self, entry: &Entry) -> usize {
        let compressed = entry.compressed.unwrap_or(MAX_ENTRY as u64).min(self.len);
        usize::try_from(compressed).unwrap_or(usize::MAX)
    }

    /// The bytes of the entry `name`, `None` when the jar has none.
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, JarError> {
        let Some(entry) = self.entry(name) else {
            return Ok(None);
        };
        self.read_at(entry).map(Some)
    }

    fn read_at(&self, entry: &Entry) -> Result<Vec<u8>, JarError> {
        read_local(&mut self.file.borrow_mut(), self.len, entry)
    }
}

/// The most bytes one read of an extension jar's handlers takes from it,
/// its index and descriptor included. Sisu reads every class its index
/// names, so no count of them bounds the read; an extension's handler
/// classes, with the classes they extend, come to some KiB.
const MAX_SCAN: usize = 128 << 20;

/// The artifact handlers the jars of one extension realm define, `jars`
/// in the realm's order, each at its path with its coordinates, merged as
/// [`rv_maven_model::merge_realm_handlers`] merges them. A class is read
/// from every jar that holds it: the realm loads it from the first, and
/// raeva does not follow the realm's order, so a handler that reads a class
/// two jars define differently is refused. A jar or an
/// entry raeva cannot read is an error. Maven 3.9.12 and 3.10.0 go on
/// without the handlers of such a jar, logging an error only when the jar
/// does not open, and type a dependency by the file of the type's own
/// name; raeva refuses instead, as it cannot tell every entry Java fails
/// to read from one only raeva does. Each entry is read from its jar once,
/// however many classes name it, and a realm whose reads come to more
/// than [`MAX_SCAN`] bytes is refused.
pub(crate) fn realm_handlers(jars: &[(&Path, &str)]) -> Result<Vec<DefinedType>, ResolveError> {
    realm_handlers_within(jars, MAX_SCAN)
}

fn realm_handlers_within(
    jars: &[(&Path, &str)],
    limit: usize,
) -> Result<Vec<DefinedType>, ResolveError> {
    let unreadable =
        |jar: usize, entry: Option<String>, error: JarError| ResolveError::UnreadableJar {
            coord: jars[jar].1.to_string(),
            entry,
            reason: error.to_string(),
        };
    let opened = (jars.iter().enumerate())
        .map(|(at, (path, _))| Jar::open(path).map_err(|error| unreadable(at, None, error)))
        .collect::<Result<Vec<_>, _>>()?;
    let read_before: RefCell<HashMap<(usize, Entry), Vec<u8>>> = RefCell::default();
    let failed: RefCell<Option<(usize, String, JarError)>> = RefCell::default();
    let left = Cell::new(limit);
    let over = Cell::new(false);
    let charge = |cost: usize| match left.get().checked_sub(cost) {
        Some(rest) => {
            left.set(rest);
            true
        }
        None => {
            over.set(true);
            false
        }
    };
    // Each read is charged the compressed bytes it takes from the file,
    // then what they inflate to past that, read before or not: the sizes
    // the directory records do not bound what Java inflates.
    let read = |at: usize, entry: Entry, name: &str| {
        if failed.borrow().is_some() || over.get() {
            return None;
        }
        let jar = &opened[at];
        let input = jar.input(&entry);
        if !charge(input) {
            return None;
        }
        let mut read_before = read_before.borrow_mut();
        let bytes = match read_before.entry((at, entry)) {
            std::collections::hash_map::Entry::Occupied(read) => read.into_mut(),
            std::collections::hash_map::Entry::Vacant(unread) => match jar.read_at(&entry) {
                Ok(bytes) => unread.insert(bytes),
                Err(error) => {
                    *failed.borrow_mut() = Some((at, name.to_string(), error));
                    return None;
                }
            },
        };
        charge(bytes.len().saturating_sub(input)).then(|| bytes.clone())
    };
    let class = |name: &str| {
        let mut copies: rv_maven_model::ClassFiles = Vec::new();
        for (at, jar) in opened.iter().enumerate() {
            let Some(entry) = jar.entry(name) else {
                continue;
            };
            let Some(bytes) = read(at, *entry, name) else {
                break;
            };
            if !copies.iter().any(|(_, known)| *known == bytes) {
                copies.push((jars[at].1.to_string(), bytes));
            }
        }
        copies
    };
    let mut defined = Vec::new();
    for (at, jar) in opened.iter().enumerate() {
        let own = |name: &str| read(at, *jar.entry(name)?, name);
        let handlers = rv_maven_model::read_artifact_handlers(&own, &class);
        if let Some((at, name, error)) = failed.borrow_mut().take() {
            return Err(unreadable(at, Some(name), error));
        }
        defined.push((jars[at].1.to_string(), handlers?));
        if over.get() {
            return Err(ResolveError::Pom(PomError::InvalidModel(format!(
                "the entries the artifact handlers of its jars take, the classes they extend \
                 included, come to more than {} MiB, more than raeva reads",
                limit >> 20
            ))));
        }
    }
    Ok(rv_maven_model::merge_realm_handlers(defined))
}

/// The uncompressed size, compressed size and local header offset of the
/// directory `record`, each its ZIP64 `extra` field gives when the record
/// marks it with all ones, as OpenJDK's `ZipFile` (JDK 27) reads them. Java
/// refuses the whole jar when a block of the extra field runs past it, or
/// when a ZIP64 block is not 8 bytes for each marked value and 4 for a
/// marked disk, values in that order, or gives a value over `i64::MAX`.
/// Without a ZIP64 block a marked value stands, though with no extra field
/// at all Java refuses it; of two blocks the first is read. Whether a block
/// gave the values comes with them.
fn zip64_values(record: &[u8], extra: &[u8]) -> Result<([u64; 3], bool), JarError> {
    let format = |what| JarError::Format(what);
    let field = |at| u32_at(record, at).ok_or(format("entry"));
    let mut values = [field(24)?, field(20)?, field(42)?];
    let marked = values.map(|value| value == 0xFFFF_FFFF);
    let disk_marked = u16_at(record, 34) == Some(0xFFFF);
    let needed = 8 * marked.iter().filter(|&&marked| marked).count() + 4 * usize::from(disk_marked);
    if extra.is_empty() && needed > 0 {
        return Err(format("ZIP64 extra field"));
    }
    let mut read = false;
    let mut at = 0;
    while at + 4 <= extra.len() {
        let tag = u16_at(extra, at).ok_or(format("extra field"))?;
        let len = u16_at(extra, at + 2).ok_or(format("extra field"))?;
        let block = (extra.get(at + 4..at + 4 + len)).ok_or(format("extra field"))?;
        at += 4 + len;
        if tag != 1 {
            continue;
        }
        if len != needed {
            return Err(format("ZIP64 extra field"));
        }
        let mut given = block
            .chunks_exact(8)
            .map(|value| u64::from_le_bytes(value.try_into().unwrap_or_default()));
        for (value, marked) in values.iter_mut().zip(marked) {
            if !marked {
                continue;
            }
            let given = given.next().ok_or(format("ZIP64 extra field"))?;
            if given > i64::MAX as u64 {
                return Err(format("ZIP64 extra field"));
            }
            if !read {
                *value = given;
            }
        }
        read = true;
    }
    Ok((values, read))
}

fn read_local(file: &mut File, len: u64, entry: &Entry) -> Result<Vec<u8>, JarError> {
    let &Entry {
        method,
        compressed,
        local,
    } = entry;
    let format = |what| JarError::Format(what);
    let mut header = [0; 30];
    if local.checked_add(30).is_none_or(|end| end > len) {
        return Err(format("local header out of bounds"));
    }
    file.seek(SeekFrom::Start(local))?;
    file.read_exact(&mut header)?;
    if !header.starts_with(b"PK\x03\x04") {
        return Err(format("local header"));
    }
    let name_len = u16_at(&header, 26).ok_or(format("local header"))? as u64;
    let extra_len = u16_at(&header, 28).ok_or(format("local header"))? as u64;
    let start = local + 30 + name_len + extra_len;
    // Java reads an entry's compressed bytes to the end of the file at most,
    // all of them when their size is unrecorded, and inflates them to the
    // end of their stream.
    let rest = len.saturating_sub(start);
    let cut = compressed.is_none() && rest > MAX_ENTRY as u64;
    let compressed = match compressed {
        Some(compressed) if compressed.min(rest) > MAX_ENTRY as u64 => {
            return Err(JarError::Limit("entry"));
        }
        Some(compressed) => compressed.min(rest),
        None if method == 8 => rest.min(MAX_ENTRY as u64),
        None if rest > MAX_ENTRY as u64 => return Err(JarError::Limit("entry")),
        None => rest,
    };
    file.seek(SeekFrom::Start(start))?;
    let mut data = vec![0; compressed as usize];
    file.read_exact(&mut data)?;
    match method {
        // As Java, the compressed size of a stored entry is its size.
        0 => Ok(data),
        // Java inflates to the end of the stream, whatever size the headers
        // record. Its inflater is given one zero byte when the data runs
        // out, which data cut at the limit has not.
        8 => {
            if !cut {
                data.push(0);
            }
            miniz_oxide::inflate::decompress_to_vec_with_limit(&data, MAX_ENTRY).map_err(|error| {
                match error.status {
                    miniz_oxide::inflate::TINFLStatus::HasMoreOutput => JarError::Limit("entry"),
                    _ => format("deflate"),
                }
            })
        }
        _ => Err(format("compression method")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The handlers of the one jar of a realm at `path`.
    fn artifact_handlers(path: &Path, coord: &str) -> Result<Vec<DefinedType>, ResolveError> {
        realm_handlers(&[(path, coord)])
    }

    fn artifact_handlers_within(
        path: &Path,
        coord: &str,
        limit: usize,
    ) -> Result<Vec<DefinedType>, ResolveError> {
        realm_handlers_within(&[(path, coord)], limit)
    }

    /// A jar of `entries`, stored or, for a name ending in `.xml` or
    /// `.class`, deflated.
    pub(crate) fn jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, contents) in entries {
            let deflate = name.ends_with(".xml") || name.ends_with(".class");
            let data = if deflate {
                miniz_oxide::deflate::compress_to_vec(contents, 6)
            } else {
                contents.to_vec()
            };
            let method: u16 = if deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(contents.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&data);
            directory.extend_from_slice(b"PK\x01\x02");
            directory.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            directory.extend_from_slice(&method.to_le_bytes());
            directory.extend_from_slice(&[0; 8]);
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(contents.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 12]);
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let start = out.len() as u32;
        out.extend_from_slice(&directory);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn reads_stored_and_deflated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.jar");
        let xml = b"<plugin><goalPrefix>x</goalPrefix></plugin>".repeat(20);
        std::fs::write(
            &path,
            jar(&[
                ("a.class", b"\xCA\xFE"),
                ("META-INF/maven/plugin.xml", &xml),
            ]),
        )
        .unwrap();
        assert_eq!(
            read_entry(&path, "META-INF/maven/plugin.xml").unwrap(),
            Some(xml)
        );
        assert_eq!(
            read_entry(&path, "a.class").unwrap(),
            Some(b"\xCA\xFE".to_vec())
        );
        assert_eq!(read_entry(&path, "missing").unwrap(), None);
    }

    /// Offsets that point past the file are an error, not a panic.
    #[test]
    fn refuses_a_truncated_or_lying_jar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.jar");
        let mut bytes = jar(&[("META-INF/maven/plugin.xml", b"<plugin/>")]);
        let end = bytes.len() - 22;
        bytes[end + 16..end + 20].copy_from_slice(&u32::MAX.wrapping_sub(1).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_entry(&path, "META-INF/maven/plugin.xml").is_err());
        std::fs::write(&path, b"not a jar").unwrap();
        assert!(read_entry(&path, "META-INF/maven/plugin.xml").is_err());
    }

    /// Sisu reads each class its index names once, however many lines name
    /// it, and finds no class the jar lacks: an index that names a class of
    /// 1 MiB 200,000 times and 200,000 classes the jar lacks is read
    /// in seconds, not the hours that reading the class once per line
    /// takes, even unoptimized on a busy machine.
    #[test]
    fn a_long_sisu_index_is_read_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let mut index = "A\n".repeat(200_000);
        index.extend((0..200_000).map(|n| format!("x.C{n}\n")));
        let big = vec![0; 1 << 20];
        let named = ("META-INF/sisu/javax.inject.Named", index.as_bytes());
        std::fs::write(&path, jar(&[named, ("A.class", &big)])).unwrap();
        let start = std::time::Instant::now();
        assert!(artifact_handlers(&path, "t:e:1").unwrap().is_empty());
        let took = start.elapsed();
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    }

    /// A jar whose handler reads pass the limit is refused, whatever the
    /// entries hold, and one within it is read.
    #[test]
    fn handler_reads_past_the_limit_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let index: String = (0..10).map(|n| format!("C{n}\n")).collect();
        let class = vec![0; 1 << 20];
        let names: Vec<String> = (0..10).map(|n| format!("C{n}.class")).collect();
        let mut entries = vec![("META-INF/sisu/javax.inject.Named", index.as_bytes())];
        entries.extend(names.iter().map(|name| (name.as_str(), &class[..])));
        std::fs::write(&path, jar(&entries)).unwrap();
        let error = artifact_handlers_within(&path, "t:e:1", 4 << 20).unwrap_err();
        assert!(error.to_string().contains("more than 4 MiB"), "{error}");
        assert!(
            artifact_handlers_within(&path, "t:e:1", 16 << 20)
                .unwrap()
                .is_empty()
        );
    }

    /// A handler class that two jars of a realm hold with other bytes is
    /// refused whichever jar comes first, as the realm loads the first and
    /// raeva does not follow its order; with the same bytes it is read once.
    #[test]
    fn a_class_two_realm_jars_hold_differently_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let xml = b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>zip</role-hint><implementation>x.Base</implementation>\
              </component></components></component-set>";
        let own = dir.path().join("own.jar");
        std::fs::write(&own, jar(&[("META-INF/plexus/components.xml", xml)])).unwrap();
        let reason = |first: &[u8], second: &[u8]| {
            let (a, z) = (dir.path().join("a.jar"), dir.path().join("z.jar"));
            std::fs::write(&a, jar(&[("x/Base.class", first)])).unwrap();
            std::fs::write(&z, jar(&[("x/Base.class", second)])).unwrap();
            let realm = [
                (own.as_path(), "t:own:1"),
                (z.as_path(), "t:z:1"),
                (a.as_path(), "t:a:1"),
            ];
            let handlers = realm_handlers(&realm).unwrap();
            let [(name, Err(reason))] = &handlers[..] else {
                panic!("{handlers:?}");
            };
            assert_eq!(name, "zip");
            reason.clone()
        };
        let differs = "t:z:1 and t:a:1 in one extension realm define class x.Base differently";
        assert_eq!(reason(b"\xCA\xFE", b"\xCA\xFE\x01"), differs);
        assert_eq!(reason(b"\xCA\xFE\x01", b"\xCA\xFE"), differs);
        assert!(!reason(b"\xCA\xFE", b"\xCA\xFE").contains("differently"));
    }

    /// Directory records that lie about the size of what they inflate to
    /// are charged what it inflates to, as Java reads past the size, and
    /// records that name one entry inflate it once: 10,000 records naming
    /// one deflated entry of 16 MiB, each claiming one byte, are refused
    /// quickly.
    #[test]
    fn records_that_share_a_lying_entry_are_refused_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let names: Vec<String> = (0..10_000).map(|n| format!("C{n}.class")).collect();
        let index: String = (names.iter())
            .map(|name| format!("{}\n", name.trim_end_matches(".class")))
            .collect();
        let mut bytes = jar(&[
            ("META-INF/sisu/javax.inject.Named", index.as_bytes()),
            ("P.class", &vec![0; 16 << 20]),
        ]);
        // Repeat the record of `P.class`, renamed and claiming one byte.
        let end = bytes.len() - 22;
        let start = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
        let mut directory = bytes[start..end].to_vec();
        let record = directory.len() - 46 - "P.class".len();
        let mut shared = directory[record..record + 46].to_vec();
        shared[24..28].copy_from_slice(&1u32.to_le_bytes());
        for name in &names {
            shared[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&shared);
            directory.extend_from_slice(name.as_bytes());
        }
        let count = (2 + names.len()) as u16;
        let mut tail = bytes[end..].to_vec();
        tail[8..10].copy_from_slice(&count.to_le_bytes());
        tail[10..12].copy_from_slice(&count.to_le_bytes());
        tail[12..16].copy_from_slice(&(directory.len() as u32).to_le_bytes());
        bytes.truncate(start);
        bytes.extend_from_slice(&directory);
        bytes.extend_from_slice(&tail);
        std::fs::write(&path, bytes).unwrap();
        let start = std::time::Instant::now();
        let error = artifact_handlers(&path, "t:e:1").unwrap_err();
        let took = start.elapsed();
        assert!(error.to_string().contains("more than 128 MiB"), "{error}");
        assert!(took < std::time::Duration::from_millis(500), "{took:?}");
    }

    /// As OpenJDK's `ZipFile`, which Maven reads descriptors through, finds
    /// them (checked against JDK 27): of two entries of one name the last;
    /// the last end record whose comment runs to the end of the file, though
    /// a comment holds the record's signature; entries after a prefix,
    /// such as a launcher script, whose offsets do not count it; and the
    /// directory a ZIP64 end record places.
    #[test]
    fn entries_are_found_as_java_finds_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "META-INF/maven/plugin.xml";
        let read = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            read_entry(&path, name).unwrap()
        };
        assert_eq!(
            read(&jar(&[(name, b"first"), (name, b"second")])),
            Some(b"second".to_vec())
        );

        let mut commented = jar(&[(name, b"plugin")]);
        let comment = [b"hello PK\x05\x06 world".as_slice(), &[0; 30]].concat();
        let end = commented.len() - 22;
        commented[end + 20..end + 22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        commented.extend_from_slice(&comment);
        assert_eq!(read(&commented), Some(b"plugin".to_vec()));
        // A comment that ends in an empty end record of its own: Java reads
        // that record, which lists no entries.
        let mut faked = jar(&[(name, b"plugin")]);
        let end = faked.len() - 22;
        faked[end + 20..end + 22].copy_from_slice(&22u16.to_le_bytes());
        faked.extend_from_slice(&[b"PK\x05\x06".as_slice(), &[0; 18]].concat());
        assert_eq!(read(&faked), None);

        let prefixed = [
            b"#!/bin/sh\nexec java -jar \"$0\"\n".as_slice(),
            &jar(&[(name, b"run")]),
        ]
        .concat();
        assert_eq!(read(&prefixed), Some(b"run".to_vec()));

        let trailing = [jar(&[(name, b"padded")]).as_slice(), b"padding"].concat();
        assert_eq!(read(&trailing), Some(b"padded".to_vec()));

        // An end record that a prefix lets pass the signature checks, but
        // whose comment is missing: Java fails to read the comment.
        let mut uncommented = prefixed.clone();
        let end = uncommented.len() - 22;
        uncommented[end + 20..end + 22].copy_from_slice(&100u16.to_le_bytes());
        std::fs::write(&path, &uncommented).unwrap();
        assert!(read_entry(&path, name).is_err());

        // ZIP64 end records before the end record, as a jar of 65,536
        // entries has: Java reads the directory where the ZIP64 record
        // says, and takes the locator's offset without a prefix.
        let zip64 = |prefix: &[u8]| {
            let plain = jar(&[(name, b"zip64")]);
            let end = plain.len() - 22;
            let field = |at: usize| u32::from_le_bytes(plain[at..at + 4].try_into().unwrap());
            let count = u16::from_le_bytes(plain[end + 10..end + 12].try_into().unwrap()) as u64;
            let (size, offset) = (field(end + 12) as u64, field(end + 16) as u64);
            let mut record = b"PK\x06\x06".to_vec();
            record.extend_from_slice(&44u64.to_le_bytes());
            record.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            for value in [count, count, size, offset] {
                record.extend_from_slice(&value.to_le_bytes());
            }
            let mut locator = b"PK\x06\x07".to_vec();
            locator.extend_from_slice(&0u32.to_le_bytes());
            locator.extend_from_slice(&(end as u64).to_le_bytes());
            locator.extend_from_slice(&1u32.to_le_bytes());
            [prefix, &plain[..end], &record, &locator, &plain[end..]].concat()
        };
        assert_eq!(read(&zip64(b"")), Some(b"zip64".to_vec()));
        std::fs::write(&path, zip64(&[b'#'; 30])).unwrap();
        assert!(read_entry(&path, name).is_err());
        // An end record at the start of the file: Java opens an empty jar
        // whatever the record says.
        let empty = [
            b"PK\x05\x06".as_slice(),
            &[0, 0, 0, 0, 1, 0, 1, 0],
            &[0; 10],
        ]
        .concat();
        assert_eq!(read(&empty), None);

        // Java takes the entry count from the ZIP64 end record it reads, and
        // refuses more entries than the directory holds.
        for count in [2, 1 << 63] {
            let mut counted = zip64(b"");
            let end = counted.len() - 22;
            let record_at = u64::from_le_bytes(counted[end - 12..end - 4].try_into().unwrap());
            let record_at = record_at as usize;
            counted[record_at + 32..record_at + 40].copy_from_slice(&u64::to_le_bytes(count));
            counted[end + 10..end + 12].copy_from_slice(&[0xFF; 2]);
            std::fs::write(&path, &counted).unwrap();
            assert!(read_entry(&path, name).is_err(), "{count}");
        }
    }

    /// One extra field block, `data` under `tag`.
    fn block(tag: u16, data: &[u8]) -> Vec<u8> {
        [&tag.to_le_bytes(), &(data.len() as u16).to_le_bytes(), data].concat()
    }

    /// A ZIP64 extra field block of `values`.
    fn zip64(values: &[u64]) -> Vec<u8> {
        block(
            1,
            &values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }

    /// `plain` with the directory record `index`, which has no extra field,
    /// given `extra` as one, and the fields `marked` names (uncompressed
    /// size, compressed size, local header offset, disk) set to all ones.
    fn marked(plain: &[u8], index: usize, marked: [bool; 4], extra: &[u8]) -> Vec<u8> {
        let mut bytes = plain.to_vec();
        let end = bytes.len() - 22;
        let u16_at = |bytes: &[u8], at: usize| u16_at(bytes, at).unwrap();
        let mut at = u32_at(&bytes, end + 16).unwrap() as usize;
        for _ in 0..index {
            at += 46 + u16_at(&bytes, at + 28) + u16_at(&bytes, at + 30) + u16_at(&bytes, at + 32);
        }
        for ((field, len), marked) in [(24, 4), (20, 4), (42, 4), (34, 2)].into_iter().zip(marked) {
            if marked {
                bytes[at + field..at + field + len].fill(0xFF);
            }
        }
        bytes[at + 30..at + 32].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        let size = u32_at(&bytes, end + 12).unwrap() as u32 + extra.len() as u32;
        bytes[end + 12..end + 16].copy_from_slice(&size.to_le_bytes());
        let extra_at = at + 46 + u16_at(&bytes, at + 28);
        bytes.splice(extra_at..extra_at, extra.iter().copied());
        bytes
    }

    /// A ZIP64 extra field, which a jar of any size may have, gives each
    /// value its directory record marks with all ones, as OpenJDK's
    /// `ZipFile` reads it (checked against JDK 27): the uncompressed size,
    /// compressed size and local header offset in that order, each only
    /// when marked, from the record's first such field.
    #[test]
    fn a_zip64_extra_field_gives_the_values_a_record_marks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "META-INF/plexus/components.xml";
        let xml = b"<component-set><components/></component-set>".repeat(20);
        let plain = jar(&[("a.txt", b"first"), (name, &xml)]);
        let deflated = miniz_oxide::deflate::compress_to_vec(&xml, 6);
        let (size, compressed) = (xml.len() as u64, deflated.len() as u64);
        let offset = (30 + "a.txt".len() + "first".len()) as u64;
        let read = |marks: [bool; 4], extra: &[u8]| {
            std::fs::write(&path, marked(&plain, 1, marks, extra)).unwrap();
            read_entry(&path, name).ok().flatten()
        };
        let cases: [([bool; 4], Vec<u8>); 8] = [
            ([false, false, true, false], zip64(&[offset])),
            (
                [true, true, true, false],
                zip64(&[size, compressed, offset]),
            ),
            ([true, false, true, false], zip64(&[size, offset])),
            ([false, true, false, false], zip64(&[compressed])),
            (
                [false, false, true, false],
                [block(0xCAFE, b"abc"), zip64(&[offset])].concat(),
            ),
            (
                [false, false, true, true],
                block(1, &[&offset.to_le_bytes()[..], &[0; 4]].concat()),
            ),
            (
                [false, false, true, false],
                [zip64(&[offset]), zip64(&[0])].concat(),
            ),
            (
                [false, false, true, false],
                [zip64(&[offset]), vec![0, 0, 0]].concat(),
            ),
        ];
        let unneeded = ([false; 4], [block(0xCAFE, b""), zip64(&[])].concat());
        // A compressed size past the end of the file: Java reads to the end.
        let past_end = ([false, true, false, false], zip64(&[1024]));
        let far_past_end = ([false, true, false, false], zip64(&[1 << 40]));
        // A record of 0xFFFF bytes, the most Java takes.
        let longest = (
            [false; 4],
            block(0xCAFE, &vec![0; 0xFFFF - 46 - name.len() - 4]),
        );
        let misread: Vec<_> =
            (cases
                .into_iter()
                .chain([unneeded, longest, past_end, far_past_end]))
            .filter(|(marks, extra)| read(*marks, extra) != Some(xml.clone()))
            .collect();
        assert!(misread.is_empty(), "{misread:?}");
    }

    /// OpenJDK's `ZipFile` refuses to open a jar that has a directory record
    /// whose ZIP64 extra field is not exactly the values the record marks,
    /// holds a value over `i64::MAX`, or is missing, and a record whose
    /// extra field blocks or extra field run past it or that is longer than
    /// 0xFFFF bytes: so do we, though the entry read is another.
    #[test]
    fn a_malformed_zip64_extra_field_refuses_the_jar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let plain = jar(&[("a.txt", b"first"), ("b.txt", b"second")]);
        let offset = (30 + "a.txt".len() + "first".len()) as u64;
        let only_offset = [false, false, true, false];
        let cases: [([bool; 4], Vec<u8>); 12] = [
            (only_offset, Vec::new()),
            ([false, false, false, true], Vec::new()),
            (only_offset, zip64(&[])),
            (only_offset, zip64(&[6, 6, offset])),
            ([false; 4], zip64(&[offset])),
            (only_offset, zip64(&[1 << 63])),
            (only_offset, [zip64(&[offset]), zip64(&[1 << 63])].concat()),
            (
                only_offset,
                [zip64(&[offset]), vec![0xFE, 0xCA, 9, 0]].concat(),
            ),
            ([true, false, false, false], zip64(&[6, 6])),
            ([true, false, false, false], zip64(&[1 << 63])),
            ([false, true, false, false], zip64(&[1 << 63])),
            (
                [false; 4],
                block(0xCAFE, &vec![0; 0x1_0000 - 46 - "b.txt".len() - 4]),
            ),
        ];
        let read: Vec<_> = (cases.into_iter())
            .filter(|(marks, extra)| {
                std::fs::write(&path, marked(&plain, 1, *marks, extra)).unwrap();
                read_entry(&path, "a.txt").is_ok()
            })
            .collect();
        assert!(read.is_empty(), "{read:?}");
        let mut overrun = plain.clone();
        let end = overrun.len() - 22;
        let start = u32_at(&overrun, end + 16).unwrap() as usize;
        let last = start + 46 + "a.txt".len();
        overrun[last + 30..last + 32].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(&path, &overrun).unwrap();
        assert!(read_entry(&path, "a.txt").is_err());
    }

    /// OpenJDK's `ZipFile` refuses to open a jar with an encrypted entry, an
    /// entry neither stored nor deflated, a name or comment that is not
    /// UTF-8, bytes after the last directory record, or more entries in its
    /// end record than its directory can hold, whichever entry is read: so
    /// do we. Fewer entries than it holds pass.
    #[test]
    fn jars_java_refuses_to_open_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let plain = jar(&[("a.txt", b"first"), ("b.txt", b"second")]);
        let end = plain.len() - 22;
        let second = u32_at(&plain, end + 16).unwrap() as usize + 46 + "a.txt".len();
        let changed = |at: usize, bytes: &[u8]| {
            let mut changed = plain.clone();
            changed[at..at + bytes.len()].copy_from_slice(bytes);
            changed
        };
        let mut commented = plain.clone();
        commented[second + 32..second + 34].copy_from_slice(&1u16.to_le_bytes());
        commented.insert(end, 0xFF);
        let size = u32_at(&commented, end + 1 + 12).unwrap() as u32 + 1;
        commented[end + 1 + 12..end + 1 + 16].copy_from_slice(&size.to_le_bytes());
        let mut trailing = plain.clone();
        trailing.splice(end..end, [0; 3]);
        let size = u32_at(&plain, end + 12).unwrap() as u32 + 3;
        trailing[end + 3 + 12..end + 3 + 16].copy_from_slice(&size.to_le_bytes());
        let cases = [
            ("encrypted", changed(second + 8, &[1])),
            ("method 12", changed(second + 10, &[12])),
            ("name not UTF-8", changed(second + 46, &[0xFF])),
            ("comment not UTF-8", commented),
            ("bytes after the last record", trailing),
            ("3 entries", changed(end + 8, &[3, 0, 3, 0])),
        ];
        let read: Vec<_> = (cases.into_iter())
            .filter(|(_, bytes)| {
                std::fs::write(&path, bytes).unwrap();
                read_entry(&path, "a.txt").is_ok()
            })
            .map(|(what, _)| what)
            .collect();
        assert!(read.is_empty(), "{read:?}");
        std::fs::write(&path, changed(end + 8, &[0, 0, 0, 0])).unwrap();
        assert_eq!(
            read_entry(&path, "b.txt").unwrap(),
            Some(b"second".to_vec())
        );
    }

    /// Java's inflater input ends in one zero byte past the compressed data,
    /// so a deflated entry whose stream ends within that byte is read, and
    /// one that needs more fails.
    #[test]
    fn a_deflated_entry_is_given_one_zero_byte_more() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        // Stored by `jar`, then marked deflated.
        let name = "p.bin";
        let deflated = miniz_oxide::deflate::compress_to_vec(b"<plugin/>", 6);
        assert_eq!(deflated.last(), Some(&0));
        let read = |short: usize| {
            let data = &deflated[..deflated.len() - short];
            let mut bytes = jar(&[(name, data)]);
            let directory = u32_at(&bytes, bytes.len() - 22 + 16).unwrap() as usize;
            for at in [8, directory + 10] {
                bytes[at..at + 2].copy_from_slice(&8u16.to_le_bytes());
            }
            for at in [22, directory + 24] {
                bytes[at..at + 4].copy_from_slice(&9u32.to_le_bytes());
            }
            std::fs::write(&path, &bytes).unwrap();
            read_entry(&path, name)
        };
        assert_eq!(read(1).unwrap(), Some(b"<plugin/>".to_vec()));
        assert!(read(2).is_err());
    }

    /// The zero byte goes only where Java's input ends: not after data cut
    /// at the entry limit, which Java reads past. Here the byte after the
    /// cut makes the stream invalid, and Java fails.
    #[test]
    fn data_cut_at_the_limit_is_given_no_zero_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "p.bin";
        // A stored block of "X", empty stored blocks, then a final block of
        // `<plugin/>` short of the byte that ends it, MAX_ENTRY bytes in all.
        let mut stream = vec![0x00, 0x01, 0x00, 0xFE, 0xFF, b'X'];
        let tail = miniz_oxide::deflate::compress_to_vec(b"<plugin/>", 6);
        let tail = &tail[..tail.len() - 1];
        let empty = [0x00, 0x00, 0x00, 0xFF, 0xFF];
        let blocks = (MAX_ENTRY - stream.len() - tail.len()) / empty.len();
        assert_eq!(stream.len() + blocks * empty.len() + tail.len(), MAX_ENTRY);
        stream.extend(empty.repeat(blocks));
        stream.extend_from_slice(tail);
        stream.push(0xFF);
        let mut plain = jar(&[(name, &stream)]);
        let directory = u32_at(&plain, plain.len() - 22 + 16).unwrap() as usize;
        for at in [8, directory + 10] {
            plain[at..at + 2].copy_from_slice(&8u16.to_le_bytes());
        }
        for at in [22, directory + 24] {
            plain[at..at + 4].copy_from_slice(&10u32.to_le_bytes());
        }
        let marks = [false, true, false, false];
        std::fs::write(&path, marked(&plain, 0, marks, &block(0xCAFE, b""))).unwrap();
        assert!(read_entry(&path, name).is_err());
    }

    /// Java finds the entry `name` or, failing that, a directory entry
    /// `name/`, the first of them where the last of `name` is read, for a
    /// name that is not empty and does not end in a slash.
    #[test]
    fn a_directory_entry_is_found_by_its_name_without_the_slash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "META-INF/maven/plugin.xml";
        let directory = format!("{name}/");
        let read = |entries: &[(&str, &[u8])]| {
            std::fs::write(&path, jar(entries)).unwrap();
            read_entry(&path, name).unwrap()
        };
        let found = read(&[(&directory, b"first"), (&directory, b"second")]);
        assert_eq!(found, Some(b"first".to_vec()));
        let found = read(&[(name, b"file"), (&directory, b"directory")]);
        assert_eq!(found, Some(b"file".to_vec()));
        // Not for an empty name or one that ends in a slash.
        std::fs::write(&path, jar(&[(&format!("{directory}/"), b"x"), ("/", b"y")])).unwrap();
        assert_eq!(read_entry(&path, &directory).unwrap(), None);
        assert_eq!(read_entry(&path, "").unwrap(), None);
    }

    /// A size a record marks with all ones and no ZIP64 block gives is not
    /// recorded, and Java reads the entry without it: a deflated entry to
    /// the end of its stream, a stored one to the end of the file.
    #[test]
    fn an_unrecorded_size_is_read_as_java_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "META-INF/plexus/components.xml";
        let xml = b"<component-set><components/></component-set>".repeat(20);
        let plain = jar(&[("a.txt", b"first"), (name, &xml), ("b.txt", b"second")]);
        let other = block(0xCAFE, b"abc");
        let read = |name: &str, marks: [bool; 4]| {
            let bytes = marked(&plain, 1 + usize::from(name == "b.txt"), marks, &other);
            std::fs::write(&path, &bytes).unwrap();
            (read_entry(&path, name).ok().flatten(), bytes)
        };
        for marks in [
            [true, false, false, false],
            [false, true, false, false],
            [true, true, false, false],
        ] {
            assert_eq!(read(name, marks).0, Some(xml.clone()), "{marks:?}");
        }
        let (stored, bytes) = read("b.txt", [true, true, false, false]);
        let start = bytes
            .windows(6)
            .position(|window| window == b"second")
            .unwrap();
        assert_eq!(stored, Some(bytes[start..].to_vec()));
        assert_eq!(read(name, [false, false, true, false]).0, None);
    }

    /// An extension jar whose `components.xml` record gives its local header
    /// offset in a ZIP64 extra field, leaves its sizes unrecorded, or gives a
    /// compressed size past the end of the file defines its handlers, as
    /// Maven reads it.
    #[test]
    fn handlers_are_read_through_a_zip64_extra_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let xml = b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>foo</role-hint><configuration><type>foo</type>\
              <extension>jar</extension></configuration>\
              </component></components></component-set>";
        let plain = jar(&[("a.txt", b"first"), ("META-INF/plexus/components.xml", xml)]);
        let offset = (30 + "a.txt".len() + "first".len()) as u64;
        let cases = [
            ([false, false, true, false], zip64(&[offset])),
            ([true, true, false, false], block(0xCAFE, b"")),
            ([false, true, false, false], zip64(&[1 << 40])),
        ];
        for (marks, extra) in cases {
            std::fs::write(&path, marked(&plain, 1, marks, &extra)).unwrap();
            let handlers = artifact_handlers(&path, "t:e:1").unwrap();
            let [(name, Ok(handler))] = &handlers[..] else {
                panic!("{marks:?} {handlers:?}");
            };
            assert_eq!((name.as_str(), handler.extension.as_str()), ("foo", "jar"));
        }
    }

    /// A jar or an entry raeva cannot read is an error, not a jar that
    /// defines no handlers, which would type a dependency by the file of
    /// the type's own name, though Maven goes on without them: so for a
    /// jar that is not one, a `components.xml` whose local header is not
    /// one, and a handler class the Sisu index names whose data does not
    /// inflate.
    #[test]
    fn an_extension_jar_that_does_not_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let name = "META-INF/plexus/components.xml";
        let xml = b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>foo</role-hint><configuration><extension>jar</extension>\
              </configuration></component></components></component-set>";
        let plain = jar(&[(name, xml)]);
        std::fs::write(&path, &plain).unwrap();
        assert_eq!(artifact_handlers(&path, "t:e:1").unwrap().len(), 1);
        std::fs::write(&path, b"not a jar").unwrap();
        assert!(artifact_handlers(&path, "t:e:1").is_err());
        let mut header = plain.clone();
        header[..4].copy_from_slice(b"PK\x03\x05");
        std::fs::write(&path, &header).unwrap();
        let error = artifact_handlers(&path, "t:e:1").unwrap_err();
        assert!(error.to_string().contains(name), "{error}");
        let class = "x/Handler.class";
        let mut index = jar(&[
            (class, &[0; 100]),
            ("META-INF/sisu/javax.inject.Named", b"x.Handler\n"),
        ]);
        index[30 + class.len()] = 0xFF;
        std::fs::write(&path, &index).unwrap();
        let error = artifact_handlers(&path, "t:e:1").unwrap_err();
        assert!(error.to_string().contains(class), "{error}");
    }

    /// As OpenJDK's `ZipFile` reads an entry (checked against JDK 27): a
    /// deflated one to the end of its stream, whatever uncompressed size the
    /// directory or the local header records, and a stored one as its
    /// compressed size. An extension whose `components.xml` records one
    /// byte more than it inflates to defines its handler, as Maven 3.9.12
    /// and 3.10.0 read it.
    #[test]
    fn sizes_are_read_as_java_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let xml = [&b"<component-set>"[..], &[b'x'; 300], b"</component-set>"].concat();
        let sizes = |name: &str, contents: &[u8], central: [u32; 2], local: [u32; 2]| {
            let mut bytes = jar(&[(name, contents)]);
            let directory = u32_at(&bytes, bytes.len() - 22 + 16).unwrap() as usize;
            for (at, value) in [(directory + 20, central[0]), (directory + 24, central[1])] {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            for (at, value) in [(18, local[0]), (22, local[1])] {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            std::fs::write(&path, &bytes).unwrap();
            read_entry(&path, name).unwrap()
        };
        let len = xml.len() as u32;
        let compressed = miniz_oxide::deflate::compress_to_vec(&xml, 6).len() as u32;
        let deflated = |size: u32, local: [u32; 2]| sizes("e.xml", &xml, [compressed, size], local);
        let plain = [compressed, len];
        for size in [len + 1, len - 1, 0, 100_000_000] {
            assert_eq!(deflated(size, plain), Some(xml.clone()), "{size}");
        }
        assert_eq!(deflated(len, [1, 7]), Some(xml.clone()));
        let stored = |central: [u32; 2]| sizes("e.txt", &xml, central, [len; 2]);
        assert_eq!(stored([len, len + 1]), Some(xml.clone()));
        assert_eq!(stored([len, len - 1]), Some(xml.clone()));
        assert_eq!(stored([len - 1, len]), Some(xml[..xml.len() - 1].to_vec()));

        let name = "META-INF/plexus/components.xml";
        let descriptor = b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>foo</role-hint><configuration><extension>jar</extension>\
              </configuration></component></components></component-set>";
        let mut bytes = jar(&[(name, descriptor)]);
        let directory = u32_at(&bytes, bytes.len() - 22 + 16).unwrap() as usize;
        let size = descriptor.len() as u32 + 1;
        bytes[directory + 24..directory + 28].copy_from_slice(&size.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let handlers = artifact_handlers(&path, "t:e:1").unwrap();
        let [(hint, Ok(handler))] = &handlers[..] else {
            panic!("{handlers:?}");
        };
        assert_eq!((hint.as_str(), handler.extension.as_str()), ("foo", "jar"));
    }

    /// A read whose compressed size is unrecorded is charged no more than
    /// the file holds: ten small classes, each with its compressed size
    /// unrecorded, pass the 128 MiB bound of a scan.
    #[test]
    fn an_unrecorded_compressed_size_is_charged_the_file_at_most() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jar");
        let index: String = (0..10).map(|n| format!("C{n}\n")).collect();
        let names: Vec<String> = (0..10).map(|n| format!("C{n}.class")).collect();
        let mut entries = vec![("META-INF/sisu/javax.inject.Named", index.as_bytes())];
        entries.extend(names.iter().map(|name| (name.as_str(), &[0; 64][..])));
        let mut bytes = jar(&entries);
        for record in 1..=names.len() {
            bytes = marked(
                &bytes,
                record,
                [false, true, false, false],
                &block(0xCAFE, b""),
            );
        }
        std::fs::write(&path, &bytes).unwrap();
        assert!(artifact_handlers(&path, "t:e:1").unwrap().is_empty());
    }
}
