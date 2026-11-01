//! Parsing a large raeva.lock on several threads.

use std::fmt::Write as _;
use std::hash::{BuildHasher, RandomState};
use std::ops::Range;

use toml::{Table, Value};

/// The header line of each module block.
const MODULE: &str = "[[platforms.modules]]\n";
/// A lock of fewer module blocks, or whose blocks are less than half its
/// text, parses as fast whole.
const MIN_BLOCKS: usize = 16;

/// `contents` parsed as one TOML document.
///
/// Most of a large lock's text is its module blocks. Each block parses on
/// its own, on several threads, and the rest of the text parses with a
/// marker element in place of each block, which the block's element then
/// replaces. A marker's key carries a random tag, so no text can forge one.
/// A block with a header other than its first line or that does not parse
/// alone or defines anything beside its element, and a marker that is
/// missing, out of order or given other keys, mean the text is not of that
/// form: it is then parsed whole, so the result and any error are always
/// the whole parse's.
pub(crate) fn parse(contents: &str) -> Result<Table, toml::de::Error> {
    split(contents).map_or_else(|| toml::from_str(contents), Ok)
}

fn split(contents: &str) -> Option<Table> {
    let blocks = module_blocks(contents)?;
    let block_bytes: usize = blocks.iter().map(ExactSizeIterator::len).sum();
    if blocks.len() < MIN_BLOCKS || block_bytes * 2 < contents.len() {
        return None;
    }
    let tag = format!("rv-block-{:016x}", RandomState::new().hash_one(()));
    let mut rest = String::with_capacity(contents.len() - block_bytes + blocks.len() * 64);
    let mut at = 0;
    for (index, block) in blocks.iter().enumerate() {
        rest.push_str(&contents[at..block.start]);
        rest.push_str(MODULE);
        let _ = writeln!(rest, "{tag} = {index}");
        at = block.end;
    }
    rest.push_str(&contents[at..]);
    let texts: Vec<&str> = std::iter::once(rest.as_str())
        .chain(blocks.iter().map(|block| &contents[block.clone()]))
        .collect();
    let mut parsed =
        rv_maven_types::par_map(&texts, |text| toml::from_str::<Table>(text).ok()).into_iter();
    let mut doc = parsed.next()??;
    let mut elements = parsed
        .map(|block| block.and_then(block_element))
        .collect::<Option<Vec<_>>>()?
        .into_iter();
    let mut next = 0;
    for platform in platforms(&mut doc) {
        let Some(Value::Array(modules)) = platform.get_mut("modules") else {
            continue;
        };
        for module in modules {
            let Value::Table(table) = module else {
                continue;
            };
            let Some(marker) = table.get(&tag) else {
                continue;
            };
            if table.len() != 1 || marker.as_integer() != i64::try_from(next).ok() {
                return None;
            }
            *module = elements.next()?;
            next += 1;
        }
    }
    (next == blocks.len()).then_some(doc)
}

/// The byte range of each module block: from its header line to the next
/// line that starts with `[`, or the end. `None` when a block has an
/// indented line starting with `[`, which may be a header: one parsed
/// alone could declare a table the whole text has already defined.
fn module_blocks(contents: &str) -> Option<Vec<Range<usize>>> {
    let mut blocks = Vec::new();
    let mut open = None;
    let mut at = 0;
    for line in contents.split_inclusive('\n') {
        if line.starts_with('[') {
            if let Some(start) = open.take() {
                blocks.push(start..at);
            }
            if line == MODULE {
                open = Some(at);
            }
        } else if open.is_some() && line.trim_start_matches([' ', '\t']).starts_with('[') {
            return None;
        }
        at += line.len();
    }
    if let Some(start) = open {
        blocks.push(start..at);
    }
    Some(blocks)
}

/// The one module element a block parsed alone defines, if that is all it
/// defines.
fn block_element(mut block: Table) -> Option<Value> {
    let Some(Value::Table(mut platforms)) = block.remove("platforms") else {
        return None;
    };
    let Some(Value::Array(mut modules)) = platforms.remove("modules") else {
        return None;
    };
    let element = modules.pop()?;
    (block.is_empty() && platforms.is_empty() && modules.is_empty() && element.is_table())
        .then_some(element)
}

/// Each platform table of `doc`, in order.
fn platforms(doc: &mut Table) -> Vec<&mut Table> {
    match doc.get_mut("platforms") {
        Some(Value::Array(platforms)) => platforms
            .iter_mut()
            .filter_map(Value::as_table_mut)
            .collect(),
        Some(Value::Table(platform)) => vec![platform],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules(count: usize) -> String {
        (0..count)
            .map(|index| {
                format!("{MODULE}path = \"m{index}/pom.xml\"\npackages = \"\"\"\na\tjar\n\"\"\"\n")
            })
            .collect()
    }

    fn same(text: &str) {
        assert_eq!(
            parse(text).map_err(|err| err.to_string()),
            toml::from_str::<Table>(text).map_err(|err| err.to_string()),
            "{text}"
        );
    }

    #[test]
    fn a_split_parse_is_the_whole_parse() {
        let blocks = modules(20);
        same(&format!(
            "schema_version = 8\n[[platforms]]\nplatform = \"a\"\n{blocks}[[platforms.support_poms]]\nx = 1\n[[platforms]]\nplatform = \"b\"\n{blocks}[metadata]\ny = 2\n"
        ));
        assert!(split(&format!("[[platforms]]\n{blocks}")).is_some());
    }

    /// Text that a block's cut would read otherwise is parsed whole: a
    /// string open across a cut, an indented header in a block, a block
    /// defining another table, and keys given to a module element after
    /// its block.
    #[test]
    fn text_that_does_not_split_is_parsed_whole() {
        let blocks = modules(20);
        for text in [
            format!("[[platforms]]\nx = \"\"\"\n{blocks}\"\"\"\n"),
            format!("[[platforms]]\n{blocks}  [metadata]\ny = 1\n"),
            format!("[[platforms]]\n{blocks}[platforms.modules.extra]\ny = 1\n"),
            format!("[[platforms]]\n{blocks}  [[platforms.modules]]\ny = 1\n"),
            format!("[[platforms]]\n{blocks}\t[platforms]\n{blocks}"),
            format!("[[platforms]]\nmodules = []\n{blocks}"),
            format!("[[platforms]]\n{blocks}[[platforms.modules]]\npath = 1\npath = 2\n"),
        ] {
            assert!(split(&text).is_none(), "{text}");
            same(&text);
        }
    }
}
