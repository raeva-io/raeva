use std::borrow::Cow;
use std::sync::{PoisonError, RwLock};
use url::Url;

const REDACTED: &str = "***";

/// The values of the secrets this configuration took, which no output shows:
/// those of secret-named inputs, and passwords and tokens.
static SECRETS: RwLock<Redactor> = RwLock::new(Redactor::new());

/// Text with the values of secrets written as `***`, each wherever it
/// occurs, as written or as a URL percent-encodes it.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    /// Each spelling of each value, the longest first.
    spellings: Vec<String>,
    /// The base64 of each value at each of the three byte alignments it may
    /// take in a longer text, such as `user:password` in a Basic
    /// `Authorization` header, without the characters its neighbours share:
    /// the whole run of base64 around one is hidden.
    base64: Vec<String>,
}

impl Redactor {
    /// A redactor that hides nothing yet.
    pub const fn new() -> Self {
        Self {
            spellings: Vec::new(),
            base64: Vec::new(),
        }
    }

    /// Hide `value` from now on. Blank text, and a whole `${...}` reference
    /// no input answered, is no secret's value.
    pub fn register(&mut self, value: &str) {
        let reference = value.starts_with("${") && value.find('}') == Some(value.len() - 1);
        if value.trim().is_empty() || reference {
            return;
        }
        let base = || Url::parse("http://h/").expect("base URL parses");
        let mut spellings = vec![value.to_string(), value.to_ascii_lowercase()];
        // A whole URL, as a message shows it parsed.
        if let Ok(url) = Url::parse(value.trim())
            && url.has_authority()
        {
            for url in [url.clone(), redact_parsed(&url, false)] {
                spellings.push(url.as_str().trim_end_matches('/').to_string());
            }
        }
        if let Ok(url) = Url::parse(&format!("http://h/{value}"))
            && url.query().is_none()
            && url.fragment().is_none()
        {
            spellings.push(url.path()[1..].to_string());
        }
        let mut url = base();
        url.set_query(Some(value));
        spellings.extend(url.query().map(str::to_string));
        let mut url = base();
        url.set_fragment(Some(value));
        spellings.extend(url.fragment().map(str::to_string));
        let mut url = base();
        if url.set_password(Some(value)).is_ok() {
            spellings.extend(url.password().map(str::to_string));
        }
        if url.set_username(value).is_ok() {
            spellings.push(url.username().to_string());
        }
        // A host label as IDNA writes it.
        if let Ok(url::Host::Domain(host)) = url::Host::parse(value) {
            spellings.push(host);
        }
        // As a message escapes and cuts untrusted text before output sees it.
        let suffix = format!("... ({} bytes)", value.len());
        for shown in [
            rv_maven_types::bounded(value).to_string(),
            rv_maven_types::quoted(value).to_string(),
        ] {
            let shown = shown.strip_suffix(&suffix).unwrap_or(&shown);
            let shown = (shown.strip_prefix('"'))
                .map_or(shown, |inner| inner.strip_suffix('"').unwrap_or(inner));
            spellings.push(shown.to_string());
        }
        // Each line of a value that spans lines, as output written a line at
        // a time shows it; a line of fewer than 4 characters gives nothing
        // away.
        if value.contains(['\n', '\r']) {
            // As a Windows program writes its lines.
            spellings.push(value.replace("\r\n", "\n").replace('\n', "\r\n"));
            spellings.extend(
                (value.split(['\n', '\r']).map(str::trim))
                    .filter(|line| line.chars().count() >= 4)
                    .map(str::to_string),
            );
        }
        // As a program escapes or encodes text it prints: XML, JSON, a
        // shell, a URL, upper case.
        if value.chars().count() >= 4 {
            spellings.extend(encodings(value));
            for core in base64_cores(value) {
                if !self.base64.contains(&core) {
                    self.base64.push(core);
                }
            }
        }
        for spelling in spellings {
            if !spelling.is_empty() && !self.spellings.contains(&spelling) {
                self.spellings.push(spelling);
            }
        }
        self.spellings
            .sort_by_key(|spelling| std::cmp::Reverse(spelling.len()));
    }

    /// Whether `text` holds a registered value.
    pub fn holds(&self, text: &str) -> bool {
        if (self.base64.iter()).any(|core| text.contains(core.as_str())) {
            return true;
        }
        (self.spellings.iter()).any(|spelling| match spelling.find('%') {
            None => text.contains(spelling.as_str()),
            // Only the hex digits of an escape match either case.
            Some(at) => {
                text.contains(&spelling[..=at])
                    && (0..text.len())
                        .any(|at| starts_with_spelling(&text.as_bytes()[at..], spelling))
            }
        })
    }

    /// `text` with each registered value in it written as `***`, the
    /// longest at each place.
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if !self.holds(text) {
            return Cow::Borrowed(text);
        }
        let mut out = String::with_capacity(text.len());
        let (mut at, mut copied) = (0, 0);
        while let Some(rest) = text.get(at..).filter(|rest| !rest.is_empty()) {
            let found = (self.spellings.iter())
                .find(|spelling| starts_with_spelling(rest.as_bytes(), spelling));
            if let Some(spelling) = found {
                out.push_str(&text[copied..at]);
                out.push_str(REDACTED);
                at += spelling.len();
                copied = at;
                continue;
            }
            match (self.base64.iter()).find(|core| rest.starts_with(core.as_str())) {
                Some(core) => {
                    let start = text[copied..at].trim_end_matches(is_base64).len() + copied;
                    let after = &text[at + core.len()..];
                    let end = text.len() - after.trim_start_matches(is_base64).len();
                    out.push_str(&text[copied..start]);
                    out.push_str(REDACTED);
                    (at, copied) = (end, end);
                }
                None => at += rest.chars().next().map_or(1, char::len_utf8),
            }
        }
        out.push_str(&text[copied..]);
        Cow::Owned(out)
    }

    /// [`Self::redact`] for a JSON document: each string value, decoded,
    /// is redacted and encoded again. Object keys and the other tokens stay,
    /// so the document still parses to the same shape whatever a value
    /// matches, as `e` or `true` would.
    pub fn redact_json<'a>(&self, json: &'a str) -> Cow<'a, str> {
        if self.spellings.is_empty() {
            return Cow::Borrowed(json);
        }
        let bytes = json.as_bytes();
        let mut out = String::new();
        let (mut at, mut copied) = (0, 0);
        while at < bytes.len() {
            if bytes[at] != b'"' {
                at += 1;
                continue;
            }
            let start = at;
            at += 1;
            while at < bytes.len() && bytes[at] != b'"' {
                at += if bytes[at] == b'\\' { 2 } else { 1 };
            }
            let Some(end) = (at < bytes.len()).then_some(at + 1) else {
                break;
            };
            at = end;
            if json[end..].trim_start().starts_with(':') {
                continue;
            }
            let Ok(value) = serde_json::from_str::<String>(&json[start..end]) else {
                continue;
            };
            if let Cow::Owned(redacted) = self.redact(&value) {
                out.push_str(&json[copied..start]);
                out.push_str(&serde_json::Value::from(redacted).to_string());
                copied = end;
            }
        }
        if copied == 0 {
            return Cow::Borrowed(json);
        }
        out.push_str(&json[copied..]);
        Cow::Owned(out)
    }
}

/// Whether `c` may be part of base64 text, in the standard or the URL-safe
/// alphabet.
fn is_base64(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '=')
}

/// The base64 of `value` at each of the three byte alignments it may take
/// in a longer text, in the standard and URL-safe alphabets, without the
/// characters that also encode its neighbours' bits; none shorter than 4.
fn base64_cores(value: &str) -> Vec<String> {
    use base64::Engine;
    let mut cores = Vec::new();
    for pad in 0..3_usize {
        let mut bytes = vec![0_u8; pad];
        bytes.extend_from_slice(value.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let start = (pad * 8).div_ceil(6);
        let end = (bytes.len() * 8) / 6;
        let Some(core) = encoded.get(start..end).filter(|core| core.len() >= 4) else {
            continue;
        };
        cores.push(core.to_string());
        cores.push(core.replace('+', "-").replace('/', "_"));
    }
    cores.dedup();
    cores
}

/// `value` as programs escape or encode text they print: XML entities by
/// name and by number, JSON and Java string escapes, `\u` escapes of
/// HTML-significant and of non-ASCII characters, a shell's quoting, the
/// percent-encoding of every byte that is not alphanumeric, or not one of
/// the characters a URL component or `encodeURIComponent` keeps, and upper
/// case.
fn encodings(value: &str) -> Vec<String> {
    let mut encoded = Vec::new();
    let entities = |table: &[(char, &str)]| {
        let mut out = String::new();
        for c in value.chars() {
            match table.iter().find(|(from, _)| *from == c) {
                Some((_, to)) => out.push_str(to),
                None => out.push(c),
            }
        }
        out
    };
    let named = [('&', "&amp;"), ('<', "&lt;"), ('>', "&gt;")];
    for quotes in [
        &[][..],
        &[('"', "&quot;"), ('\'', "&apos;")],
        &[('"', "&quot;"), ('\'', "&#x27;")],
        &[('"', "&quot;"), ('\'', "&#39;")],
    ] {
        encoded.push(entities(&[&named[..], quotes].concat()));
    }
    let numeric = |hex: bool| {
        let mut out = String::new();
        for c in value.chars() {
            match (matches!(c, '&' | '<' | '>' | '"' | '\''), hex) {
                (true, false) => out.push_str(&format!("&#{};", c as u32)),
                (true, true) => out.push_str(&format!("&#x{:x};", c as u32)),
                (false, _) => out.push(c),
            }
        }
        out
    };
    encoded.extend([numeric(false), numeric(true)]);
    let json = serde_json::Value::from(value).to_string();
    let json = json[1..json.len() - 1].to_string();
    // `\u` escapes of what HTML gives a meaning, as Go and others write
    // them, with non-ASCII characters too.
    let unicode = |escaped: &str, non_ascii: bool| {
        let mut out = String::new();
        for c in json.chars() {
            if escaped.contains(c) || (non_ascii && !c.is_ascii()) {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    let (escaped, quote, ascii) = (
        unicode("<>&", false),
        unicode("<>&'", false),
        unicode("<>&", true),
    );
    encoded.extend([json, escaped, quote, ascii]);
    // A shell's single quotes, and its backslash escapes.
    encoded.push(value.replace('\'', "'\"'\"'"));
    encoded.push(value.replace('\'', "'\\''"));
    encoded.push(
        (value.chars())
            .flat_map(|c| {
                let plain = c.is_ascii_alphanumeric() || "_./-+=:,@%^".contains(c) || !c.is_ascii();
                (!plain).then_some('\\').into_iter().chain([c])
            })
            .collect(),
    );
    let percent = |keep: &str, plus: bool| {
        let mut out = String::new();
        for byte in value.bytes() {
            match byte {
                b' ' if plus => out.push('+'),
                _ if byte.is_ascii_alphanumeric() || keep.as_bytes().contains(&byte) => {
                    out.push(byte as char);
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    };
    for percent in [
        percent("", false),
        percent("-._~", false),
        percent("-._~", true),
        percent("-_.!~*'()", false),
    ] {
        encoded.push(percent.to_ascii_lowercase());
        encoded.push(percent);
    }
    encoded.push(value.to_uppercase());
    encoded
}

/// Whether `text` starts with `spelling`, the hex digits of a percent
/// escape in either case, as a URL may write each escape.
fn starts_with_spelling(text: &[u8], spelling: &str) -> bool {
    let spelling = spelling.as_bytes();
    if text.len() < spelling.len() {
        return false;
    }
    let mut escape = 0_u8;
    spelling.iter().zip(text).all(|(&want, &got)| {
        let hex = escape > 0;
        escape = if want == b'%' {
            2
        } else {
            escape.saturating_sub(1)
        };
        match hex {
            true => want.eq_ignore_ascii_case(&got),
            false => want == got,
        }
    })
}

/// Hide `value`, the value of a secret this configuration took, from every
/// output: [`redact_secrets`] writes it as `***`.
pub fn register_secret(value: &str) {
    (SECRETS.write().unwrap_or_else(PoisonError::into_inner)).register(value);
}

/// Hide `value`, the value of an input raeva takes for a secret by its name
/// alone ([`secret_named`]), unless it is too short or too ordinary to be
/// one: `-Dapp.key=1.2.3` or `-Dskip.key.check=true` would otherwise mask
/// every version or word it matches, coordinates included. A password or
/// token goes to [`register_secret`] whatever its value.
pub fn register_named_secret(value: &str) {
    if !ordinary_value(value) {
        register_secret(value);
    }
}

/// Words and versions that coordinates, scopes and switches spell, and text
/// shorter than 4 characters.
pub(crate) fn ordinary_value(value: &str) -> bool {
    const WORDS: [&str; 12] = [
        "true", "false", "null", "none", "compile", "runtime", "provided", "system", "import",
        "test", "release", "latest",
    ];
    let value = value.trim();
    if value.chars().count() < 4 || WORDS.iter().any(|word| value.eq_ignore_ascii_case(word)) {
        return true;
    }
    // A version: dotted numbers, or a year-sized one, then qualifier parts
    // such as `-SNAPSHOT`, `.Final` or `-rc-1`.
    const QUALIFIERS: [&str; 15] = [
        "snapshot",
        "release",
        "final",
        "ga",
        "sp",
        "jre",
        "android",
        "alpha",
        "beta",
        "rc",
        "cr",
        "m",
        "milestone",
        "a",
        "b",
    ];
    let end = value.find(['-', '_']).unwrap_or(value.len());
    let (numbers, qualifier) = value.split_at(end);
    let mut groups = numbers.split('.').peekable();
    let mut count = 0;
    let mut numeric = 0;
    while let Some(group) = groups.next() {
        count += 1;
        match group.bytes().all(|b| b.is_ascii_digit()) && (1..=8).contains(&group.len()) {
            true => numeric += 1,
            // A qualifier after the dotted numbers, as in `1.0.Final`.
            false if count > 1 && groups.peek().is_none() && qualifier.is_empty() => {
                let digits = group.trim_end_matches(|c: char| c.is_ascii_digit());
                if !QUALIFIERS.iter().any(|q| digits.eq_ignore_ascii_case(q)) {
                    return false;
                }
            }
            false => return false,
        }
    }
    if numeric == 1 && count == 1 && numbers.len() > 4 {
        return false;
    }
    (qualifier.split(['-', '_', '.']).skip(1)).all(|part| {
        let word = part.trim_end_matches(|c: char| c.is_ascii_digit());
        match word.is_empty() {
            // A build number, as in `1.0-1`.
            true => (1..=3).contains(&part.len()),
            false => QUALIFIERS.iter().any(|q| word.eq_ignore_ascii_case(q)),
        }
    })
}

/// Hide the value of each `-Dname=value` in `text`, JVM options or a shell
/// file that sets them, whose name is a secret's ([`register_named_secret`]),
/// as `option_secrets` reads them.
pub fn register_option_secrets(text: &str) {
    for value in option_secrets(text, &|name| std::env::var(name).ok()) {
        register_named_secret(&value);
    }
}

/// The values of the secret-named `-Dname=value`, `-D name=value` and
/// `--define name=value` options in `text`. A value is bare up to white
/// space or a quote, or runs to the quote that opens the option or the
/// value; a quote in the name is dropped, as the java launcher drops it. A
/// value that takes a shell variable, as a mavenrc file may write it, also
/// gives the variable's value: an assignment in `text`, or `env`'s.
pub(crate) fn option_secrets(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut values = Vec::new();
    let starts = (text.match_indices("-D").map(|(at, _)| (at, 2)))
        .chain(text.match_indices("--define").map(|(at, _)| (at, 8)));
    for (at, length) in starts {
        let before = text[..at].chars().next_back();
        if !before.is_none_or(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '=')) {
            continue;
        }
        let open = before.filter(|c| matches!(c, '"' | '\''));
        let rest = text[at + length..].trim_start_matches([' ', '\t', '=']);
        let Some(equals) = rest.find('=') else {
            continue;
        };
        let name: String = (rest[..equals].chars())
            .filter(|c| !matches!(c, '"' | '\''))
            .collect();
        if name.is_empty() || name.contains(char::is_whitespace) || !secret_named(&name) {
            continue;
        }
        let value = &rest[equals + 1..];
        let bare = || (value.split(|c: char| c.is_whitespace() || c == '"' || c == '\'')).next();
        // `mvn` keeps a quote in `$MAVEN_OPTS` as it is.
        let literal = value.split(char::is_whitespace).next();
        // A quote that opens the option holds it whole for the java
        // launcher, not for the shell that splits `MAVEN_OPTS`: both.
        let spans = match (value.chars().next(), open) {
            (Some(quote @ ('"' | '\'')), _) => vec![value[1..].split(quote).next(), literal],
            (_, Some(quote)) => vec![bare(), value.split(quote).next(), literal],
            _ => vec![bare(), literal],
        };
        for value in spans.into_iter().flatten() {
            for variable in shell_variables(value) {
                values.extend(assignments(text, variable));
                values.extend(env(variable));
            }
            values.push(value.to_string());
        }
    }
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
    values
}

/// The names `$NAME` and `${NAME}` in `text` read.
fn shell_variables(text: &str) -> Vec<&str> {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    (text.match_indices('$'))
        .filter_map(|(at, _)| {
            let rest = &text[at + 1..];
            let rest = rest.strip_prefix('{').unwrap_or(rest);
            let name = &rest[..rest.find(|c| !is_name(c)).unwrap_or(rest.len())];
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// The values `text` assigns the shell variable `name`, as `NAME=value`,
/// `export NAME=value` or `set NAME=value`.
fn assignments(text: &str, name: &str) -> Vec<String> {
    let pattern = format!("{name}=");
    (text.match_indices(&pattern))
        .filter(|(at, _)| {
            text[..*at]
                .chars()
                .next_back()
                .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '"'))
        })
        .filter_map(|(at, _)| {
            let value = &text[at + pattern.len()..];
            match value.chars().next() {
                Some(quote @ ('"' | '\'')) => value[1..].split(quote).next(),
                _ => value.split(|c: char| c.is_whitespace() || c == ';').next(),
            }
        })
        .map(str::to_string)
        .collect()
}

/// `text` with the value of each secret [`register_secret`] took written as
/// `***`, for what raeva prints: messages, logs and reports.
pub fn redact_secrets(text: &str) -> Cow<'_, str> {
    (SECRETS.read().unwrap_or_else(PoisonError::into_inner)).redact(text)
}

/// [`redact_secrets`] for a JSON document, which still parses after it.
pub fn redact_secrets_in_json(json: &str) -> Cow<'_, str> {
    (SECRETS.read().unwrap_or_else(PoisonError::into_inner)).redact_json(json)
}

/// Mirror URLs that settings.xml expanded with a secret-named variable,
/// each ending in `/`, with the name [`stored_urls`] gives them, in the
/// order they were registered.
static STORED_NAMES: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());

/// Have [`stored_urls`] name the mirror `url` `mirror:<id>/`, the name a
/// seed gives it: `url` is a mirror URL as settings.xml expanded it with a
/// secret-named variable, and the store index and `metadata.db`, which CI
/// caches, keep that name in its place.
pub fn register_stored_name(url: &str, id: &str) {
    let url = url.trim();
    let slashed = |url: &str| match url.ends_with('/') {
        true => url.to_string(),
        false => format!("{url}/"),
    };
    // A `file:` URL is kept as it parses.
    let parsed = Url::parse(url).map(|url| slashed(url.as_str()));
    let mut names = STORED_NAMES.write().unwrap_or_else(PoisonError::into_inner);
    for url in std::iter::once(slashed(url)).chain(parsed) {
        if !names.iter().any(|(known, _)| *known == url) {
            names.push((url, format!("mirror:{id}/")));
        }
    }
}

/// Give `to`, the URL a mirror registered at `from` is read at, the stored
/// name ([`register_stored_name`]) `from` has, so the store records hide
/// the secret too.
pub(crate) fn register_moved_url(from: &str, to: &str) {
    let slashed = |url: &str| match url.ends_with('/') {
        true => url.to_string(),
        false => format!("{url}/"),
    };
    let spellings = |url: &str| {
        let url = url.trim();
        std::iter::once(slashed(url))
            .chain(Url::parse(url).map(|url| slashed(url.as_str())))
            .collect::<Vec<_>>()
    };
    let mut names = STORED_NAMES.write().unwrap_or_else(PoisonError::into_inner);
    let from = spellings(from);
    let Some(at) = names.iter().position(|(known, _)| from.contains(known)) else {
        return;
    };
    let name = names[at].1.clone();
    // Ahead of `from`, as [`restored_urls`] gives a name the first URL.
    for url in spellings(to).into_iter().rev() {
        if !names.iter().any(|(known, _)| *known == url) {
            names.insert(at, (url, name.clone()));
        }
    }
}

/// What the store index, the metadata cache and a seed name a repository
/// whose URL is no http, https or file URL by: only a mirror serves it, and
/// its text may hold a secret no parser can find.
pub const UNRECORDED_REPOSITORY: &str = "unrecorded:";

/// `url`, or [`UNRECORDED_REPOSITORY`] for a repository URL that is no
/// http, https or file URL, as raeva.lock records none for it.
pub fn stored_repository(url: &str) -> &str {
    let fetchable = Url::parse(url.trim())
        .is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https" | "file"));
    match fetchable || url.trim().is_empty() {
        true => url,
        false => UNRECORDED_REPOSITORY,
    }
}

/// Why raeva refuses a part of the repository URL `url` that may hold a
/// secret, as a clause after "which": raeva.lock records an http, https or
/// file URL, `expanded` when settings.xml expanded a variable in it. It
/// records no other, but raeva takes no secret from a URL of any scheme.
pub fn secret_part_refusal(url: &str, expanded: bool) -> &'static str {
    match (stored_repository(url) == UNRECORDED_REPOSITORY, expanded) {
        (true, _) => {
            "raeva refuses in a URL of any scheme, though raeva.lock records only http, https \
             and file URLs"
        }
        (false, false) => "raeva.lock would record",
        (false, true) => "raeva.lock would record expanded",
    }
}

/// What messages and logs show for a repository URL with no http, https or
/// file scheme: only a mirror serves it, and its text may hold the value of
/// a variable that nothing else shows.
pub const UNRECORDED_URL: &str = "<URL raeva.lock does not record>";

/// [`redact_url`] for a repository URL, or [`UNRECORDED_URL`] for one with
/// no http, https or file scheme.
pub fn redact_repository_url(url: &str) -> String {
    match stored_repository(url) {
        UNRECORDED_REPOSITORY => UNRECORDED_URL.to_string(),
        url => redact_url(url),
    }
}

/// `text` with each mirror URL [`register_stored_name`] took, and each URL
/// under one, written with the mirror's name in place of its URL.
pub fn stored_urls(text: &str) -> Cow<'_, str> {
    replace_names(text, false)
}

/// [`stored_urls`] undone: `text` with each mirror name in it written as
/// the URL of the mirror this configuration gives that name, the first
/// registered of two. A name no mirror here has stays.
pub fn restored_urls(text: &str) -> Cow<'_, str> {
    replace_names(text, true)
}

fn replace_names(text: &str, restore: bool) -> Cow<'_, str> {
    let names = STORED_NAMES.read().unwrap_or_else(PoisonError::into_inner);
    if names.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut pairs: Vec<(&str, &str)> = (names.iter())
        .map(|(url, name)| match restore {
            false => (url, name),
            true => (name, url),
        })
        .map(|(from, to)| (from.as_str(), to.as_str()))
        .collect();
    // The longest first, so a mirror under another's path is replaced whole.
    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    let mut text = Cow::Borrowed(text);
    let mut done = Vec::new();
    for (from, to) in pairs {
        if !done.contains(&from) && text.contains(from) {
            text = Cow::Owned(text.replace(from, to));
        }
        done.push(from);
    }
    text
}

/// Whether [`redact_url`] hides part of `url`, a credential or the whole
/// URL when it does not parse, or `url` is at or under a mirror URL that
/// settings.xml expanded with a secret ([`register_stored_name`]).
pub fn url_holds_secret(url: &str) -> bool {
    Url::parse(url).map_or(true, |parsed| {
        let stored = |url: &str| {
            let slashed = format!("{}/", url.trim_end_matches('/'));
            stored_urls(&slashed) != slashed
        };
        redact_url(url) != parsed.as_str() || stored(url) || stored(parsed.as_str())
    })
}

/// What stands in for text that does not parse as a URL.
pub const UNPARSABLE_URL: &str = "<unparsable URL>";

/// What [`redacted_url`] returns for a URL without an authority, whose
/// scheme and path may be a misread `user:password`.
const UNPARSABLE_URL_PLACEHOLDER: &str = "https://redacted.invalid/";

/// A URL with everything that may carry a secret removed, for messages and
/// logs: the userinfo (`user:pass@`) is dropped, a query string becomes
/// `?***` because its names can be tokens too, and the fragment is dropped.
/// A URL without userinfo whose authority has a port, and an `@` after it,
/// may still hold userinfo that the parser read as host and port, as in
/// `https://user:1234/x@host/`, where the password starts with `1234/`.
/// Such a URL loses everything before its last `@`, or everything after the
/// scheme when that `@` comes after a `?` or `#`, where it may sit in a
/// query. Without a port, a later `@` is kept, as in a signed download URL
/// that names an account in its query.
///
/// Text that does not parse as a URL with an authority, such as
/// `user:pass@host/path` or `user:/pass@host/path`, which parse with `user`
/// as their scheme, is not shown at all: it may be a token pasted in place of a URL, or a URL whose
/// credentials made it fail to parse. It becomes [`UNPARSABLE_URL`].
pub fn redact_url(url: impl AsRef<str>) -> String {
    let raw = url.as_ref();
    match Url::parse(raw) {
        Ok(parsed) if parsed.has_authority() => {
            // The parser drops an empty or default port, as in
            // `https://user:443/x@host/`, so look for it in the text.
            redact_parsed(&parsed, raw_authority_has_port(raw)).to_string()
        }
        _ => UNPARSABLE_URL.to_string(),
    }
}

/// [`redact_url`] for a parsed URL, as a `Url` so it can be attached to an
/// error in place of the original. A URL without an authority becomes
/// `https://redacted.invalid/`. It cannot see a port that parsing
/// dropped, so `https://user:443/x@host/` keeps `user` as the host and `/x@`
/// in the path; the text form passed to [`redact_url`] does not.
pub fn redacted_url(url: &Url) -> Url {
    redact_parsed(url, false)
}

/// A `\` in the `http` or `https` URL `url`, or outside Windows in any
/// other, or a host or a `#` or `?` in the `file:` URL `url`, with the
/// clause after "its URL" that refuses it;
/// see [`rv_maven_model::file_transport::host_refusal`] for the host.
/// Maven's HTTP transport fails each request to a URL with a `\`, and Maven
/// 3.9 the build on one after the port, where a URL parser reads it as `/`.
/// Maven's file transporter reads a `#` or `?` as part of the directory
/// name, as in a `${user.home}` that holds one, where a URL parser starts a
/// fragment or query, so raeva would read another directory.
pub fn url_refusal(url: &str) -> Option<String> {
    if let Some(refusal) = rv_maven_model::file_transport::host_refusal(url) {
        return Some(refusal);
    }
    let url: String = (url.chars())
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let http = (url.trim_start().split_once(':')).is_some_and(|(scheme, _)| {
        matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
    });
    if http && url.contains('\\') {
        return Some(
            "has '\\' in it, which Maven's HTTP transport refuses and raeva would read as '/'; \
             write '/' in its place"
                .to_string(),
        );
    }
    // Outside Windows, `java.io.File` keeps it as part of a name; on Windows
    // it is a separator in every path Maven's file transporter reads.
    if url.contains('\\') && !cfg!(windows) {
        return Some(
            "has '\\' in it, which Maven reads as part of a name and raeva would read as '/'; \
             write '/' in its place"
                .to_string(),
        );
    }
    if !(url.trim_start().get(..5)).is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:")) {
        return None;
    }
    let found = url.chars().find(|c| matches!(c, '#' | '?'))?;
    Some(format!(
        "has '{found}' in it, which Maven's file transport reads as part of the path and \
         raeva cannot; move the repository to a directory without '{found}', or write \
         it as {}",
        if found == '#' { "%23" } else { "%3F" }
    ))
}

/// The part of `url` that [`redact_url`] would remove because it may carry
/// a secret: `"userinfo"`, `"a query"` or `"a fragment"`, or `None` when
/// the redacted form is the URL itself. A repository URL with such a part
/// cannot be recorded in raeva.lock or shown without leaking it. Text that does
/// not parse as a URL with an authority counts as userinfo when it holds an
/// `@`, since that is what made it fail, as a query or a fragment when it
/// holds a `?` or a `#`, and as clean otherwise.
pub fn secret_url_part(url: &str) -> Option<&'static str> {
    let parsed = match Url::parse(url) {
        Ok(parsed) if parsed.has_authority() => parsed,
        _ if url.contains('@') => return Some("userinfo"),
        _ if url.contains('?') => return Some("a query"),
        _ => return url.contains('#').then_some("a fragment"),
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("userinfo");
    }
    if parsed.query().is_some() {
        return Some("a query");
    }
    if parsed.fragment().is_some() {
        return Some("a fragment");
    }
    // A port read from a password, as in `https://user:1234/x@host/`.
    let redacted = redact_parsed(&parsed, raw_authority_has_port(url)).to_string();
    (redacted != parsed.as_str()).then_some("userinfo")
}

/// Whether a property or environment variable name looks like it holds a
/// secret: it has `TOKEN`, `SECRET`, `PASS`, `KEY`, `AUTH`, `CREDENTIAL` or
/// `ENTITLEMENT` in it, in any case.
pub fn secret_named(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASS",
        "KEY",
        "AUTH",
        "CREDENTIAL",
        "ENTITLEMENT",
    ]
    .iter()
    .any(|word| upper.contains(word))
}

/// The path of a repository URL as written, where services such as
/// Cloudsmith take a token: what follows the authority, or the whole text
/// when it has no `://`, as the scheme or host may still be unexpanded. A
/// `file:` URL's path is a directory, which raeva.lock records too.
pub(crate) fn repository_url_path(url: &str) -> &str {
    match url.split_once("://") {
        // A backslash ends an http(s) authority too.
        Some((_, rest)) => rest.find(['/', '\\']).map_or("", |slash| &rest[slash..]),
        None => url,
    }
}

/// Whether `value` makes up one or more whole segments of the path of the
/// repository URL `url`, as a token a service takes there does: what
/// follows the authority, or the whole text without a `://`. A value with
/// at least `TOKEN_LENGTH` characters other than separators counts
/// inside a segment too, as in `repo-${repo.token}`. A `${...}` left in
/// `value`, which only a model can expand, stands for any text, so such a
/// value counts by the text around it. A value with no text but
/// separators never counts.
pub fn url_path_holds(url: &str, value: &str) -> bool {
    let path = repository_url_path(url);
    let length: usize = (literal_parts(value).iter())
        .map(|part| part.chars().filter(|c| !matches!(c, '/' | '\\')).count())
        .sum();
    holds_value(path, value, length < TOKEN_LENGTH)
}

/// The fewest characters a value takes to count anywhere in a URL path: a
/// shorter one, such as `1` or `prod`, is likely there by chance.
const TOKEN_LENGTH: usize = 8;

/// Whether `text` holds `value`, as whole segments when `segments`, with
/// each `${...}` in `value` standing for any text.
fn holds_value(text: &str, value: &str, segments: bool) -> bool {
    let separator = |c: char| matches!(c, '/' | '\\');
    let parts = literal_parts(value);
    if !(parts.iter()).any(|part| part.contains(|c| !separator(c))) {
        return false;
    }
    let edge = |c: Option<char>| !segments || c.is_none_or(separator);
    let starts_segment =
        |at: usize, part: &str| edge(text[..at].chars().next_back()) || edge(part.chars().next());
    let ends_segment = |at: usize, part: &str| {
        let end = at + part.len();
        edge(text[end..].chars().next()) || edge(part.chars().next_back())
    };
    let found = |from, part| occurrences(text, from, part);
    let (first, rest) = parts.split_first().expect("a value has a first part");
    let Some((last, middle)) = rest.split_last() else {
        return found(0, first).any(|at| starts_segment(at, first) && ends_segment(at, first));
    };
    // The earliest start leaves the most room for the rest.
    let Some(start) = found(0, first).find(|&at| starts_segment(at, first)) else {
        return false;
    };
    let mut at = start + first.len();
    for part in middle {
        match text[at..].find(part) {
            Some(found) => at += found + part.len(),
            None => return false,
        }
    }
    found(at, last).any(|at| ends_segment(at, last))
}

/// Each place `part` starts in `text` at or after `from`, overlapping ones
/// too.
fn occurrences<'a>(text: &'a str, from: usize, part: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut at = from;
    std::iter::from_fn(move || {
        let found = at + text.get(at..)?.find(part)?;
        at = found + text[found..].chars().next().map_or(1, char::len_utf8);
        Some(found)
    })
}

/// The text of `value` around each `${...}` in it, one more than there are
/// of those. Expressions nest, as in `${${name}}`.
fn literal_parts(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("${")
        && let Some(end) = closing_brace(&rest[start + 2..])
    {
        parts.push(&rest[..start]);
        rest = &rest[start + 2 + end + 1..];
    }
    parts.push(rest);
    parts
}

fn closing_brace(text: &str) -> Option<usize> {
    let mut depth = 1;
    text.char_indices().find_map(|(at, c)| {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        (depth == 0).then_some(at)
    })
}

/// How a message names the first of `reads`, the names a model looked up
/// to interpolate a repository URL, that is named like a secret
/// ([`secret_named`]) or takes a value from one, as `names`
/// ([`crate::Config::secret_input_names`]) lists them. The URL takes that
/// secret whatever its value and wherever it lands in the URL.
pub fn secret_read(reads: &[String], names: &[(String, String)]) -> Option<String> {
    // An input `names` lists first, as it names where the value comes from.
    let listed = reads.iter().find_map(|read| {
        (names.iter())
            .find(|(name, _)| name == read)
            .map(|(_, input)| input.clone())
    });
    listed.or_else(|| {
        (reads.iter())
            .find(|read| secret_named(read))
            .map(|read| format!("${{{}}}", rv_maven_types::bounded(read)))
    })
}

/// How a message names the first of `secrets`, each a name and a value as
/// [`crate::Config::secret_named_inputs`] gives them, whose value makes up
/// part of the path of `url` as [`url_path_holds`] reads it.
pub fn secret_input_in_path<'a>(url: &str, secrets: &'a [(String, String)]) -> Option<&'a str> {
    (secrets.iter())
        .find(|(_, value)| url_path_holds(url, value))
        .map(|(input, _)| input.as_str())
}

/// `text`, such as a repository id, for a message, or `***` when it holds
/// the value of one of `secrets`, read as [`url_path_holds`] reads it but
/// anywhere in `text`.
pub fn without_secret_values<'a>(text: &'a str, secrets: &[(String, String)]) -> &'a str {
    if (secrets.iter()).any(|(_, value)| holds_value(text, value, false)) {
        REDACTED
    } else {
        text
    }
}

fn redact_parsed(url: &Url, had_port: bool) -> Url {
    if !url.has_authority() {
        return Url::parse(UNPARSABLE_URL_PLACEHOLDER).expect("placeholder URL parses");
    }
    let mut redacted = url.clone();
    if url.username().is_empty()
        && url.password().is_none()
        && (had_port || url.port().is_some())
        && url.as_str().contains('@')
    {
        // Parses with `***` as the userinfo, which is dropped below.
        redacted = Url::parse(&strip_misread_userinfo(url.as_str())).unwrap_or_else(|_| {
            let mut placeholder = url.clone();
            let _ = placeholder.set_host(Some("redacted.invalid"));
            let _ = placeholder.set_port(None);
            placeholder.set_path("");
            placeholder
        });
    }
    // Fails only for URLs that cannot have userinfo, such as `mailto:`.
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    if redacted.query().is_some() {
        redacted.set_query(Some(REDACTED));
    }
    redacted.set_fragment(None);
    redacted
}

fn raw_authority_has_port(raw: &str) -> bool {
    // The parser trims C0 controls and spaces around the input and drops
    // tabs and newlines anywhere in it.
    let cleaned: String = raw
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let Some((scheme, rest)) = cleaned.split_once(':') else {
        return false;
    };
    if !is_scheme(scheme) {
        return false;
    }
    let (rest, delimiters): (&str, &[char]) = match scheme.to_ascii_lowercase().as_str() {
        // These take any run of `/` or `\` after the scheme, including
        // none, as in `https:host:443/`.
        "http" | "https" | "ws" | "wss" | "ftp" => {
            (rest.trim_start_matches(['/', '\\']), &['/', '?', '#', '\\'])
        }
        // A file URL has no port; `C:` in `file:///C:/` is a drive.
        "file" => return false,
        _ => match rest.strip_prefix("//") {
            Some(rest) => (rest, &['/', '?', '#']),
            None => return false,
        },
    };
    let authority = &rest[..rest.find(delimiters).unwrap_or(rest.len())];
    let host_end = authority.rfind(']').map_or(0, |index| index + 1);
    authority[host_end..].contains(':')
}

fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Removes everything up to the last `@` of a URL's text, and its query and
/// fragment, so the rest parses without the userinfo the parser misread.
fn strip_misread_userinfo(raw: &str) -> String {
    // A scheme only when it is one by RFC 3986, so a `user:pass://` prefix
    // is not kept as one.
    let scheme_len = raw
        .find("://")
        .filter(|&end| is_scheme(&raw[..end]))
        .map_or(0, |end| end + 3);
    let (scheme, rest) = raw.split_at(scheme_len);
    let mut out = String::with_capacity(raw.len());
    out.push_str(scheme);
    let query = rest.find(['?', '#']);
    // The last `@`, wherever it is: a password may contain `/` or `@`.
    let rest = match rest.rfind('@') {
        // After a `?` or `#` it may end a password holding one, or sit in
        // a query, so nothing after the scheme can be shown as a host.
        Some(at) if query.is_some_and(|query| query < at) => {
            out.push_str(REDACTED);
            return out;
        }
        Some(at) => {
            out.push_str(REDACTED);
            &rest[at..]
        }
        None => rest,
    };
    match rest.find(['?', '#']) {
        Some(index) => {
            out.push_str(&rest[..index]);
            out.push('?');
            out.push_str(REDACTED);
        }
        None => out.push_str(rest),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Redactor, option_secrets, ordinary_value, redact_url};

    #[test]
    fn a_secret_is_hidden_as_messages_and_logs_spell_it() {
        let mut redactor = Redactor::new();
        redactor.register("zq^é");
        redactor.register("zqAA\nzqBB");
        redactor.register(&"zqLONG".repeat(30));
        for text in [
            "zq%5e%C3%A9",
            "zq%5E%c3%a9",
            "zqAA\\u{a}zqBB",
            "zqAA",
            "zqBB",
        ] {
            assert_eq!(redactor.redact(text), "***", "{text}");
        }
        let cut = rv_maven_types::bounded(&"zqLONG".repeat(30)).to_string();
        assert!(!redactor.redact(&cut).contains("zqLONG"), "{cut}");
    }

    #[test]
    fn a_name_alone_hides_no_ordinary_version_or_word() {
        for value in [
            "abc",
            "1.2.3",
            "1.0-SNAPSHOT",
            "2.0.0.Final",
            "1.0-rc-1",
            "3.1.0-M2",
            "2024",
            "true",
            "Compile",
            "1.0-1",
        ] {
            assert!(ordinary_value(value), "{value}");
        }
        for value in [
            "hunter2",
            "s3cr3t-token",
            "123456",
            "1234-5678-9012",
            "1.0-hunter2",
            "ghp_0123456789",
            "4111111111.1111111111",
        ] {
            assert!(!ordinary_value(value), "{value}");
        }
    }

    /// Each form a program may print a secret in, as `forms` lists them.
    #[test]
    fn a_secret_is_hidden_in_each_escaped_or_encoded_form() {
        let mut redactor = Redactor::new();
        redactor.register("zqA&<>\"'P1zq");
        let forms = [
            "zqA&amp;&lt;&gt;&quot;&#x27;P1zq",
            "zqA&amp;&lt;&gt;&quot;&apos;P1zq",
            "zqA&#38;&#60;&#62;&#34;&#39;P1zq",
            "zqA&<>\\\"'P1zq",
            "zqA\\u0026\\u003c\\u003e\\\"'P1zq",
            "zqa%26%3c%3e%22%27p1zq",
            "zqA%26%3C%3E%22%27P1zq",
            "zqA%26%3c%3E%22%27P1zq",
            "'zqA&<>\"'\"'\"'P1zq'",
            "ZQA&<>\"'P1ZQ",
        ];
        for form in forms {
            assert!(!redactor.redact(form).contains("P1"), "{form}");
        }
        let mut redactor = Redactor::new();
        redactor.register("zqHT+/=:@!Pzq");
        use base64::Engine;
        for user in ["", "u", "uZ", "uZQ:"] {
            let text = format!("{user}zqHT+/=:@!Pzq");
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE,
            ] {
                let encoded = engine.encode(&text);
                let shown = format!("Authorization: Basic {encoded} sent");
                assert_eq!(
                    redactor.redact(&shown),
                    "Authorization: Basic *** sent",
                    "{user}"
                );
            }
        }
        for form in [
            "zqHT%2B%2F%3D%3A%40%21Pzq",
            "zqHT%2B%2F%3D%3A%40!Pzq",
            "zqHT%2b%2f%3d%3a%40%21Pzq",
        ] {
            assert_eq!(redactor.redact(form), "***", "{form}");
        }
    }

    #[test]
    fn option_secrets_take_each_secret_named_define() {
        let text = "MAVEN_OPTS=\"-Xmx1g -Dapi.key=zqKEYzq -Dplain=v\"\n\
                    -Ddeploy.token='a b' -Dx=-Dauth.pass=nope export\t-DPASS=zq2zq";
        // `-Dx`'s value reads as a define too, which hides more, not less,
        // and a quote is kept as `mvn` splits `$MAVEN_OPTS`.
        let none = |_: &str| None;
        assert_eq!(
            option_secrets(text, &none),
            ["zqKEYzq", "a b", "'a", "nope", "zq2zq"]
        );
        // As the java launcher, Maven's `-D name=value` and a mavenrc file
        // write them.
        let text = "-D\"api.token\"=zqQzq \"-Dapi.key=abc zqSPACEzq\" -D my.secret=zqSEPzq \
                    --define deploy.pass=zqDEFzq\nV=zqVARzq; MAVEN_OPTS=\"-Dapi.token=$V -Dw.token=${W}\"";
        let env = |name: &str| (name == "W").then(|| "zqENVzq".to_string());
        assert_eq!(
            option_secrets(text, &env),
            [
                "zqQzq",
                "abc",
                "abc zqSPACEzq",
                "zqSEPzq",
                "zqVARzq",
                "$V",
                "zqENVzq",
                "$V -Dw.token=${W}",
                "${W}",
                "${W}\"",
                "zqDEFzq"
            ]
        );
    }

    fn redactor(values: &[&str]) -> Redactor {
        let mut redactor = Redactor::new();
        for value in values {
            redactor.register(value);
        }
        redactor
    }

    #[test]
    fn a_secret_of_any_length_is_hidden_wherever_it_occurs() {
        let redactor = redactor(&["QzWj"]);
        assert_eq!(
            redactor.redact("not to http://h/QzWj/g/a.pom, QzWj again"),
            "not to http://h/***/g/a.pom, *** again"
        );
        assert_eq!(redactor.redact("nothing here"), "nothing here");
    }

    #[test]
    fn the_longest_value_at_a_place_is_hidden_whole() {
        let redactor = redactor(&["tok", "tok-long"]);
        assert_eq!(redactor.redact("a tok-long b tok"), "a *** b ***");
    }

    #[test]
    fn a_value_is_hidden_as_a_url_encodes_it() {
        let redactor = redactor(&["zq M^K\"z"]);
        let path = url::Url::parse("http://h/zq M^K\"z/x").expect("parses");
        let mut userinfo = url::Url::parse("http://h/").expect("parses");
        userinfo.set_password(Some("zq M^K\"z")).expect("password");
        // A host is shown in lower case, an escape in either.
        for shown in [
            path.as_str(),
            userinfo.as_str(),
            "zq m^k\"z",
            "zq%20M%5eK%22z",
        ] {
            let redacted = redactor.redact(shown).to_ascii_lowercase();
            assert!(
                !redacted.contains("m^k") && !redacted.contains("m%5ek"),
                "{shown}"
            );
            assert!(redacted.contains("***"), "{shown}");
        }
    }

    #[test]
    fn a_host_label_is_hidden_as_idna_writes_it() {
        let redactor = redactor(&["bücher"]);
        let url = url::Url::parse("https://bücher.example/m2/").expect("parses");
        assert_eq!(redactor.redact(url.as_str()), "https://***.example/m2/");
    }

    #[test]
    fn blank_text_and_an_unexpanded_reference_are_no_secret() {
        let redactor = redactor(&["", "  ", "${env.TOKEN}", "abc${def"]);
        assert_eq!(redactor.redact("a  ${env.TOKEN} b"), "a  ${env.TOKEN} b");
        assert_eq!(redactor.redact("pw abc${def"), "pw ***");
    }

    #[test]
    fn json_keeps_its_shape_whatever_a_secret_matches() {
        let redactor = redactor(&["e", "true", "QzWj"]);
        let json = r#"{"error": "see http://h/QzWj/", "code":"e","ok":true,"n\"e":["QzWj\n"]}"#;
        let redacted = redactor.redact_json(json);
        let value: serde_json::Value = serde_json::from_str(&redacted).expect("still JSON");
        let mut keys: Vec<&String> = value.as_object().expect("object").keys().collect();
        keys.sort();
        assert_eq!(keys, ["code", "error", "n\"e", "ok"]);
        assert_eq!(value["error"], "s****** http://h/***/");
        assert_eq!(value["ok"], true);
        assert_eq!(value["code"], "***");
        assert_eq!(value["n\"e"][0], "***\n");
        assert!(!redacted.contains("QzWj"), "{redacted}");
        assert_eq!(redactor.redact_json(r#"{"a":"b"}"#), r#"{"a":"b"}"#);
    }

    #[test]
    fn a_url_holds_a_secret_when_its_redaction_hides_part_of_it() {
        use super::{register_stored_name, url_holds_secret};
        register_stored_name("https://w7.example/tok-w/m2/", "w");
        register_stored_name("https://t7.example/tok-t7/m2", "t");
        for (url, secret) in [
            ("https://w7.example/tok-w/m2/", true),
            ("https://W7.example:443/tok-w/m2", true),
            ("https://T7.example:443/tok-t7/m2/a.pom", true),
            ("https://user:pass@repo.example/m2/", true),
            ("not a url", true),
            ("https://REPO.example:443/m2/", false),
            ("file:///tmp/repo/", false),
        ] {
            assert_eq!(url_holds_secret(url), secret, "{url}");
        }
    }

    #[test]
    fn a_repository_url_raeva_lock_cannot_record_is_stored_by_one_name() {
        use super::{UNRECORDED_REPOSITORY, stored_repository};
        for (url, stored) in [
            ("https://repo.example/m2/", "https://repo.example/m2/"),
            ("file:///tmp/repo/", "file:///tmp/repo/"),
            ("", ""),
            ("http://[::1", UNRECORDED_REPOSITORY),
            ("./repo/", UNRECORDED_REPOSITORY),
            ("ftp://repo.example/", UNRECORDED_REPOSITORY),
            (UNRECORDED_REPOSITORY, UNRECORDED_REPOSITORY),
        ] {
            assert_eq!(stored_repository(url), stored, "{url}");
        }
    }

    #[test]
    fn a_stored_mirror_url_is_named_by_its_id() {
        use super::{register_stored_name, restored_urls, stored_urls};
        register_stored_name("https://n4.example/tok-n4", "n");
        register_stored_name("https://n4.example/tok-n4/sub/", "s");
        let scope = "https://repo.example/\u{1f}https://n4.example/tok-n4/\u{1f}id=n";
        let stored = "https://repo.example/\u{1f}mirror:n/\u{1f}id=n";
        assert_eq!(stored_urls(scope), stored);
        assert_eq!(restored_urls(stored), scope);
        assert_eq!(stored_urls("https://n4.example/tok-n4/sub/"), "mirror:s/");
        assert_eq!(restored_urls("mirror:s/"), "https://n4.example/tok-n4/sub/");
        assert_eq!(
            stored_urls("https://n4.example/tok-n4x/"),
            "https://n4.example/tok-n4x/"
        );
        assert_eq!(restored_urls("mirror:gone/"), "mirror:gone/");
    }

    /// A mirror URL a variable gives whole is hidden as messages show it
    /// parsed, and one a token is part of shows the rest.
    #[test]
    fn a_secret_mirror_url_is_hidden_as_a_message_shows_it() {
        let redactor = redactor(&["https://M.example:443/m2", "tok3n-zq", "Q9h"]);
        for (raw, shown) in [
            ("https://m.example/m2/a/1/a-1.jar", "***/a/1/a-1.jar"),
            (
                "https://x.example/tok3n-zq/m2/a.pom",
                "https://x.example/***/m2/a.pom",
            ),
            (
                "https://q9h.example/m2/a.pom",
                "https://***.example/m2/a.pom",
            ),
            (
                "https://repo1.maven.org/maven2/m2/",
                "https://repo1.maven.org/maven2/m2/",
            ),
        ] {
            let url = redact_url(raw);
            assert_eq!(redactor.redact(&url), shown, "{raw}");
        }
    }

    #[test]
    fn secret_url_parts_are_named() {
        use super::secret_url_part;
        for (raw, part) in [
            ("https://repo1.maven.org/maven2/", None),
            ("https://Repo.Example:8443/m2", None),
            ("file:///C:/Users/alice@corp/.m2/repository/", None),
            ("https://repo.example/npm/@types/node/", None),
            ("https://user:pass@repo.example/m2/", Some("userinfo")),
            ("https://token@repo.example/m2/", Some("userinfo")),
            ("https://alice:1234/x@repo.example/m2/", Some("userinfo")),
            ("https://user:pa/ss@repo.example/m2/", Some("userinfo")),
            ("user:pass@repo.example/m2/", Some("userinfo")),
            ("https://repo.example/m2/?token=abc", Some("a query")),
            ("https://repo.example/m2/#abc", Some("a fragment")),
            ("not a url", None),
            ("http://[::1", None),
            ("http://[::1?token=abc", Some("a query")),
            ("http://[::1#abc", Some("a fragment")),
        ] {
            assert_eq!(secret_url_part(raw), part, "{raw}");
        }
    }

    #[test]
    fn secret_names_are_recognised_in_any_case() {
        use super::secret_named;
        for name in [
            "cs.token",
            "CLOUDSMITH_API_KEY",
            "nexus.Password",
            "repo.secret",
            "auth.header",
            "aws.credentials",
            "entitlement",
        ] {
            assert!(secret_named(name), "{name}");
        }
        for name in ["nexus.url", "CI_PROJECT_ID", "repo.path", "revision"] {
            assert!(!secret_named(name), "{name}");
        }
    }

    /// A value counts when it makes up whole segments of the path, a
    /// `file:` URL's directory too, or anywhere in the path when it has at
    /// least eight characters; never when it is in the host. An expression
    /// left in it stands for any text.
    #[test]
    fn url_path_values_are_whole_segments() {
        use super::url_path_holds;
        for (url, value) in [
            ("https://dl.example/abc123/org/maven/", "abc123"),
            ("https://dl.example/maven/abc123", "abc123"),
            ("https://dl.example\\abc123\\maven/", "abc123"),
            ("https://dl.example/org/abc/123/maven/", "abc/123"),
            ("https://dl.example/org/abc/123/maven/", "/abc/123/"),
            ("https://dl.example/xa/a/a/", "a/a"),
            ("dl.example/abc123/maven/", "abc123"),
            ("abc123/maven/", "abc123"),
            (
                "https://dl.example/amd64/abc123/maven/",
                "${os.arch}/abc123",
            ),
            (
                "https://dl.example/app-abc123/maven/",
                "${project.artifactId}-abc123",
            ),
            ("https://dl.example/x/abc/y/123/", "abc/${a}/123"),
            ("https://dl.example/abc123/x/", "abc${a}"),
            ("https://dl.example/prod/abc123/x/", "${${selector}}/abc123"),
            ("https://dl.example/ab/abc/", "${a}/abc"),
            ("file:///srv/abc123/m2/", "abc123"),
            ("FILE:/C:/abc123/", "abc123"),
            ("file:///srv/repo-abc12345/", "abc12345"),
            ("https://dl.example/v-abc12345.x/maven/", "abc12345"),
            ("https://dl.example/repo-abc12345/", "${a}-abc12345"),
        ] {
            assert!(url_path_holds(url, value), "{url} {value}");
        }
        for (url, value) in [
            ("https://abc123.example/maven/", "abc123"),
            ("https://dl.example/abc1234/maven/", "abc123"),
            ("https://dl.example/v1/maven/", "1"),
            ("https://dl.example/maven/", ""),
            ("file:///srv/abc1234/m2/", "abc123"),
            ("https://dl.example/xabc123/maven/", "abc123${a}"),
            ("https://dl.example/abc/maven/", "${a}abc123"),
            ("https://dl.example/a/b/", "${a}/${b}"),
            ("https://dl.example/abc/abc12/", "${a}/abc123"),
            ("https://abc12345.example/maven/", "abc12345"),
            ("https://dl.example/repo-abc1234/", "abc1234"),
        ] {
            assert!(!url_path_holds(url, value), "{url} {value}");
        }
    }

    #[test]
    fn texts_that_hold_a_secret_value_are_hidden() {
        use super::without_secret_values;
        let secrets = [("-Dcs.token".to_string(), "${stage}/abc123".to_string())];
        assert_eq!(without_secret_values("id-prod/abc123", &secrets), "***");
        assert_eq!(without_secret_values("id-x/abc123y", &secrets), "***");
        assert_eq!(without_secret_values("idabc123", &secrets), "idabc123");
        assert_eq!(without_secret_values("releases", &secrets), "releases");
    }

    #[test]
    fn parsed_urls_lose_userinfo_query_and_fragment() {
        for (raw, expected) in [
            (
                "https://user:pass@repo.example/maven/?token=secret&sig=abc#frag",
                "https://repo.example/maven/?***",
            ),
            (
                "https://user@repo.example/maven/",
                "https://repo.example/maven/",
            ),
            (
                "https://repo.example/maven/?ghp_bare",
                "https://repo.example/maven/?***",
            ),
            (
                "https://repo1.maven.org/maven2/",
                "https://repo1.maven.org/maven2/",
            ),
            ("file:///srv/m2/", "file:///srv/m2/"),
            ("https:user:pass@repo.example/m2", "https://repo.example/m2"),
            // These parse, with the password's digits as the port.
            (
                "https://alice:1234/x@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            ("https://alice:1234?x@repo.example/", "https://***/"),
            ("https://alice:1234#x@repo.example/", "https://***/"),
            // With a port, an `@` in the query may end a password.
            (
                "https://repo.example:8443/m2/?token=user@secret",
                "https://***/",
            ),
            ("https://repo.example:8443/m2/#user@secret", "https://***/"),
            ("https://alice:443/x@repo.example/", "https://repo.example/"),
            ("https://alice:/x@repo.example/", "https://repo.example/"),
            // The parser takes any run of `/` or `\` after the scheme.
            (
                "https:alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https:///alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https:\\\\alice:/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            // The parser trims spaces and drops tabs and newlines.
            (
                " https://alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "ht\ttps:/\t/alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https://alice:4\n43/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            // A drive letter is not a port.
            (
                "file:///C:/Users/alice@corp/.m2/repository/",
                "file:///C:/Users/alice@corp/.m2/repository/",
            ),
            // With userinfo, a later `@` is part of the path.
            ("https://u:p@repo.example/a@b/", "https://repo.example/a@b/"),
            // Without a port, a later `@` is part of the path or query.
            (
                "https://repo.example/npm/@types/node",
                "https://repo.example/npm/@types/node",
            ),
            (
                "https://storage.example/b/o?cred=svc@project.example",
                "https://storage.example/b/o?***",
            ),
            ("https://[::1]/a@b/", "https://[::1]/a@b/"),
        ] {
            assert_eq!(redact_url(raw), expected, "{raw}");
        }
        let url = url::Url::parse("https://u:p@repo.example/a?b=c").unwrap();
        assert_eq!(redact_url(&url), "https://repo.example/a?***");
        let url = url::Url::parse("https://alice:1234/x@[bad/").unwrap();
        let redacted = super::redacted_url(&url).to_string();
        assert!(
            !redacted.contains("1234") && !redacted.contains("alice"),
            "{redacted}"
        );
    }

    /// Text that does not parse is not shown, however much of it is a URL.
    #[test]
    fn unparsable_text_is_not_shown() {
        for raw in [
            // The port does not parse: `pa/ss` is part of the password.
            "https://user:pa/ss@repo.example/m2/",
            "https://user:secret@[::1/m2/",
            "https://user:p@ss@repo example/",
            // Parses, with `user` as the scheme and no authority.
            "user:secret@repo.example/m2",
            "https://repo example/m2?token=secret",
            "https://alice:secret?tail@repo.example/",
            "alice:secret://x@repo.example",
            // Parse with `alice` as the scheme, a path and no authority.
            "alice:/s3cret@repo.example/m2",
            "alice:s3cret@repo.example",
            "ghp_secret",
            "",
        ] {
            assert_eq!(redact_url(raw), super::UNPARSABLE_URL, "{raw:?}");
        }
    }

    #[test]
    fn typed_redaction_needs_an_authority() {
        use super::redacted_url;
        for raw in ["alice:s3cret@repo.example", "alice:/s3cret@repo.example/m2"] {
            let url = url::Url::parse(raw).unwrap();
            assert_eq!(
                redacted_url(&url).as_str(),
                "https://redacted.invalid/",
                "{raw}"
            );
        }
        let url = url::Url::parse("file:///srv/m2/").unwrap();
        assert_eq!(redacted_url(&url).as_str(), "file:///srv/m2/");
        assert_eq!(super::redact_url("file:///srv/m2/"), "file:///srv/m2/");
        assert_eq!(super::redact_url("file:/srv/m2/"), "file:///srv/m2/");
    }
}
