//! Maven `settings-security.xml` password decryption.
//!
//! Reads `{base64(...)}`-wrapped values produced by `mvn --encrypt-password` /
//! plexus-cipher 2.x. Algorithm: AES-128/CBC/PKCS5 with key+IV derived as
//! `SHA-256(password || salt8)` split into a 16-byte key and 16-byte IV.
//! Payload layout inside the braces: `salt[8] || pad_len[1] || ciphertext ||
//! random_pad[pad_len]`.
//!
//! Raeva-native at-rest encryption is a future feature and will use a distinct
//! `{rv1:...}` marker so the two formats can never be confused.

use std::fs;
use std::path::{Path, PathBuf};

use aes::Aes128;
use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;

use crate::error::ConfigError;
use crate::maven_settings::harden_xml;

// Default-redact: ASCII-decoded ciphertext fragments could otherwise leak
// into logs; only known-safe structural messages pass through.
fn sanitize_error_message(msg: &str) -> String {
    const SAFE_PREFIXES: &[&str] = &[
        "decryption failed",
        "invalid encrypted data format",
        "invalid base64",
        "invalid format",
        "missing master password",
    ];
    let lower = msg.to_ascii_lowercase();
    if SAFE_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        // Cap length to keep verbose error chains out of logs; clamp to a
        // char boundary so we never panic on a multi-byte prefix.
        if msg.len() > 100 {
            let mut cut = 100;
            while cut > 0 && !msg.is_char_boundary(cut) {
                cut -= 1;
            }
            format!("{}...", &msg[..cut])
        } else {
            msg.to_string()
        }
    } else {
        "[REDACTED]".to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SecuritySettings {
    pub master: Option<String>,
    pub relocation: Option<PathBuf>,
}

// Shadow struct mirroring the `<settingsSecurity>` schema. Only the two
// fields we actually read are captured; unknown elements are ignored by
// quick-xml's serde adapter, which keeps parity with the previous SAX
// loop's behaviour.
#[derive(Debug, Deserialize)]
struct SecurityXml {
    master: Option<String>,
    relocation: Option<String>,
}

impl SecuritySettings {
    const MAX_RELOCATION_DEPTH: usize = 10;

    pub fn load_default() -> Result<Option<Self>, ConfigError> {
        let Some(path) = default_security_path() else {
            return Ok(None);
        };
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Option<Self>, ConfigError> {
        Self::load_with_depth(path, 0)
    }

    fn load_with_depth(path: &Path, depth: usize) -> Result<Option<Self>, ConfigError> {
        if depth > Self::MAX_RELOCATION_DEPTH {
            return Err(ConfigError::RelocationDepthExceeded);
        }

        // Pre-allocation size check: reject grossly-oversized inputs before
        // we read them into memory. The post-allocation check in
        // `harden_xml` is still applied as defence-in-depth.
        if let Ok(meta) = fs::metadata(path)
            && meta.len() > crate::maven_settings::MAX_SETTINGS_SIZE as u64
        {
            return Err(ConfigError::InvalidSettings(format!(
                "settings-security.xml at {} is {} bytes, exceeds {}-byte limit",
                path.display(),
                meta.len(),
                crate::maven_settings::MAX_SETTINGS_SIZE
            )));
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let base_dir = path.parent();
        let mut settings_opt = Self::parse_with_depth(&content, depth, base_dir)?;
        // Surface the resolved (absolute) relocation path on the returned struct so
        // callers can inspect where the chain ultimately pointed.
        if let Some(ref mut settings) = settings_opt
            && let Some(ref reloc) = settings.relocation.clone()
            && reloc.is_relative()
            && let Some(parent) = base_dir
        {
            settings.relocation = Some(parent.join(reloc));
        }
        Ok(settings_opt)
    }

    #[cfg(test)]
    pub fn parse(xml: &str) -> Result<Option<Self>, ConfigError> {
        Self::parse_with_depth(xml, 0, None)
    }

    fn parse_with_depth(
        xml: &str,
        depth: usize,
        base_dir: Option<&Path>,
    ) -> Result<Option<Self>, ConfigError> {
        // settings-security.xml runs through the same hardening as the main
        // settings.xml parse: 5 MiB ceiling, BOM strip, DOCTYPE reject. The
        // file format is even simpler than settings.xml, so it sees the same
        // attacks (UTF-8 BOM on Windows, hostile DTD) for an even smaller
        // payload.
        let xml = harden_xml(xml)?;

        // Match `MavenSettings`'s serde-based parse style. quick-xml's
        // serialize feature is on by definition for the workspace, so we get
        // the same parser semantics as settings.xml with much less code.
        // A malformed XML payload is logged and treated as "no settings"
        // to preserve the prior best-effort behaviour of the SAX loop.
        let mut settings = match quick_xml::de::from_str::<SecurityXml>(xml) {
            Ok(parsed) => SecuritySettings {
                master: parsed.master.and_then(|m| {
                    let trimmed = m.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }),
                relocation: parsed.relocation.and_then(|r| {
                    let trimmed = r.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(trimmed))
                    }
                }),
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "XML parse error in settings-security.xml; encrypted passwords will not be decrypted"
                );
                SecuritySettings::default()
            }
        };

        // Follow relocation if present. Relative relocation paths are resolved
        // against the directory of the *source* file (passed in via base_dir),
        // never the process cwd. Without this, a relative <relocation> entry
        // would be opened relative to wherever the binary happened to be run.
        if let Some(relocation_path) = &settings.relocation {
            let resolved = if relocation_path.is_relative() {
                match base_dir {
                    Some(dir) => dir.join(relocation_path),
                    None => relocation_path.clone(),
                }
            } else {
                relocation_path.clone()
            };
            // Maven's sec-dispatcher treats a `<relocation>` as "the master
            // actually lives in this other file": the relocated file fully
            // supersedes the source master. We therefore replace `master`
            // outright with whatever the relocation chain resolves to,
            // including replacing it with `None` when the target has no
            // master, so a stale source `<master>` never leaks through when
            // a relocation is declared.
            settings.master = match Self::load_with_depth(&resolved, depth + 1)? {
                Some(relocated) => relocated.master,
                None => None,
            };
        }

        if settings.master.is_some() || settings.relocation.is_some() {
            Ok(Some(settings))
        } else {
            Ok(None)
        }
    }
}

pub fn default_security_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".m2").join("settings-security.xml"))
}

/// Extracts the brace-delimited cipher payload from a possibly decorated value.
///
/// Maven's sec-dispatcher allows free-text decorations around the braces, e.g.
/// `Oleg reset this on 2009-03-11 {COQLCE6DU6GtcS5P=}`. Its `unDecorate` takes
/// the text between the LAST `{` in the value and the FIRST `}` after it; we
/// replicate that faithfully. Returns the inner content without braces, or
/// `None` when no such chunk exists.
fn extract_cipher_payload(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let start = trimmed.rfind('{')?;
    let after = &trimmed[start + 1..];
    let end = after.find('}')?;
    Some(&after[..end])
}

/// Checks if a value appears to be in the Maven `{base64}` encrypted format,
/// optionally decorated with surrounding free text (see
/// [`extract_cipher_payload`]).
///
/// The format mirrors plexus-cipher's `{base64content}` shape so that values
/// can be detected in mixed settings.xml inputs. The check validates that a
/// brace-delimited chunk exists and that its content contains only base64
/// characters, which distinguishes encrypted values from literal values that
/// happen to be wrapped in braces (e.g., `{my-literal-password}`).
pub fn is_encrypted(value: &str) -> bool {
    let Some(inner) = extract_cipher_payload(value) else {
        return false;
    };
    // Inner content must be non-empty and contain only valid base64 characters.
    // This is the Maven plexus-cipher format.
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("invalid base64: {0}")]
    Base64(String),
    #[error("invalid encrypted data format")]
    InvalidFormat,
    #[error("decryption failed: {0}")]
    Decryption(String),
}

// plexus-cipher 2.x: single SHA-256(password || salt), split into 16-byte
// key and 16-byte IV. Upstream's PBE_ITERATIONS=1000 loop is dead code since
// the first digest already fills both halves.
fn derive_key_iv(password: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    let digest = hasher.finalize();

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    iv.copy_from_slice(&digest[16..32]);
    (key, iv)
}

// Reads Maven plexus-cipher AES/CBC. raeva-native secrets will use a distinct {rv1:...} marker.
/// Decrypts a Maven-encrypted password using the master password.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted string contains no `{...}` cipher chunk
/// - The base64 decoding fails
/// - The encrypted data format is invalid
/// - The decryption operation fails
/// - The decrypted bytes are not valid UTF-8
pub fn decrypt_maven_password(encrypted: &str, master: &str) -> Result<String, EncryptionError> {
    // Decorations around the braces are allowed and discarded, matching
    // sec-dispatcher's `unDecorate` (see `extract_cipher_payload`).
    let inner = extract_cipher_payload(encrypted).ok_or(EncryptionError::InvalidFormat)?;

    if inner.is_empty() {
        return Err(EncryptionError::InvalidFormat);
    }

    decrypt_plexus_cipher(inner, master)
}

/// Decrypt the inner base64-encoded plexus-cipher payload.
///
/// Layout: `salt[8] || pad_len[1] || ciphertext || random_pad[pad_len]`.
///
/// # LIMITATIONS
///
/// This implements Maven's plexus-cipher 2.x wire format: AES-128/CBC + PKCS#7.
/// CBC mode is vulnerable to padding-oracle timing attacks if an adversary can (a)
/// write to the user's `settings.xml` and (b) observe error-response timing.
/// We cannot change the wire format without breaking compatibility with `mvn`.
/// Threat model: local-only; the attacker must already have write access to
/// `settings.xml`, at which point credentials are already at risk by other means.
/// Any future Raeva-native at-rest encryption should use a `{rv1:...}` marker
/// and AES-256-GCM or ChaCha20-Poly1305 (authenticated encryption, no oracle).
fn decrypt_plexus_cipher(
    encrypted_base64: &str,
    master_password: &str,
) -> Result<String, EncryptionError> {
    let clean_input: String = encrypted_base64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let decoded = STANDARD
        .decode(&clean_input)
        .with_context(|| "failed to decode encrypted password base64")
        .map_err(|err| EncryptionError::Base64(err.to_string()))?;

    // Minimum: 8 (salt) + 1 (pad_len) + 16 (one AES block of ciphertext) = 25.
    if decoded.len() < 25 {
        return Err(EncryptionError::InvalidFormat);
    }

    let salt = &decoded[..8];
    let pad_len = decoded[8] as usize;

    let header = 9usize;
    let ct_end = decoded
        .len()
        .checked_sub(pad_len)
        .ok_or(EncryptionError::InvalidFormat)?;
    if ct_end <= header {
        return Err(EncryptionError::InvalidFormat);
    }
    let ciphertext = &decoded[header..ct_end];
    if ciphertext.len() % 16 != 0 {
        return Err(EncryptionError::InvalidFormat);
    }

    let (key, iv) = derive_key_iv(master_password.as_bytes(), salt);
    let mut buffer = ciphertext.to_vec();
    let decryptor = cbc::Decryptor::<Aes128>::new(&key.into(), &iv.into());

    // Map all errors to a generic failure to avoid leaking padding-oracle bits.
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| EncryptionError::Decryption("decryption failed".to_string()))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|_| EncryptionError::Decryption("decryption failed".to_string()))
}

pub fn try_decrypt_password(password: &str, security: Option<&SecuritySettings>) -> Option<String> {
    if !is_encrypted(password) {
        return Some(password.to_string());
    }

    let Some(settings) = security else {
        warn!(
            context = "[REDACTED]",
            "encrypted password detected but settings-security.xml not found"
        );
        return None;
    };

    let Some(master) = settings.master.as_deref() else {
        warn!(
            context = "[REDACTED]",
            "encrypted password detected but no master password in settings-security.xml"
        );
        return None;
    };

    let master_plain = if is_encrypted(master) {
        // Fixed master-of-master key "settings.security" decrypts garbage
        // without error; validation lives in `is_plausible_master`.
        let Ok(value) = decrypt_maven_password(master, "settings.security") else {
            warn!(
                context = "[REDACTED]",
                "failed to decrypt master password from settings-security.xml"
            );
            return None;
        };
        if !is_plausible_master(&value) {
            warn!(
                context = "[REDACTED]",
                "master password decryption produced an implausible result; \
                 settings-security.xml may be corrupt or written by an \
                 incompatible tool"
            );
            return None;
        }
        value
    } else {
        master.to_string()
    };

    decrypt_maven_password(password, &master_plain)
        .inspect_err(|err| {
            warn!(
                context = "[REDACTED]",
                error = %sanitize_error_message(&err.to_string()),
                "failed to decrypt password"
            );
        })
        .ok()
}

// AES decrypts of garbage often pass PKCS#7 padding; require non-empty,
// all-printable-ASCII so a corrupt master surfaces instead of silently
// producing wrong credentials downstream. We do NOT impose a minimum length
// beyond non-empty: Maven lets users pick any master password, and a short
// one (e.g. a 3-char passphrase) is perfectly valid. The printable-ASCII
// gate already rejects the overwhelming majority of wrong-key decryptions,
// which contain control bytes or non-ASCII noise.
fn is_plausible_master(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| matches!(c, ' '..='~'))
}

pub fn sanitize_password(value: String, security: Option<&SecuritySettings>) -> Option<String> {
    if !is_encrypted(&value) {
        return Some(value);
    }
    try_decrypt_password(&value, security)
}

/// Round-trip-encrypt `plaintext_bytes` under `master` with a caller-supplied
/// 8-byte `salt` and zero trailing random pad. Mirrors the plexus-cipher 2.x
/// layout (`salt || pad_len || ciphertext || pad`) so tests can synthesise
/// deterministic fixtures without shelling out to `mvn --encrypt-password`.
#[cfg(test)]
pub(crate) fn encrypt_for_tests(plaintext_bytes: &[u8], master: &str, salt: [u8; 8]) -> String {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    let (key, iv) = derive_key_iv(master.as_bytes(), &salt);
    let blocks = plaintext_bytes.len() / 16 + 1;
    let mut buf = vec![0u8; blocks * 16];
    buf[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
    let encryptor = cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into());
    let ct = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_bytes.len())
        .unwrap()
        .to_vec();
    let pad_len = (16 - (8 + ct.len() + 1) % 16) % 16;
    let mut payload = Vec::with_capacity(8 + 1 + ct.len() + pad_len);
    payload.extend_from_slice(&salt);
    payload.push(pad_len as u8);
    payload.extend_from_slice(&ct);
    payload.extend(std::iter::repeat_n(0u8, pad_len));
    format!("{{{}}}", STANDARD.encode(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_encrypted_passwords() {
        assert!(is_encrypted("{xyz123}"));
        assert!(is_encrypted("  {abc}  "));
        assert!(is_encrypted("{EbvSxq8u/P5Y6MJqsF8=}"));
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted("{incomplete"));
        assert!(!is_encrypted("incomplete}"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn detects_comment_wrapped_encrypted_passwords() {
        // sec-dispatcher allows decorations around the braces; the chunk is
        // the text between the last `{` and the first `}` after it.
        assert!(is_encrypted(
            "Oleg reset this on 2009-03-11 {COQLCE6DU6GtcS5P=}"
        ));
        assert!(is_encrypted("{COQLCE6DU6GtcS5P=} expires 2009-04-11"));
        assert!(is_encrypted("pre {COQLCE6DU6GtcS5P=} post"));
        // Brace-wrapped literals that are not base64 stay plaintext.
        assert!(!is_encrypted("note {my-literal-password}"));
        // A trailing `{` with no closing brace after it is not a chunk.
        assert!(!is_encrypted("{abc=} trailing {"));
    }

    #[test]
    fn decrypts_comment_wrapped_vector_identically_to_bare_form() {
        let bare = "{ibeHrdCOonkH7d7YnH7sarQLbwOk1ljkkM/z8hUhl4c=}";
        let decorated = format!("Oleg reset this on 2009-03-11, expires on 2009-04-11 {bare}");
        assert_eq!(
            decrypt_maven_password(&decorated, "testtest").unwrap(),
            decrypt_maven_password(bare, "testtest").unwrap()
        );
        assert_eq!(
            decrypt_maven_password(&decorated, "testtest").unwrap(),
            "veryOpenText"
        );
    }

    #[test]
    fn sanitize_drops_comment_wrapped_cipher_without_master() {
        // Same fallback as a bare `{...}` value that cannot be decrypted:
        // the credential is dropped rather than sent as a literal password.
        let result = sanitize_password("reset note {abc123DEF456=}".to_string(), None);
        assert!(result.is_none());
    }

    #[test]
    fn sanitize_keeps_braced_literal_inside_longer_string() {
        // The braces do not enclose plausible cipher text, so the whole
        // value passes through as a literal password.
        let value = "note {my-literal-password}".to_string();
        let result = sanitize_password(value.clone(), None);
        assert_eq!(result, Some(value));
    }

    #[test]
    fn parses_master_from_security_settings() {
        let xml = r"
        <settingsSecurity>
            <master>mysecretmaster</master>
        </settingsSecurity>
        ";
        let settings = SecuritySettings::parse(xml).unwrap().unwrap();
        assert_eq!(settings.master.as_deref(), Some("mysecretmaster"));
        assert!(settings.relocation.is_none());
    }

    #[test]
    fn parses_encrypted_master() {
        let xml = r"
        <settingsSecurity>
            <master>{encrypted-master-password}</master>
        </settingsSecurity>
        ";
        let settings = SecuritySettings::parse(xml).unwrap().unwrap();
        assert_eq!(
            settings.master.as_deref(),
            Some("{encrypted-master-password}")
        );
    }

    #[test]
    fn parses_relocation() {
        let xml = r"
        <settingsSecurity>
            <relocation>/path/to/secure/settings-security.xml</relocation>
        </settingsSecurity>
        ";
        let settings = SecuritySettings::parse(xml).unwrap().unwrap();
        assert_eq!(
            settings.relocation.as_deref(),
            Some(Path::new("/path/to/secure/settings-security.xml"))
        );
    }

    #[test]
    fn handles_empty_security_file() {
        let xml = "<settingsSecurity></settingsSecurity>";
        assert!(SecuritySettings::parse(xml).unwrap().is_none());
    }

    #[test]
    fn sanitize_returns_plaintext_unchanged() {
        let result = sanitize_password("plainpassword".to_string(), None);
        assert_eq!(result, Some("plainpassword".to_string()));
    }

    #[test]
    fn sanitize_returns_none_for_encrypted_without_master() {
        let result = sanitize_password("{encrypted}".to_string(), None);
        assert!(result.is_none());
    }

    #[test]
    fn decrypts_canonical_plexus_cipher_vector() {
        // Verbatim fixture from plexus-cipher 2.0 PBECipherTest.java:
        // assertEquals("veryOpenText", pbeCipher.decrypt64(
        //     "ibeHrdCOonkH7d7YnH7sarQLbwOk1ljkkM/z8hUhl4c=", "testtest"));
        let encrypted = "{ibeHrdCOonkH7d7YnH7sarQLbwOk1ljkkM/z8hUhl4c=}";
        let decrypted = decrypt_maven_password(encrypted, "testtest").unwrap();
        assert_eq!(decrypted, "veryOpenText");
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let encrypted = encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567");
        assert_eq!(
            decrypt_maven_password(&encrypted, "my-master").unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn round_trip_master_password() {
        // Master-of-master key is the fixed string "settings.security".
        let encrypted = encrypt_for_tests(b"maven-master", "settings.security", *b"saltsalt");
        assert_eq!(
            decrypt_maven_password(&encrypted, "settings.security").unwrap(),
            "maven-master"
        );
    }

    #[test]
    fn relative_relocation_is_resolved_against_source_file_directory() {
        use std::io::Write;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        // The target file holding the actual master password.
        let target_name = "actual-security.xml";
        let target_path = dir.join(target_name);
        {
            let mut f = std::fs::File::create(&target_path).unwrap();
            f.write_all(b"<settingsSecurity><master>from-relocation</master></settingsSecurity>")
                .unwrap();
        }

        // Source file pointing at the target via a relative path.
        let source_path = dir.join("settings-security.xml");
        {
            let mut f = std::fs::File::create(&source_path).unwrap();
            let xml = format!(
                "<settingsSecurity><relocation>{}</relocation></settingsSecurity>",
                target_name
            );
            f.write_all(xml.as_bytes()).unwrap();
        }

        // Switch the process cwd to a directory that does NOT contain the
        // target file. Without the fix, the relative relocation would be
        // resolved against this cwd and the target would not be found.
        let other_dir = TempDir::new().unwrap();
        let _cwd_guard = ChdirGuard::new(other_dir.path());

        let loaded = SecuritySettings::load(&source_path).unwrap().unwrap();
        assert_eq!(loaded.master.as_deref(), Some("from-relocation"));
    }

    #[test]
    fn relocation_target_master_supersedes_source_master() {
        use std::io::Write;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        let target_path = dir.join("relocated.xml");
        {
            let mut f = std::fs::File::create(&target_path).unwrap();
            f.write_all(b"<settingsSecurity><master>relocated-master</master></settingsSecurity>")
                .unwrap();
        }

        // Source declares both a (stale) master AND a relocation. Maven's
        // sec-dispatcher treats the relocation as authoritative, so the
        // relocated master must win over the source's own.
        let source_path = dir.join("settings-security.xml");
        {
            let mut f = std::fs::File::create(&source_path).unwrap();
            f.write_all(
                b"<settingsSecurity><master>stale-source-master</master>\
                  <relocation>relocated.xml</relocation></settingsSecurity>",
            )
            .unwrap();
        }

        let loaded = SecuritySettings::load(&source_path).unwrap().unwrap();
        assert_eq!(loaded.master.as_deref(), Some("relocated-master"));
    }

    #[test]
    fn relocation_to_master_less_target_drops_source_master() {
        use std::io::Write;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        // Relocation target exists but defines no master.
        let target_path = dir.join("empty-relocated.xml");
        {
            let mut f = std::fs::File::create(&target_path).unwrap();
            f.write_all(b"<settingsSecurity></settingsSecurity>")
                .unwrap();
        }

        // Source carries a master plus a relocation to the master-less target.
        // Because a relocation is declared, the relocated file is authoritative
        // and the stale source master must NOT leak through.
        let source_path = dir.join("settings-security.xml");
        {
            let mut f = std::fs::File::create(&source_path).unwrap();
            f.write_all(
                b"<settingsSecurity><master>stale-source-master</master>\
                  <relocation>empty-relocated.xml</relocation></settingsSecurity>",
            )
            .unwrap();
        }

        let loaded = SecuritySettings::load(&source_path).unwrap().unwrap();
        assert!(
            loaded.master.is_none(),
            "source master must not survive a relocation to a master-less file, got {:?}",
            loaded.master
        );
        // The relocation itself is still surfaced on the returned struct.
        assert!(loaded.relocation.is_some());
    }

    /// Helper that restores the process cwd on drop. Used so tests don't
    /// leak cwd changes to other test cases running in the same process.
    struct ChdirGuard {
        original: PathBuf,
    }

    impl ChdirGuard {
        fn new(new_dir: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(new_dir).unwrap();
            ChdirGuard { original }
        }
    }

    impl Drop for ChdirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    #[test]
    fn implausible_master_decrypt_returns_none() {
        // Master that decrypts cleanly under "settings.security" to bytes
        // failing `is_plausible_master` (null bytes are non-printable). Without
        // the plausibility gate, `try_decrypt_password` would proceed to
        // "decrypt" the inner password with this garbage master and surface a
        // misleading payload; with the gate, the call short-circuits to None.
        let garbage_master =
            encrypt_for_tests(b"\0\0\0\0\0\0\0\0\0\0", "settings.security", *b"AAAAAAAA");
        let inner_encrypted = encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567");
        let settings = SecuritySettings {
            master: Some(garbage_master),
            relocation: None,
        };
        let result = try_decrypt_password(&inner_encrypted, Some(&settings));
        assert!(
            result.is_none(),
            "implausible master must short-circuit, got {result:?}"
        );
    }

    #[test]
    fn plausible_master_passes_check() {
        assert!(is_plausible_master("maven-master"));
        assert!(is_plausible_master("12345678"));
        // Short master passwords are valid: Maven imposes no minimum length,
        // so the plausibility gate must not reject them.
        assert!(is_plausible_master("abc"));
        assert!(is_plausible_master("x"));
    }

    #[test]
    fn implausible_master_rejected_by_check() {
        assert!(!is_plausible_master(""));
        assert!(!is_plausible_master("contains\0null"));
        assert!(!is_plausible_master("non-ascii\u{ff}aaaa"));
    }

    #[test]
    fn relocation_depth_limit_prevents_infinite_recursion() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a chain of relocations that exceeds MAX_RELOCATION_DEPTH
        let mut files = Vec::new();

        // Create 12 temp files (exceeds MAX_RELOCATION_DEPTH of 10)
        for _ in 0..12 {
            files.push(NamedTempFile::new().unwrap());
        }

        // Write each file to point to the next one
        for i in 0..files.len() - 1 {
            let next_path = files[i + 1].path().to_str().unwrap();
            let xml = format!(
                "<settingsSecurity><relocation>{}</relocation></settingsSecurity>",
                next_path
            );
            files[i].as_file().write_all(xml.as_bytes()).unwrap();
            files[i].as_file().sync_all().unwrap();
        }

        // Last file has the master password
        files
            .last_mut()
            .unwrap()
            .as_file()
            .write_all(b"<settingsSecurity><master>final-master</master></settingsSecurity>")
            .unwrap();
        files.last_mut().unwrap().as_file().sync_all().unwrap();

        // Attempting to load the first file should fail with RelocationDepthExceeded
        let result = SecuritySettings::load(files[0].path());
        assert!(matches!(result, Err(ConfigError::RelocationDepthExceeded)));
    }
}
