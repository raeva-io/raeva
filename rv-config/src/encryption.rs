//! Maven `settings-security.xml` password decryption.
//!
//! Reads `{base64(...)}`-wrapped values produced by `mvn --encrypt-password` /
//! plexus-cipher 2.x. Algorithm: AES-128/CBC/PKCS5 with key+IV derived as
//! `SHA-256(password || salt8)` split into a 16-byte key and 16-byte IV.
//! Payload layout inside the braces: `salt[8] || pad_len[1] || ciphertext ||
//! random_pad[pad_len]`.

use std::path::{Path, PathBuf};

use aes::Aes128;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{ConfigError, ConfigOrigin};
use crate::maven_settings::harden_xml;

/// A `settings-security.xml` that names a master password or relocates it.
/// `master` is `None` when a relocation leads to a file without one.
#[derive(Debug, Clone, Default)]
pub(crate) struct SecuritySettings {
    pub master: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecurityXml {
    master: Option<String>,
    relocation: Option<String>,
}

impl SecuritySettings {
    const MAX_RELOCATION_DEPTH: usize = 10;

    pub(crate) fn load_default() -> Result<Option<Self>, ConfigError> {
        let Some(path) = default_security_path() else {
            return Ok(None);
        };
        Self::load(&path)
    }

    pub(crate) fn load(path: &Path) -> Result<Option<Self>, ConfigError> {
        Self::load_with_depth(path, 0).map_err(|err| match err {
            ConfigError::Invalid { .. } => err,
            other => invalid(path, other.to_string()),
        })
    }

    fn load_with_depth(path: &Path, depth: usize) -> Result<Option<Self>, ConfigError> {
        if depth > Self::MAX_RELOCATION_DEPTH {
            return Err(ConfigError::RelocationDepthExceeded);
        }
        let Some(content) = crate::maven_settings::read_settings_text(path)
            .map_err(|message| invalid(path, message))?
        else {
            return Ok(None);
        };
        Self::parse_with_depth(&content, depth, path.parent()).map_err(|err| match err {
            ConfigError::InvalidSettings(message) => invalid(path, message),
            other => other,
        })
    }

    #[cfg(test)]
    pub(crate) fn parse(xml: &str) -> Result<Option<Self>, ConfigError> {
        Self::parse_with_depth(xml, 0, None)
    }

    fn parse_with_depth(
        xml: &str,
        depth: usize,
        base_dir: Option<&Path>,
    ) -> Result<Option<Self>, ConfigError> {
        let (xml, _) = harden_xml(xml)?;
        // A malformed file counts as none. Its parse error stays out of the
        // warning: the file holds the master password.
        let parsed = crate::maven_settings::from_xml::<SecurityXml>(xml).unwrap_or_else(|_| {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                "XML parse error in settings-security.xml; encrypted passwords will not be decrypted"
            );
            SecurityXml {
                master: None,
                relocation: None,
            }
        });
        let non_empty = |value: Option<String>| {
            value
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let mut master = non_empty(parsed.master);
        let Some(relocation) = non_empty(parsed.relocation).map(PathBuf::from) else {
            return Ok(master.map(|master| Self {
                master: Some(master),
            }));
        };
        // A relative relocation is resolved against the source file's
        // directory, never the working directory. As in Maven's
        // sec-dispatcher, the relocated file replaces the source's master,
        // even with none.
        let resolved = match base_dir {
            Some(dir) => dir.join(&relocation),
            None => relocation,
        };
        master = Self::load_with_depth(&resolved, depth + 1)?.and_then(|target| target.master);
        Ok(Some(Self { master }))
    }
}

fn invalid(path: &Path, message: String) -> ConfigError {
    ConfigError::Invalid {
        origin: ConfigOrigin::MavenSettingsSecurity(path.to_path_buf()),
        message,
    }
}

pub(crate) fn default_security_path() -> Option<PathBuf> {
    crate::paths::maven_user_home().map(|home| home.join(".m2").join("settings-security.xml"))
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
pub(crate) fn is_encrypted(value: &str) -> bool {
    let Some(inner) = extract_cipher_payload(value) else {
        return false;
    };
    // Maven plexus-cipher `{base64}` payload.
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

// plexus-cipher 2.x: single SHA-256(password || salt), split into 16-byte
// key and 16-byte IV. Upstream's PBE_ITERATIONS=1000 loop is dead code since
// the first digest already fills both halves.
fn derive_key_iv(password: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 16]) {
    let digest = Sha256::new()
        .chain_update(password)
        .chain_update(salt)
        .finalize();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    iv.copy_from_slice(&digest[16..32]);
    (key, iv)
}

/// Decrypts a Maven-encrypted password with `master`: the `{...}` chunk of
/// `encrypted`, laid out as `salt[8] || pad_len[1] || ciphertext ||
/// random_pad[pad_len]`. `None` for any failure, so a failure says nothing
/// about the padding.
///
/// This is plexus-cipher 2.x's AES-128/CBC with PKCS#7, which `mvn` writes.
/// CBC is open to padding-oracle timing attacks, but only to an attacker who
/// can already write `settings.xml`.
pub(crate) fn decrypt_maven_password(encrypted: &str, master: &str) -> Option<String> {
    let inner = extract_cipher_payload(encrypted).filter(|inner| !inner.is_empty())?;
    let clean: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = STANDARD.decode(&clean).ok()?;
    // Salt, pad length and one AES block of ciphertext.
    if decoded.len() < 25 {
        return None;
    }
    let ct_end = decoded.len().checked_sub(usize::from(decoded[8]))?;
    if ct_end <= 9 || (ct_end - 9) % 16 != 0 {
        return None;
    }
    let (key, iv) = derive_key_iv(master.as_bytes(), &decoded[..8]);
    let mut buffer = decoded[9..ct_end].to_vec();
    let plaintext = cbc::Decryptor::<Aes128>::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .ok()?;
    String::from_utf8(plaintext.to_vec()).ok()
}

/// Decrypt a Maven-encrypted `password` with the master password in
/// `security`; a value that is not encrypted comes back unchanged. The error
/// is a fixed reason, so it holds no secret.
pub(crate) fn decrypt_password(
    password: &str,
    security: Option<&SecuritySettings>,
) -> Result<String, &'static str> {
    if !is_encrypted(password) {
        return Ok(password.to_string());
    }
    let Some(settings) = security else {
        return Err("no settings-security.xml was found");
    };
    let Some(master) = settings.master.as_deref() else {
        return Err("settings-security.xml has no master password");
    };
    let master_plain = if is_encrypted(master) {
        decrypt_maven_password(master, "settings.security")
            .ok_or("the master password in settings-security.xml could not be decrypted")?
    } else {
        master.to_string()
    };
    decrypt_maven_password(password, &master_plain)
        .ok_or("the password could not be decrypted with the master password")
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
    use std::fs;

    #[test]
    fn detects_encrypted_values_as_sec_dispatcher_does() {
        for (value, encrypted) in [
            ("{xyz123}", true),
            ("  {abc}  ", true),
            ("{EbvSxq8u/P5Y6MJqsF8=}", true),
            ("Oleg reset this on 2009-03-11 {COQLCE6DU6GtcS5P=}", true),
            ("{COQLCE6DU6GtcS5P=} expires 2009-04-11", true),
            ("plaintext", false),
            ("{incomplete", false),
            ("incomplete}", false),
            ("", false),
            ("note {my-literal-password}", false),
            ("{abc=} trailing {", false),
        ] {
            assert_eq!(is_encrypted(value), encrypted, "{value:?}");
        }
    }

    #[test]
    fn decrypts_plexus_cipher_payloads() {
        // The vector from plexus-cipher 2.0's PBECipherTest.
        let bare = "{ibeHrdCOonkH7d7YnH7sarQLbwOk1ljkkM/z8hUhl4c=}";
        let decorated = format!("Oleg reset this on 2009-03-11, expires on 2009-04-11 {bare}");
        for value in [bare, decorated.as_str()] {
            assert_eq!(
                decrypt_maven_password(value, "testtest").as_deref(),
                Some("veryOpenText")
            );
        }
        let encrypted = encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567");
        assert_eq!(
            decrypt_maven_password(&encrypted, "my-master").as_deref(),
            Some("s3cr3t")
        );
        for (value, master) in [("{}", "m"), ("{!!}", "m"), ("{AAAA}", "m"), (bare, "wrong")] {
            assert_eq!(decrypt_maven_password(value, master), None, "{value}");
        }
    }

    #[test]
    fn decrypt_password_with_a_master() {
        let security = |master: &str| SecuritySettings {
            master: Some(master.to_string()),
        };
        let inner = encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567");
        let master = encrypt_for_tests(b"my-master", "settings.security", *b"saltsalt");
        let garbage = encrypt_for_tests(b"\0\0\0\0", "settings.security", *b"AAAAAAAA");
        let literal = "note {my-literal-password}";
        assert_eq!(decrypt_password("plain", None).as_deref(), Ok("plain"));
        assert_eq!(decrypt_password(literal, None).as_deref(), Ok(literal));
        assert!(decrypt_password("reset note {abc123DEF456=}", None).is_err());
        let no_master = SecuritySettings { master: None };
        assert!(decrypt_password(&inner, Some(&no_master)).is_err());
        let plain_master = security("my-master");
        assert_eq!(
            decrypt_password(&inner, Some(&plain_master)).as_deref(),
            Ok("s3cr3t")
        );
        assert_eq!(
            decrypt_password(&inner, Some(&security(&master))).as_deref(),
            Ok("s3cr3t")
        );
        assert!(decrypt_password(&inner, Some(&security(&garbage))).is_err());
        // Maven takes any master password, in UTF-8.
        let inner = encrypt_for_tests(b"s3cr3t", "bl\u{e5}b\u{e6}r", *b"01234567");
        let master = encrypt_for_tests(
            "bl\u{e5}b\u{e6}r".as_bytes(),
            "settings.security",
            *b"saltsalt",
        );
        assert_eq!(
            decrypt_password(&inner, Some(&security(&master))).as_deref(),
            Ok("s3cr3t")
        );
    }

    #[test]
    fn parses_master_and_follows_relocations() {
        let parse = |xml: &str| SecuritySettings::parse(xml).unwrap().map(|s| s.master);
        assert_eq!(
            parse("<settingsSecurity><master> m </master></settingsSecurity>"),
            Some(Some("m".to_string()))
        );
        assert_eq!(
            parse("<settingsSecurity><master>a&eacute;</master></settingsSecurity>"),
            Some(Some("a\u{E9}".to_string()))
        );
        assert_eq!(parse("<settingsSecurity></settingsSecurity>"), None);
        assert_eq!(parse("<settingsSecurity><master>"), None);

        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, xml: &str| {
            let path = dir.path().join(name);
            fs::write(&path, format!("<settingsSecurity>{xml}</settingsSecurity>")).unwrap();
            path
        };
        write("target.xml", "<master>relocated</master>");
        write("empty.xml", "");
        // Relative relocations resolve against the source file's directory,
        // and the relocated file replaces the source's master.
        for (target, master) in [("target.xml", Some("relocated")), ("empty.xml", None)] {
            let source = write(
                "source.xml",
                &format!("<master>stale</master><relocation>{target}</relocation>"),
            );
            let loaded = SecuritySettings::load(&source).unwrap().unwrap();
            assert_eq!(loaded.master.as_deref(), master, "{target}");
        }

        let chain: Vec<PathBuf> = (0..12)
            .map(|i| dir.path().join(format!("{i}.xml")))
            .collect();
        for pair in chain.windows(2) {
            let relocation = format!("<relocation>{}</relocation>", pair[1].display());
            fs::write(
                &pair[0],
                format!("<settingsSecurity>{relocation}</settingsSecurity>"),
            )
            .unwrap();
        }
        assert_eq!(
            SecuritySettings::load(&chain[0]).unwrap_err().to_string(),
            format!(
                "invalid Maven settings security file {}: {}",
                chain[0].display(),
                ConfigError::RelocationDepthExceeded
            )
        );
    }

    #[test]
    fn load_errors_name_the_security_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings-security.xml");
        fs::write(&path, "<!DOCTYPE x><settingsSecurity/>").unwrap();
        assert_eq!(
            SecuritySettings::load(&path).unwrap_err().to_string(),
            format!(
                "invalid Maven settings security file {}: contains a DTD, which is not \
                 allowed for security reasons",
                path.display()
            )
        );
        fs::write(
            &path,
            vec![b' '; crate::maven_settings::MAX_SETTINGS_SIZE + 1],
        )
        .unwrap();
        let message = SecuritySettings::load(&path).unwrap_err().to_string();
        assert!(message.ends_with("-byte limit"), "{message}");

        fs::remove_file(&path).unwrap();
        assert!(SecuritySettings::load(&path).unwrap().is_none());
        fs::create_dir(&path).unwrap();
        let message = SecuritySettings::load(&path).unwrap_err().to_string();
        let prefix = format!(
            "invalid Maven settings security file {}: cannot read it: ",
            path.display()
        );
        assert!(message.starts_with(&prefix), "{message}");
    }
}
