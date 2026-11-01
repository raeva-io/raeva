//! Content digests in the algorithms Maven repositories publish, held as
//! validated lowercase hex.
//!
//! [`Sha256`] (also exported as [`BlobId`]) names a blob in the content
//! store. [`Sha1`] and [`Md5`] exist because most Maven sidecar files are
//! SHA-1 and a few only MD5. A [`Digest`] is any one of them. Constructing
//! one checks the length and the hex alphabet and lowercases, so equality is
//! byte equality.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha1::Digest as _;

/// A checksum algorithm. The variant order is the sort order of
/// `(algorithm, digest)` rows in a lock file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// MD5, the algorithm of Maven `.md5` sidecar files. Only a sidecar
    /// holds one: [`HashAlgorithm::parse`] does not accept it.
    Md5,
    /// SHA-1, the algorithm of Maven `.sha1` sidecar files.
    Sha1,
    /// SHA-256, the algorithm of content-store blob ids.
    Sha256,
}

impl HashAlgorithm {
    /// The canonical lowercase name, as written in raeva.lock.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Accepts `sha256`, `sha-256`, `sha1` and `sha-1` in any case, with
    /// surrounding whitespace ignored. Anything else is `None`.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("sha256") || trimmed.eq_ignore_ascii_case("sha-256") {
            Some(Self::Sha256)
        } else if trimmed.eq_ignore_ascii_case("sha1") || trimmed.eq_ignore_ascii_case("sha-1") {
            Some(Self::Sha1)
        } else {
            None
        }
    }

    /// Length of a hex digest in characters.
    pub fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a string is not a digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DigestError {
    /// The algorithm name is not one [`HashAlgorithm::parse`] accepts.
    #[error("unsupported checksum algorithm")]
    UnsupportedAlgorithm,
    /// The hex string is not [`HashAlgorithm::hex_len`] characters long.
    #[error("{}", length_message(*.0))]
    InvalidLength(HashAlgorithm),
    /// The hex string has a character outside `0-9a-fA-F`.
    #[error("{}", characters_message(*.0))]
    InvalidCharacters(HashAlgorithm),
}

// The SHA-256 texts predate the digest types: they are what a bad blob id
// has always printed.
fn length_message(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "invalid blob id length",
        HashAlgorithm::Sha1 => "sha1 digest must be 40 hex chars",
        HashAlgorithm::Md5 => "md5 digest must be 32 hex chars",
    }
}

fn characters_message(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "invalid blob id characters",
        HashAlgorithm::Sha1 => "sha1 digest must be 40 hex chars",
        HashAlgorithm::Md5 => "md5 digest must be 32 hex chars",
    }
}

fn normalize_hex(algorithm: HashAlgorithm, hex: &str) -> Result<Box<str>, DigestError> {
    if hex.len() != algorithm.hex_len() {
        return Err(DigestError::InvalidLength(algorithm));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DigestError::InvalidCharacters(algorithm));
    }
    Ok(hex.to_ascii_lowercase().into_boxed_str())
}

fn hash_reader<H: sha1::Digest>(mut reader: impl Read) -> io::Result<String> {
    let mut hasher = H::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

macro_rules! define_digest {
    ($(#[$meta:meta])* $name:ident, $hasher:ty, $algorithm:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Box<str>);

        impl $name {
            /// Hashes `bytes`.
            pub fn from_bytes(bytes: &[u8]) -> Self {
                Self(hex::encode(<$hasher>::digest(bytes)).into_boxed_str())
            }

            /// Hashes everything `reader` yields, reading 128 KiB at a time.
            pub fn from_reader(reader: impl Read) -> io::Result<Self> {
                hash_reader::<$hasher>(reader).map(|hex| Self(hex.into_boxed_str()))
            }

            /// Hashes the contents of the file at `path`.
            pub fn from_file(path: &Path) -> io::Result<Self> {
                Self::from_reader(File::open(path)?)
            }

            /// The digest as lowercase hex.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = DigestError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                normalize_hex($algorithm, s).map(Self)
            }
        }

        impl TryFrom<String> for $name {
            type Error = DigestError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl From<$name> for String {
            fn from(digest: $name) -> String {
                digest.0.into_string()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_digest! {
    /// A SHA-256 digest: 64 lowercase hex characters. Deserializing checks
    /// the value, so a string from a lock file or an index cannot name a
    /// path.
    Sha256, sha2::Sha256, HashAlgorithm::Sha256
}

define_digest! {
    /// A SHA-1 digest: 40 lowercase hex characters.
    Sha1, sha1::Sha1, HashAlgorithm::Sha1
}

define_digest! {
    /// An MD5 digest: 32 lowercase hex characters.
    Md5, md5::Md5, HashAlgorithm::Md5
}

/// The id of a blob in the content store.
pub type BlobId = Sha256;

/// A checksum in one of the supported algorithms. They sort as the
/// algorithm names do.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Digest {
    /// An MD5 checksum.
    Md5(Md5),
    /// A SHA-1 checksum.
    Sha1(Sha1),
    /// A SHA-256 checksum.
    Sha256(Sha256),
}

impl Digest {
    /// Uppercase hex is lowered. SHA-1 may have surrounding whitespace, as Maven `.sha1` files often do; SHA-256 may not.
    pub fn parse(algorithm: &str, hex: &str) -> Result<Self, DigestError> {
        let algorithm = HashAlgorithm::parse(algorithm).ok_or(DigestError::UnsupportedAlgorithm)?;
        Self::from_hex(algorithm, hex)
    }

    /// [`Digest::parse`] for an algorithm already known, MD5 included.
    pub fn from_hex(algorithm: HashAlgorithm, hex: &str) -> Result<Self, DigestError> {
        match algorithm {
            HashAlgorithm::Sha256 => hex.parse().map(Self::Sha256),
            HashAlgorithm::Sha1 => hex.trim().parse().map(Self::Sha1),
            HashAlgorithm::Md5 => hex.trim().parse().map(Self::Md5),
        }
    }

    /// The algorithm of the held digest.
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Md5(_) => HashAlgorithm::Md5,
            Self::Sha1(_) => HashAlgorithm::Sha1,
            Self::Sha256(_) => HashAlgorithm::Sha256,
        }
    }

    /// The digest as lowercase hex.
    pub fn hex(&self) -> &str {
        match self {
            Self::Md5(digest) => digest.as_str(),
            Self::Sha1(digest) => digest.as_str(),
            Self::Sha256(digest) => digest.as_str(),
        }
    }

    /// The SHA-256 digest, which is also a content-store blob id.
    pub fn as_sha256(&self) -> Option<&Sha256> {
        match self {
            Self::Sha256(digest) => Some(digest),
            Self::Md5(_) | Self::Sha1(_) => None,
        }
    }

    /// Hashes `bytes` with `algorithm`.
    pub fn of_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Self {
        match algorithm {
            HashAlgorithm::Md5 => Self::Md5(Md5::from_bytes(bytes)),
            HashAlgorithm::Sha1 => Self::Sha1(Sha1::from_bytes(bytes)),
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::from_bytes(bytes)),
        }
    }

    /// Hashes everything `reader` yields with `algorithm`.
    pub fn of_reader(algorithm: HashAlgorithm, reader: impl Read) -> io::Result<Self> {
        Ok(match algorithm {
            HashAlgorithm::Md5 => Self::Md5(Md5::from_reader(reader)?),
            HashAlgorithm::Sha1 => Self::Sha1(Sha1::from_reader(reader)?),
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::from_reader(reader)?),
        })
    }

    /// Hashes the contents of the file at `path` with `algorithm`.
    pub fn of_file(algorithm: HashAlgorithm, path: &Path) -> io::Result<Self> {
        Self::of_reader(algorithm, File::open(path)?)
    }
}

impl From<Sha256> for Digest {
    fn from(digest: Sha256) -> Self {
        Self::Sha256(digest)
    }
}

impl From<Sha1> for Digest {
    fn from(digest: Sha1) -> Self {
        Self::Sha1(digest)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm(), self.hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_bytes_and_readers_alike() {
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(Sha256::from_bytes(b"abc").as_str(), sha256);
        let sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
        assert_eq!(Sha1::from_bytes(b"abc").as_str(), sha1);
        let md5 = "900150983cd24fb0d6963f7d28e17f72";
        assert_eq!(Md5::from_bytes(b"abc").as_str(), md5);
        let parsed = Digest::from_hex(HashAlgorithm::Md5, &format!(" {} ", md5.to_uppercase()));
        assert_eq!(
            parsed.unwrap(),
            Digest::of_bytes(HashAlgorithm::Md5, b"abc")
        );
        let data = vec![7u8; 300_000];
        let read = Digest::Sha256(Sha256::from_reader(&data[..]).unwrap());
        assert_eq!(read, Digest::of_bytes(HashAlgorithm::Sha256, &data));
        let read = Digest::Sha1(Sha1::from_reader(&data[..]).unwrap());
        assert_eq!(read, Digest::of_bytes(HashAlgorithm::Sha1, &data));
    }

    #[test]
    fn parse_lowers_hex_and_normalizes_the_algorithm() {
        let upper = "A".repeat(64);
        let digest = Digest::parse("SHA-256", &upper).unwrap();
        assert_eq!(digest.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(digest.hex(), "a".repeat(64));
        let sha1 = Digest::parse(" sha-1 ", &format!(" {} ", "B".repeat(40))).unwrap();
        assert_eq!(sha1.hex(), "b".repeat(40));
    }

    #[test]
    fn parse_refuses_bad_values_with_the_established_messages() {
        let cases = [
            ("sha256", "abc".to_string(), "invalid blob id length"),
            ("sha256", "g".repeat(64), "invalid blob id characters"),
            ("sha1", "a".repeat(39), "sha1 digest must be 40 hex chars"),
            ("sha1", "g".repeat(40), "sha1 digest must be 40 hex chars"),
            ("md5", "a".repeat(32), "unsupported checksum algorithm"),
        ];
        for (algorithm, hex, message) in cases {
            let err = Digest::parse(algorithm, &hex).unwrap_err();
            assert_eq!(err.to_string(), message, "{algorithm} {hex}");
        }
    }

    #[test]
    fn sha256_deserialization_validates() {
        let ok: Sha256 = serde_json::from_str(&format!("\"{}\"", "a".repeat(64))).unwrap();
        assert_eq!(ok.as_str(), "a".repeat(64));
        assert!(serde_json::from_str::<Sha256>("\"../../x\"").is_err());
        assert_eq!(
            serde_json::to_string(&ok).unwrap(),
            format!("\"{}\"", "a".repeat(64))
        );
    }

    #[test]
    fn digests_sort_by_algorithm_then_hex() {
        let sha1 = Digest::Sha1("f".repeat(40).parse().unwrap());
        let low = Digest::Sha256("0".repeat(64).parse().unwrap());
        let high = Digest::Sha256("1".repeat(64).parse().unwrap());
        let mut digests = vec![high.clone(), sha1.clone(), low.clone()];
        digests.sort();
        assert_eq!(digests, [sha1, low, high]);
    }
}
