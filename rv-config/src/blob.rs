use derive_more::{AsRef, Display};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Display, AsRef)]
#[serde(transparent)]
#[as_ref(str)]
pub struct BlobId(String);

impl BlobId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        BlobId(hex::encode(digest))
    }

    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 128 * 1024];
        loop {
            let read = file.read(&mut buf)?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        let digest = hasher.finalize();
        Ok(BlobId(hex::encode(digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BlobId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err("invalid blob id length".to_string());
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid blob id characters".to_string());
        }
        Ok(BlobId(s.to_ascii_lowercase()))
    }
}
