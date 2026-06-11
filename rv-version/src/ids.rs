use std::borrow::Borrow;
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

use derive_more::{AsRef, Deref, Display, From};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// WHY: GroupId and ArtifactId share an Arc<str>-backed Maven identifier shape:
// same hash impl, same Borrow<str>, same From conversions, same serde
// representation. The macro keeps both wrappers byte-for-byte identical so a
// fix to one (e.g. interning, canonicalisation) automatically lands on the
// other.
macro_rules! define_id_string {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, From, Display, AsRef, Deref)]
        pub struct $name(Arc<str>);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.as_str().hash(state);
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(Arc::from(s))
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(Arc::from(s))
            }
        }

        impl FromStr for $name {
            type Err = Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self::from(s))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Ok(Self::from(value))
            }
        }
    };
}

define_id_string! {
    /// A Maven group identifier (e.g. `"org.springframework"`).
    /// Backed by `Arc<str>` for cheap cloning.
    GroupId
}

define_id_string! {
    /// A Maven artifact identifier (e.g. `"spring-core"`).
    /// Backed by `Arc<str>` for cheap cloning.
    ArtifactId
}
