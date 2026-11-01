use std::borrow::Borrow;
use std::sync::Arc;

use derive_more::{Deref, Display};

macro_rules! define_id_string {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display, Deref)]
        pub struct $name(Arc<str>);

        impl $name {
            /// The identifier as written. No character rules are checked.
            pub fn as_str(&self) -> &str {
                &self.0
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
