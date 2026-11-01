//! Filesystem helpers shared by the Raeva crates.
//!
//! [`write_file_atomic`] replaces a file so a reader never sees a partial
//! write, and [`temp_file_in`] stages a file for writers that rename several
//! at once; [`NewFileAccess`] picks the mode of the file either creates.
//! [`lock_exclusive_until`] waits for an advisory file lock until a deadline.
//! [`canonicalize_existing_prefix`], [`plain_path`] and the `join_*`
//! functions resolve and join paths, including Windows verbatim paths.
//! [`plain_name_is_safe`] and [`is_short_name_alias`] test one file name
//! against what Windows would rewrite or alias.
//!
//! The crate does not know where Raeva keeps its files and does not decide
//! which paths a caller may write: containment checks and the choice of
//! store, config and lockfile paths belong to the callers. It reads no
//! environment variables; relative paths resolve against the current
//! directory.

mod atomic_write;
mod file_lock;
mod path_utils;

pub use atomic_write::{NewFileAccess, temp_file_in, write_file_atomic};
pub use file_lock::lock_exclusive_until;
pub use path_utils::{
    canonicalize_existing_prefix, is_short_name_alias, join_module_pom, join_pom_entry,
    join_pom_entry_pom_xml, plain_name_is_safe, plain_path,
};
