# rv-store

The Content-Addressed Storage (CAS) layer for Raeva. This crate manages the physical storage of artifacts (JARs, POMs, binaries) on disk.

## Design

Raeva's storage is global (shared across projects) and content-addressed. This means artifacts are stored based on their content hash (SHA-256), not their file name or version number. This automatically deduplicates identical files (e.g., if `commons-lang3:3.12.0` and `my-lib:1.0` embed the same resource).

### Directory Structure

```text
~/.local/share/raeva/store/
├── blobs/                  # The content
│   └── 8f/                 # Sharding (first 2 chars of hash)
│       └── 8f4b2...        # The actual file (named by full hash)
├── index.sqlite            # The metadata index
├── index.sqlite-wal        # Write-Ahead Log
├── tmp/                    # Temporary download location
└── .lock                   # Inter-process lock file
```

### Components

1.  **Blob Store**: Raw file storage.
    *   Writes are atomic: download to `tmp/`, verify hash, then rename/persist to `blobs/`.
    *   Files are read-only once written.
2.  **Index (SQLite)**: Maps logical coordinates to physical blobs.
    *   Table: `artifacts (group_id, artifact_id, version, packaging, classifier, blob_id, size_bytes)`, with the primary key `(group_id, artifact_id, version, packaging, classifier)`.
    *   The `classifier` column is `NOT NULL`; "no classifier" is stored as the empty string (`""`) and reconstructed back to `None` on read.
    *   Allows fast lookups like "Where is `com.example:foo:1.0.0`?"
3.  **Concurrency Control**:
    *   Uses `fs2` for file-level locking (`.lock`) to ensure safe access by multiple concurrent Raeva processes.
    *   Uses SQLite's WAL mode for high-concurrency read/write.

## Usage

Prefer the atomic persist-and-index path. `put_stream_and_index` holds the store lock across both the blob persist and the index write, so a concurrent garbage-collection sweep cannot observe the freshly-written blob before its index row exists and delete it out from under you:

```rust
use rv_store::Store;
use rv_config::ArtifactKey;

let store = Store::open(path)?;

// Persist the bytes and index them under a coordinate in one locked step.
let key = ArtifactKey::new("group", "artifact", "1.0", "jar", None);
let (blob_id, _origin) = store
    .put_stream_and_index(&key, byte_stream)
    .await?;

// Retrieval
if let Some(id) = store.lookup_artifact(&key).await? {
    let path = store.get_path(&id);
    println!("File is at: {:?}", path);
}
```

The lower-level `put_bytes` / `put_file` / `put_stream` calls persist a blob *without* indexing it, and `add_artifact` adds an index row for an already-persisted blob. Splitting a store-then-index across those two calls is racy with GC (a sweep between them can collect the un-referenced blob), so reserve them for cases where no coordinate applies yet; use `put_stream_and_index` for the common put-then-index flow.
