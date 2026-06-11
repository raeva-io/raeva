use crate::error::{Result, StoreError, db_error_with_context};
use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use rv_config::{ArtifactKey, BlobId};
use std::collections::HashMap;
use std::str::FromStr;

pub(crate) fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS artifacts (
            group_id   TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            version    TEXT NOT NULL,
            packaging  TEXT NOT NULL,
            classifier TEXT NOT NULL,
            blob_id    TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, artifact_id, version, packaging, classifier)
        );
        CREATE INDEX IF NOT EXISTS idx_artifacts_blob_id ON artifacts (blob_id);",
    )
    .with_context(|| "failed to initialize artifacts table")
    .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

    // Backward-compatible migration (#20): older databases predate
    // `size_bytes`. ALTER TABLE … ADD COLUMN is not directly idempotent
    // in SQLite; treat the "duplicate column" error as a no-op so we
    // can call this on every open without an explicit schema_version.
    match conn.execute(
        "ALTER TABLE artifacts ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0",
        [],
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
            if msg.contains("duplicate column name") => {}
        Err(e) => {
            return Err(StoreError::DbContext {
                ctx: "failed to add size_bytes column to artifacts".to_string(),
                source: e,
            });
        }
    }
    Ok(())
}

pub(crate) fn add_artifact(
    conn: &Connection,
    key: &ArtifactKey,
    id: &BlobId,
    size_bytes: u64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO artifacts (group_id, artifact_id, version, packaging, classifier, blob_id, size_bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(group_id, artifact_id, version, packaging, classifier)
         DO UPDATE SET blob_id = excluded.blob_id, size_bytes = excluded.size_bytes",
        params![
            &key.group_id,
            &key.artifact_id,
            &key.version,
            &key.packaging,
            key.classifier_key(),
            id.as_str(),
            size_bytes as i64
        ],
    )
    .with_context(|| format!("failed to upsert artifact {key}"))
    .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    Ok(())
}

/// Remove the index row for `key`, if present. Used to repair a row that was
/// committed before a checksum verification failed so the next sync re-fetches
/// rather than trusting unverified bytes. Does not touch the blob.
pub(crate) fn remove_artifact(conn: &Connection, key: &ArtifactKey) -> Result<()> {
    conn.execute(
        "DELETE FROM artifacts
         WHERE group_id = ?1 AND artifact_id = ?2 AND version = ?3
         AND packaging = ?4 AND classifier = ?5",
        params![
            &key.group_id,
            &key.artifact_id,
            &key.version,
            &key.packaging,
            key.classifier_key()
        ],
    )
    .with_context(|| format!("failed to remove artifact {key}"))
    .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    Ok(())
}

pub(crate) fn lookup_artifact(conn: &Connection, key: &ArtifactKey) -> Result<Option<BlobId>> {
    let blob_id: Option<String> = conn
        .query_row(
            "SELECT blob_id FROM artifacts
             WHERE group_id = ?1 AND artifact_id = ?2 AND version = ?3
             AND packaging = ?4 AND classifier = ?5",
            params![
                &key.group_id,
                &key.artifact_id,
                &key.version,
                &key.packaging,
                key.classifier_key()
            ],
            |row| row.get(0),
        )
        .optional()
        .with_context(|| format!("failed to lookup artifact {key}"))
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

    let Some(value) = blob_id else {
        return Ok(None);
    };
    match BlobId::from_str(&value) {
        Ok(id) => Ok(Some(id)),
        Err(_) => {
            // A row whose blob_id does not parse can never resolve to a
            // file. Treating it as a hard error would fail the sync for
            // this key forever; scrub the row and report a miss so the
            // artifact re-fetches.
            tracing::warn!(
                %key,
                blob_id = %value,
                "index row has unparseable blob_id; deleting row and treating as miss"
            );
            scrub_corrupt_row(conn, key, &value)?;
            Ok(None)
        }
    }
}

/// Delete the row for `key` only if it still holds `corrupt_blob_id`. The
/// unlocked lookup path calls this without the store lock, so the DELETE is
/// conditional on the corrupt value: a concurrent upsert that just wrote a
/// valid blob_id for the same key is preserved.
fn scrub_corrupt_row(conn: &Connection, key: &ArtifactKey, corrupt_blob_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM artifacts
         WHERE group_id = ?1 AND artifact_id = ?2 AND version = ?3
         AND packaging = ?4 AND classifier = ?5 AND blob_id = ?6",
        params![
            &key.group_id,
            &key.artifact_id,
            &key.version,
            &key.packaging,
            key.classifier_key(),
            corrupt_blob_id
        ],
    )
    .with_context(|| format!("failed to scrub corrupt index row for {key}"))
    .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    Ok(())
}

pub(crate) fn lookup_artifacts_batch(
    conn: &Connection,
    keys: &[ArtifactKey],
) -> Result<HashMap<ArtifactKey, BlobId>> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let mut result = HashMap::with_capacity(keys.len());
    // Rows whose blob_id fails to parse, scrubbed after the chunk loop so
    // the DELETE does not run while a SELECT is iterating the same table.
    let mut corrupt: Vec<(ArtifactKey, String)> = Vec::new();
    const BATCH_SIZE: usize = 100;

    for chunk in keys.chunks(BATCH_SIZE) {
        let mut sql = String::from(
            "WITH keys(group_id, artifact_id, version, packaging, classifier) AS (VALUES ",
        );

        let value_tuples: Vec<_> = std::iter::repeat_n("(?, ?, ?, ?, ?)", chunk.len()).collect();
        sql.push_str(&value_tuples.join(", "));
        sql.push_str(
            ") SELECT a.group_id, a.artifact_id, a.version, a.packaging, a.classifier, a.blob_id \
             FROM artifacts a \
             INNER JOIN keys k ON a.group_id = k.group_id \
             AND a.artifact_id = k.artifact_id \
             AND a.version = k.version \
             AND a.packaging = k.packaging \
             AND a.classifier = k.classifier",
        );

        let mut stmt = conn
            .prepare(&sql)
            .with_context(|| "failed to prepare batch artifact lookup")
            .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

        let classifier_keys: Vec<String> = chunk
            .iter()
            .map(|k| k.classifier_key().to_string())
            .collect();

        let mut all_params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(chunk.len() * 5);
        for (i, key) in chunk.iter().enumerate() {
            all_params.push(&key.group_id);
            all_params.push(&key.artifact_id);
            all_params.push(&key.version);
            all_params.push(&key.packaging);
            all_params.push(&classifier_keys[i]);
        }

        let rows = stmt
            .query_map(rusqlite::params_from_iter(all_params), |row| {
                let group_id: String = row.get(0)?;
                let artifact_id: String = row.get(1)?;
                let version: String = row.get(2)?;
                let packaging: String = row.get(3)?;
                let classifier: String = row.get(4)?;
                let blob_id: String = row.get(5)?;

                // Reconstruct via the canonical helper so an empty stored
                // classifier maps back to `None` consistently with how keys are
                // written (`classifier_key`), keeping the round-trip lossless
                // and the resulting key equal to the one the caller queried (#55).
                Ok((
                    ArtifactKey::new(
                        group_id,
                        artifact_id,
                        version,
                        packaging,
                        rv_config::artifact::classifier_from_key(classifier),
                    ),
                    blob_id,
                ))
            })
            .with_context(|| "failed to query artifact index")
            .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

        for row in rows {
            let (key, blob_id_str) = row
                .with_context(|| "failed to read artifact row")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            match BlobId::from_str(&blob_id_str) {
                Ok(blob_id) => {
                    result.insert(key, blob_id);
                }
                Err(_) => {
                    // Same repair as lookup_artifact: report a miss for this
                    // key and scrub the unusable row so it re-fetches.
                    tracing::warn!(
                        %key,
                        blob_id = %blob_id_str,
                        "index row has unparseable blob_id; deleting row and treating as miss"
                    );
                    corrupt.push((key, blob_id_str));
                }
            }
        }
    }

    for (key, blob_id_str) in &corrupt {
        scrub_corrupt_row(conn, key, blob_id_str)?;
    }

    Ok(result)
}

pub(crate) fn remove_artifacts_for_blobs(conn: &mut Connection, ids: &[BlobId]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }

    const BATCH_SIZE: usize = 500;

    let tx = conn
        .transaction()
        .with_context(|| "failed to start artifact cleanup transaction")
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

    for chunk in ids.chunks(BATCH_SIZE) {
        let placeholders: String = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("DELETE FROM artifacts WHERE blob_id IN ({})", placeholders);

        let params: Vec<&str> = chunk.iter().map(|id| id.as_str()).collect();

        tx.execute(&sql, rusqlite::params_from_iter(params))
            .with_context(|| "failed to batch delete artifacts")
            .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    }

    tx.commit()
        .with_context(|| "failed to commit artifact cleanup transaction")
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    Ok(())
}

pub(crate) fn clear_artifacts(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM artifacts", [])
        .with_context(|| "failed to clear artifact index")
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    Ok(())
}

/// Returns the set of distinct blob ids referenced by the index.
///
/// This is the "protected set" the GC uses under StoreLock: any blob whose
/// hash appears in the artifacts table is reachable from at least one
/// indexed coordinate, and a prune sweep must not delete it no matter what
/// `keep` the caller passes in.
pub(crate) fn referenced_blob_ids(conn: &Connection) -> Result<std::collections::HashSet<BlobId>> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT blob_id FROM artifacts")
        .with_context(|| "failed to prepare referenced_blob_ids query")
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .with_context(|| "failed to query referenced_blob_ids")
        .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
    let mut out = std::collections::HashSet::new();
    for row in rows {
        let s = row
            .with_context(|| "failed to read referenced blob_id row")
            .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
        if let Ok(id) = BlobId::from_str(&s) {
            out.insert(id);
        }
    }
    Ok(out)
}
