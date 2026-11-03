use crate::error::{DbResultExt, Result};
use rusqlite::{Connection, OptionalExtension, params};
use rv_maven_types::{ArtifactCoord, BlobId};
use std::str::FromStr;

const KEY_MATCHES: &str = "group_id = ?1 AND artifact_id = ?2 AND version = ?3
     AND packaging = ?4 AND classifier = ?5";

pub(crate) fn init_db(conn: &Connection) -> Result<()> {
    let path = std::path::Path::new(conn.path().unwrap_or_default());
    let tx = crate::sqlite::write_transaction(conn, path, crate::store::INDEX.generation)?;
    let upgraded = crate::sqlite::has_table(&tx, "artifact_origins_v2")?;
    // Legacy origins could precede a rejected lock pin. Keep served evidence
    // for pinned restores, but retire the trust used by unpinned resolution.
    tx.execute_batch(
        "DROP TABLE IF EXISTS artifact_origins_v2;
        CREATE TABLE IF NOT EXISTS artifacts (
            group_id   TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            version    TEXT NOT NULL,
            packaging  TEXT NOT NULL,
            classifier TEXT NOT NULL,
            blob_id    TEXT NOT NULL,
            PRIMARY KEY (group_id, artifact_id, version, packaging, classifier)
        );
        CREATE TABLE IF NOT EXISTS artifact_origins_v3 (
            group_id    TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            version     TEXT NOT NULL,
            packaging   TEXT NOT NULL,
            classifier  TEXT NOT NULL,
            repo_url    TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            blob_id     TEXT NOT NULL,
            checksum_verified INTEGER NOT NULL,
            PRIMARY KEY (group_id, artifact_id, version, packaging, classifier, repo_url, endpoint_url)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS served_files (
            group_id    TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            version     TEXT NOT NULL,
            packaging   TEXT NOT NULL,
            classifier  TEXT NOT NULL,
            repo_url    TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            blob_id     TEXT NOT NULL,
            PRIMARY KEY (group_id, artifact_id, version, packaging, classifier, repo_url, endpoint_url, blob_id)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS checked_blobs (
            blob_id TEXT PRIMARY KEY,
            stamp   TEXT NOT NULL
        ) WITHOUT ROWID;",
    )
    .db_context(|| "failed to initialize artifacts table")?;
    let generation: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .db_context(|| "failed to read the database generation")?;
    if generation < crate::store::INDEX.generation {
        tx.pragma_update(None, "user_version", crate::store::INDEX.generation)
            .db_context(|| "failed to write the database generation")?;
    }
    tx.commit()
        .db_context(|| "failed to initialize artifacts table")?;
    if upgraded {
        crate::sqlite::warn_upgraded(path, "its record of which repository served each file");
    }
    Ok(())
}

pub(crate) fn add_artifact(conn: &Connection, key: &ArtifactCoord, id: &BlobId) -> Result<()> {
    conn.execute(
        "INSERT INTO artifacts (group_id, artifact_id, version, packaging, classifier, blob_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(group_id, artifact_id, version, packaging, classifier)
         DO UPDATE SET blob_id = excluded.blob_id",
        params![
            key.group_id(),
            key.artifact_id(),
            key.version(),
            key.extension(),
            key.classifier_key(),
            id.as_str()
        ],
    )
    .db_context(|| format!("failed to upsert artifact {key}"))?;
    Ok(())
}

pub(crate) fn lookup_artifact(conn: &Connection, key: &ArtifactCoord) -> Result<Option<BlobId>> {
    let columns = params![
        key.group_id(),
        key.artifact_id(),
        key.version(),
        key.extension(),
        key.classifier_key()
    ];
    let Some(value) = conn
        .prepare_cached(&format!(
            "SELECT blob_id FROM artifacts WHERE {KEY_MATCHES}"
        ))
        .and_then(|mut statement| statement.query_row(columns, |row| row.get::<_, String>(0)))
        .optional()
        .db_context(|| format!("failed to lookup artifact {key}"))?
    else {
        return Ok(None);
    };
    if let Ok(id) = BlobId::from_str(&value) {
        return Ok(Some(id));
    }
    // A row whose blob_id does not parse can never resolve to a file. It is
    // deleted and reported as a miss, so the artifact is fetched again. The
    // unlocked lookup runs without the store lock, so only a row still
    // holding the bad value is deleted: a concurrent upsert survives.
    tracing::debug!(%key, blob_id = %value, "index row has unparseable blob_id; deleting it");
    let path = std::path::Path::new(conn.path().unwrap_or_default());
    let tx = crate::sqlite::write_transaction(conn, path, crate::store::INDEX.generation)?;
    tx.execute(
        &format!("DELETE FROM artifacts WHERE {KEY_MATCHES} AND blob_id = ?6"),
        params![
            key.group_id(),
            key.artifact_id(),
            key.version(),
            key.extension(),
            key.classifier_key(),
            value
        ],
    )
    .db_context(|| format!("failed to scrub corrupt index row for {key}"))?;
    tx.commit()
        .db_context(|| format!("failed to scrub corrupt index row for {key}"))?;
    Ok(None)
}

/// Record `origin` as the answer for `key` at its repository and endpoint
/// and, when the repository served the bytes, keep that as evidence: a later
/// answer replaces the first, the evidence stays.
pub(crate) fn add_origin(
    conn: &Connection,
    key: &ArtifactCoord,
    id: &BlobId,
    origin: &crate::Origin,
) -> Result<()> {
    let row = params![
        key.group_id(),
        key.artifact_id(),
        key.version(),
        key.extension(),
        key.classifier_key(),
        origin.repo_url,
        origin.endpoint_url,
        id.as_str(),
        origin.checksum_verified
    ];
    conn.prepare_cached(
        "INSERT INTO artifact_origins_v3 (group_id, artifact_id, version, packaging, classifier,
             repo_url, endpoint_url, blob_id, checksum_verified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(group_id, artifact_id, version, packaging, classifier, repo_url, endpoint_url)
         DO UPDATE SET blob_id = excluded.blob_id, checksum_verified = excluded.checksum_verified",
    )
    .and_then(|mut statement| statement.execute(row))
    .db_context(|| format!("failed to record the origin of artifact {key}"))?;
    if origin.served {
        add_served(conn, key, id, &origin.repo_url, &origin.endpoint_url)?;
    }
    Ok(())
}

/// Keep as evidence that `endpoint_url` served `id` for `key` under
/// `repo_url`.
pub(crate) fn add_served(
    conn: &Connection,
    key: &ArtifactCoord,
    id: &BlobId,
    repo_url: &str,
    endpoint_url: &str,
) -> Result<()> {
    conn.prepare_cached(
        "INSERT OR IGNORE INTO served_files (group_id, artifact_id, version, packaging,
             classifier, repo_url, endpoint_url, blob_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .and_then(|mut statement| {
        statement.execute(params![
            key.group_id(),
            key.artifact_id(),
            key.version(),
            key.extension(),
            key.classifier_key(),
            repo_url,
            endpoint_url,
            id.as_str(),
        ])
    })
    .db_context(|| format!("failed to record the origin of artifact {key}"))?;
    Ok(())
}

/// The repository and endpoint URLs that served `id` for `key`.
pub(crate) fn served_by(
    conn: &Connection,
    key: &ArtifactCoord,
    id: &BlobId,
) -> Result<Vec<(String, String)>> {
    conn.prepare_cached(&format!(
        "SELECT repo_url, endpoint_url FROM served_files WHERE {KEY_MATCHES} AND blob_id = ?6"
    ))
    .and_then(|mut statement| {
        let columns = params![
            key.group_id(),
            key.artifact_id(),
            key.version(),
            key.extension(),
            key.classifier_key(),
            id.as_str()
        ];
        statement
            .query_map(columns, |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
    })
    .db_context(|| format!("failed to look up the origins of artifact {key}"))
}

/// The answer recorded for `key` at a repository and endpoint. Unless
/// `allow_recorded`, only bytes that route served count, not ones a lock
/// recorded there.
pub(crate) fn lookup_origin(
    conn: &Connection,
    key: &ArtifactCoord,
    repo_url: &str,
    endpoint_url: &str,
    allow_unverified: bool,
    allow_recorded: bool,
) -> Result<Option<BlobId>> {
    let value: Option<String> = conn
        .prepare_cached(&format!(
            "SELECT blob_id FROM artifact_origins_v3 AS o WHERE {KEY_MATCHES} AND repo_url = ?6
             AND endpoint_url = ?7 AND (checksum_verified OR ?8)
             AND (?9 OR EXISTS (SELECT 1 FROM served_files AS s
                 WHERE s.group_id = o.group_id AND s.artifact_id = o.artifact_id
                 AND s.version = o.version AND s.packaging = o.packaging
                 AND s.classifier = o.classifier AND s.repo_url = o.repo_url
                 AND s.endpoint_url = o.endpoint_url AND s.blob_id = o.blob_id))"
        ))
        .and_then(|mut statement| {
            let columns = params![
                key.group_id(),
                key.artifact_id(),
                key.version(),
                key.extension(),
                key.classifier_key(),
                repo_url,
                endpoint_url,
                allow_unverified,
                allow_recorded
            ];
            statement.query_row(columns, |row| row.get(0))
        })
        .optional()
        .db_context(|| format!("failed to look up the origin of artifact {key}"))?;
    // A row that does not parse is a miss; the download replaces it.
    Ok(value.and_then(|value| BlobId::from_str(&value).ok()))
}

pub(crate) fn checked_stamp(conn: &Connection, id: &BlobId) -> Result<Option<String>> {
    conn.prepare_cached("SELECT stamp FROM checked_blobs WHERE blob_id = ?1")
        .and_then(|mut statement| statement.query_row([id.as_str()], |row| row.get(0)))
        .optional()
        .db_context(|| format!("failed to look up the check of blob {id}"))
}

pub(crate) fn set_checked_stamp(conn: &Connection, id: &BlobId, stamp: &str) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO checked_blobs (blob_id, stamp) VALUES (?1, ?2)
         ON CONFLICT(blob_id) DO UPDATE SET stamp = excluded.stamp",
    )
    .and_then(|mut statement| statement.execute(params![id.as_str(), stamp]))
    .db_context(|| format!("failed to record the check of blob {id}"))?;
    Ok(())
}

pub(crate) fn clear_checked_stamp(conn: &Connection, id: &BlobId) -> Result<()> {
    conn.prepare_cached("DELETE FROM checked_blobs WHERE blob_id = ?1")
        .and_then(|mut statement| statement.execute([id.as_str()]))
        .db_context(|| format!("failed to invalidate the check of blob {id}"))?;
    Ok(())
}
