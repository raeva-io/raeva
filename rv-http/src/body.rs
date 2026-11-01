//! Reading a response body into memory under a size limit.

use bytes::Bytes;
use futures::StreamExt;

/// Why a bounded body read failed.
#[derive(Debug)]
pub enum BodyError {
    /// The body is larger than the limit.
    TooLarge {
        /// The limit the read was given, in bytes.
        limit: u64,
        /// The Content-Length when it alone exceeded the limit, before any
        /// byte was read. `None` when the streamed bytes went over.
        declared: Option<u64>,
    },
    /// The connection failed while the body was read.
    Transport(reqwest::Error),
}

/// Read `response`'s body, failing as soon as it would exceed `limit` bytes.
/// A Content-Length over the limit fails before any byte is read, and the
/// buffer never grows past the limit. `on_chunk` sees each chunk's length.
pub async fn read_limited(
    response: reqwest::Response,
    limit: u64,
    mut on_chunk: impl FnMut(usize),
) -> Result<Bytes, BodyError> {
    let declared = response.content_length();
    if declared.is_some_and(|length| length > limit) {
        return Err(BodyError::TooLarge { limit, declared });
    }
    let capacity = declared.unwrap_or(4096).min(limit);
    let mut body = Vec::with_capacity(usize::try_from(capacity).unwrap_or(usize::MAX));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BodyError::Transport)?;
        // The sum is in u64 so a hostile chunk cannot wrap the check on a
        // 32-bit target.
        if (body.len() as u64).saturating_add(chunk.len() as u64) > limit {
            return Err(BodyError::TooLarge {
                limit,
                declared: None,
            });
        }
        body.extend_from_slice(&chunk);
        on_chunk(chunk.len());
    }
    Ok(Bytes::from(body))
}
