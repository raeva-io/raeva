use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use backoff::ExponentialBackoff;
use futures::StreamExt;
use reqwest::StatusCode;
use reqwest::header::RETRY_AFTER;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::warn;

use crate::{Affected, Reference, Result, Severity, VulnError, VulnResult, Vulnerability};

const DEFAULT_BASE_URL: &str = "https://api.osv.dev/v1";
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 10;
const MAX_ELAPSED_TIME_SECS: u64 = 120;
const SEMAPHORE_ACQUIRE_TIMEOUT_SECS: u64 = 30;
const MAX_OSV_PAGES: usize = 100;
const MAX_SUCCESS_BODY_BYTES: usize = 20 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// Maximum number of PURLs per batch query to avoid oversized requests.
const BATCH_CHUNK_SIZE: usize = 1000;

/// Result of fetching a single vulnerability record.
#[derive(Debug, Clone)]
pub enum FetchResult {
    Success(Vulnerability),
    /// Fetch failed after exhausting retries.
    Failed {
        id: String,
        error: String,
    },
}

/// Result of a batch query operation
#[derive(Debug, Clone)]
pub struct BatchQueryResult {
    /// Successfully resolved vulnerability results per PURL
    pub results: Vec<VulnResult>,
    /// Vulnerabilities that failed to fetch (after retries)
    pub failed_fetches: Vec<FetchResult>,
}

pub struct OsvClient {
    client: reqwest::Client,
    base_url: String,
    max_concurrent_requests: usize,
}

impl OsvClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base_url: DEFAULT_BASE_URL.to_string(),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
        })
    }

    /// Create a new OsvClient with a custom concurrency limit.
    ///
    /// Clamps the value to a minimum of 1 to prevent zero-concurrency deadlocks.
    pub fn with_concurrency(max_concurrent_requests: usize) -> Result<Self> {
        let max_concurrent_requests = max_concurrent_requests.max(1);
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base_url: DEFAULT_BASE_URL.to_string(),
            max_concurrent_requests,
        })
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
        })
    }

    pub async fn query(&self, purl: &str) -> Result<Vec<Vulnerability>> {
        validate_purl(purl)?;
        let url = format!("{}/query", self.base_url.trim_end_matches('/'));

        let mut all_vulns: Vec<OsvVulnerability> = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut seen_tokens = HashSet::new();
        let mut page_token: Option<String> = None;
        let mut page_count = 0;

        // OSV returns a page token when more results are available.
        loop {
            page_count += 1;
            if page_count > MAX_OSV_PAGES {
                return Err(VulnError::InvalidResponse(format!(
                    "OSV query exceeded the {MAX_OSV_PAGES}-page limit"
                )));
            }

            let request = OsvQueryRequest {
                package: OsvPackage {
                    purl: purl.to_string(),
                },
                page_token: page_token.clone(),
            };

            let response = retry_with_backoff(|| async {
                let response = self
                    .client
                    .post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_timeout() || e.is_connect() {
                            backoff::Error::transient(VulnError::Http(e))
                        } else {
                            backoff::Error::permanent(VulnError::Http(e))
                        }
                    })?;
                handle_response_for_retry(response).await
            })
            .await?;

            let parsed: OsvQueryResponse = parse_json_response(response).await?;
            for vulnerability in parsed.vulns.unwrap_or_default() {
                if seen_ids.insert(vulnerability.id.clone()) {
                    all_vulns.push(vulnerability);
                }
            }

            match parsed.next_page_token {
                Some(token) if !token.is_empty() => {
                    if !seen_tokens.insert(token.clone()) {
                        return Err(VulnError::InvalidResponse(
                            "OSV query returned a repeated page token".to_string(),
                        ));
                    }
                    page_token = Some(token);
                }
                _ => break,
            }
        }

        Ok(all_vulns.into_iter().map(Vulnerability::from).collect())
    }

    pub async fn query_batch(&self, purls: &[String]) -> Result<BatchQueryResult> {
        if purls.is_empty() {
            return Ok(BatchQueryResult {
                results: Vec::new(),
                failed_fetches: Vec::new(),
            });
        }

        // Chunk large requests to avoid hitting API limits.
        let mut all_results: Vec<VulnResult> = Vec::with_capacity(purls.len());
        let mut all_failed_fetches: Vec<FetchResult> = Vec::new();

        for chunk in purls.chunks(BATCH_CHUNK_SIZE) {
            let chunk_result = self.query_batch_chunk(chunk).await?;
            all_results.extend(chunk_result.results);
            all_failed_fetches.extend(chunk_result.failed_fetches);
        }

        Ok(BatchQueryResult {
            results: all_results,
            failed_fetches: all_failed_fetches,
        })
    }

    async fn query_batch_chunk(&self, purls: &[String]) -> Result<BatchQueryResult> {
        for purl in purls {
            validate_purl(purl)?;
        }

        // Keep vulnerability ids in API order while removing duplicates.
        let mut per_purl_ids: Vec<Vec<String>> = vec![Vec::new(); purls.len()];
        let mut per_purl_seen: Vec<HashSet<String>> = vec![HashSet::new(); purls.len()];

        self.collect_batch_pages(purls, &mut per_purl_ids, &mut per_purl_seen)
            .await?;

        // Resolve each vulnerability record once across the whole batch.
        let mut all_ids_seen: HashSet<String> = HashSet::new();
        let mut all_ids: Vec<String> = Vec::new();
        for ids in &per_purl_ids {
            for id in ids {
                if all_ids_seen.insert(id.clone()) {
                    all_ids.push(id.clone());
                }
            }
        }

        let fetch_results = self.fetch_vulnerabilities(&all_ids).await;

        let mut vuln_map: HashMap<String, Vulnerability> = HashMap::new();
        let mut failed_fetches: Vec<FetchResult> = Vec::new();

        for fetch_result in fetch_results {
            match fetch_result {
                FetchResult::Success(vulnerability) => {
                    vuln_map.insert(vulnerability.id.clone(), vulnerability);
                }
                failed @ FetchResult::Failed { .. } => {
                    failed_fetches.push(failed);
                }
            }
        }

        let results = purls
            .iter()
            .cloned()
            .zip(per_purl_ids)
            .map(|(purl, ids)| {
                let vulnerabilities = ids
                    .into_iter()
                    .map(|id| {
                        vuln_map.get(&id).cloned().ok_or_else(|| {
                            VulnError::InvalidResponse(format!(
                                "OSV did not return the requested vulnerability record '{id}'"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(VulnResult {
                    purl,
                    vulnerabilities,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(BatchQueryResult {
            results,
            failed_fetches,
        })
    }

    /// Fetch every page for each query in a batch.
    async fn collect_batch_pages(
        &self,
        purls: &[String],
        per_purl_ids: &mut [Vec<String>],
        per_purl_seen: &mut [HashSet<String>],
    ) -> Result<()> {
        let url = format!("{}/querybatch", self.base_url.trim_end_matches('/'));

        // Each token belongs to the purl at the paired index.
        let mut pending: Vec<(usize, Option<String>)> =
            (0..purls.len()).map(|i| (i, None)).collect();
        let mut seen_tokens: Vec<HashSet<String>> = vec![HashSet::new(); purls.len()];
        let mut page_counts = vec![0usize; purls.len()];

        while !pending.is_empty() {
            let mut queries = Vec::with_capacity(pending.len());
            for (idx, token) in &pending {
                page_counts[*idx] += 1;
                if page_counts[*idx] > MAX_OSV_PAGES {
                    return Err(VulnError::InvalidResponse(format!(
                        "OSV batch query exceeded the {MAX_OSV_PAGES}-page limit for query {idx}"
                    )));
                }
                queries.push(OsvQueryRequest {
                    package: OsvPackage {
                        purl: purls[*idx].clone(),
                    },
                    page_token: token.clone(),
                });
            }

            let request = OsvBatchRequest { queries };
            let response = retry_with_backoff(|| async {
                let response = self
                    .client
                    .post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_timeout() || e.is_connect() {
                            backoff::Error::transient(VulnError::Http(e))
                        } else {
                            backoff::Error::permanent(VulnError::Http(e))
                        }
                    })?;
                handle_response_for_retry(response).await
            })
            .await?;

            let parsed: OsvBatchResponse = parse_json_response(response).await?;

            if parsed.results.len() != pending.len() {
                // Missing slots cannot safely be treated as having no vulnerabilities.
                return Err(VulnError::InvalidResponse(format!(
                    "expected {} results, got {} (partial response, not caching)",
                    pending.len(),
                    parsed.results.len()
                )));
            }

            let mut next_pending: Vec<(usize, Option<String>)> = Vec::new();
            for ((idx, _), result) in pending.iter().zip(parsed.results) {
                if let Some(vulns) = result.vulns {
                    for vuln in vulns {
                        if per_purl_seen[*idx].insert(vuln.id.clone()) {
                            per_purl_ids[*idx].push(vuln.id);
                        }
                    }
                }
                if let Some(token) = result.next_page_token
                    && !token.is_empty()
                {
                    if !seen_tokens[*idx].insert(token.clone()) {
                        return Err(VulnError::InvalidResponse(format!(
                            "OSV batch query returned a repeated page token for query {idx}"
                        )));
                    }
                    next_pending.push((*idx, Some(token)));
                }
            }
            pending = next_pending;
        }

        Ok(())
    }

    async fn fetch_vulnerabilities(&self, ids: &[String]) -> Vec<FetchResult> {
        use futures::stream::{self, StreamExt};

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_requests));

        stream::iter(ids)
            .map(|id| {
                let id = id.clone();
                let semaphore = semaphore.clone();
                async move {
                    let permit = timeout(
                        Duration::from_secs(SEMAPHORE_ACQUIRE_TIMEOUT_SECS),
                        semaphore.acquire(),
                    )
                    .await;

                    let _permit = match permit {
                        Ok(Ok(p)) => p,
                        Ok(Err(_)) => {
                            // The semaphore should remain open for the request lifetime.
                            return FetchResult::Failed {
                                id: id.clone(),
                                error: "semaphore closed unexpectedly".to_string(),
                            };
                        }
                        Err(_) => {
                            warn!(vuln_id = %id, "semaphore acquire timeout");
                            return FetchResult::Failed {
                                id: id.clone(),
                                error: "semaphore acquire timeout".to_string(),
                            };
                        }
                    };
                    self.fetch_vulnerability_with_retry(&id).await
                }
            })
            .buffer_unordered(self.max_concurrent_requests)
            .collect()
            .await
    }

    async fn fetch_vulnerability_with_retry(&self, id: &str) -> FetchResult {
        let backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(MAX_ELAPSED_TIME_SECS)),
            ..ExponentialBackoff::default()
        };

        let operation = || async {
            match self.fetch_vulnerability(id).await {
                Ok(vuln) => Ok(vuln),
                Err(err @ VulnError::RateLimited { retry_after }) => {
                    warn!(
                        vuln_id = %id,
                        retry_after = ?retry_after,
                        "rate limited, will retry"
                    );
                    Err(backoff::Error::transient(err))
                }
                Err(VulnError::Http(source)) if source.is_timeout() || source.is_connect() => {
                    warn!(vuln_id = %id, "transient OSV request error, will retry");
                    Err(backoff::Error::transient(VulnError::Http(source)))
                }
                // Server errors are transient.
                Err(err @ VulnError::HttpStatus { status, .. }) if status.is_server_error() => {
                    warn!(
                        vuln_id = %id,
                        status = %status,
                        "server error fetching vulnerability, will retry"
                    );
                    Err(backoff::Error::transient(err))
                }
                Err(err) => Err(backoff::Error::permanent(err)),
            }
        };

        match backoff::future::retry(backoff, operation).await {
            Ok(vulnerability) if vulnerability.id == id => FetchResult::Success(vulnerability),
            Ok(vulnerability) => FetchResult::Failed {
                id: id.to_string(),
                error: format!(
                    "OSV returned vulnerability '{}' for requested id '{id}'",
                    vulnerability.id
                ),
            },
            Err(err) => FetchResult::Failed {
                id: id.to_string(),
                error: safe_error_message(&err),
            },
        }
    }

    async fn fetch_vulnerability(&self, id: &str) -> Result<Vulnerability> {
        let url = format!("{}/vulns/{}", self.base_url.trim_end_matches('/'), id);
        let response = self.client.get(&url).send().await?;
        let response = handle_response(response).await?;
        let parsed: OsvVulnerability = parse_json_response(response).await?;
        Ok(Vulnerability::from(parsed))
    }
}

/// Run an async operation with exponential backoff, retrying on transient errors.
async fn retry_with_backoff<F, Fut, T>(operation: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, backoff::Error<VulnError>>>,
{
    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(MAX_ELAPSED_TIME_SECS)),
        ..ExponentialBackoff::default()
    };
    backoff::future::retry(backoff, operation).await
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    /// Pagination cursor returned by a previous response. Omitted on the first page.
    #[serde(rename = "page_token", skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    purl: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQueryRequest>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVulnerability>>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResult {
    vulns: Option<Vec<OsvVulnerability>>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<Severity>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    affected: Vec<Affected>,
}

impl From<OsvVulnerability> for Vulnerability {
    fn from(value: OsvVulnerability) -> Self {
        let severity = select_highest_severity(&value.severity);
        Self {
            id: value.id,
            aliases: value.aliases,
            summary: value.summary.unwrap_or_default(),
            details: value.details,
            severity,
            references: value.references,
            affected: value.affected,
        }
    }
}

fn select_highest_severity(severities: &[Severity]) -> Option<Severity> {
    let mut best: Option<(crate::SeverityBand, f32, Severity)> = None;
    for severity in severities {
        if let Some(score) = severity.score_value() {
            let band = severity.severity_band();
            let replace = match &best {
                Some((best_band, best_score, _)) => {
                    band > *best_band || (band == *best_band && score > *best_score)
                }
                None => true,
            };
            if replace {
                best = Some((band, score, severity.clone()));
            }
        }
    }

    if best.is_none() {
        return severities.first().cloned();
    }

    best.map(|(_, _, severity)| severity)
}

async fn handle_response(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = parse_retry_after(response.headers());
        return Err(VulnError::RateLimited { retry_after });
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = sanitize_server_text(&read_response_text(response, MAX_ERROR_BODY_BYTES).await?);
        return Err(VulnError::HttpStatus { status, body });
    }

    Ok(response)
}

/// Like `handle_response` but returns `backoff::Error` so it can be used inside retry closures.
/// 429 and 5xx responses are treated as transient; everything else is permanent.
async fn handle_response_for_retry(
    response: reqwest::Response,
) -> std::result::Result<reqwest::Response, backoff::Error<VulnError>> {
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = parse_retry_after(response.headers());
        warn!(retry_after = ?retry_after, "rate limited by OSV API, will retry");
        return Err(backoff::Error::transient(VulnError::RateLimited {
            retry_after,
        }));
    }

    if response.status().is_server_error() {
        let status = response.status();
        let body = read_response_text(response, MAX_ERROR_BODY_BYTES)
            .await
            .map(|text| sanitize_server_text(&text))
            .map_err(backoff::Error::permanent)?;
        warn!(status = %status, "OSV server error, will retry");
        return Err(backoff::Error::transient(VulnError::HttpStatus {
            status,
            body,
        }));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = read_response_text(response, MAX_ERROR_BODY_BYTES)
            .await
            .map(|text| sanitize_server_text(&text))
            .map_err(backoff::Error::permanent)?;
        return Err(backoff::Error::permanent(VulnError::HttpStatus {
            status,
            body,
        }));
    }

    Ok(response)
}

async fn parse_json_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let body = read_response_bytes(response, MAX_SUCCESS_BODY_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|err| VulnError::InvalidResponse(format!("invalid OSV JSON: {err}")))
}

async fn read_response_text(response: reqwest::Response, limit: usize) -> Result<String> {
    let body = read_response_bytes(response, limit).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn read_response_bytes(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(VulnError::InvalidResponse(format!(
            "OSV response exceeds the {limit}-byte limit"
        )));
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(VulnError::InvalidResponse(format!(
                "OSV response exceeds the {limit}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn sanitize_server_text(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn safe_error_message(error: &VulnError) -> String {
    match error {
        VulnError::Http(source) if source.is_timeout() => "OSV request timed out".to_string(),
        VulnError::Http(source) if source.is_connect() => {
            "could not connect to the OSV service".to_string()
        }
        VulnError::Http(_) => "OSV HTTP request failed".to_string(),
        _ => sanitize_server_text(&error.to_string()),
    }
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn validate_purl(purl: &str) -> Result<()> {
    let parsed = packageurl::PackageUrl::from_str(purl)
        .map_err(|e| VulnError::InvalidPurl(format!("{}: {}", purl, e)))?;

    if parsed.ty() != "maven" {
        return Err(VulnError::InvalidPurl(format!(
            "{}: expected type 'maven', got '{}'",
            purl,
            parsed.ty()
        )));
    }

    let namespace = parsed.namespace().ok_or_else(|| {
        VulnError::InvalidPurl(format!("{}: missing Maven group_id (namespace)", purl))
    })?;
    if namespace.is_empty() {
        return Err(VulnError::InvalidPurl(format!(
            "{}: Maven group_id (namespace) cannot be empty",
            purl
        )));
    }

    if parsed.name().is_empty() {
        return Err(VulnError::InvalidPurl(format!(
            "{}: Maven artifact_id (name) cannot be empty",
            purl
        )));
    }

    let version = parsed
        .version()
        .ok_or_else(|| VulnError::InvalidPurl(format!("{}: missing Maven version", purl)))?;
    if version.is_empty() {
        return Err(VulnError::InvalidPurl(format!(
            "{}: Maven version cannot be empty",
            purl
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::{MAX_ERROR_BODY_BYTES, MAX_SUCCESS_BODY_BYTES, OsvClient, VulnError};

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        let mut expected_length = None;

        loop {
            let size = stream.read(&mut buffer).expect("read request");
            assert_ne!(size, 0, "request ended before its body was complete");
            request.extend_from_slice(&buffer[..size]);

            if expected_length.is_none()
                && let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("Content-Length"))
                        })
                    })
                    .unwrap_or(0);
                expected_length = Some(header_end + 4 + content_length);
            }

            if expected_length.is_some_and(|length| request.len() >= length) {
                break;
            }
        }

        String::from_utf8(request).expect("request UTF-8")
    }

    fn request_path(request: &str) -> &str {
        request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request path")
    }

    fn spawn_mock_server(response_body: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let request = read_request(&mut stream);
            assert!(request.starts_with("POST /v1/query"));
            assert!(request.contains("pkg:maven/com.example/demo@1.2.3"));
            assert!(!request.contains("\"ecosystem\""));
            assert!(!request.contains("\"name\""));

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        (format!("http://{}/v1", addr), handle)
    }

    fn spawn_routed_mock_server(
        routes: Vec<(&'static str, Vec<&'static str>)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        let total: usize = routes.iter().map(|(_, responses)| responses.len()).sum();
        let mut routes: HashMap<String, VecDeque<&'static str>> = routes
            .into_iter()
            .map(|(path, responses)| (path.to_string(), responses.into()))
            .collect();

        let handle = std::thread::spawn(move || {
            let mut requests = Vec::with_capacity(total);
            for _ in 0..total {
                let (mut stream, _) = listener.accept().expect("accept connection");
                let request = read_request(&mut stream);
                let path = request_path(&request);
                let body = routes
                    .get_mut(path)
                    .and_then(VecDeque::pop_front)
                    .unwrap_or_else(|| panic!("unexpected request path {path}"));
                requests.push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
            requests
        });

        (format!("http://{}/v1", addr), handle)
    }

    fn spawn_custom_mock_server(
        status: &'static str,
        body: &'static str,
        declared_length: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let _request = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {declared_length}\r\n\r\n{body}"
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (format!("http://{addr}/v1"), handle)
    }

    fn spawn_chunked_mock_server(
        status: &'static str,
        body_size: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let _request = read_request(&mut stream);
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n{body_size:x}\r\n"
            );
            stream.write_all(headers.as_bytes()).expect("write headers");
            stream
                .write_all(&vec![b'x'; body_size])
                .expect("write chunk");
            stream.write_all(b"\r\n0\r\n\r\n").expect("end chunks");
        });
        (format!("http://{addr}/v1"), handle)
    }

    fn current_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime build")
    }

    #[test]
    fn query_follows_pagination() {
        let page1 = r#"{
            "vulns": [{"id": "OSV-A", "summary": "a", "affected": []}],
            "next_page_token": "tok-1"
        }"#;
        let page2 = r#"{
            "vulns": [{"id": "OSV-B", "summary": "b", "affected": []}]
        }"#;

        let (base_url, handle) = spawn_routed_mock_server(vec![("/v1/query", vec![page1, page2])]);
        let client = OsvClient::with_base_url(base_url).expect("client");
        let runtime = current_thread_runtime();

        let vulns = runtime
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect("query succeeds");

        let bodies = handle.join().expect("server thread");
        assert_eq!(bodies.len(), 2, "client should issue two requests");
        // Only follow-up requests carry a page token.
        assert!(!bodies[0].contains("page_token"));
        assert!(bodies[1].contains("tok-1"));

        let ids: Vec<&str> = vulns.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["OSV-A", "OSV-B"]);
    }

    #[test]
    fn query_batch_follows_per_result_pagination() {
        let batch_page1 =
            r#"{"results": [{"vulns": [{"id": "OSV-A"}], "next_page_token": "tok-1"}]}"#;
        let batch_page2 = r#"{"results": [{"vulns": [{"id": "OSV-B"}]}]}"#;
        let vuln_a = r#"{"id": "OSV-A", "summary": "a", "affected": []}"#;
        let vuln_b = r#"{"id": "OSV-B", "summary": "b", "affected": []}"#;

        // Full records are fetched concurrently after both batch pages.
        let (base_url, handle) = spawn_routed_mock_server(vec![
            ("/v1/querybatch", vec![batch_page1, batch_page2]),
            ("/v1/vulns/OSV-A", vec![vuln_a]),
            ("/v1/vulns/OSV-B", vec![vuln_b]),
        ]);
        let client = OsvClient::with_base_url(base_url).expect("client");
        let runtime = current_thread_runtime();

        let result = runtime
            .block_on(client.query_batch(&["pkg:maven/com.example/demo@1.2.3".to_string()]))
            .expect("batch query succeeds");

        handle.join().expect("server thread");

        assert_eq!(result.results.len(), 1);
        let mut ids: Vec<&str> = result.results[0]
            .vulnerabilities
            .iter()
            .map(|v| v.id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["OSV-A", "OSV-B"]);
        assert!(result.failed_fetches.is_empty());
    }

    #[test]
    fn query_deduplicates_vulnerabilities_across_pages() {
        let page1 = r#"{"vulns":[{"id":"OSV-A"}],"next_page_token":"next"}"#;
        let page2 = r#"{"vulns":[{"id":"OSV-A"},{"id":"OSV-B"}]}"#;
        let (base_url, handle) = spawn_routed_mock_server(vec![("/v1/query", vec![page1, page2])]);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let vulnerabilities = current_thread_runtime()
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect("query succeeds");

        handle.join().expect("server thread");
        let ids: Vec<&str> = vulnerabilities
            .iter()
            .map(|vuln| vuln.id.as_str())
            .collect();
        assert_eq!(ids, vec!["OSV-A", "OSV-B"]);
    }

    #[test]
    fn query_rejects_repeated_page_token() {
        let page = r#"{"vulns":[],"next_page_token":"cycle"}"#;
        let (base_url, handle) = spawn_routed_mock_server(vec![("/v1/query", vec![page, page])]);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect_err("cyclic pagination must fail");

        handle.join().expect("server thread");
        assert!(error.to_string().contains("repeated page token"));
    }

    #[test]
    fn query_batch_rejects_repeated_page_token() {
        let page = r#"{"results":[{"vulns":[],"next_page_token":"cycle"}]}"#;
        let (base_url, handle) =
            spawn_routed_mock_server(vec![("/v1/querybatch", vec![page, page])]);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query_batch(&["pkg:maven/com.example/demo@1.2.3".to_string()]))
            .expect_err("cyclic pagination must fail");

        handle.join().expect("server thread");
        assert!(error.to_string().contains("repeated page token"));
    }

    #[test]
    fn query_batch_rejects_detail_id_mismatch() {
        let batch = r#"{"results":[{"vulns":[{"id":"OSV-A"}]}]}"#;
        let mismatched = r#"{"id":"OSV-B"}"#;
        let (base_url, handle) = spawn_routed_mock_server(vec![
            ("/v1/querybatch", vec![batch]),
            ("/v1/vulns/OSV-A", vec![mismatched]),
        ]);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query_batch(&["pkg:maven/com.example/demo@1.2.3".to_string()]))
            .expect_err("mismatched detail id must fail");

        handle.join().expect("server thread");
        assert!(error.to_string().contains("OSV-A"));
    }

    #[test]
    fn query_rejects_oversized_success_body() {
        let (base_url, handle) =
            spawn_custom_mock_server("200 OK", "{}", MAX_SUCCESS_BODY_BYTES + 1);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect_err("oversized response must fail");

        handle.join().expect("server thread");
        assert!(matches!(error, VulnError::InvalidResponse(_)));
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn query_rejects_oversized_streamed_error_body() {
        let (base_url, handle) =
            spawn_chunked_mock_server("400 Bad Request", MAX_ERROR_BODY_BYTES + 1);
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect_err("oversized response must fail");

        handle.join().expect("server thread");
        assert!(matches!(error, VulnError::InvalidResponse(_)));
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn query_strips_control_characters_from_error_body() {
        let body = "bad\u{1b}[31m\r\nquery";
        let (base_url, handle) = spawn_custom_mock_server("400 Bad Request", body, body.len());
        let client = OsvClient::with_base_url(base_url).expect("client");

        let error = current_thread_runtime()
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect_err("bad response must fail");

        handle.join().expect("server thread");
        assert_eq!(
            error.to_string(),
            "unexpected OSV status 400 Bad Request: bad[31mquery"
        );
    }

    #[test]
    fn query_parses_vulnerabilities() {
        let response_body = r#"{
            "vulns": [
                {
                    "id": "OSV-2024-0001",
                    "aliases": ["CVE-2024-0001"],
                    "summary": "Example issue",
                    "details": "More details",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "references": [{"type": "ADVISORY", "url": "https://example.com"}],
                    "affected": []
                }
            ]
        }"#;

        let (base_url, handle) = spawn_mock_server(response_body);
        let client = OsvClient::with_base_url(base_url).expect("client");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime build");

        let vulnerabilities = runtime
            .block_on(client.query("pkg:maven/com.example/demo@1.2.3"))
            .expect("query succeeds");
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "OSV-2024-0001");
        assert_eq!(vulnerabilities[0].aliases, vec!["CVE-2024-0001"]);

        handle.join().expect("server thread");
    }

    #[test]
    fn with_concurrency_clamps_zero_to_one() {
        let client = OsvClient::with_concurrency(0).unwrap();
        assert_eq!(client.max_concurrent_requests, 1);
    }

    #[test]
    fn with_concurrency_sets_limit() {
        let client = OsvClient::with_concurrency(5).unwrap();
        assert_eq!(client.max_concurrent_requests, 5);
    }

    #[test]
    fn validate_purl_accepts_valid_maven_purl() {
        use super::validate_purl;
        assert!(validate_purl("pkg:maven/com.example/demo@1.2.3").is_ok());
        assert!(validate_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0").is_ok());
    }

    #[test]
    fn validate_purl_rejects_non_maven_type() {
        use super::validate_purl;
        let result = validate_purl("pkg:npm/lodash@4.17.21");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected type 'maven'"));
    }

    #[test]
    fn validate_purl_rejects_missing_namespace() {
        use super::validate_purl;
        let result = validate_purl("pkg:maven/demo@1.2.3");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing Maven group_id"));
    }

    #[test]
    fn validate_purl_rejects_empty_artifact_id() {
        use super::validate_purl;
        let result = validate_purl("pkg:maven/com.example/@1.2.3");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("artifact_id") || err.contains("name"));
    }

    #[test]
    fn validate_purl_rejects_missing_version() {
        use super::validate_purl;
        let result = validate_purl("pkg:maven/com.example/demo");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing Maven version"));
    }

    #[test]
    fn validate_purl_rejects_malformed_purl() {
        use super::validate_purl;
        // The problematic PURL from the issue description
        let result = validate_purl("pkg:maven///1.0.0");
        assert!(result.is_err());
    }
}
