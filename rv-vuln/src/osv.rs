use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use indexmap::{IndexMap, IndexSet};
use reqwest::StatusCode;
use rv_http::body::{BodyError, read_limited};
use rv_http::retry::{Cooldown, Outcome, RetryPolicy};
use rv_http::transient::{status_is_transient, transport_is_retryable};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{Affected, Reference, Result, Severity, VulnError, VulnResult, Vulnerability};

/// OSV answers a record in about 0.2 s and a batch of 1000 purls in more
/// than a second, so batches are split and requests share the one HTTP/2
/// connection.
const MAX_CONCURRENT_REQUESTS: usize = 50;
const MAX_OSV_PAGES: usize = 100;
const MAX_SUCCESS_BODY_BYTES: usize = 20 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const BATCH_CHUNK_SIZE: usize = 100;
const MAX_REDIRECTS: usize = 5;

/// A vulnerability record that a batch query named but that could not be
/// fetched from `/vulns/{id}`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FailedFetch {
    /// The vulnerability id, as the batch query returned it. Only ids that
    /// look like OSV ids are fetched, so it is safe to print.
    pub id: String,
    /// The purls the batch query listed the id for, in input order.
    pub purls: Vec<String>,
    /// Why the fetch failed, after retries: the request error, or
    /// [`VulnError::InvalidResponse`] when OSV answered with another record.
    pub error: Arc<VulnError>,
}

impl FailedFetch {
    /// The record `id`, listed for `purls`, that failed with `error`.
    pub fn new(id: impl Into<String>, purls: Vec<String>, error: Arc<VulnError>) -> Self {
        Self {
            id: id.into(),
            purls,
            error,
        }
    }
}

/// An OSV API client. It queries Maven purls with `/query` and
/// `/querybatch`, follows OSV pagination up to 100 pages per query, and
/// fetches each record a batch names from `/vulns/{id}`.
///
/// Response bodies are capped (20 MiB for results, 64 KiB for errors), and
/// server text reaches errors only as sizes and positions.
pub struct OsvClient {
    client: reqwest::Client,
    base_url: String,
    retry: RetryPolicy,
    cooldown: Cooldown,
    on_retry: Option<RetryNotice>,
}

/// Receives one line for each wait before a retry, naming the request, the
/// wait, the attempt and the failure. The line holds no URL.
pub type RetryNotice = std::sync::Arc<dyn Fn(String) + Send + Sync>;

/// How an [`OsvClient`] reaches the OSV service: the proxies the user
/// configured, the per-request timeout, and the retries, which follow the
/// same rule as repository requests (see [`rv_http::retry`]).
#[derive(Clone)]
pub struct OsvSettings {
    /// Proxies to route OSV requests through. No proxy is used when empty.
    pub proxies: Vec<reqwest::Proxy>,
    /// Timeout of one request. The retry budget is derived from it.
    pub timeout: Duration,
    /// Retries after the first attempt of a request that failed
    /// transiently.
    pub retries: usize,
    /// Told of each wait before a retry.
    pub on_retry: Option<RetryNotice>,
}

/// Counts the proxies instead of showing them: their Debug shows
/// credentials.
impl std::fmt::Debug for OsvSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsvSettings")
            .field("proxies", &self.proxies.len())
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .finish_non_exhaustive()
    }
}

impl Default for OsvSettings {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            timeout: Duration::from_secs(30),
            retries: 3,
            on_retry: None,
        }
    }
}

/// Follow a redirect only to the origin that issued it. A redirect to
/// another origin is not followed: its 3xx response becomes the answer and
/// fails as an unexpected status.
fn same_origin_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
        }
        let same_origin = attempt
            .previous()
            .last()
            .is_some_and(|issuer| issuer.origin() == attempt.url().origin());
        if same_origin {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

impl OsvClient {
    /// The public OSV API, `https://api.osv.dev/v1`.
    pub const DEFAULT_BASE_URL: &str = "https://api.osv.dev/v1";

    /// A client for `base_url`, the prefix before `/query`, that reaches it
    /// as `settings` say. It trusts the same roots and sends the same user
    /// agent as repository fetches.
    ///
    /// Fails with [`VulnError::Http`] when the HTTP client cannot be built.
    pub fn with_settings(base_url: impl Into<String>, settings: OsvSettings) -> Result<Self> {
        let mut builder = rv_http::client_defaults()
            .timeout(settings.timeout)
            .redirect(same_origin_redirects());
        for proxy in settings.proxies {
            builder = builder.proxy(proxy);
        }
        Ok(Self {
            client: builder.build()?,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            retry: RetryPolicy::new(settings.retries, settings.timeout),
            cooldown: Cooldown::default(),
            on_retry: settings.on_retry,
        })
    }

    /// The vulnerabilities OSV lists for one Maven purl, from every page of
    /// `/query`, deduplicated by id in the order OSV returned them.
    pub(crate) async fn query(&self, purl: &str) -> Result<Vec<Vulnerability>> {
        let url = format!("{}/query", self.base_url);
        let mut vulnerabilities = IndexMap::new();
        let mut seen_tokens = HashSet::new();
        let mut page_token = None;
        loop {
            if seen_tokens.len() >= MAX_OSV_PAGES {
                return Err(VulnError::InvalidResponse(format!(
                    "OSV query exceeded the {MAX_OSV_PAGES}-page limit"
                )));
            }
            let request = QueryRequest::new(purl, page_token);
            let page: Page = self.post(&url, "query", &request).await?;
            for vulnerability in page.vulns.unwrap_or_default() {
                vulnerabilities
                    .entry(vulnerability.id.clone())
                    .or_insert(vulnerability);
            }
            match page.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) if !seen_tokens.insert(token.clone()) => {
                    return Err(VulnError::InvalidResponse(
                        "OSV query returned a repeated page token".to_string(),
                    ));
                }
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        Ok(vulnerabilities
            .into_values()
            .map(Vulnerability::from)
            .collect())
    }

    /// Query many Maven purls with `/querybatch`, in concurrent chunks of
    /// 100, then fetch each named record once from `/vulns/{id}`.
    ///
    /// Returns one [`VulnResult`] per input purl, in input order, and the
    /// records that could not be fetched, in the order the batch named
    /// them. An implausible vulnerability id or a batch answer with the
    /// wrong number of results fails the whole call; a record that cannot
    /// be fetched does not.
    pub(crate) async fn query_batch(
        &self,
        purls: &[String],
    ) -> Result<(Vec<VulnResult>, Vec<FailedFetch>)> {
        use futures::stream::{self, StreamExt, TryStreamExt};

        let mut per_purl_ids = vec![IndexSet::new(); purls.len()];
        // The first failure in chunk order ends the call and drops the
        // chunks still in flight.
        stream::iter(
            purls
                .chunks(BATCH_CHUNK_SIZE)
                .zip(per_purl_ids.chunks_mut(BATCH_CHUNK_SIZE)),
        )
        .map(|(chunk, ids)| self.collect_batch_pages(chunk, ids))
        .buffered(MAX_CONCURRENT_REQUESTS)
        .try_collect::<()>()
        .await?;

        let all_ids: IndexSet<&str> = per_purl_ids.iter().flatten().map(String::as_str).collect();
        let fetched: Vec<(&str, Result<Vulnerability>)> = stream::iter(all_ids.iter().copied())
            .map(|id| async move { (id, self.fetch_vulnerability(id).await) })
            .buffer_unordered(MAX_CONCURRENT_REQUESTS)
            .collect()
            .await;
        let mut records = HashMap::new();
        let mut errors = HashMap::new();
        for (id, result) in fetched {
            match result {
                Ok(vulnerability) => records.insert(id, vulnerability).is_none(),
                Err(error) => errors.insert(id, error).is_none(),
            };
        }

        let mut failed_fetches: Vec<FailedFetch> = all_ids
            .iter()
            .filter_map(|id| {
                let error = errors.remove(id)?;
                Some(FailedFetch::new(*id, Vec::new(), Arc::new(error)))
            })
            .collect();
        let results = purls
            .iter()
            .zip(&per_purl_ids)
            .map(|(purl, ids)| {
                let mut vulnerabilities = Vec::new();
                for id in ids {
                    if let Some(vulnerability) = records.get(id.as_str()) {
                        vulnerabilities.push(vulnerability.clone());
                    } else if let Some(failed) =
                        failed_fetches.iter_mut().find(|failed| failed.id == *id)
                    {
                        failed.purls.push(purl.clone());
                    }
                }
                VulnResult {
                    purl: purl.clone(),
                    vulnerabilities,
                }
            })
            .collect();
        Ok((results, failed_fetches))
    }

    async fn collect_batch_pages(
        &self,
        purls: &[String],
        ids: &mut [IndexSet<String>],
    ) -> Result<()> {
        let url = format!("{}/querybatch", self.base_url);
        let mut seen_tokens = vec![HashSet::new(); purls.len()];
        let mut pending: Vec<(usize, Option<String>)> =
            (0..purls.len()).map(|i| (i, None)).collect();

        while !pending.is_empty() {
            let mut queries = Vec::with_capacity(pending.len());
            for (idx, token) in &pending {
                if seen_tokens[*idx].len() >= MAX_OSV_PAGES {
                    return Err(VulnError::InvalidResponse(format!(
                        "OSV batch query exceeded the {MAX_OSV_PAGES}-page limit for query {idx}"
                    )));
                }
                queries.push(QueryRequest::new(&purls[*idx], token.clone()));
            }
            let response: BatchResponse = self
                .post(&url, "querybatch", &BatchRequest { queries })
                .await?;
            if response.results.len() != pending.len() {
                // Missing slots cannot safely be treated as having no vulnerabilities.
                return Err(VulnError::InvalidResponse(format!(
                    "expected {} results, got {} (partial response, not caching)",
                    pending.len(),
                    response.results.len()
                )));
            }

            let mut next_pending = Vec::new();
            for ((idx, _), page) in pending.iter().zip(response.results) {
                for vulnerability in page.vulns.unwrap_or_default() {
                    if !is_plausible_vulnerability_id(&vulnerability.id) {
                        return Err(VulnError::InvalidResponse(format!(
                            "OSV batch query returned a vulnerability id that is not a valid \
                             OSV id for query {idx} ({} bytes)",
                            vulnerability.id.len()
                        )));
                    }
                    ids[*idx].insert(vulnerability.id);
                }
                if let Some(token) = page.next_page_token.filter(|token| !token.is_empty()) {
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

    async fn fetch_vulnerability(&self, id: &str) -> Result<Vulnerability> {
        let url = format!("{}/vulns/{id}", self.base_url);
        let record: OsvVulnerability = self
            .retry(id, || async {
                let response = handle_response(self.client.get(&url).send().await).await?;
                parse_json_response(response).await.map_err(outcome)
            })
            .await?;
        if record.id != id {
            return Err(VulnError::InvalidResponse(format!(
                "OSV returned a different vulnerability for requested id '{id}'"
            )));
        }
        Ok(record.into())
    }

    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        request: &str,
        body: &impl Serialize,
    ) -> Result<T> {
        self.retry(request, || async {
            let response = handle_response(self.client.post(url).json(body).send().await).await?;
            parse_json_response(response).await.map_err(outcome)
        })
        .await
    }

    async fn retry<T, F, Fut>(&self, request: &str, attempt: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, Outcome<VulnError>>>,
    {
        let mut retries = 0;
        rv_http::retry::run(&self.retry, &self.cooldown, attempt, |error, wait| {
            retries += 1;
            debug!(
                request,
                error = %safe_error_message(error),
                retry_in = ?wait,
                "OSV request failed, will retry"
            );
            if let Some(on_retry) = &self.on_retry {
                on_retry(format!(
                    "Retrying OSV {request} in {:.1} s (attempt {} of {}): {}",
                    wait.as_secs_f64(),
                    retries + 1,
                    self.retry.retries.saturating_add(1),
                    safe_error_message(error)
                ));
            }
        })
        .await
    }
}

fn outcome(error: VulnError) -> Outcome<VulnError> {
    let transient = match &error {
        VulnError::RateLimited { retry_after } => {
            let retry_after = *retry_after;
            return Outcome::Busy { error, retry_after };
        }
        VulnError::Http(source) => transport_is_retryable(source),
        VulnError::HttpStatus { status, .. } => status_is_transient(*status),
        _ => false,
    };
    if transient {
        Outcome::transient(error)
    } else {
        Outcome::permanent(error)
    }
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    package: PackageQuery<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

impl<'a> QueryRequest<'a> {
    fn new(purl: &'a str, page_token: Option<String>) -> Self {
        Self {
            package: PackageQuery { purl },
            page_token,
        }
    }
}

#[derive(Serialize)]
struct PackageQuery<'a> {
    purl: &'a str,
}

#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: Vec<QueryRequest<'a>>,
}

#[derive(Deserialize)]
struct Page {
    vulns: Option<Vec<OsvVulnerability>>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<Page>,
}

#[derive(Deserialize)]
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
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

impl From<OsvVulnerability> for Vulnerability {
    fn from(value: OsvVulnerability) -> Self {
        // Scores of different CVSS versions do not compare, so the newest
        // version wins, then the highest band and score; without any usable
        // score, the first entry.
        let version = |severity: &Severity| match severity.type_.to_ascii_uppercase().as_str() {
            "CVSS_V4" => 3,
            "CVSS_V3" => 2,
            "CVSS_V2" => 1,
            _ => 0,
        };
        let severity = value
            .severity
            .iter()
            .filter_map(|severity| {
                Some((
                    (
                        version(severity),
                        severity.severity_band(),
                        severity.score_value()?,
                    ),
                    severity,
                ))
            })
            .reduce(|best, next| if next.0 > best.0 { next } else { best })
            .map(|(_, severity)| severity)
            .or(value.severity.first())
            .cloned();
        let database_severity = value
            .database_specific
            .as_ref()
            .and_then(|specific| specific.get("severity")?.as_str())
            .map(str::to_string);
        Self {
            id: value.id,
            aliases: value.aliases,
            summary: value.summary.unwrap_or_default(),
            details: value.details,
            severity,
            database_severity,
            references: value.references,
            affected: value.affected,
        }
    }
}

/// The response to one attempt, or how it failed. A transient status keeps
/// the delay its `Retry-After` asks for.
async fn handle_response(
    response: reqwest::Result<reqwest::Response>,
) -> std::result::Result<reqwest::Response, Outcome<VulnError>> {
    let response = response.map_err(|error| outcome(error.into()))?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let retry_after = rv_http::headers::retry_after(response.headers());
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(Outcome::Busy {
            error: VulnError::RateLimited { retry_after },
            retry_after,
        });
    }
    // The status decides whether to retry, so a failed body read must not
    // turn a 4xx into a retryable timeout. The body is server text: only
    // its size reaches the error.
    let body_size = match read_response_bytes(response, MAX_ERROR_BODY_BYTES).await {
        Ok(body) => Some(body.len()),
        Err(VulnError::Http(_)) => None,
        Err(err) => return Err(Outcome::permanent(err)),
    };
    let error = VulnError::HttpStatus { status, body_size };
    if status_is_transient(status) {
        Err(Outcome::Busy { error, retry_after })
    } else {
        Err(Outcome::permanent(error))
    }
}

async fn parse_json_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let body = read_response_bytes(response, MAX_SUCCESS_BODY_BYTES).await?;
    serde_json::from_slice(&body).map_err(|err| json_error(&err, body.len()))
}

/// serde_json's message can quote the document, which is server text, so
/// the error names the kind of problem, where it is, and the size.
fn json_error(err: &serde_json::Error, size: usize) -> VulnError {
    let problem = match err.classify() {
        serde_json::error::Category::Syntax => "malformed JSON",
        serde_json::error::Category::Eof => "truncated JSON",
        serde_json::error::Category::Data => "JSON of an unexpected shape",
        serde_json::error::Category::Io => "unreadable JSON",
    };
    VulnError::InvalidResponse(format!(
        "OSV answered with {problem} at line {}, column {} ({size} bytes)",
        err.line(),
        err.column()
    ))
}

async fn read_response_bytes(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    match read_limited(response, limit as u64, |_| {}).await {
        Ok(body) => Ok(body.to_vec()),
        Err(BodyError::Transport(error)) => Err(VulnError::Http(error)),
        Err(BodyError::TooLarge { .. }) => Err(VulnError::InvalidResponse(format!(
            "OSV response exceeds the {limit}-byte limit"
        ))),
    }
}

/// Whether `id` looks like an OSV identifier (`GHSA-...`, `CVE-...`,
/// `RHSA-2024:1234`). Ids from a batch response become a request path and
/// reach error messages, so anything else is refused rather than escaped.
fn is_plausible_vulnerability_id(id: &str) -> bool {
    id.len() <= 128
        && id.starts_with(|c: char| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '+'))
}

fn safe_error_message(error: &VulnError) -> String {
    match error {
        VulnError::Http(source) if source.is_timeout() => "OSV request timed out".to_string(),
        VulnError::Http(source) if source.is_connect() => {
            // reqwest reports a failed handshake as a connect error; name the
            // TLS cause when retrying cannot fix it.
            match rv_http::tls_cause(source).filter(|tls| rv_http::tls_failure_is_permanent(tls)) {
                Some(tls) => format!(
                    "could not connect to the OSV service (TLS failed: {})",
                    rv_http::describe_tls_failure(tls)
                ),
                None => match rv_http::transient::transport_detail(source) {
                    Some(cause) => format!("could not connect to the OSV service: {cause}"),
                    None => "could not connect to the OSV service".to_string(),
                },
            }
        }
        VulnError::Http(source) => match rv_http::transient::transport_detail(source) {
            Some(cause) => format!("OSV HTTP request failed: {cause}"),
            None => "OSV HTTP request failed".to_string(),
        },
        _ => error
            .to_string()
            .chars()
            .filter(|character| !character.is_control())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use rv_test_support::http::{Response, StubServer};

    use super::{MAX_ERROR_BODY_BYTES, MAX_SUCCESS_BODY_BYTES, OsvClient, OsvSettings, VulnError};

    const PURL: &str = "pkg:maven/com.example/demo@1.2.3";
    const OTHER: &str = "pkg:maven/com.example/other@1.0";
    const ONE_VULN_PAGE: &str = r#"{"vulns": [{"id": "OSV-A", "summary": "a", "affected": []}]}"#;

    fn json(body: impl Into<Vec<u8>>) -> Response {
        Response::new(200, body).header("Content-Type", "application/json")
    }

    /// Answers with `respond(path, n)`, where `n` counts earlier requests to that path.
    fn osv(
        respond: impl Fn(&str, usize) -> Response + Send + Sync + 'static,
    ) -> (OsvClient, StubServer) {
        let counts = std::sync::Mutex::new(std::collections::HashMap::<String, usize>::new());
        let server = StubServer::start(move |request| {
            let n = {
                let mut counts = counts.lock().expect("request counts");
                let count = counts.entry(request.path.clone()).or_default();
                *count += 1;
                *count - 1
            };
            respond(&request.path, n)
        });
        (client(format!("http://{}/v1", server.addr())), server)
    }

    fn client(base_url: String) -> OsvClient {
        OsvClient::with_settings(base_url, OsvSettings::default()).expect("client")
    }

    /// A one-shot server that writes `head` and then `body` raw, so a
    /// response can lie about its length or stream an endless chunk.
    fn raw_server(head: String, body: Vec<u8>) -> (OsvClient, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            rv_test_support::http::read_request_head_blocking(&mut stream);
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            // Read until the client hangs up, so the close never resets the
            // connection under a response it is still reading.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
        });
        (client(format!("http://{addr}/v1")), handle)
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn ids(vulnerabilities: &[crate::Vulnerability]) -> Vec<&str> {
        vulnerabilities.iter().map(|v| v.id.as_str()).collect()
    }

    /// The newest CVSS version sets the severity, whatever an older one
    /// scores; without a usable score, `database_specific.severity` does.
    #[test]
    fn severity_prefers_the_newest_cvss_version_then_the_database_rating() {
        use crate::SeverityBand;
        let band = |record: serde_json::Value| {
            let osv: super::OsvVulnerability = serde_json::from_value(record).expect("record");
            let vulnerability = crate::Vulnerability::from(osv);
            let score = vulnerability.severity.as_ref().map(|s| s.score.clone());
            (vulnerability.severity_band(), score)
        };
        let v2 = serde_json::json!({ "type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C" });
        let v3 = serde_json::json!({ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N" });
        assert_eq!(
            band(serde_json::json!({ "id": "OSV-1", "severity": [v2, v3] })),
            (
                SeverityBand::Medium,
                v3["score"].as_str().map(str::to_string)
            )
        );
        assert_eq!(
            band(serde_json::json!({
                "id": "OSV-1",
                "severity": [v3],
                "database_specific": { "severity": "CRITICAL" },
            })),
            (
                SeverityBand::Medium,
                v3["score"].as_str().map(str::to_string)
            )
        );
        for (rating, expected) in [
            ("LOW", SeverityBand::Low),
            ("MODERATE", SeverityBand::Medium),
            ("High", SeverityBand::High),
            ("CRITICAL", SeverityBand::Critical),
            ("SEVERE", SeverityBand::Unknown),
        ] {
            assert_eq!(
                band(serde_json::json!({
                    "id": "OSV-1",
                    "severity": [{ "type": "Ubuntu", "score": "medium" }],
                    "database_specific": { "severity": rating },
                }))
                .0,
                expected,
                "{rating}"
            );
        }
        assert_eq!(
            band(serde_json::json!({
                "id": "OSV-1",
                "database_specific": { "severity": { "nested": true } },
            })),
            (SeverityBand::Unknown, None)
        );
    }

    #[test]
    fn settings_debug_leaves_out_proxy_credentials() {
        let proxy = reqwest::Proxy::all("http://proxy.example:3128")
            .unwrap()
            .basic_auth("proxy-user", "proxy-pass");
        let settings = OsvSettings {
            proxies: vec![proxy],
            ..OsvSettings::default()
        };
        let rendered = format!("{settings:?}");
        assert!(rendered.contains("proxies: 1"), "{rendered}");
        assert!(!rendered.contains("proxy-pass"), "{rendered}");
        assert!(!rendered.contains("proxy.example"), "{rendered}");
    }

    /// A rejected handshake fails the record once, without retries, and
    /// names the TLS cause the way repository errors do.
    #[tokio::test]
    async fn a_rejected_handshake_names_the_tls_cause() {
        let (address, server) =
            rv_test_support::tls::reject_one_handshake(rv_test_support::tls::BAD_CERTIFICATE);
        let client = client(format!("https://{address}/v1"));
        let result = client.fetch_vulnerability("GHSA-test").await;
        server.join().expect("server");
        let error = result.expect_err("the handshake fails");
        assert_eq!(
            super::safe_error_message(&error),
            "could not connect to the OSV service (TLS failed: received fatal alert: \
             BadCertificate)"
        );
    }

    /// 502, 503 and 504 are retried; other failures are the answer.
    #[test]
    fn only_transient_statuses_are_retried() {
        let (client, server) = osv(|path, n| match (path, n) {
            ("/v1/querybatch", _) => json(r#"{"results":[{"vulns":[{"id":"OSV-A"}]}]}"#),
            ("/v1/vulns/OSV-A", 0) => Response::new(503, "busy"),
            _ => json(r#"{"id":"OSV-A","summary":"a","affected":[]}"#),
        });
        let (results, failed) = block_on(client.query_batch(&[PURL.to_string()])).expect("batch");
        assert_eq!(server.answered(), 3);
        assert!(failed.is_empty());
        assert_eq!(ids(&results[0].vulnerabilities), ["OSV-A"]);

        for status in [400, 500] {
            let (client, server) = osv(move |_, _| Response::new(status, "bad"));
            let error = block_on(client.query(PURL)).expect_err("fails");
            assert_eq!(server.answered(), 1);
            assert!(matches!(error, VulnError::HttpStatus { status: s, .. } if s == status));
        }

        // A body that ends early still leaves the status as the answer.
        let head = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 100\r\n\r\n";
        let (client, handle) = raw_server(head.to_string(), b"{".to_vec());
        let error = block_on(client.query(PURL)).expect_err("401 fails");
        handle.join().expect("server thread");
        assert!(matches!(error, VulnError::HttpStatus { status, .. } if status == 401));
    }

    /// A batch answer that breaks off mid-body is asked for again.
    #[test]
    fn a_cut_off_batch_answer_is_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("address");
        let body = r#"{"results":[{"vulns":[]}]}"#;
        let head = |length: usize| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\
                 Content-Length: {length}\r\n\r\n"
            )
        };
        let answers = [head(100) + "{", head(body.len()) + body];
        let handle = std::thread::spawn(move || {
            for answer in answers {
                let (mut stream, _) = listener.accept().expect("accept");
                rv_test_support::http::read_request_head_blocking(&mut stream);
                let _ = stream.write_all(answer.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            }
        });
        let client = client(format!("http://{addr}/v1"));
        let (results, failed) = block_on(client.query_batch(&[PURL.to_string()])).expect("batch");
        handle.join().expect("server thread");
        assert!(failed.is_empty() && results[0].vulnerabilities.is_empty());
    }

    #[test]
    fn retry_after_past_the_budget_fails_without_waiting() {
        let (mut client, server) = osv(|_, _| Response::new(429, "").header("Retry-After", "30"));
        client.retry.budget = Duration::from_secs(5);
        let start = Instant::now();
        let error = block_on(client.query_batch(&[PURL.to_string()])).expect_err("rate limited");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(server.answered(), 1);
        assert!(matches!(
            error,
            VulnError::RateLimited { retry_after: Some(after) } if after == Duration::from_secs(30)
        ));
    }

    /// A record that cannot be fetched leaves the others in the result and
    /// names every purl the batch listed it for, whatever the cause.
    #[test]
    fn a_failed_record_keeps_the_fetched_ones() {
        let (mut client, _server) = osv(|path, _| match path {
            "/v1/querybatch" => json(
                r#"{"results":[{"vulns":[{"id":"OSV-A"},{"id":"OSV-B"},{"id":"OSV-C"},{"id":"OSV-D"}]},{"vulns":[{"id":"OSV-B"}]}]}"#,
            ),
            "/v1/vulns/OSV-A" => json(r#"{"id":"OSV-A","summary":"a","affected":[]}"#),
            "/v1/vulns/OSV-C" => Response::new(429, "").header("Retry-After", "30"),
            "/v1/vulns/OSV-D" => json(r#"{"id":"OSV-E"}"#),
            _ => Response::new(404, ""),
        });
        client.retry.budget = Duration::from_secs(5);
        let start = Instant::now();
        let (results, failed) =
            block_on(client.query_batch(&[PURL.to_string(), OTHER.to_string()])).expect("batch");
        assert!(start.elapsed() < Duration::from_secs(2));

        assert_eq!(ids(&results[0].vulnerabilities), ["OSV-A"]);
        assert!(results[1].vulnerabilities.is_empty());
        let listed: Vec<(&str, Vec<&str>)> = failed
            .iter()
            .map(|f| (f.id.as_str(), f.purls.iter().map(String::as_str).collect()))
            .collect();
        assert_eq!(
            listed,
            [
                ("OSV-B", vec![PURL, OTHER]),
                ("OSV-C", vec![PURL]),
                ("OSV-D", vec![PURL]),
            ]
        );
        assert!(matches!(*failed[0].error, VulnError::HttpStatus { status, .. } if status == 404));
        assert!(matches!(*failed[1].error, VulnError::RateLimited { .. }));
        assert!(
            matches!(&*failed[2].error, VulnError::InvalidResponse(m) if m.contains("OSV-D")),
            "{:?}",
            failed[2].error
        );
    }

    #[test]
    fn a_redirect_to_another_origin_is_not_followed() {
        let (_, target) = osv(|_, _| json(ONE_VULN_PAGE));
        let location = format!("http://{}/v1/query", target.addr());
        let (client, _source) =
            osv(move |_, _| Response::new(302, "").header("Location", location.as_str()));
        let error = block_on(client.query(PURL)).expect_err("the redirect is the answer");
        assert_eq!(target.answered(), 0);
        assert!(matches!(error, VulnError::HttpStatus { status, .. } if status == 302));
    }

    #[test]
    fn queries_follow_pagination_and_deduplicate() {
        let (client, server) = osv(|_, n| match n {
            0 => json(r#"{"vulns":[{"id":"OSV-A"}],"next_page_token":"tok-1"}"#),
            _ => json(r#"{"vulns":[{"id":"OSV-A"},{"id":"OSV-B"}]}"#),
        });
        let vulns = block_on(client.query(PURL)).expect("query succeeds");
        let bodies: Vec<_> = server.requests().into_iter().map(|r| r.raw).collect();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains(PURL));
        assert!(!bodies[0].contains("page_token"));
        assert!(bodies[1].contains(r#""page_token":"tok-1""#));
        assert_eq!(ids(&vulns), ["OSV-A", "OSV-B"]);

        let (client, server) = osv(|path, n| match (path, n) {
            ("/v1/querybatch", 0) => {
                json(r#"{"results": [{"vulns": [{"id": "OSV-A"}], "next_page_token": "t"}]}"#)
            }
            ("/v1/querybatch", _) => json(r#"{"results": [{"vulns": [{"id": "OSV-B"}]}]}"#),
            (path, _) => {
                let id = path.trim_start_matches("/v1/vulns/");
                json(format!(
                    r#"{{"id": "{id}", "summary": "", "affected": []}}"#
                ))
            }
        });
        let (results, failed) = block_on(client.query_batch(&[PURL.to_string()])).expect("batch");
        assert_eq!(server.answered(), 4);
        assert_eq!(ids(&results[0].vulnerabilities), ["OSV-A", "OSV-B"]);
        assert!(failed.is_empty());
    }

    #[test]
    fn batch_chunks_keep_each_answer_with_its_purl() {
        let server = StubServer::start(|request| {
            if request.path != "/v1/querybatch" {
                let id = request.path.trim_start_matches("/v1/vulns/");
                return json(format!(r#"{{"id": "{id}", "affected": []}}"#));
            }
            let body: serde_json::Value = serde_json::from_slice(&request.body).expect("body");
            let results: Vec<_> = (body["queries"].as_array().expect("queries").iter())
                .map(|query| {
                    let purl = query["package"]["purl"].as_str().expect("purl");
                    let n = purl
                        .trim_start_matches("pkg:maven/g/a")
                        .trim_end_matches("@1");
                    serde_json::json!({"vulns": [{"id": format!("OSV-{n}")}]})
                })
                .collect();
            json(serde_json::json!({ "results": results }).to_string())
        });
        let client = client(format!("http://{}/v1", server.addr()));
        let purls: Vec<_> = (0..250).map(|n| format!("pkg:maven/g/a{n}@1")).collect();
        let (results, failed) = block_on(client.query_batch(&purls)).expect("batch");
        assert!(failed.is_empty());
        for (n, result) in results.iter().enumerate() {
            assert_eq!(result.purl, purls[n]);
            assert_eq!(ids(&result.vulnerabilities), [format!("OSV-{n}")]);
        }
        let mut sizes: Vec<_> = (server.requests().into_iter())
            .filter(|request| request.path == "/v1/querybatch")
            .map(|request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                body["queries"].as_array().unwrap().len()
            })
            .collect();
        sizes.sort_unstable();
        assert_eq!(sizes, [50, 100, 100]);
    }

    #[test]
    fn a_repeated_page_token_fails_the_query() {
        let (client, _server) = osv(|_, _| json(r#"{"vulns":[],"next_page_token":"cycle"}"#));
        let error = block_on(client.query(PURL)).expect_err("cyclic pagination must fail");
        assert!(error.to_string().contains("repeated page token"));

        let (client, _server) =
            osv(|_, _| json(r#"{"results":[{"vulns":[],"next_page_token":"cycle"}]}"#));
        let error = block_on(client.query_batch(&[PURL.to_string()])).expect_err("cyclic");
        assert!(error.to_string().contains("repeated page token"));
    }

    #[test]
    fn oversized_bodies_are_refused() {
        let head = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            MAX_SUCCESS_BODY_BYTES + 1
        );
        let (client, handle) = raw_server(head, b"{}".to_vec());
        let error = block_on(client.query(PURL)).expect_err("oversized response must fail");
        handle.join().expect("server thread");
        assert!(error.to_string().contains("byte limit"), "{error}");

        let size = MAX_ERROR_BODY_BYTES + 1;
        let head = format!(
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n"
        );
        let mut body = vec![b'x'; size];
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        let (client, handle) = raw_server(head, body);
        let error = block_on(client.query(PURL)).expect_err("oversized response must fail");
        handle.join().expect("server thread");
        assert!(matches!(error, VulnError::InvalidResponse(_)));
        assert!(error.to_string().contains("byte limit"), "{error}");
    }

    /// Bodies are server text, so errors name the status, a fixed
    /// description and the size, never the body; serde_json quotes the
    /// values it rejects, so its messages are not passed on either.
    #[test]
    fn server_text_is_not_echoed() {
        let (client, _server) = osv(|_, _| Response::new(400, "bad\u{1b}[31m\r\nquery"));
        let error = block_on(client.query(PURL)).expect_err("bad response must fail");
        assert_eq!(
            error.to_string(),
            "unexpected OSV status 400 Bad Request: OSV refused the request \
             (15-byte response body not shown)"
        );

        for body in [
            r#"{"vulns":[{"id":"OSV-1","aliases":"\u001b[31mevil"}]}"#,
            r#"{"vulns":"evil-token"}"#,
            "evil{",
        ] {
            let (client, _server) = osv(move |_, _| json(body));
            let message = block_on(client.query(PURL)).expect_err("fails").to_string();
            assert!(message.starts_with("invalid response: "), "{message}");
            assert!(!message.contains("evil"), "{message}");
            assert!(
                message.contains(&format!("({} bytes)", body.len())),
                "{message}"
            );
        }
    }

    #[test]
    fn a_batch_id_that_is_not_an_osv_id_fails_the_query() {
        for id in [
            "../querybatch",
            "OSV-1?x=1",
            "OSV-1#frag",
            "OSV%2F1",
            "\\u001b[31mOSV",
            ".",
            "",
        ] {
            let body = format!(r#"{{"results":[{{"vulns":[{{"id":"{id}"}}]}}]}}"#);
            let (client, server) = osv(move |path, _| match path {
                "/v1/querybatch" => json(body.clone()),
                _ => Response::new(500, "unexpected record request"),
            });
            let error = block_on(client.query_batch(&[PURL.to_string()])).expect_err("invalid id");
            assert!(
                matches!(error, VulnError::InvalidResponse(_)),
                "{id}: {error}"
            );
            assert_eq!(server.answered(), 1, "{id}: no record request");
        }
        for id in [
            "GHSA-vp9c-fpxx-744v",
            "CVE-2021-44228",
            "RHSA-2024:1234",
            "MAL-2024_1.2",
        ] {
            assert!(super::is_plausible_vulnerability_id(id), "{id}");
        }
    }
}
