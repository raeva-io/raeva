use crate::{RepoError, Repository};

/// Failures encountered during one ordered repository search that should
/// warn if another repository serves the file.
#[derive(Default)]
pub struct RepositoryFallback(Vec<(Repository, Failure)>);

enum Failure {
    Authentication { status: u16, unset: String },
    Unavailable(String),
}

impl RepositoryFallback {
    /// Remember an auth refusal, unreachable host or non-retried server
    /// error from the effective, post-mirror repository. Returns whether
    /// the failure will be reported when another repository serves it.
    pub fn failed(&mut self, repo: &Repository, error: &RepoError) -> bool {
        let failure = if let Some(status @ (401 | 403)) = error.status_code() {
            let unset = match error.cause() {
                RepoError::Unauthorized {
                    sent: Some(sent), ..
                } => sent.unset_variables.join(","),
                _ => String::new(),
            };
            Failure::Authentication { status, unset }
        } else if let RepoError::Http(http) = error.cause()
            && error.is_unreachable()
        {
            Failure::Unavailable(if http.is_dns() {
                "host name did not resolve".to_string()
            } else {
                rv_http::transient::transport_detail(http)
                    .unwrap_or_else(|| "repository unreachable".to_string())
            })
        } else if let Some(tls) = error.tls_cause() {
            Failure::Unavailable(format!("TLS handshake failed: {tls}"))
        } else if let Some(status @ 500..=599) = error.status_code()
            && !error.is_transient()
        {
            Failure::Unavailable(format!("HTTP {status}"))
        } else {
            return false;
        };
        self.0.push((repo.clone(), failure));
        true
    }

    /// Report a file served by the effective, post-mirror repository.
    pub fn served(&self, repo: &Repository, request: &crate::ArtifactRequest, file: String) {
        let coordinate = format!(
            "{}:{}:{}",
            request.group_id, request.artifact_id, request.version
        );
        self.served_for(repo, &coordinate, file);
    }

    /// [`Self::served`] for a file named by `coordinate` rather than one
    /// version's, such as a version listing.
    pub fn served_for(&self, repo: &Repository, coordinate: &str, file: String) {
        let serving_endpoint = endpoint(repo);
        for (skipped, failure) in &self.0 {
            // Compared unredacted: two mirrors may differ only in a path
            // secret that redaction hides.
            if same_endpoint(skipped, repo) {
                continue;
            }
            let skipped_endpoint = endpoint(skipped);
            let skipped = repository_name(skipped);
            let serving = repository_name(repo);
            match failure {
                Failure::Authentication { status, unset } => tracing::warn!(
                    sec_code = "AUTH_FALLBACK",
                    refusing_endpoint = skipped_endpoint.as_str(),
                    serving_endpoint = serving_endpoint.as_str(),
                    refusing = skipped.as_str(),
                    serving,
                    status,
                    unset_variables = (!unset.is_empty()).then_some(unset.as_str()),
                    file = file.as_str(),
                    coordinate,
                    "a later repository served a file after an authentication refusal"
                ),
                Failure::Unavailable(reason) => tracing::warn!(
                    sec_code = "REPOSITORY_FALLBACK",
                    skipped_endpoint,
                    serving_endpoint = serving_endpoint.as_str(),
                    skipped,
                    serving,
                    reason = reason.as_str(),
                    file = file.as_str(),
                    coordinate,
                    "a later repository served a file after a repository failed"
                ),
            }
        }
    }
}

/// The parsed base URL without credentials, so spellings of one endpoint
/// such as an uppercase host or the default port compare equal.
fn endpoint(repo: &Repository) -> String {
    repo.base_url().map_or_else(
        |_| rv_config::redact_url(&repo.url),
        |url| rv_config::redacted_url(&url).to_string(),
    )
}

fn same_endpoint(a: &Repository, b: &Repository) -> bool {
    let bare = |repo: &Repository| {
        repo.base_url().ok().map(|mut url| {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url
        })
    };
    match (bare(a), bare(b)) {
        (Some(a), Some(b)) => a == b,
        _ => endpoint(a) == endpoint(b),
    }
}

fn repository_name(repo: &Repository) -> String {
    repo.id
        .clone()
        .unwrap_or_else(|| rv_config::redact_url(&repo.url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_that_differ_in_a_masked_token_stay_apart() {
        for token in ["tokA-71", "tokB-72"] {
            let url = format!("https://m.example/{token}/m2/");
            rv_config::register_masked_url(&url, "https://m.example/***/m2/");
        }
        let a = Repository::new(
            Some("a".into()),
            "https://m.example/tokA-71/m2/",
            true,
            false,
        );
        let b = Repository::new(
            Some("b".into()),
            "https://m.example/tokB-72/m2/",
            true,
            false,
        );
        let a_again = Repository::new(None, "https://user@M.example:443/tokA-71/m2/", true, false);
        assert_eq!(endpoint(&a), endpoint(&b));
        assert!(!same_endpoint(&a, &b));
        assert!(same_endpoint(&a, &a_again));
    }

    #[test]
    fn only_auth_refusals_and_non_retried_server_statuses_are_remembered() {
        let repo = Repository::new(Some("corp".into()), "https://corp.example/", true, false);
        for status in 400..=599 {
            let mut fallback = RepositoryFallback::default();
            let remembered = fallback.failed(
                &repo,
                &RepoError::HttpStatus {
                    status: reqwest::StatusCode::from_u16(status).unwrap(),
                    url: repo.url.clone(),
                    retry_after: None,
                },
            );
            assert_eq!(
                remembered,
                matches!(status, 401 | 403 | 500..=501 | 505..=599),
                "HTTP {status}"
            );
        }
    }

    #[test]
    fn a_non_retried_server_failure_warns_when_another_repository_serves() {
        let skipped = Repository::new(Some("corp".into()), "https://corp.example/", true, false);
        let serving = Repository::new(
            Some("central".into()),
            "https://public.example/",
            true,
            false,
        );
        let log = rv_test_support::capture_warnings(|| {
            let mut fallback = RepositoryFallback::default();
            fallback.failed(
                &skipped,
                &RepoError::HttpStatus {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    url: skipped.url.clone(),
                    retry_after: None,
                },
            );
            fallback.served(
                &serving,
                &crate::ArtifactRequest::new("g", "a", "1"),
                "a.pom".into(),
            );
        });
        assert!(log.contains("REPOSITORY_FALLBACK"), "{log}");
        for expected in ["corp", "central", "g:a:1", "HTTP 500"] {
            assert!(log.contains(expected), "{log}");
        }
        assert!(!log.contains("AUTH_FALLBACK"), "{log}");
    }

    /// A repository whose certificate is not trusted, such as one behind a
    /// TLS-inspecting proxy whose root is not installed, is skipped like an
    /// unreachable one.
    #[tokio::test]
    async fn a_failed_tls_handshake_warns_when_another_repository_serves() {
        let (address, server) =
            rv_test_support::tls::reject_one_handshake(rv_test_support::tls::BAD_CERTIFICATE);
        let client = rv_http::client_builder().build().expect("client");
        let err = client
            .get(format!("https://{address}/"))
            .send()
            .await
            .expect_err("handshake must fail");
        server.join().expect("server");
        let skipped = Repository::new(
            Some("corp".into()),
            format!("https://{address}/"),
            true,
            false,
        );
        let serving = Repository::new(
            Some("central".into()),
            "https://public.example/",
            true,
            false,
        );
        let log = rv_test_support::capture_warnings(|| {
            let mut fallback = RepositoryFallback::default();
            assert!(fallback.failed(&skipped, &RepoError::Http(err)));
            fallback.served(
                &serving,
                &crate::ArtifactRequest::new("g", "a", "1"),
                "a.pom".into(),
            );
        });
        for expected in [
            "REPOSITORY_FALLBACK",
            "corp",
            "central",
            "TLS handshake failed",
        ] {
            assert!(log.contains(expected), "{log}");
        }
    }

    #[test]
    fn the_same_endpoint_is_not_a_fallback_even_under_another_id_or_policy() {
        let refusing = Repository::new(Some("corp".into()), "https://corp.example/", true, false);
        let serving = Repository::new(
            Some("alias".into()),
            "https://CORP.example:443/",
            false,
            true,
        );
        let log = rv_test_support::capture_warnings(|| {
            let mut fallback = RepositoryFallback::default();
            fallback.failed(
                &refusing,
                &RepoError::Unauthorized {
                    status: reqwest::StatusCode::UNAUTHORIZED,
                    url: refusing.url.clone(),
                    sent: None,
                },
            );
            fallback.served(
                &serving,
                &crate::ArtifactRequest::new("g", "a", "1"),
                "a.pom".into(),
            );
        });
        assert!(!log.contains("AUTH_FALLBACK"), "{log}");
    }

    #[test]
    fn unnamed_endpoints_use_the_existing_url_redactor() {
        let refusing = Repository::new(
            None,
            "https://user:secret@corp.example/?token=secret",
            true,
            false,
        );
        let serving = Repository::new(None, "https://public.example/", true, false);
        let log = rv_test_support::capture_warnings(|| {
            let mut fallback = RepositoryFallback::default();
            fallback.failed(
                &refusing,
                &RepoError::Unauthorized {
                    status: reqwest::StatusCode::FORBIDDEN,
                    url: refusing.url.clone(),
                    sent: None,
                },
            );
            fallback.served(
                &serving,
                &crate::ArtifactRequest::new("g", "a", "1"),
                "a.pom".into(),
            );
        });
        assert!(log.contains("AUTH_FALLBACK"), "{log}");
        assert!(log.contains(&rv_config::redact_url(&refusing.url)), "{log}");
        assert!(!log.contains("secret"), "{log}");
    }
}
