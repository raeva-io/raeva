use crate::{RepoError, Repository};

/// Auth refusals encountered during one ordered repository search, with
/// the unset `${env.NAME}` variables of the credential each refused, joined
/// by `,`.
#[derive(Default)]
pub struct AuthFallback(Vec<(Repository, u16, String)>);

impl AuthFallback {
    /// Remember a 401 or 403 from the effective, post-mirror repository.
    pub fn refused(&mut self, repo: &Repository, error: &RepoError) {
        if let Some(status @ (401 | 403)) = error.status_code() {
            let unset = match error {
                RepoError::Unauthorized {
                    sent: Some(sent), ..
                } => sent.unset_variables.join(","),
                _ => String::new(),
            };
            self.0.push((repo.clone(), status, unset));
        }
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
        for (refusing, status, unset) in &self.0 {
            let refusing_endpoint = endpoint(refusing);
            if refusing_endpoint == serving_endpoint {
                continue;
            }
            let refusing = repository_name(refusing);
            let serving = repository_name(repo);
            tracing::warn!(
                sec_code = "AUTH_FALLBACK",
                refusing_endpoint,
                serving_endpoint = serving_endpoint.as_str(),
                refusing,
                serving,
                status,
                unset_variables = (!unset.is_empty()).then_some(unset.as_str()),
                file = file.as_str(),
                coordinate,
                "a later repository served a file after an authentication refusal"
            );
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

fn repository_name(repo: &Repository) -> String {
    repo.id
        .clone()
        .unwrap_or_else(|| rv_config::redact_url(&repo.url))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut fallback = AuthFallback::default();
            fallback.refused(
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
            let mut fallback = AuthFallback::default();
            fallback.refused(
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
