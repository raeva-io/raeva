//! Response headers that change how a client proceeds.

use std::time::{Duration, SystemTime};

use reqwest::header::{HeaderMap, RETRY_AFTER};

/// The `Retry-After` delay (RFC 9110 section 10.2.3): delta-seconds or any of
/// the three HTTP-date forms. A date in the past is a zero delay; a missing or
/// unparsable header is `None`.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let text = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = text.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let target = httpdate::parse_http_date(text).ok()?;
    Some(
        target
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn delta_seconds_and_http_dates_parse() {
        assert_eq!(retry_after(&headers("120")), Some(Duration::from_secs(120)));
        assert_eq!(retry_after(&headers("soon")), None);
        assert_eq!(retry_after(&HeaderMap::new()), None);
        let future = SystemTime::now() + Duration::from_secs(3600);
        let delay = retry_after(&headers(&httpdate::fmt_http_date(future))).unwrap();
        assert!(delay.as_secs() > 3500, "got {delay:?}");
        let past = "Sunday, 06-Nov-94 08:49:37 GMT";
        assert_eq!(retry_after(&headers(past)), Some(Duration::ZERO));
    }
}
