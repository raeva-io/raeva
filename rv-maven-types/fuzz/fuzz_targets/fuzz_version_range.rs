#![no_main]
use libfuzzer_sys::fuzz_target;
use rv_maven_types::{Version, VersionRange, VersionReq};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = s.split('\n');
    let req_text = parts.next().unwrap_or_default();
    let vs: Vec<Version> = parts
        .take(8)
        .filter_map(|p| Version::parse(p).ok())
        .collect();
    if let Ok(range) = VersionRange::parse(req_text) {
        let text = range.to_string();
        let again =
            VersionRange::parse(&text).unwrap_or_else(|e| panic!("{text:?} does not reparse: {e}"));
        assert_eq!(again, range);
        assert_eq!(again.to_string(), text);
        for v in &vs {
            assert_eq!(range.matches(v), again.matches(v));
        }
    }
    let Ok(req) = VersionReq::parse(req_text) else {
        return;
    };
    let text = req.to_string();
    let again = VersionReq::parse(&text)
        .unwrap_or_else(|e| panic!("{req:?} as {text:?} does not reparse: {e}"));
    assert_eq!(again, req, "{text:?}");
    assert_eq!(again.to_string(), text);
    if let Some(exact) = req.exact_version() {
        assert!(
            req.matches(exact),
            "{req:?} does not match its exact version"
        );
    }
    for v in &vs {
        assert_eq!(req.matches(v), again.matches(v));
    }
});
