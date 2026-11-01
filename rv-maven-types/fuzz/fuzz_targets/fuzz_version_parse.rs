#![no_main]
use libfuzzer_sys::fuzz_target;
use rv_maven_types::{Version, VersionReq};
use std::cmp::Ordering::Equal;
use std::hash::BuildHasher;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let vs: Vec<Version> = s
        .split('\n')
        .take(12)
        .filter_map(|p| Version::parse(p).ok())
        .collect();
    let h = std::hash::RandomState::new();
    for a in &vs {
        assert_eq!(a.cmp(a), Equal, "{a} != itself");
        let r = Version::parse(&a.to_string()).expect("display reparses");
        assert_eq!(r.to_string(), a.to_string());
        assert_eq!(a.cmp(&r), Equal);
        assert_eq!(h.hash_one(a), h.hash_one(&r));
        for b in &vs {
            assert_eq!(a.cmp(b), b.cmp(a).reverse(), "antisymmetry {a:?} {b:?}");
            assert_eq!(a == b, a.cmp(b) == Equal, "eq vs cmp {a:?} {b:?}");
            assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));
            if a == b {
                assert_eq!(h.hash_one(a), h.hash_one(b), "hash {a:?} {b:?}");
            }
            assert_eq!(r.cmp(b), a.cmp(b));
        }
        // A soft requirement matches the version it names.
        if !a.as_str().contains(['[', ']', '(', ')', ',']) {
            let req = VersionReq::parse(a.as_str()).expect("soft");
            assert!(req.matches(a));
        }
    }
    let mut sorted = vs.clone();
    Version::sort_by_key(&mut sorted, |v| v);
    assert_eq!(sorted.len(), vs.len());
    for w in sorted.windows(2) {
        assert!(w[0] <= w[1], "sorted out of order {:?} {:?}", w[0], w[1]);
    }
});
