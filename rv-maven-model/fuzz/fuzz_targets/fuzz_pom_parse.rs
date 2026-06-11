#![no_main]
use libfuzzer_sys::fuzz_target;
use rv_maven_model::Pom;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Pom::parse(s);
    }
});
