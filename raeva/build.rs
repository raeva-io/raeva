//! Embeds the Windows application manifest, which opts `raeva.exe` into long
//! paths, when building with the MSVC toolchain.

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=raeva.exe.manifest");
    // tempfile's Windows keep/persist call Win32 with plain paths, so paths
    // past MAX_PATH work only in a process whose manifest opts into long paths.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let manifest = Path::new(&manifest_dir).join("raeva.exe.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
