//! Skip-list completeness for `test-fixtures/` directories that no other
//! module inventories. A new top-level directory, a stray file, or a README
//! table that omits a directory must fail here.

use rv_test_support::fixtures;

#[test]
fn every_test_fixture_directory_is_accounted_for() {
    let root = fixtures::root();
    let readme = fixtures::workspace_file("test-fixtures/README.md");
    let copied = fixtures::markdown_first_column(&readme, "## Copied POMs")
        .into_iter()
        .map(|path| {
            path.split_once('/')
                .unwrap_or_else(|| panic!("Copied POMs table path {path}"))
                .0
                .to_string()
        });
    let synthetic = fixtures::markdown_first_column(&readme, "## Synthetic fixtures")
        .into_iter()
        .map(|name| name.trim_end_matches('/').to_string());
    let mut expected: Vec<String> = copied.chain(synthetic).collect();
    expected.sort();
    expected.dedup();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    fixtures::assert_children(&root, &expected, &["README.md"]);
}

/// Files under `error-golden/` that `errors_render_as_the_golden_file_shows`
/// opens. A second file must fail here until that test names it.
#[test]
fn every_error_golden_file_is_used() {
    let mut files: Vec<String> = fixtures::quoted_after(
        include_str!("../../src/error/diagnose.rs"),
        concat!("path", "("),
    )
    .into_iter()
    .filter_map(|path| path.strip_prefix("error-golden/").map(str::to_string))
    .collect();
    files.sort();
    files.dedup();
    assert!(
        !files.is_empty(),
        "diagnose.rs must name an error-golden file"
    );
    let files: Vec<&str> = files.iter().map(String::as_str).collect();
    fixtures::assert_children(&fixtures::path("error-golden"), &[], &files);
}

/// `reproduce.py` is the only file under `nearest-backtracking/`. A new file
/// must fail here until `rv-resolver` solver tests cover it.
#[test]
fn every_nearest_backtracking_file_is_used() {
    fixtures::assert_children(
        &fixtures::path("nearest-backtracking"),
        &[],
        &["reproduce.py"],
    );
}
