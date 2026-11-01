//! Downloading the locked artifacts and mapping download failures to the
//! command's error and exit code.

use rv_lock::Lockfile;
use rv_repo::RestoreContext;
use rv_store::Store;

use crate::error::report::LISTED_FAILURES;
use crate::error::{CliError, Result};
use crate::output::command_line;

pub(super) async fn ensure_artifacts(
    lock: &Lockfile,
    store: &Store,
    contexts: &[RestoreContext<'_>],
) -> Result<()> {
    let results = rv_repo::ensure_artifacts(store, lock, contexts).await?;

    // A mismatch against a lock pin means raeva.lock no longer describes what
    // the repository serves, which a new `raeva sync` fixes. Every other
    // failure, a sidecar mismatch included, keeps its own class through
    // `CliError::Download`, so a transient error still exits as a network
    // failure.
    let mut failures = Vec::new();
    let mut checksum_failure_lines = Vec::new();
    let mut first_repo_error: Option<rv_repo::RepoError> = None;
    for rv_repo::DownloadResult {
        package, result, ..
    } in results
    {
        let Err(err) = result else {
            continue;
        };
        if let rv_repo::RepoError::ChecksumMismatch {
            subject,
            expected,
            actual,
            check: rv_repo::IntegritySource::LockPin,
            ..
        } = &err
        {
            // Render the coordinate and the two hashes verbatim. The
            // coordinate the mismatch is reported under names which pin
            // failed, and it is not always the package's own artifact: a
            // package's companion POM carries a `...:pom` coordinate and its
            // own pin.
            checksum_failure_lines.push(format!(
                "{subject}: expected {} {}, got {}",
                expected.algorithm(),
                expected.hex(),
                actual.hex()
            ));
        } else {
            failures.push(format!("{package}: {err}"));
            first_repo_error.get_or_insert(err);
        }
    }

    if !checksum_failure_lines.is_empty() {
        return Err(replaced_files(format_checksum_failure_details(
            &checksum_failure_lines,
            &failures,
        )));
    }

    if let Some(first) = first_repo_error {
        return Err(CliError::Download { failures, first });
    }

    Ok(())
}

/// Refuse a resolution that pins a release file of `lock` to other bytes.
/// Only `sync --update` accepts them, as it does for a download.
pub(super) fn check_repinned(lock: &Lockfile, fresh: &Lockfile) -> Result<()> {
    let lines: Vec<_> = (lock.repinned_releases(fresh).into_iter())
        .map(|(path, locked, served)| format!("{path}: expected sha256 {locked}, got {served}"))
        .collect();
    if lines.is_empty() {
        return Ok(());
    }
    Err(replaced_files(format!(
        "{} resolved file(s) do not match their checksums in raeva.lock:\n{}",
        lines.len(),
        listed(&lines, LISTED_FAILURES)
    )))
}

fn replaced_files(details: String) -> CliError {
    CliError::lockfile_mismatch_with(
        details,
        format!(
            "If the repository replaced these files on purpose, run '{}' to lock the new bytes",
            command_line("sync --update")
        ),
    )
}

/// How many non-checksum failures are listed verbatim alongside a checksum
/// mismatch before the rest collapse into a "... and N more" footer.
const OTHER_FAILURES_DISPLAY_CAP: usize = 3;

/// The first `cap` of `lines`, one per line, then "... and N more".
fn listed(lines: &[String], cap: usize) -> String {
    let mut out = (lines.iter().take(cap))
        .map(|line| crate::output::inline_text(line))
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > cap {
        out.push_str(&format!("\n... and {} more", lines.len() - cap));
    }
    out
}

/// Render the checksum-mismatch failure message for a download batch. The
/// checksum class drives the exit code, but other failures from the same
/// batch are appended so they are not silently discarded.
fn format_checksum_failure_details(checksum_lines: &[String], other_failures: &[String]) -> String {
    let mut details = format!(
        "{} downloaded file(s) do not match their checksums in raeva.lock:\n{}",
        checksum_lines.len(),
        listed(checksum_lines, LISTED_FAILURES)
    );
    if !other_failures.is_empty() {
        details.push_str(&format!(
            "\nand {} other download failure(s):\n{}",
            other_failures.len(),
            listed(other_failures, OTHER_FAILURES_DISPLAY_CAP)
        ));
    }
    details
}

#[cfg(test)]
mod tests {
    use super::format_checksum_failure_details;

    #[test]
    fn a_batch_of_replaced_files_lists_ten() {
        let lines: Vec<String> = (0..25).map(|n| format!("g:a:{n}:jar")).collect();
        let others: Vec<String> = (0..5).map(|n| format!("g:b:{n}")).collect();
        let details = format_checksum_failure_details(&lines, &others);
        assert!(details.starts_with("25 downloaded file(s)"), "{details}");
        assert!(
            details.contains("g:a:9:jar\n... and 15 more\n"),
            "{details}"
        );
        assert!(!details.contains("g:a:10:jar"), "{details}");
        assert!(details.ends_with("g:b:2\n... and 2 more"), "{details}");
    }
}
