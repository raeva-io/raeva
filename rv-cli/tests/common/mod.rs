use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

pub fn rv_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rv"))
}

pub fn temp_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("temp project dir");
    let home = TempDir::new().expect("temp raeva home");
    (project, home)
}

pub fn rv_command(project_root: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(rv_bin());
    cmd.arg("-C").arg(project_root);
    cmd.env("RAEVA_HOME", home);
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd
}
