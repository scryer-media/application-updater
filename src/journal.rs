//! The durable, crash-safe upgrade journal and the file cleanup it drives.
//!
//! The journal is written before anything on disk moves, so a crash between the
//! write and the promotion still leaves the next boot a record of what was
//! attempted and which backups exist. Its schema is frozen: additive fields are
//! `#[serde(default)]` so a journal written by one version stays readable by
//! another, in both directions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Crash-safe handoff between applying an upgrade and validating the next boot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationUpgradeJournal {
    pub schema: String,
    pub run_id: String,
    pub expected_version: String,
    pub expected_tag: String,
    pub executable_path: PathBuf,
    pub backup_path: PathBuf,
    #[serde(default)]
    pub backup_paths: Vec<PathBuf>,
    pub phase: String,
    pub helper_error: Option<String>,
    #[serde(default)]
    pub written_at: Option<DateTime<Utc>>,
}

pub fn write_journal(path: &Path, journal: &ApplicationUpgradeJournal) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Repository("application upgrade journal path has no parent directory".to_string())
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        Error::Repository(format!(
            "failed to create application upgrade journal directory: {error}"
        ))
    })?;
    let bytes = serde_json::to_vec(journal).map_err(|error| {
        Error::Repository(format!(
            "failed to encode application upgrade journal: {error}"
        ))
    })?;
    let temporary = parent.join(format!(".journal-{}.tmp", journal.run_id));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|error| {
        Error::Repository(format!(
            "failed to create application upgrade journal: {error}"
        ))
    })?;
    file.write_all(&bytes).map_err(|error| {
        Error::Repository(format!(
            "failed to write application upgrade journal: {error}"
        ))
    })?;
    file.sync_all().map_err(|error| {
        Error::Repository(format!(
            "failed to flush application upgrade journal: {error}"
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|error| {
            Error::Repository(format!(
                "failed to protect application upgrade journal: {error}"
            ))
        })?;
    }
    activate_journal(&temporary, path).map_err(|error| {
        Error::Repository(format!(
            "failed to activate application upgrade journal: {error}"
        ))
    })
}

#[cfg(not(windows))]
fn activate_journal(temporary: &Path, path: &Path) -> std::io::Result<()> {
    fs::rename(temporary, path)
}

/// Atomically replace an existing journal on Windows.
///
/// `std::fs::rename` cannot replace an existing destination there. `MoveFileExW`
/// does, and `MOVEFILE_WRITE_THROUGH` keeps the helper's terminal state durable
/// before it relaunches the application.
#[cfg(windows)]
fn activate_journal(temporary: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let existing = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let replacement = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: Both paths are NUL-terminated UTF-16 buffers that outlive the call.
    if unsafe {
        MoveFileExW(
            existing.as_ptr(),
            replacement.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn load_journal(path: &Path) -> Result<Option<ApplicationUpgradeJournal>> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Repository(format!(
                "failed to read application upgrade journal: {error}"
            )));
        }
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|error| Error::Validation(format!("invalid application upgrade journal: {error}")))
}

/// Persist a terminal status observed by the temporary upgrade helper.
///
/// Journal mutation stays with the schema owner rather than duplicating the
/// atomic-write logic inside each application's helper executable.
pub fn application_upgrade_helper_update_journal(
    path: &Path,
    phase: &str,
    helper_error: Option<String>,
) -> Result<()> {
    let mut journal = load_journal(path)?.ok_or_else(|| {
        Error::NotFound(format!(
            "application upgrade journal '{}' was not found",
            path.display()
        ))
    })?;
    journal.phase = phase.to_string();
    journal.helper_error = helper_error;
    write_journal(path, &journal)
}

pub fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Repository(format!(
            "failed to remove application upgrade file '{}': {error}",
            path.display()
        ))),
    }
}

pub fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Repository(format!(
            "failed to remove application upgrade staging directory '{}': {error}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases;
    use crate::product::test_product::EXAMPLEAPP;

    #[test]
    fn journal_round_trip_is_schema_stable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("application-upgrade/journal.json");
        let journal = ApplicationUpgradeJournal {
            schema: EXAMPLEAPP.journal_schema.to_string(),
            run_id: "run-1".to_string(),
            expected_version: "0.18.22".to_string(),
            expected_tag: "v0.18.22".to_string(),
            executable_path: PathBuf::from("/opt/exampleapp/exampleapp"),
            backup_path: PathBuf::from("/opt/exampleapp/exampleapp.pre-upgrade-0.18.21"),
            backup_paths: vec![PathBuf::from(
                "/opt/exampleapp/exampleapp.pre-upgrade-0.18.21",
            )],
            phase: phases::RESTARTING.to_string(),
            helper_error: None,
            written_at: Some(Utc::now()),
        };
        write_journal(&path, &journal).expect("write journal");
        assert_eq!(load_journal(&path).expect("load journal"), Some(journal));
    }

    #[test]
    fn legacy_journal_without_additive_fields_still_parses() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("application-upgrade/journal.json");
        fs::create_dir_all(path.parent().expect("journal parent")).expect("create parent");
        fs::write(
            &path,
            r#"{
                "schema":"exampleapp.upgrade.journal.v1",
                "run_id":"run-1",
                "expected_version":"0.18.22",
                "expected_tag":"v0.18.22",
                "executable_path":"/opt/exampleapp/exampleapp",
                "backup_path":"/opt/exampleapp/exampleapp.pre-upgrade-0.18.21",
                "phase":"reboot_required",
                "helper_error":null
            }"#,
        )
        .expect("write legacy journal");
        let journal = load_journal(&path)
            .expect("load legacy journal")
            .expect("journal exists");
        assert!(journal.backup_paths.is_empty());
        assert_eq!(journal.written_at, None);
    }

    #[test]
    fn helper_journal_updates_replace_an_existing_journal_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("application-upgrade/journal.json");
        let journal = ApplicationUpgradeJournal {
            schema: EXAMPLEAPP.journal_schema.to_string(),
            run_id: "run-1".to_string(),
            expected_version: "0.18.22".to_string(),
            expected_tag: "v0.18.22".to_string(),
            executable_path: PathBuf::from("C:/ExampleApp/exampleapp.exe"),
            backup_path: PathBuf::from("C:/ExampleApp/exampleapp.exe.pre-upgrade-0.18.21"),
            backup_paths: vec![PathBuf::from(
                "C:/ExampleApp/exampleapp.exe.pre-upgrade-0.18.21",
            )],
            phase: phases::RESTARTING.to_string(),
            helper_error: None,
            written_at: Some(Utc::now()),
        };
        write_journal(&path, &journal).expect("write journal");

        application_upgrade_helper_update_journal(
            &path,
            phases::REBOOT_REQUIRED,
            Some("elevation was declined".to_string()),
        )
        .expect("update an existing journal in place");

        let updated = load_journal(&path)
            .expect("load updated journal")
            .expect("journal exists");
        assert_eq!(updated.phase, phases::REBOOT_REQUIRED);
        assert_eq!(
            updated.helper_error.as_deref(),
            Some("elevation was declined")
        );
        assert_eq!(updated.run_id, journal.run_id);
        assert_eq!(updated.written_at, journal.written_at);
    }
}
