//! In-place upgrade of a macOS `.app` bundle.
//!
//! A bundle cannot be upgraded the way a portable install is. Its signature
//! seals every file in it, so replacing the executables inside one leaves an
//! app macOS refuses to launch. The whole bundle is replaced instead: a fully
//! signed replacement is extracted beside the installed one, verified with
//! `codesign` before anything moves, and swapped in by two renames.
//!
//! Every path here is derived from the running executable, never from the
//! manifest, and the staging directory is deliberately a sibling of the bundle
//! so both renames stay within one filesystem and are therefore atomic.
//!
//! Nothing in this module is host-specific: the signature check and the rename
//! primitive are injected, which is also what lets the failure paths be driven
//! from tests against a tree of temporary directories.

use std::fs;
use std::path::{Path, PathBuf};

use crate::installation::{InstallationKind, macos_app_bundle_path};
use crate::{Error, ProductDescriptor, Result};

/// The suffix, after the bundle name, of the retained previous bundle.
pub const PRE_UPGRADE_SUFFIX: &str = ".pre-upgrade-";

/// Host-supplied staged-bundle signature check.
///
/// Injected so the promotion tests never need a signing identity, and so a host
/// that signs differently can say so.
pub type BundleSignatureCheck = fn(&Path) -> Result<()>;

/// Every location a bundle promotion touches, resolved before the durable
/// journal is written so a crash mid-promotion leaves a record of all of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosBundleUpgradePaths {
    /// The installed bundle, e.g. `/Applications/ExampleApp.app`.
    pub bundle_path: PathBuf,
    /// Where the installed bundle is moved to, beside itself.
    pub backup_path: PathBuf,
    /// The sibling staging directory the artifact is downloaded into and
    /// extracted under. A sibling, so the promotion renames never cross a
    /// filesystem boundary.
    pub staging_dir: PathBuf,
    /// The replacement bundle inside the staging directory.
    pub staged_bundle_path: PathBuf,
}

/// Failure state of a bundle promotion after its journal was written.
pub enum BundlePromotionFailure {
    /// The installed bundle is back where it belongs.
    Restored(Error),
    /// The installed bundle could not be put back; the journal and the backup
    /// must be retained for the next boot to recover from.
    RecoveryRequired(Error),
}

impl From<Error> for BundlePromotionFailure {
    fn from(error: Error) -> Self {
        Self::Restored(error)
    }
}

impl BundlePromotionFailure {
    /// The error to report, and whether the installed bundle was restored.
    pub fn into_parts(self) -> (Error, bool) {
        match self {
            Self::Restored(error) => (error, true),
            Self::RecoveryRequired(error) => (error, false),
        }
    }
}

/// Resolve every location a bundle promotion will use.
///
/// Performs every check that must precede the durable journal: the
/// installation must be a macOS bundle, the running executable must resolve
/// into a bundle whose name is this product's, that bundle must have a parent
/// directory, and no earlier backup may be overwritten.
pub fn macos_bundle_upgrade_paths(
    product: &ProductDescriptor,
    installation_kind: InstallationKind,
    executable_path: Option<&Path>,
    current_version: &str,
    expected_version: &str,
) -> Result<MacosBundleUpgradePaths> {
    if installation_kind != InstallationKind::MacosAppBundle {
        return Err(Error::Validation(
            "bundle replacement is only available for macOS application-bundle installations"
                .to_string(),
        ));
    }
    let executable_path = executable_path
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| {
            Error::Repository("failed to resolve the running executable path".to_string())
        })?;
    let bundle_path = macos_app_bundle_path(&executable_path)
        .ok_or_else(|| {
            Error::Validation(format!(
                "running executable '{}' is not inside a macOS application bundle",
                executable_path.display()
            ))
        })?
        .to_path_buf();
    if bundle_path.file_name().and_then(|name| name.to_str()) != Some(product.macos_bundle_name) {
        return Err(Error::Validation(format!(
            "running application bundle '{}' is not '{}'",
            bundle_path.display(),
            product.macos_bundle_name
        )));
    }
    let parent = bundle_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::Validation("running application bundle has no parent directory".to_string())
        })?
        .to_path_buf();

    let backup_path = parent.join(format!(
        "{}{PRE_UPGRADE_SUFFIX}{current_version}",
        product.macos_bundle_name
    ));
    if backup_path.exists() {
        return Err(Error::Validation(format!(
            "refusing to overwrite existing application backup '{}'",
            backup_path.display()
        )));
    }
    let staging_dir = parent.join(format!(
        "{}{expected_version}",
        product.staged_replacement_prefix
    ));
    let staged_bundle_path = staging_dir
        .join("extracted")
        .join(product.macos_bundle_name);

    Ok(MacosBundleUpgradePaths {
        bundle_path,
        backup_path,
        staging_dir,
        staged_bundle_path,
    })
}

/// Verify a staged bundle with the system `codesign`.
///
/// `--deep --strict` is what actually proves the archive round-tripped: it
/// re-reads every sealed resource and every nested Mach-O, so a lost executable
/// bit, a truncated `_CodeSignature`, or a mangled `Info.plist` all fail here —
/// before anything on disk has moved.
pub fn verify_bundle_signature(bundle_path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/bin/codesign")
            .arg("--verify")
            .arg("--deep")
            .arg("--strict")
            .arg(bundle_path)
            .output()
            .map_err(|error| {
                Error::Repository(format!(
                    "failed to run codesign on the staged bundle: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(Error::Validation(format!(
                "staged application bundle failed signature verification: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bundle_path;
        Err(Error::Validation(
            "application bundle verification is only available on macOS".to_string(),
        ))
    }
}

/// Swap the staged bundle over the installed one, retaining the previous
/// bundle beside it.
///
/// The signature of the staged bundle is checked first: a bundle that would not
/// launch must never reach the install path, not even for the moment between
/// the two renames. On a failed swap the previous bundle is renamed back.
pub fn apply_macos_bundle_upgrade<V, R>(
    paths: &MacosBundleUpgradePaths,
    verify_signature: V,
    rename: R,
) -> std::result::Result<(), BundlePromotionFailure>
where
    V: Fn(&Path) -> Result<()>,
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    if !paths.staged_bundle_path.is_dir() {
        return Err(Error::Validation(format!(
            "the upgrade archive did not contain '{}'",
            paths
                .staged_bundle_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ))
        .into());
    }
    verify_signature(&paths.staged_bundle_path)?;

    rename(&paths.bundle_path, &paths.backup_path).map_err(|error| {
        BundlePromotionFailure::Restored(Error::Repository(format!(
            "failed to retain current application bundle backup: {error}"
        )))
    })?;
    if let Err(error) = rename(&paths.staged_bundle_path, &paths.bundle_path) {
        return match rename(&paths.backup_path, &paths.bundle_path) {
            Ok(()) => Err(BundlePromotionFailure::Restored(Error::Repository(
                format!(
                    "failed to replace the application bundle: {error}; the previous bundle was restored"
                ),
            ))),
            Err(rollback_error) => Err(BundlePromotionFailure::RecoveryRequired(
                Error::Repository(format!(
                    "failed to replace the application bundle: {error}; failed to restore the previous bundle from '{}': {rollback_error}",
                    paths.backup_path.display()
                )),
            )),
        };
    }
    Ok(())
}

/// Undo a completed bundle promotion after a later step failed.
///
/// Mirrors the portable rollback: the journal is removed only once the previous
/// bundle is back, so an interrupted rollback keeps the paths recovery needs.
pub fn roll_back_macos_bundle_promotion<R>(
    paths: &MacosBundleUpgradePaths,
    journal_path: &Path,
    rename: R,
    error: Error,
) -> Error
where
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    // The replaced bundle has to go first, or the backup has nowhere to land.
    let discarded = paths.staging_dir.join("rolled-back");
    let _ = rename(&paths.bundle_path, &discarded);
    let outcome = match rename(&paths.backup_path, &paths.bundle_path) {
        Ok(()) => {
            let mut outcome = "the previous application bundle was restored".to_string();
            if let Err(cleanup_error) = crate::journal::remove_file_if_exists(journal_path) {
                outcome.push_str(&format!(
                    "; the application upgrade journal could not be removed: {cleanup_error}"
                ));
            }
            outcome
        }
        Err(rollback_error) => format!(
            "the previous application bundle could not be restored from '{}': {rollback_error}; the recovery journal was retained",
            paths.backup_path.display()
        ),
    };
    Error::Repository(format!(
        "application upgrade failed after the application bundle was replaced: {error}; {outcome}"
    ))
}

/// Remove a directory this upgrade created, refusing anything else.
///
/// Recursive deletion next to a user's `/Applications` is only ever safe when
/// the name says the upgrade owns it, so the same rule the portable cleanup
/// follows is enforced here literally: the final path component must be this
/// product's staged-replacement prefix or its own bundle name followed by
/// `.pre-upgrade-`. Symlinks are never followed, and a missing path is not an
/// error.
pub fn remove_upgrade_owned_directory(product: &ProductDescriptor, path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let pre_upgrade_prefix = format!("{}{PRE_UPGRADE_SUFFIX}", product.macos_bundle_name);
    if !(name.starts_with(product.staged_replacement_prefix)
        || name.starts_with(&pre_upgrade_prefix))
    {
        return Err(Error::Validation(format!(
            "refusing to remove '{}': not an application upgrade directory",
            path.display()
        )));
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::Repository(format!(
                "failed to inspect application upgrade directory '{}': {error}",
                path.display()
            )));
        }
    };
    if !metadata.is_dir() {
        // A symlink or a stray file wearing the name is removed as a file, so
        // deletion never traverses something the upgrade did not create.
        return crate::journal::remove_file_if_exists(path);
    }
    fs::remove_dir_all(path).map_err(|error| {
        Error::Repository(format!(
            "failed to remove application upgrade directory '{}': {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product::test_product::EXAMPLEAPP;

    fn install(root: &Path) -> PathBuf {
        let bundle = root.join("Applications").join(EXAMPLEAPP.macos_bundle_name);
        fs::create_dir_all(bundle.join("Contents/MacOS")).expect("create bundle");
        fs::write(bundle.join("Contents/MacOS/exampleapp"), b"old server")
            .expect("write bundle server");
        bundle
    }

    fn paths_for(root: &Path) -> MacosBundleUpgradePaths {
        let bundle = install(root);
        macos_bundle_upgrade_paths(
            &EXAMPLEAPP,
            InstallationKind::MacosAppBundle,
            Some(&bundle.join("Contents/MacOS/exampleapp")),
            "1.2.2",
            "1.2.3",
        )
        .expect("resolve bundle paths")
    }

    fn stage(paths: &MacosBundleUpgradePaths, marker: &[u8]) {
        fs::create_dir_all(paths.staged_bundle_path.join("Contents/MacOS"))
            .expect("create staged bundle");
        fs::write(
            paths.staged_bundle_path.join("Contents/MacOS/exampleapp"),
            marker,
        )
        .expect("write staged server");
    }

    fn accept(_bundle: &Path) -> Result<()> {
        Ok(())
    }

    #[test]
    fn paths_are_siblings_of_the_installed_bundle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        let applications = temp.path().join("Applications");
        assert_eq!(
            paths.bundle_path,
            applications.join(EXAMPLEAPP.macos_bundle_name)
        );
        assert_eq!(
            paths.backup_path,
            applications.join(format!(
                "{}.pre-upgrade-1.2.2",
                EXAMPLEAPP.macos_bundle_name
            ))
        );
        assert_eq!(
            paths.staging_dir,
            applications.join(format!("{}1.2.3", EXAMPLEAPP.staged_replacement_prefix))
        );
        assert_eq!(
            paths.staged_bundle_path,
            paths
                .staging_dir
                .join("extracted")
                .join(EXAMPLEAPP.macos_bundle_name)
        );
    }

    #[test]
    fn refuses_a_layout_that_is_not_this_products_bundle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = install(temp.path());
        let error = macos_bundle_upgrade_paths(
            &EXAMPLEAPP,
            InstallationKind::Portable,
            Some(&bundle.join("Contents/MacOS/exampleapp")),
            "1.2.2",
            "1.2.3",
        )
        .expect_err("portable installations take the portable path");
        assert!(error.to_string().contains("only available for macOS"));

        let error = macos_bundle_upgrade_paths(
            &EXAMPLEAPP,
            InstallationKind::MacosAppBundle,
            Some(Path::new("/opt/exampleapp/exampleapp")),
            "1.2.2",
            "1.2.3",
        )
        .expect_err("a loose executable is not a bundle");
        assert!(
            error
                .to_string()
                .contains("not inside a macOS application bundle")
        );

        let other = temp
            .path()
            .join("Applications/Other.app/Contents/MacOS/exampleapp");
        fs::create_dir_all(other.parent().expect("parent")).expect("create other bundle");
        let error = macos_bundle_upgrade_paths(
            &EXAMPLEAPP,
            InstallationKind::MacosAppBundle,
            Some(&other),
            "1.2.2",
            "1.2.3",
        )
        .expect_err("a foreign bundle is refused");
        assert!(error.to_string().contains("is not 'ExampleApp.app'"));
    }

    #[test]
    fn refuses_to_overwrite_an_existing_backup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = install(temp.path());
        fs::create_dir_all(temp.path().join(format!(
            "Applications/{}.pre-upgrade-1.2.2",
            EXAMPLEAPP.macos_bundle_name
        )))
        .expect("create existing backup");
        let error = macos_bundle_upgrade_paths(
            &EXAMPLEAPP,
            InstallationKind::MacosAppBundle,
            Some(&bundle.join("Contents/MacOS/exampleapp")),
            "1.2.2",
            "1.2.3",
        )
        .expect_err("an existing backup stops the upgrade");
        assert!(error.to_string().contains("refusing to overwrite"));
    }

    #[test]
    fn promotion_swaps_the_bundle_and_retains_the_previous_one() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        stage(&paths, b"new server");

        apply_macos_bundle_upgrade(&paths, accept, |from, to| fs::rename(from, to))
            .map_err(|failure| failure.into_parts().0)
            .expect("promotion succeeds");

        assert_eq!(
            fs::read(paths.bundle_path.join("Contents/MacOS/exampleapp")).expect("read new server"),
            b"new server"
        );
        assert_eq!(
            fs::read(paths.backup_path.join("Contents/MacOS/exampleapp")).expect("read backup"),
            b"old server"
        );
        assert!(!paths.staged_bundle_path.exists());
    }

    #[test]
    fn an_unverifiable_staged_bundle_never_reaches_the_install_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        stage(&paths, b"new server");

        let failure = apply_macos_bundle_upgrade(
            &paths,
            |_| Err(Error::Validation("injected codesign failure".to_string())),
            |from, to| fs::rename(from, to),
        )
        .expect_err("verification failure stops the promotion");
        let (error, restored) = failure.into_parts();
        assert!(error.to_string().contains("injected codesign failure"));
        assert!(restored);
        assert_eq!(
            fs::read(paths.bundle_path.join("Contents/MacOS/exampleapp")).expect("read server"),
            b"old server"
        );
        assert!(!paths.backup_path.exists());
    }

    #[test]
    fn a_missing_staged_bundle_stops_the_promotion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        let failure = apply_macos_bundle_upgrade(&paths, accept, |from, to| fs::rename(from, to))
            .expect_err("an empty staging directory stops the promotion");
        assert!(
            failure
                .into_parts()
                .0
                .to_string()
                .contains("did not contain 'ExampleApp.app'")
        );
    }

    #[test]
    fn a_failed_swap_puts_the_previous_bundle_back() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        stage(&paths, b"new server");

        let staged = paths.staged_bundle_path.clone();
        let failure = apply_macos_bundle_upgrade(&paths, accept, |from, to| {
            if from == staged {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected swap failure",
                ));
            }
            fs::rename(from, to)
        })
        .expect_err("the swap fails");
        let (error, restored) = failure.into_parts();
        assert!(
            error
                .to_string()
                .contains("the previous bundle was restored")
        );
        assert!(restored);
        assert_eq!(
            fs::read(paths.bundle_path.join("Contents/MacOS/exampleapp")).expect("read server"),
            b"old server"
        );
    }

    #[test]
    fn a_swap_that_cannot_be_rolled_back_keeps_the_backup_for_recovery() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        stage(&paths, b"new server");

        let staged = paths.staged_bundle_path.clone();
        let backup = paths.backup_path.clone();
        let failure = apply_macos_bundle_upgrade(&paths, accept, |from, to| {
            if from == staged || from == backup {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected swap and rollback failure",
                ));
            }
            fs::rename(from, to)
        })
        .expect_err("the swap fails");
        let (error, restored) = failure.into_parts();
        assert!(!restored);
        assert!(
            error
                .to_string()
                .contains("failed to restore the previous bundle")
        );
        assert!(paths.backup_path.is_dir());
    }

    #[test]
    fn rolling_back_a_completed_promotion_restores_the_previous_bundle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = paths_for(temp.path());
        stage(&paths, b"new server");
        apply_macos_bundle_upgrade(&paths, accept, |from, to| fs::rename(from, to))
            .map_err(|failure| failure.into_parts().0)
            .expect("promotion succeeds");
        let journal_path = temp.path().join("journal.json");
        fs::write(&journal_path, b"{}").expect("write journal");

        let error = roll_back_macos_bundle_promotion(
            &paths,
            &journal_path,
            |from, to| fs::rename(from, to),
            Error::Repository("later step failed".to_string()),
        );
        assert!(
            error
                .to_string()
                .contains("the previous application bundle was restored")
        );
        assert_eq!(
            fs::read(paths.bundle_path.join("Contents/MacOS/exampleapp")).expect("read server"),
            b"old server"
        );
        assert!(!journal_path.exists());
    }

    #[test]
    fn only_upgrade_owned_directories_are_removed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let owned = [
            format!("{}1.2.3", EXAMPLEAPP.staged_replacement_prefix),
            format!("{}.pre-upgrade-1.2.2", EXAMPLEAPP.macos_bundle_name),
        ];
        for name in &owned {
            let path = temp.path().join(name);
            fs::create_dir_all(path.join("Contents")).expect("create directory");
            remove_upgrade_owned_directory(&EXAMPLEAPP, &path).expect("remove upgrade directory");
            assert!(!path.exists(), "{name} must be removed");
        }

        for name in [
            EXAMPLEAPP.macos_bundle_name,
            "Applications",
            "pre-upgrade-1.2.2",
            // One character short of the staged prefix.
            ".exampleapp-upgrade-new",
            // The right suffix on the wrong bundle name.
            "Other.app.pre-upgrade-1.2.2",
        ] {
            let path = temp.path().join(name);
            fs::create_dir_all(&path).expect("create directory");
            let error = remove_upgrade_owned_directory(&EXAMPLEAPP, &path)
                .expect_err("a directory the upgrade does not own is refused");
            assert!(
                error
                    .to_string()
                    .contains("not an application upgrade directory")
            );
            assert!(path.is_dir(), "{name} must survive");
        }

        // A path that is not there at all is not an error.
        remove_upgrade_owned_directory(
            &EXAMPLEAPP,
            &temp
                .path()
                .join(format!("{}9.9.9", EXAMPLEAPP.staged_replacement_prefix)),
        )
        .expect("a missing directory is not an error");
    }

    /// A symlink wearing an upgrade-owned name is unlinked, never traversed.
    #[cfg(unix)]
    #[test]
    fn an_upgrade_named_symlink_is_unlinked_rather_than_followed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("precious");
        fs::create_dir_all(&target).expect("create target");
        fs::write(target.join("keep"), b"keep").expect("write target file");
        let link = temp
            .path()
            .join(format!("{}1.2.3", EXAMPLEAPP.staged_replacement_prefix));
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        remove_upgrade_owned_directory(&EXAMPLEAPP, &link).expect("remove the link");
        assert!(!link.exists());
        assert!(
            target.join("keep").is_file(),
            "the link target must survive"
        );
    }
}
