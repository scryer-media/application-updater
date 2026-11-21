//! The one host abstraction: everything about an upgrade that is specific to
//! the product being upgraded.
//!
//! A [`ProductDescriptor`] is a plain `const`-constructible value so a host can
//! declare it once, next to the rest of its identity. Nothing else in this
//! crate names a product.

use std::path::{Path, PathBuf};
use std::time::Duration;

use artifact_trust::RequiredSigner;

/// Product identity and the frozen wire identifiers an upgrade uses.
///
/// Every string here appears either in a signed manifest, on disk, or in a
/// process argument, so changing one for a shipped product is a compatibility
/// break: a helper from one version must still read a plan and journal written
/// by another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductDescriptor {
    /// Human-readable product name used in operator-facing helper messages.
    pub display_name: &'static str,
    /// GitHub repository that publishes releases, e.g. `example/exampleapp`.
    pub release_repository: &'static str,
    /// Workflow path required of the release signer, e.g.
    /// `.github/workflows/exampleapp.yml`.
    pub release_workflow: &'static str,
    /// Release-asset filename of the signed upgrade manifest.
    pub manifest_asset_name: &'static str,
    /// Release-asset filename of the manifest's Sigstore bundle.
    pub manifest_signature_asset_name: &'static str,
    /// Schema identifier accepted for signed upgrade manifests.
    pub manifest_schema: &'static str,
    /// Release-asset filename of the signed v2 upgrade manifest.
    pub manifest_v2_asset_name: &'static str,
    /// Release-asset filename of the v2 manifest's Sigstore bundle.
    pub manifest_v2_signature_asset_name: &'static str,
    /// Schema identifier accepted for signed v2 upgrade manifests.
    pub manifest_v2_schema: &'static str,
    /// macOS application-bundle directory name, e.g. `ExampleApp.app`.
    pub macos_bundle_name: &'static str,
    /// Schema identifier written into the durable upgrade journal.
    pub journal_schema: &'static str,
    /// Schema identifier written into the Windows helper plan.
    pub helper_plan_schema: &'static str,
    /// Windows server executable filename, e.g. `exampleapp.exe`.
    pub windows_server_executable: &'static str,
    /// Windows tray executable filename, e.g. `exampleapp-tray.exe`.
    pub windows_tray_executable: &'static str,
    /// Filename of the temporary Windows upgrade helper copy.
    pub windows_helper_executable: &'static str,
    /// Every executable filename the product runs from its installation
    /// directory on Windows, e.g. `["exampleapp.exe", "exampleapp-tray.exe"]`.
    ///
    /// Before an installer or a portable replacement touches the installation,
    /// the helper stops every running process whose image is one of these
    /// names directly inside that directory, including processes nothing
    /// recorded (an orphaned server). List only the product's own long-running
    /// executables; never the helper copy itself.
    pub windows_product_process_names: &'static [&'static str],
    /// Filename prefix of the staged replacement executable written beside the
    /// installed one during a portable promotion.
    pub staged_replacement_prefix: &'static str,
    /// Environment marker that disables in-app upgrades entirely.
    pub disable_self_upgrade_env: &'static str,
    /// Environment marker naming the distribution package (`docker`, `homebrew`).
    pub package_env: &'static str,
    /// Environment marker set when a desktop tray supervises this process.
    pub tray_supervised_env: &'static str,
    /// Machine registry key holding `DistributionOwner`, Windows only.
    pub windows_registry_key: &'static str,
    /// Filename prefix of the install-directory write probe.
    pub write_probe_prefix: &'static str,
    /// Bounded budget for a single upgrade HTTP operation. Release artifacts
    /// take longer than an ordinary API call on slow links.
    pub http_operation_timeout: Duration,
}

impl ProductDescriptor {
    /// The Sigstore identity required of this product's release workflow for a
    /// given release tag.
    ///
    /// The signer requirement is derived from the host's own identity and the
    /// tag the host asked for, never from the artifact being verified.
    pub fn release_required_signer(&self, release_tag: &str) -> RequiredSigner {
        RequiredSigner {
            github_repository: self.release_repository.to_string(),
            github_workflow: Some(self.release_workflow.to_string()),
            github_ref: Some(format!("refs/tags/{release_tag}")),
        }
    }

    /// The URL prefix every artifact in a manifest for `tag` must start with.
    pub fn release_download_prefix(&self, tag: &str) -> String {
        format!(
            "https://github.com/{}/releases/download/{tag}/",
            self.release_repository
        )
    }

    /// The two Windows executables a portable upgrade replaces, in the order
    /// the helper plan lists them.
    pub fn windows_replacement_executables(&self) -> [&'static str; 2] {
        [self.windows_server_executable, self.windows_tray_executable]
    }
}

/// Where an upgrade keeps its working state.
///
/// The host owns these locations; the core never derives them from an
/// environment of its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeDirectories {
    /// Root directory holding staging, helper and journal state.
    pub root: PathBuf,
}

impl UpgradeDirectories {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn staging(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn helper(&self) -> PathBuf {
        self.root.join("helper")
    }

    pub fn journal_path(&self) -> PathBuf {
        self.root.join("journal.json")
    }

    /// Where the Windows helper asks `msiexec` to write its verbose log for
    /// one run, or `None` when the run id is not safe to put in a file name.
    pub fn msi_log_path(&self, run_id: &str) -> Option<PathBuf> {
        msi_log_path_beside_journal(&self.journal_path(), run_id)
    }
}

/// The verbose `msiexec` log for one run: `msi-<run_id>.log` in the directory
/// that holds the journal.
///
/// It is derived rather than stored so neither the frozen helper plan nor the
/// frozen journal has to carry it: the helper knows the journal path and reads
/// the run id from the journal, and the host knows both too.
pub fn msi_log_path_beside_journal(journal_path: &Path, run_id: &str) -> Option<PathBuf> {
    let safe = !run_id.is_empty()
        && run_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if !safe {
        return None;
    }
    Some(journal_path.parent()?.join(format!("msi-{run_id}.log")))
}

#[cfg(test)]
pub(crate) mod test_product {
    use super::*;

    /// A synthetic product used by this crate's own tests. No real application
    /// identity appears in the crate outside signed fixtures.
    pub(crate) const EXAMPLEAPP: ProductDescriptor = ProductDescriptor {
        display_name: "ExampleApp",
        release_repository: "example-media/exampleapp",
        release_workflow: ".github/workflows/exampleapp.yml",
        manifest_asset_name: "exampleapp-upgrade-manifest.json",
        manifest_signature_asset_name: "exampleapp-upgrade-manifest.json.sigstore.json",
        manifest_schema: "exampleapp.upgrade.manifest.v1",
        manifest_v2_asset_name: "exampleapp-upgrade-manifest.v2.json",
        manifest_v2_signature_asset_name: "exampleapp-upgrade-manifest.v2.json.sigstore.json",
        manifest_v2_schema: "exampleapp.upgrade.manifest.v2",
        macos_bundle_name: "ExampleApp.app",
        journal_schema: "exampleapp.upgrade.journal.v1",
        helper_plan_schema: "exampleapp.upgrade.helper-plan.v1",
        windows_server_executable: "exampleapp.exe",
        windows_tray_executable: "exampleapp-tray.exe",
        windows_helper_executable: "exampleapp-upgrade-helper.exe",
        windows_product_process_names: &["exampleapp.exe", "exampleapp-tray.exe"],
        staged_replacement_prefix: ".exampleapp-upgrade-new-",
        disable_self_upgrade_env: "EXAMPLEAPP_DISABLE_SELF_UPGRADE",
        package_env: "EXAMPLEAPP_PACKAGE",
        tray_supervised_env: "EXAMPLEAPP_TRAY_SUPERVISED",
        windows_registry_key: "Software\\Example Media\\ExampleApp",
        write_probe_prefix: ".exampleapp-write-probe-",
        http_operation_timeout: Duration::from_secs(600),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_product::EXAMPLEAPP;

    #[test]
    fn release_signer_is_pinned_to_the_release_workflow() {
        let signer = EXAMPLEAPP.release_required_signer("exampleapp-v0.19.4");
        assert_eq!(signer.github_repository, EXAMPLEAPP.release_repository);
        assert_eq!(
            signer.github_workflow.as_deref(),
            Some(EXAMPLEAPP.release_workflow)
        );
        assert_eq!(
            signer.github_ref.as_deref(),
            Some("refs/tags/exampleapp-v0.19.4")
        );
    }

    #[test]
    fn upgrade_directories_are_derived_from_one_root() {
        let dirs = UpgradeDirectories::new(PathBuf::from("/data/application-upgrade"));
        assert_eq!(
            dirs.staging(),
            PathBuf::from("/data/application-upgrade/staging")
        );
        assert_eq!(
            dirs.helper(),
            PathBuf::from("/data/application-upgrade/helper")
        );
        assert_eq!(
            dirs.journal_path(),
            PathBuf::from("/data/application-upgrade/journal.json")
        );
        assert_eq!(
            dirs.msi_log_path("0b9f6c2e-4f7a-4a51-9d0e-2c3b4a5d6e7f"),
            Some(PathBuf::from(
                "/data/application-upgrade/msi-0b9f6c2e-4f7a-4a51-9d0e-2c3b4a5d6e7f.log"
            ))
        );
    }

    #[test]
    fn msi_log_path_refuses_run_ids_that_would_leave_the_upgrade_directory() {
        let journal = PathBuf::from("/data/application-upgrade/journal.json");
        for run_id in ["", "../escape", "a\\b", "run id", "a\"quote"] {
            assert_eq!(
                msi_log_path_beside_journal(&journal, run_id),
                None,
                "{run_id}"
            );
        }
        assert_eq!(
            msi_log_path_beside_journal(&journal, "run_1-A"),
            Some(PathBuf::from("/data/application-upgrade/msi-run_1-A.log"))
        );
    }
}
