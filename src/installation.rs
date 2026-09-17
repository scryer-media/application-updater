//! Installation-layout classification for the in-application upgrade surface.

use std::path::{Path, PathBuf};

/// Operating-system family observed while collecting installation evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InstallationOs {
    /// Microsoft Windows.
    Windows,
    /// Apple macOS.
    Macos,
    /// Linux.
    Linux,
    /// Any other operating system.
    #[default]
    Other,
}

/// Plain startup evidence used to assess whether in-app upgrades are available.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstallationEvidence {
    /// Raw disable-self-upgrade environment marker, when set.
    /// (`ProductDescriptor::disable_self_upgrade_env`.)
    pub disable_self_upgrade: Option<String>,
    /// Raw distribution-package environment marker, when set.
    /// (`ProductDescriptor::package_env`.)
    pub package: Option<String>,
    /// Executable path, when it can be resolved.
    pub executable_path: Option<PathBuf>,
    /// Whether the executable directory accepted a create-and-delete probe.
    pub executable_dir_writable: bool,
    /// Whether the Docker sentinel file is present.
    pub docker_env_present: bool,
    /// Operating-system family.
    pub os: InstallationOs,
    /// Whether the Windows process runs in session zero.
    pub windows_session_zero: bool,
    /// Whether Task Scheduler directly launched the Windows process.
    pub windows_task_scheduler_parent: bool,
    /// `DistributionOwner` from the product's machine registry key, when present.
    pub windows_distribution_owner: Option<String>,
    /// Whether the executable path is contained by Program Files.
    pub windows_executable_under_program_files: bool,
    /// Whether the legacy product machine registry key exists.
    pub windows_legacy_msi_registry_key_exists: bool,
    /// Whether the desktop tray launched and supervises this process.
    pub tray_supervised: bool,
    /// Whether the macOS `.app` bundle's parent directory accepted a
    /// create-and-delete probe. Only meaningful for a bundle layout.
    pub macos_app_bundle_parent_writable: bool,
    /// Whether the running bundle was launched through Gatekeeper's App
    /// Translocation, which mounts it on a throwaway read-only image.
    pub macos_app_translocated: bool,
    /// Whether the volume holding the bundle is mounted read-only, which is
    /// what a bundle still running from its distribution disk image looks like.
    pub macos_bundle_volume_read_only: bool,
}

/// Installation layout classification used by the in-app upgrade surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationKind {
    Portable,
    DirectMsi,
    /// A macOS `.app` bundle upgraded in place by replacing the whole bundle.
    MacosAppBundle,
    Docker,
    Homebrew,
    Winget,
    WindowsSupervised,
    Disabled,
    Unsupported,
}

/// Party responsible for managing application upgrades.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementOwner {
    InApp,
    Operator,
}

/// Stable code explaining upgrade eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EligibilityReason {
    DisabledByOperator,
    ManagedByDocker,
    ManagedByHomebrew,
    WindowsSupervised,
    ManagedByWinget,
    Eligible,
    UnsupportedLayout,
    InstallDirNotWritable,
    /// The `.app` bundle is running from Gatekeeper's App Translocation copy,
    /// so the path it sees is a throwaway read-only mount, not the install.
    AppBundleTranslocated,
    /// The `.app` bundle is running from a read-only volume — a mounted disk
    /// image, most often the one it was distributed on.
    AppBundleReadOnlyVolume,
    /// The `.app` bundle is not supervised by the tray inside it, so nothing
    /// can relaunch the application once the bundle has been replaced.
    AppBundleNotTraySupervised,
}

impl EligibilityReason {
    /// Return the stable snake_case API code for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisabledByOperator => "disabled_by_operator",
            Self::ManagedByDocker => "managed_by_docker",
            Self::ManagedByHomebrew => "managed_by_homebrew",
            Self::WindowsSupervised => "windows_supervised",
            Self::ManagedByWinget => "managed_by_winget",
            Self::Eligible => "eligible",
            Self::UnsupportedLayout => "unsupported_layout",
            Self::InstallDirNotWritable => "install_dir_not_writable",
            Self::AppBundleTranslocated => "app_bundle_translocated",
            Self::AppBundleReadOnlyVolume => "app_bundle_read_only_volume",
            Self::AppBundleNotTraySupervised => "app_bundle_not_tray_supervised",
        }
    }
}

/// Immutable installation assessment captured during startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallationAssessment {
    pub kind: InstallationKind,
    pub owner: ManagementOwner,
    pub eligible: bool,
    pub reason: EligibilityReason,
    /// Whether the Windows tray is responsible for shutting down and relaunching this process.
    pub tray_supervised: bool,
}

impl Default for InstallationAssessment {
    fn default() -> Self {
        Self {
            kind: InstallationKind::Unsupported,
            owner: ManagementOwner::Operator,
            eligible: false,
            reason: EligibilityReason::UnsupportedLayout,
            tray_supervised: false,
        }
    }
}

/// Classify an installation from startup evidence using upgrade-safety precedence.
pub fn classify_installation(evidence: &InstallationEvidence) -> InstallationAssessment {
    if env_marker_enabled(evidence.disable_self_upgrade.as_deref()) {
        return operator_assessment(
            InstallationKind::Disabled,
            EligibilityReason::DisabledByOperator,
        );
    }

    if package_is(evidence.package.as_deref(), "docker") || evidence.docker_env_present {
        return operator_assessment(InstallationKind::Docker, EligibilityReason::ManagedByDocker);
    }

    if package_is(evidence.package.as_deref(), "homebrew") || is_homebrew_layout(evidence) {
        return operator_assessment(
            InstallationKind::Homebrew,
            EligibilityReason::ManagedByHomebrew,
        );
    }

    if evidence.os == InstallationOs::Windows
        && (evidence.windows_session_zero || evidence.windows_task_scheduler_parent)
    {
        return operator_assessment(
            InstallationKind::WindowsSupervised,
            EligibilityReason::WindowsSupervised,
        );
    }

    if evidence.os == InstallationOs::Windows
        && package_is(evidence.windows_distribution_owner.as_deref(), "winget")
    {
        return operator_assessment(InstallationKind::Winget, EligibilityReason::ManagedByWinget);
    }

    if evidence.os == InstallationOs::Windows
        && (package_is(evidence.windows_distribution_owner.as_deref(), "msi")
            || (evidence.windows_distribution_owner.is_none()
                && evidence.windows_legacy_msi_registry_key_exists
                && evidence.windows_executable_under_program_files))
    {
        return in_app_assessment(InstallationKind::DirectMsi, evidence.tray_supervised);
    }

    if evidence.os == InstallationOs::Windows
        && evidence
            .windows_distribution_owner
            .as_deref()
            .is_some_and(|owner| {
                !owner.trim().is_empty()
                    && !package_is(Some(owner), "winget")
                    && !package_is(Some(owner), "msi")
            })
    {
        return operator_assessment(
            InstallationKind::Unsupported,
            EligibilityReason::UnsupportedLayout,
        );
    }

    // A macOS .app is a signed, self-contained bundle: replacing individual
    // binaries inside it would break the bundle's signature and, for an ad-hoc
    // signature, leave an app Gatekeeper refuses to launch. /Applications is
    // writable by an admin user, so without this branch the bundle would
    // classify as Portable and the portable promotion would happily corrupt it.
    //
    // The bundle is instead upgraded whole: a fully signed replacement bundle
    // is staged beside it and swapped in by rename. That is only possible when
    // the bundle really is the install — not a translocated copy, not the
    // distribution disk image — its parent directory is writable, and the tray
    // inside it supervises this process and can relaunch the new bundle.
    if evidence.os == InstallationOs::Macos && is_macos_app_bundle(evidence) {
        if evidence.macos_app_translocated {
            return operator_assessment(
                InstallationKind::MacosAppBundle,
                EligibilityReason::AppBundleTranslocated,
            );
        }
        if evidence.macos_bundle_volume_read_only {
            return operator_assessment(
                InstallationKind::MacosAppBundle,
                EligibilityReason::AppBundleReadOnlyVolume,
            );
        }
        if !evidence.macos_app_bundle_parent_writable {
            return operator_assessment(
                InstallationKind::MacosAppBundle,
                EligibilityReason::InstallDirNotWritable,
            );
        }
        if !evidence.tray_supervised {
            return operator_assessment(
                InstallationKind::MacosAppBundle,
                EligibilityReason::AppBundleNotTraySupervised,
            );
        }
        return in_app_assessment(InstallationKind::MacosAppBundle, true);
    }

    if evidence.executable_dir_writable {
        return in_app_assessment(InstallationKind::Portable, evidence.tray_supervised);
    }

    let reason = if evidence.executable_path.is_some() {
        EligibilityReason::InstallDirNotWritable
    } else {
        EligibilityReason::UnsupportedLayout
    };
    operator_assessment(InstallationKind::Unsupported, reason)
}

fn env_marker_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn package_is(value: Option<&str>, expected: &str) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

/// Whether the executable sits in `…/<Something>.app/Contents/MacOS/`, which is
/// the only layout a macOS DMG produces.
fn is_macos_app_bundle(evidence: &InstallationEvidence) -> bool {
    evidence
        .executable_path
        .as_deref()
        .and_then(macos_app_bundle_path)
        .is_some()
}

/// The `…/<Something>.app` directory containing `executable`, when the
/// executable really sits at `<bundle>/Contents/MacOS/<name>`.
///
/// Evidence collection and classification both go through this so they can
/// never disagree about what "is a bundle" means.
pub fn macos_app_bundle_path(executable: &Path) -> Option<&Path> {
    let macos_dir = executable.parent()?;
    if macos_dir.file_name()?.to_str()? != "MacOS" {
        return None;
    }
    let contents_dir = macos_dir.parent()?;
    if contents_dir.file_name()?.to_str()? != "Contents" {
        return None;
    }
    let bundle = contents_dir.parent()?;
    bundle
        .file_name()?
        .to_str()?
        .ends_with(".app")
        .then_some(bundle)
}

/// Whether `path` is inside Gatekeeper's App Translocation mount.
///
/// A translocated launch sees the bundle at a randomized read-only path under
/// `/private/var/folders/…/AppTranslocation/<uuid>/d/<Name>.app`, and the real
/// install is somewhere else entirely, so nothing there may be replaced.
pub fn is_app_translocated(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| name == "AppTranslocation")
    })
}

fn is_homebrew_layout(evidence: &InstallationEvidence) -> bool {
    if evidence.os == InstallationOs::Windows {
        return false;
    }

    evidence.executable_path.as_ref().is_some_and(|path| {
        let path = path.to_string_lossy();
        // `/usr/local/opt` is the Intel-macOS keg link root and
        // `/home/linuxbrew/.linuxbrew` is the Linuxbrew prefix; both reach the
        // Cellar through symlinks that a canonicalized path may not show.
        path.contains("/Cellar/")
            || path.starts_with("/opt/homebrew/")
            || path.starts_with("/usr/local/Cellar/")
            || path.starts_with("/usr/local/opt/")
            || path.starts_with("/home/linuxbrew/.linuxbrew/")
    })
}

fn in_app_assessment(kind: InstallationKind, tray_supervised: bool) -> InstallationAssessment {
    InstallationAssessment {
        kind,
        owner: ManagementOwner::InApp,
        eligible: true,
        reason: EligibilityReason::Eligible,
        tray_supervised,
    }
}

fn operator_assessment(
    kind: InstallationKind,
    reason: EligibilityReason,
) -> InstallationAssessment {
    InstallationAssessment {
        kind,
        owner: ManagementOwner::Operator,
        eligible: false,
        reason,
        tray_supervised: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> InstallationEvidence {
        InstallationEvidence {
            executable_path: Some(PathBuf::from("/opt/scryer/scryer")),
            executable_dir_writable: true,
            os: InstallationOs::Linux,
            ..Default::default()
        }
    }

    fn assert_assessment(
        evidence: InstallationEvidence,
        kind: InstallationKind,
        owner: ManagementOwner,
        eligible: bool,
        reason: EligibilityReason,
    ) {
        assert_eq!(
            classify_installation(&evidence),
            InstallationAssessment {
                kind,
                owner,
                eligible,
                reason,
                tray_supervised: evidence.tray_supervised && eligible,
            }
        );
    }

    /// An eligible bundle install: the real bundle, on a writable volume, with
    /// the tray inside it supervising this process.
    fn bundle_evidence() -> InstallationEvidence {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Macos;
        evidence.executable_path = Some(PathBuf::from(
            "/Applications/ExampleApp.app/Contents/MacOS/exampleapp",
        ));
        evidence.macos_app_bundle_parent_writable = true;
        evidence.tray_supervised = true;
        evidence
    }

    /// A macOS install outside a bundle is still an ordinary portable install.
    #[test]
    fn a_macos_install_outside_a_bundle_is_portable() {
        let mut loose = evidence();
        loose.os = InstallationOs::Macos;
        loose.executable_path = Some(PathBuf::from("/Users/example/exampleapp/exampleapp"));
        assert_assessment(
            loose,
            InstallationKind::Portable,
            ManagementOwner::InApp,
            true,
            EligibilityReason::Eligible,
        );
    }

    #[test]
    fn a_supervised_writable_app_bundle_is_upgraded_in_place() {
        assert_assessment(
            bundle_evidence(),
            InstallationKind::MacosAppBundle,
            ManagementOwner::InApp,
            true,
            EligibilityReason::Eligible,
        );
    }

    #[test]
    fn a_translocated_app_bundle_is_not_eligible() {
        let mut translocated = bundle_evidence();
        translocated.macos_app_translocated = true;
        assert_assessment(
            translocated,
            InstallationKind::MacosAppBundle,
            ManagementOwner::Operator,
            false,
            EligibilityReason::AppBundleTranslocated,
        );
    }

    /// The distribution disk image is mounted read-only, and a bundle running
    /// from it was never installed at all.
    #[test]
    fn an_app_bundle_on_a_read_only_volume_is_not_eligible() {
        let mut mounted = bundle_evidence();
        mounted.macos_bundle_volume_read_only = true;
        assert_assessment(
            mounted,
            InstallationKind::MacosAppBundle,
            ManagementOwner::Operator,
            false,
            EligibilityReason::AppBundleReadOnlyVolume,
        );
    }

    #[test]
    fn an_app_bundle_whose_parent_is_not_writable_is_not_eligible() {
        let mut read_only_parent = bundle_evidence();
        read_only_parent.macos_app_bundle_parent_writable = false;
        assert_assessment(
            read_only_parent,
            InstallationKind::MacosAppBundle,
            ManagementOwner::Operator,
            false,
            EligibilityReason::InstallDirNotWritable,
        );
    }

    /// Nothing else can relaunch the application once the bundle — the tray
    /// binary included — has been replaced, so an unsupervised bundle is left
    /// to the operator rather than given a second, invented restart path.
    #[test]
    fn an_unsupervised_app_bundle_is_not_eligible() {
        let mut unsupervised = bundle_evidence();
        unsupervised.tray_supervised = false;
        assert_assessment(
            unsupervised,
            InstallationKind::MacosAppBundle,
            ManagementOwner::Operator,
            false,
            EligibilityReason::AppBundleNotTraySupervised,
        );
    }

    /// Translocation is reported ahead of every other disqualifier: the path
    /// the process sees is not the install, so nothing else observed about it
    /// describes the install either.
    #[test]
    fn translocation_precedes_every_other_bundle_disqualifier() {
        let mut everything_wrong = bundle_evidence();
        everything_wrong.macos_app_translocated = true;
        everything_wrong.macos_bundle_volume_read_only = true;
        everything_wrong.macos_app_bundle_parent_writable = false;
        everything_wrong.tray_supervised = false;
        assert_eq!(
            classify_installation(&everything_wrong).reason,
            EligibilityReason::AppBundleTranslocated
        );
    }

    /// Docker, Homebrew and the operator kill switch still outrank a bundle.
    #[test]
    fn managed_evidence_precedes_an_eligible_app_bundle() {
        let mut disabled = bundle_evidence();
        disabled.disable_self_upgrade = Some("1".to_string());
        assert_eq!(
            classify_installation(&disabled).kind,
            InstallationKind::Disabled
        );

        let mut homebrew = bundle_evidence();
        homebrew.package = Some("homebrew".to_string());
        assert_eq!(
            classify_installation(&homebrew).kind,
            InstallationKind::Homebrew
        );
    }

    #[test]
    fn recognizes_the_bundle_directory_and_translocated_paths() {
        assert_eq!(
            macos_app_bundle_path(Path::new(
                "/Applications/ExampleApp.app/Contents/MacOS/exampleapp"
            )),
            Some(Path::new("/Applications/ExampleApp.app"))
        );
        for path in [
            "/Applications/ExampleApp.app/Contents/exampleapp",
            "/Applications/ExampleApp/Contents/MacOS/exampleapp",
            "/usr/local/bin/exampleapp",
        ] {
            assert_eq!(macos_app_bundle_path(Path::new(path)), None, "{path}");
        }

        assert!(is_app_translocated(Path::new(
            "/private/var/folders/x1/AppTranslocation/0BC/d/ExampleApp.app"
        )));
        assert!(!is_app_translocated(Path::new(
            "/Applications/ExampleApp.app"
        )));
    }

    #[test]
    fn classifies_every_installation_kind() {
        let portable = evidence();
        assert_assessment(
            portable,
            InstallationKind::Portable,
            ManagementOwner::InApp,
            true,
            EligibilityReason::Eligible,
        );

        let mut direct_msi = evidence();
        direct_msi.os = InstallationOs::Windows;
        direct_msi.windows_distribution_owner = Some("msi".to_string());
        assert_assessment(
            direct_msi,
            InstallationKind::DirectMsi,
            ManagementOwner::InApp,
            true,
            EligibilityReason::Eligible,
        );

        let mut docker = evidence();
        docker.package = Some("docker".to_string());
        assert_assessment(
            docker,
            InstallationKind::Docker,
            ManagementOwner::Operator,
            false,
            EligibilityReason::ManagedByDocker,
        );

        let mut homebrew = evidence();
        homebrew.package = Some("homebrew".to_string());
        assert_assessment(
            homebrew,
            InstallationKind::Homebrew,
            ManagementOwner::Operator,
            false,
            EligibilityReason::ManagedByHomebrew,
        );

        let mut winget = evidence();
        winget.os = InstallationOs::Windows;
        winget.windows_distribution_owner = Some("winget".to_string());
        assert_assessment(
            winget,
            InstallationKind::Winget,
            ManagementOwner::Operator,
            false,
            EligibilityReason::ManagedByWinget,
        );

        let mut supervised = evidence();
        supervised.os = InstallationOs::Windows;
        supervised.windows_session_zero = true;
        assert_assessment(
            supervised,
            InstallationKind::WindowsSupervised,
            ManagementOwner::Operator,
            false,
            EligibilityReason::WindowsSupervised,
        );

        let mut task_scheduler = evidence();
        task_scheduler.os = InstallationOs::Windows;
        task_scheduler.windows_task_scheduler_parent = true;
        assert_assessment(
            task_scheduler,
            InstallationKind::WindowsSupervised,
            ManagementOwner::Operator,
            false,
            EligibilityReason::WindowsSupervised,
        );

        let mut disabled = evidence();
        disabled.disable_self_upgrade = Some("true".to_string());
        assert_assessment(
            disabled,
            InstallationKind::Disabled,
            ManagementOwner::Operator,
            false,
            EligibilityReason::DisabledByOperator,
        );

        let mut unsupported = evidence();
        unsupported.executable_dir_writable = false;
        unsupported.executable_path = None;
        assert_assessment(
            unsupported,
            InstallationKind::Unsupported,
            ManagementOwner::Operator,
            false,
            EligibilityReason::UnsupportedLayout,
        );
    }

    #[test]
    fn classifies_whitespace_padded_windows_distribution_owner() {
        let mut direct_msi = evidence();
        direct_msi.os = InstallationOs::Windows;
        direct_msi.windows_distribution_owner = Some("  msi  ".to_string());
        assert_assessment(
            direct_msi,
            InstallationKind::DirectMsi,
            ManagementOwner::InApp,
            true,
            EligibilityReason::Eligible,
        );
    }

    #[test]
    fn carries_tray_supervision_into_an_eligible_assessment() {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Windows;
        evidence.tray_supervised = true;
        let assessment = classify_installation(&evidence);
        assert_eq!(assessment.kind, InstallationKind::Portable);
        assert!(assessment.eligible);
        assert!(assessment.tray_supervised);
    }

    #[test]
    fn reports_install_directory_not_writable_when_that_is_the_only_disqualifier() {
        let mut evidence = evidence();
        evidence.executable_dir_writable = false;
        assert_assessment(
            evidence,
            InstallationKind::Unsupported,
            ManagementOwner::Operator,
            false,
            EligibilityReason::InstallDirNotWritable,
        );
    }

    #[test]
    fn managed_evidence_precedes_writable_portable_layout() {
        let mut disabled = evidence();
        disabled.disable_self_upgrade = Some("1".to_string());
        disabled.package = Some("docker".to_string());
        assert_eq!(
            classify_installation(&disabled).kind,
            InstallationKind::Disabled
        );

        let mut docker = evidence();
        docker.docker_env_present = true;
        assert_eq!(
            classify_installation(&docker).kind,
            InstallationKind::Docker
        );

        let mut docker_before_homebrew = evidence();
        docker_before_homebrew.package = Some("homebrew".to_string());
        docker_before_homebrew.docker_env_present = true;
        assert_eq!(
            classify_installation(&docker_before_homebrew).kind,
            InstallationKind::Docker
        );

        let mut homebrew = evidence();
        homebrew.executable_path = Some(PathBuf::from("/usr/local/Cellar/scryer/bin/scryer"));
        assert_eq!(
            classify_installation(&homebrew).kind,
            InstallationKind::Homebrew
        );

        let mut homebrew_before_session_zero = evidence();
        homebrew_before_session_zero.os = InstallationOs::Windows;
        homebrew_before_session_zero.package = Some("homebrew".to_string());
        homebrew_before_session_zero.windows_session_zero = true;
        assert_eq!(
            classify_installation(&homebrew_before_session_zero).kind,
            InstallationKind::Homebrew
        );
    }

    #[test]
    fn detects_every_homebrew_prefix_layout() {
        for path in [
            "/opt/homebrew/Cellar/scryer/0.18.22/bin/scryer",
            "/opt/homebrew/bin/scryer",
            "/usr/local/Cellar/scryer/0.18.22/bin/scryer",
            "/usr/local/opt/scryer/bin/scryer",
            "/home/linuxbrew/.linuxbrew/bin/scryer",
            "/home/linuxbrew/.linuxbrew/Cellar/scryer/0.18.22/bin/scryer",
        ] {
            let mut evidence = evidence();
            evidence.executable_path = Some(PathBuf::from(path));
            assert_eq!(
                classify_installation(&evidence).kind,
                InstallationKind::Homebrew,
                "{path} must classify as Homebrew"
            );
        }

        for path in ["/opt/scryer/scryer", "/usr/local/bin/scryer"] {
            let mut evidence = evidence();
            evidence.executable_path = Some(PathBuf::from(path));
            assert_eq!(
                classify_installation(&evidence).kind,
                InstallationKind::Portable,
                "{path} must not classify as Homebrew"
            );
        }

        // Windows paths never take the Homebrew branch.
        let mut windows = evidence();
        windows.os = InstallationOs::Windows;
        windows.executable_path = Some(PathBuf::from("C:/usr/local/opt/scryer/scryer.exe"));
        assert_eq!(
            classify_installation(&windows).kind,
            InstallationKind::Portable
        );
    }

    #[test]
    fn session_zero_precedes_windows_distribution_evidence() {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Windows;
        evidence.windows_session_zero = true;
        evidence.windows_distribution_owner = Some("msi".to_string());
        assert_eq!(
            classify_installation(&evidence).kind,
            InstallationKind::WindowsSupervised
        );
    }

    #[test]
    fn winget_owner_precedes_legacy_msi_evidence() {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Windows;
        evidence.windows_distribution_owner = Some("winget".to_string());
        evidence.windows_legacy_msi_registry_key_exists = true;
        evidence.windows_executable_under_program_files = true;
        assert_eq!(
            classify_installation(&evidence).kind,
            InstallationKind::Winget
        );
    }

    #[test]
    fn detects_legacy_msi_only_when_key_and_program_files_evidence_are_present() {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Windows;
        evidence.windows_legacy_msi_registry_key_exists = true;
        evidence.windows_executable_under_program_files = true;
        assert_eq!(
            classify_installation(&evidence).kind,
            InstallationKind::DirectMsi
        );

        let mut missing_program_files = evidence.clone();
        missing_program_files.windows_executable_under_program_files = false;
        assert_eq!(
            classify_installation(&missing_program_files).kind,
            InstallationKind::Portable
        );

        let mut explicit_owner = evidence;
        explicit_owner.windows_distribution_owner = Some("other".to_string());
        assert_eq!(
            classify_installation(&explicit_owner).kind,
            InstallationKind::Unsupported
        );
    }

    #[test]
    fn unknown_distribution_owner_is_operator_managed() {
        let mut evidence = evidence();
        evidence.os = InstallationOs::Windows;
        evidence.windows_distribution_owner = Some("future-msi-channel".to_string());
        assert_assessment(
            evidence,
            InstallationKind::Unsupported,
            ManagementOwner::Operator,
            false,
            EligibilityReason::UnsupportedLayout,
        );
    }

    #[test]
    fn tray_supervision_does_not_change_a_portable_assessment() {
        let mut evidence = evidence();
        evidence.tray_supervised = true;
        assert_eq!(
            classify_installation(&evidence).kind,
            InstallationKind::Portable
        );
    }
}
