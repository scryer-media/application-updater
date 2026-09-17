//! Building the Windows handoff: the journal and helper plan the temporary
//! upgrade helper reads after the application exits.
//!
//! Windows cannot replace a running executable, so the application writes a
//! durable journal and a plan, copies itself aside as a helper, and exits. Every
//! decision the helper will make is fixed here, while the application is still
//! running and can still report a failure.

#[cfg(windows)]
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::helper_plan::{
    ApplicationUpgradeHelperMode, ApplicationUpgradeHelperOwner, ApplicationUpgradeHelperPlan,
    ApplicationUpgradeHelperRelaunch, ApplicationUpgradeHelperReplacement,
};
use crate::installation::InstallationKind;
use crate::journal::ApplicationUpgradeJournal;
use crate::manifest::UpgradeArtifact;
use crate::{Error, ProductDescriptor, Result, phases};

/// Everything the handoff builder needs about the running installation.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WindowsUpgradeHandoffInput<'a> {
    pub run_id: &'a str,
    pub expected_version: &'a str,
    pub expected_tag: &'a str,
    pub installation_kind: InstallationKind,
    pub tray_supervised: bool,
    pub executable_path: &'a Path,
    pub install_dir: &'a Path,
    /// Process id of the backend the helper must outlive before it replaces files.
    pub backend_process_id: u32,
    pub artifact: Option<&'a UpgradeArtifact>,
    pub extracted_dir: Option<&'a Path>,
    pub msi_path: Option<&'a Path>,
    pub journal_path: PathBuf,
    pub direct_relaunch_args: &'a [String],
    pub direct_relaunch_cwd: &'a Path,
    pub current_version: &'a str,
    pub written_at: DateTime<Utc>,
}

/// The durable journal, the helper plan, and the phase the host should report.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WindowsUpgradeHandoff {
    pub journal: ApplicationUpgradeJournal,
    pub plan: ApplicationUpgradeHelperPlan,
    pub progress_phase: &'static str,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn build_windows_upgrade_handoff(
    product: &ProductDescriptor,
    input: WindowsUpgradeHandoffInput<'_>,
) -> Result<WindowsUpgradeHandoff> {
    let owner = if input.tray_supervised {
        ApplicationUpgradeHelperOwner::Tray
    } else {
        ApplicationUpgradeHelperOwner::Direct
    };
    let tray_path = input.install_dir.join(product.windows_tray_executable);
    let relaunch = if owner == ApplicationUpgradeHelperOwner::Tray {
        ApplicationUpgradeHelperRelaunch {
            program: tray_path.clone(),
            args: vec!["--login-start".to_string()],
            cwd: input.install_dir.to_path_buf(),
        }
    } else {
        ApplicationUpgradeHelperRelaunch {
            program: input.executable_path.to_path_buf(),
            args: input.direct_relaunch_args.to_vec(),
            cwd: input.direct_relaunch_cwd.to_path_buf(),
        }
    };
    let backup_suffix = format!(".pre-upgrade-{}", input.current_version);
    let (mode, replace, backup_paths, staged_dir, msi_path, progress_phase) = match input
        .installation_kind
    {
        InstallationKind::Portable => {
            let artifact = input.artifact.ok_or_else(|| {
                Error::Validation(
                    "portable Windows upgrade handoff requires an artifact".to_string(),
                )
            })?;
            let extracted_dir = input.extracted_dir.ok_or_else(|| {
                Error::Validation(
                    "portable Windows upgrade handoff requires an extracted directory".to_string(),
                )
            })?;
            let replacements =
                windows_portable_replacements(product, extracted_dir, artifact, input.install_dir)?;
            let backup_paths = replacements
                .iter()
                .map(|replacement| {
                    PathBuf::from(format!(
                        "{}{}",
                        replacement.to_install.display(),
                        backup_suffix
                    ))
                })
                .collect();
            (
                ApplicationUpgradeHelperMode::Portable,
                replacements,
                backup_paths,
                Some(extracted_dir.to_path_buf()),
                None,
                phases::RESTARTING,
            )
        }
        InstallationKind::DirectMsi => {
            let msi_path = input.msi_path.ok_or_else(|| {
                Error::Validation(
                    "MSI Windows upgrade handoff requires an installer path".to_string(),
                )
            })?;
            (
                ApplicationUpgradeHelperMode::Msi,
                Vec::new(),
                Vec::new(),
                None,
                Some(msi_path.to_path_buf()),
                phases::AWAITING_ELEVATION,
            )
        }
        _ => {
            return Err(Error::Validation(
                "application upgrade installation is not eligible".to_string(),
            ));
        }
    };
    let journal = ApplicationUpgradeJournal {
        schema: product.journal_schema.to_string(),
        run_id: input.run_id.to_string(),
        expected_version: input.expected_version.to_string(),
        expected_tag: input.expected_tag.to_string(),
        executable_path: input.executable_path.to_path_buf(),
        backup_path: PathBuf::from(format!(
            "{}{}",
            input.executable_path.display(),
            backup_suffix
        )),
        backup_paths,
        phase: phases::RESTARTING.to_string(),
        helper_error: None,
        written_at: Some(input.written_at),
        macos_bundle_upgrade: false,
        staging_dir: None,
    };
    let plan = ApplicationUpgradeHelperPlan {
        schema: product.helper_plan_schema.to_string(),
        mode,
        owner,
        journal_path: input.journal_path,
        staged_dir,
        msi_path,
        install_dir: input.install_dir.to_path_buf(),
        wait_process_ids: vec![input.backend_process_id],
        replace,
        backup_suffix,
        relaunch,
        tray_shutdown_program: (owner == ApplicationUpgradeHelperOwner::Tray).then_some(tray_path),
        expected_version: input.expected_version.to_string(),
        expected_tag: input.expected_tag.to_string(),
    };
    plan.validate(product).map_err(Error::Validation)?;
    Ok(WindowsUpgradeHandoff {
        journal,
        plan,
        progress_phase,
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_portable_replacements(
    product: &ProductDescriptor,
    extracted_dir: &Path,
    artifact: &UpgradeArtifact,
    install_dir: &Path,
) -> Result<Vec<ApplicationUpgradeHelperReplacement>> {
    product
        .windows_replacement_executables()
        .into_iter()
        .map(|filename| {
            let member = artifact
                .members
                .iter()
                .find(|member| {
                    Path::new(&member.path)
                        .file_name()
                        .is_some_and(|name| name == filename)
                })
                .ok_or_else(|| {
                    Error::Validation(format!(
                        "upgrade archive does not contain required Windows executable '{filename}'"
                    ))
                })?;
            Ok(ApplicationUpgradeHelperReplacement {
                from_staged: extracted_dir.join(&member.path),
                to_install: install_dir.join(filename),
            })
        })
        .collect()
}

/// Write the helper plan atomically beside the helper copy.
#[cfg(windows)]
pub fn write_helper_plan(path: &Path, plan: &ApplicationUpgradeHelperPlan) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Repository(
            "application upgrade helper plan path has no parent directory".to_string(),
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        Error::Repository(format!(
            "failed to create application upgrade helper directory: {error}"
        ))
    })?;
    let bytes = serde_json::to_vec(plan).map_err(|error| {
        Error::Repository(format!(
            "failed to encode application upgrade helper plan: {error}"
        ))
    })?;
    let temporary = parent.join(".plan.tmp");
    fs::write(&temporary, bytes).map_err(|error| {
        Error::Repository(format!(
            "failed to write application upgrade helper plan: {error}"
        ))
    })?;
    fs::rename(&temporary, path).map_err(|error| {
        Error::Repository(format!(
            "failed to activate application upgrade helper plan: {error}"
        ))
    })
}

/// Copy the running executable aside as the temporary helper and start it.
///
/// The helper is a copy of the application itself so no separate binary has to
/// be shipped, signed, or found on disk at upgrade time.
#[cfg(windows)]
pub fn copy_and_spawn_windows_upgrade_helper(helper_path: &Path, plan_path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let source = std::env::current_exe().map_err(|error| {
        Error::Repository(format!(
            "failed to resolve upgrade helper source executable: {error}"
        ))
    })?;
    fs::copy(&source, helper_path).map_err(|error| {
        Error::Repository(format!("failed to copy temporary upgrade helper: {error}"))
    })?;
    std::process::Command::new(helper_path)
        .arg("--upgrade-helper")
        .arg(plan_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| {
            Error::Repository(format!("failed to spawn temporary upgrade helper: {error}"))
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::extract_archive;
    use crate::pipeline::tests::{
        WINDOWS_ARCHIVE_MEMBERS, windows_manifest_members, windows_member,
        windows_portable_artifact, write_windows_archive,
    };
    use crate::product::test_product::EXAMPLEAPP;
    use std::fs;

    #[test]
    fn windows_tar_extraction_produces_the_layout_the_helper_swap_expects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive_path = write_windows_archive(temp.path(), &WINDOWS_ARCHIVE_MEMBERS);
        let artifact =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));
        let extracted_dir = temp.path().join("extracted");
        extract_archive(&archive_path, &artifact, &extracted_dir).expect("extract archive");

        for (path, bytes, _) in WINDOWS_ARCHIVE_MEMBERS {
            let output = extracted_dir.join(path);
            assert!(
                output.is_file(),
                "{path} is a regular file after extraction"
            );
            assert_eq!(fs::read(&output).expect("read extracted member"), bytes);
        }

        // The helper swaps the two executables by their manifest member paths,
        // so extraction must place them exactly where the plan will look.
        let install_dir = Path::new("C:/Program Files/ExampleApp");
        let replacements =
            windows_portable_replacements(&EXAMPLEAPP, &extracted_dir, &artifact, install_dir)
                .expect("build helper replacements");
        assert_eq!(
            replacements,
            vec![
                ApplicationUpgradeHelperReplacement {
                    from_staged: extracted_dir.join("exampleapp.exe"),
                    to_install: install_dir.join("exampleapp.exe"),
                },
                ApplicationUpgradeHelperReplacement {
                    from_staged: extracted_dir.join("exampleapp-tray.exe"),
                    to_install: install_dir.join("exampleapp-tray.exe"),
                },
            ]
        );
        for replacement in &replacements {
            assert!(
                replacement.from_staged.is_file(),
                "staged {} exists",
                replacement.from_staged.display()
            );
        }
    }

    #[test]
    fn windows_handoff_builder_covers_portable_and_msi_direct_and_tray_owners() {
        let executable_path = PathBuf::from("C:/ExampleApp/exampleapp.exe");
        let install_dir = PathBuf::from("C:/ExampleApp");
        let extracted_dir = PathBuf::from("C:/data/application-upgrade/staging/extracted");
        let msi_path = PathBuf::from("C:/data/application-upgrade/staging/artifact");
        let journal_path = PathBuf::from("C:/data/application-upgrade/journal.json");
        let direct_args = vec!["--data-dir".to_string(), "C:/data".to_string()];
        let direct_cwd = PathBuf::from("C:/working");
        let artifact = windows_portable_artifact(vec![
            windows_member("bin/exampleapp.exe", 1),
            windows_member("bin/exampleapp-tray.exe", 1),
        ]);
        let written_at = Utc::now();

        for (installation_kind, tray_supervised) in [
            (InstallationKind::Portable, false),
            (InstallationKind::Portable, true),
            (InstallationKind::DirectMsi, false),
            (InstallationKind::DirectMsi, true),
        ] {
            let handoff = build_windows_upgrade_handoff(
                &EXAMPLEAPP,
                WindowsUpgradeHandoffInput {
                    run_id: "run-1",
                    expected_version: "99.0.0",
                    expected_tag: "v99.0.0",
                    installation_kind,
                    tray_supervised,
                    executable_path: &executable_path,
                    install_dir: &install_dir,
                    backend_process_id: 4242,
                    artifact: Some(&artifact),
                    extracted_dir: Some(&extracted_dir),
                    msi_path: Some(&msi_path),
                    journal_path: journal_path.clone(),
                    direct_relaunch_args: &direct_args,
                    direct_relaunch_cwd: &direct_cwd,
                    current_version: "98.0.0",
                    written_at,
                },
            )
            .expect("build Windows upgrade handoff");

            handoff
                .plan
                .validate(&EXAMPLEAPP)
                .expect("validate helper plan");
            assert_eq!(handoff.journal.phase, phases::RESTARTING);
            assert_eq!(handoff.journal.written_at, Some(written_at));
            assert_eq!(handoff.plan.backup_suffix, ".pre-upgrade-98.0.0");
            assert_eq!(handoff.plan.wait_process_ids, vec![4242]);
            assert_eq!(
                handoff.journal.backup_path,
                PathBuf::from("C:/ExampleApp/exampleapp.exe.pre-upgrade-98.0.0")
            );
            assert_eq!(handoff.plan.journal_path, journal_path);

            if tray_supervised {
                assert_eq!(handoff.plan.owner, ApplicationUpgradeHelperOwner::Tray);
                assert_eq!(
                    handoff.plan.relaunch.program,
                    install_dir.join("exampleapp-tray.exe")
                );
                assert_eq!(handoff.plan.relaunch.args, vec!["--login-start"]);
                assert_eq!(handoff.plan.relaunch.cwd, install_dir);
                assert_eq!(
                    handoff.plan.tray_shutdown_program,
                    Some(install_dir.join("exampleapp-tray.exe"))
                );
            } else {
                assert_eq!(handoff.plan.owner, ApplicationUpgradeHelperOwner::Direct);
                assert_eq!(handoff.plan.relaunch.program, executable_path);
                assert_eq!(handoff.plan.relaunch.args, direct_args);
                assert_eq!(handoff.plan.relaunch.cwd, direct_cwd);
                assert_eq!(handoff.plan.tray_shutdown_program, None);
            }

            match installation_kind {
                InstallationKind::Portable => {
                    assert_eq!(handoff.plan.mode, ApplicationUpgradeHelperMode::Portable);
                    assert_eq!(handoff.progress_phase, phases::RESTARTING);
                    assert_eq!(handoff.plan.staged_dir, Some(extracted_dir.clone()));
                    assert_eq!(handoff.plan.msi_path, None);
                    assert_eq!(
                        handoff.plan.replace,
                        vec![
                            ApplicationUpgradeHelperReplacement {
                                from_staged: extracted_dir.join("bin/exampleapp.exe"),
                                to_install: install_dir.join("exampleapp.exe"),
                            },
                            ApplicationUpgradeHelperReplacement {
                                from_staged: extracted_dir.join("bin/exampleapp-tray.exe"),
                                to_install: install_dir.join("exampleapp-tray.exe"),
                            },
                        ]
                    );
                    assert_eq!(
                        handoff.journal.backup_paths,
                        vec![
                            PathBuf::from("C:/ExampleApp/exampleapp.exe.pre-upgrade-98.0.0"),
                            PathBuf::from("C:/ExampleApp/exampleapp-tray.exe.pre-upgrade-98.0.0"),
                        ]
                    );
                }
                InstallationKind::DirectMsi => {
                    assert_eq!(handoff.plan.mode, ApplicationUpgradeHelperMode::Msi);
                    assert_eq!(handoff.progress_phase, phases::AWAITING_ELEVATION);
                    assert_eq!(handoff.plan.staged_dir, None);
                    assert_eq!(handoff.plan.msi_path, Some(msi_path.clone()));
                    assert!(handoff.plan.replace.is_empty());
                    assert!(handoff.journal.backup_paths.is_empty());
                }
                _ => unreachable!("test only covers eligible Windows installation kinds"),
            }
        }
    }
}
