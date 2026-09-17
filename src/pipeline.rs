//! Download, verification, extraction, promotion and rollback.
//!
//! Every function here is host-agnostic. The three seams a host injects —
//! filesystem-space accounting, the rename primitive, and the HTTP client —
//! are parameters, which is also what lets a host's tests drive failure paths
//! without touching a real installation.

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::installation::InstallationKind;
use crate::manifest::{
    UpgradeArchitecture, UpgradeArchive, UpgradeArtifact, UpgradeArtifactMember, UpgradeChannel,
    UpgradeManifest, UpgradePlatform,
};
use crate::{Error, ProductDescriptor, Result};

/// The maximum accepted signature-bundle size for an upgrade manifest.
pub const UPGRADE_BUNDLE_MAX_BYTES: u64 = 256 * 1024;

/// Fixed working reserve required on the staging filesystem, on top of the
/// artifact and everything it decompresses into.
pub const UPGRADE_STAGING_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

const DOWNLOAD_PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

/// Host-supplied free-space admission check.
pub type UpgradeSpaceCheck = fn(&Path, u64) -> Result<()>;

/// Host-supplied rename primitive. Injectable so a host's tests can drive the
/// promotion and rollback failure paths.
pub type UpgradeRename = fn(&Path, &Path) -> std::io::Result<()>;

/// The default rename: a plain filesystem rename.
pub fn rename_path(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

pub type ProgressFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Periodic download progress, reported to whatever the host persists it in.
pub trait DownloadProgress: Send {
    fn report(&mut self, downloaded_bytes: u64, total_bytes: u64) -> ProgressFuture<'_>;
}

/// A progress sink that discards everything, for hosts and tests with nothing
/// to persist.
pub struct DiscardProgress;

impl DownloadProgress for DiscardProgress {
    fn report(&mut self, _downloaded_bytes: u64, _total_bytes: u64) -> ProgressFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

/// Executable and backup locations for a portable promotion.
///
/// These are resolved before anything is moved so the durable journal can be
/// written ahead of the promotion it describes.
#[derive(Clone, Debug)]
#[cfg_attr(windows, allow(dead_code))]
pub struct PortableUpgradePaths {
    pub executable_path: PathBuf,
    pub backup_path: PathBuf,
}

/// Failure state of a portable promotion after its journal was written.
///
/// Once the current executable has moved aside, a failed restoration must keep
/// the journal and backup paths available for recovery on the next boot.
#[cfg_attr(windows, allow(dead_code))]
pub enum PortablePromotionFailure {
    Restored(Error),
    RecoveryRequired(Error),
}

#[cfg_attr(windows, allow(dead_code))]
impl From<Error> for PortablePromotionFailure {
    fn from(error: Error) -> Self {
        Self::Restored(error)
    }
}

#[cfg_attr(windows, allow(dead_code))]
impl PortablePromotionFailure {
    /// The error to report, and whether the previous executable was restored.
    pub fn into_parts(self) -> (Error, bool) {
        match self {
            Self::Restored(error) => (error, true),
            Self::RecoveryRequired(error) => (error, false),
        }
    }
}

/// The HTTP client used for every upgrade fetch.
///
/// The client is built without a TLS provider of its own: the host installs the
/// process-wide rustls crypto provider before any upgrade runs.
pub fn application_upgrade_http_client(product: &ProductDescriptor) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(30))
        // Release artifacts can legitimately take longer than an ordinary API
        // request on slow links; retain a bounded long-running HTTP budget.
        .timeout(product.http_operation_timeout)
        .build()
        .map_err(|error| Error::Repository(format!("failed to build upgrade HTTP client: {error}")))
}

/// Verify a signed upgrade manifest against the product's release identity for
/// exactly the tag the host asked for.
pub async fn verify_upgrade_manifest_signature(
    product: &ProductDescriptor,
    manifest_raw: Vec<u8>,
    bundle_raw: Vec<u8>,
    release_tag: &str,
) -> Result<()> {
    artifact_trust::verify_signed_blob(
        manifest_raw,
        bundle_raw,
        product.release_required_signer(release_tag),
    )
    .await
    .map_err(|error| {
        Error::Validation(format!(
            "upgrade manifest signature verification failed: {error}"
        ))
    })
}

/// The canonical release-asset URL for `filename` in release `tag`.
pub fn release_asset_url(
    product: &ProductDescriptor,
    tag: &str,
    filename: &str,
) -> Result<url::Url> {
    let mut url = url::Url::parse(&format!(
        "https://github.com/{}/releases/download/",
        product.release_repository
    ))
    .map_err(|error| Error::Repository(format!("invalid release URL base: {error}")))?;
    url.path_segments_mut()
        .map_err(|_| Error::Repository("release URL base cannot accept path segments".to_string()))?
        .push(tag)
        .push(filename);
    Ok(url)
}

/// Fetch a small resource, refusing anything larger than `cap` both by the
/// advertised length and by what actually arrives.
pub async fn fetch_capped_bytes(
    client: &reqwest::Client,
    url: &str,
    cap: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| Error::Repository(format!("failed to fetch {label}: {error}")))?
        .error_for_status()
        .map_err(|error| Error::Repository(format!("failed to fetch {label}: {error}")))?;
    if response
        .content_length()
        .is_some_and(|content_length| content_length > cap)
    {
        return Err(Error::Validation(format!(
            "{label} exceeds the maximum size of {cap} bytes"
        )));
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| Error::Repository(format!("failed to read {label}: {error}")))?;
        let next_len = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if next_len > cap {
            return Err(Error::Validation(format!(
                "{label} exceeds the maximum size of {cap} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// The artifact in `manifest` matching this host's platform, architecture and
/// installation channel.
pub fn select_artifact(
    manifest: &UpgradeManifest,
    installation_kind: InstallationKind,
) -> Result<&UpgradeArtifact> {
    let platform = match std::env::consts::OS {
        "macos" => UpgradePlatform::Darwin,
        "linux" => UpgradePlatform::Linux,
        "windows" => UpgradePlatform::Windows,
        os => {
            return Err(Error::Validation(format!(
                "no application upgrade artifact is available for operating system {os}"
            )));
        }
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => UpgradeArchitecture::Arm64,
        "x86_64" => UpgradeArchitecture::X86_64,
        arch => {
            return Err(Error::Validation(format!(
                "no application upgrade artifact is available for architecture {arch}"
            )));
        }
    };
    let channel = match installation_kind {
        InstallationKind::Portable => UpgradeChannel::Portable,
        InstallationKind::DirectMsi => UpgradeChannel::Msi,
        _ => {
            return Err(Error::Validation(
                "application upgrade installation is not eligible".to_string(),
            ));
        }
    };
    manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.platform == platform && artifact.arch == arch && artifact.channel == channel
        })
        .ok_or_else(|| {
            Error::Validation("no upgrade artifact is available for this platform".to_string())
        })
}

/// Stream the artifact to `destination`, refusing anything that exceeds or
/// falls short of the signed length and hashing as it goes.
pub async fn download_artifact(
    client: &reqwest::Client,
    artifact: &UpgradeArtifact,
    artifact_url_override: Option<&str>,
    destination: &Path,
    progress: &mut dyn DownloadProgress,
) -> Result<()> {
    let response = client
        .get(artifact_url_override.unwrap_or(&artifact.url))
        .send()
        .await
        .map_err(|error| {
            Error::Repository(format!("failed to download upgrade artifact: {error}"))
        })?
        .error_for_status()
        .map_err(|error| {
            Error::Repository(format!("failed to download upgrade artifact: {error}"))
        })?;
    if response
        .content_length()
        .is_some_and(|content_length| content_length > artifact.size)
    {
        return Err(Error::Validation(
            "upgrade artifact exceeds the manifest size".to_string(),
        ));
    }

    let mut file = tokio::fs::File::create(destination)
        .await
        .map_err(|error| {
            Error::Repository(format!("failed to create upgrade staging file: {error}"))
        })?;
    let mut downloaded = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut last_progress = Instant::now() - DOWNLOAD_PROGRESS_INTERVAL;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            Error::Repository(format!("failed to read upgrade artifact response: {error}"))
        })?;
        let next_downloaded =
            downloaded.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if next_downloaded > artifact.size {
            return Err(Error::Validation(
                "upgrade artifact exceeds the manifest size".to_string(),
            ));
        }
        file.write_all(&chunk).await.map_err(|error| {
            Error::Repository(format!("failed to write upgrade staging file: {error}"))
        })?;
        hasher.update(&chunk);
        downloaded = next_downloaded;
        if last_progress.elapsed() >= DOWNLOAD_PROGRESS_INTERVAL {
            progress.report(downloaded, artifact.size).await?;
            last_progress = Instant::now();
        }
    }
    file.flush().await.map_err(|error| {
        Error::Repository(format!("failed to flush upgrade staging file: {error}"))
    })?;
    if downloaded != artifact.size {
        return Err(Error::Validation(format!(
            "upgrade artifact size mismatch: expected {} bytes, received {downloaded}",
            artifact.size
        )));
    }
    let expected_hash = blake3::Hash::from_hex(&artifact.blake3)
        .map_err(|error| Error::Validation(format!("invalid manifest BLAKE3 hash: {error}")))?;
    if hasher.finalize() != expected_hash {
        return Err(Error::Validation(
            "upgrade artifact BLAKE3 hash does not match the manifest".to_string(),
        ));
    }
    progress.report(downloaded, artifact.size).await
}

/// Re-hash the artifact on disk against the signed manifest.
pub fn verify_artifact_hash(path: &Path, artifact: &UpgradeArtifact) -> Result<()> {
    let mut file = fs::File::open(path)
        .map_err(|error| Error::Repository(format!("failed to open upgrade artifact: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Error::Repository(format!("failed to read upgrade artifact: {error}"))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hasher.finalize().to_hex().as_str() != artifact.blake3 {
        return Err(Error::Validation(
            "upgrade artifact BLAKE3 hash does not match the manifest".to_string(),
        ));
    }
    Ok(())
}

/// Confirm the archive contains exactly the members the signed manifest names,
/// at exactly the sizes it names, before anything is written to disk.
pub fn validate_archive_members(path: &Path, artifact: &UpgradeArtifact) -> Result<()> {
    match artifact.archive {
        UpgradeArchive::TarGz => validate_tar_members(path, artifact),
        UpgradeArchive::Msi => Ok(()),
    }
}

fn validate_tar_members(path: &Path, artifact: &UpgradeArtifact) -> Result<()> {
    let file = fs::File::open(path)
        .map_err(|error| Error::Repository(format!("failed to open upgrade archive: {error}")))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut actual = BTreeMap::new();
    for entry in archive.entries().map_err(archive_error)? {
        let entry = entry.map_err(archive_error)?;
        let member_path = archive_member_path(entry.path().map_err(archive_error)?.as_ref())?;
        if !entry.header().entry_type().is_file() {
            return Err(Error::Validation(format!(
                "upgrade archive member '{member_path}' is not a regular file"
            )));
        }
        let size = entry.size();
        if actual.insert(member_path.clone(), size).is_some() {
            return Err(Error::Validation(format!(
                "upgrade archive has duplicate member '{member_path}'"
            )));
        }
    }
    ensure_member_set_matches(&actual, artifact)
}

fn ensure_member_set_matches(
    actual: &BTreeMap<String, u64>,
    artifact: &UpgradeArtifact,
) -> Result<()> {
    let expected = artifact
        .members
        .iter()
        .map(|member| (member.path.clone(), member.size))
        .collect::<BTreeMap<_, _>>();
    if actual != &expected {
        return Err(Error::Validation(
            "upgrade archive members do not exactly match the signed manifest".to_string(),
        ));
    }
    Ok(())
}

/// Extract the archive, admitting only members the signed manifest names.
pub fn extract_archive(path: &Path, artifact: &UpgradeArtifact, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).map_err(|error| {
        Error::Repository(format!(
            "failed to create extracted upgrade directory: {error}"
        ))
    })?;
    match artifact.archive {
        UpgradeArchive::TarGz => extract_tar(path, artifact, destination),
        UpgradeArchive::Msi => Ok(()),
    }
}

fn extract_tar(path: &Path, artifact: &UpgradeArtifact, destination: &Path) -> Result<()> {
    let file = fs::File::open(path)
        .map_err(|error| Error::Repository(format!("failed to open upgrade archive: {error}")))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let expected = artifact_member_paths(artifact);
    for entry in archive.entries().map_err(archive_error)? {
        let mut entry = entry.map_err(archive_error)?;
        let member_path = archive_member_path(entry.path().map_err(archive_error)?.as_ref())?;
        let member = expected.get(&member_path).ok_or_else(|| {
            Error::Validation(format!("unexpected upgrade archive member '{member_path}'"))
        })?;
        if !entry.header().entry_type().is_file() || entry.size() != member.size {
            return Err(Error::Validation(format!(
                "invalid upgrade archive member '{member_path}'"
            )));
        }
        let output = destination.join(&member_path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(archive_error)?;
        }
        let mut output_file = fs::File::create(&output).map_err(archive_error)?;
        std::io::copy(&mut entry, &mut output_file).map_err(archive_error)?;
        set_extracted_permissions(
            &output,
            entry.header().mode().unwrap_or(0o644),
            member.executable,
        )?;
    }
    Ok(())
}

fn artifact_member_paths(artifact: &UpgradeArtifact) -> BTreeMap<String, UpgradeArtifactMember> {
    artifact
        .members
        .iter()
        .cloned()
        .map(|member| (member.path.clone(), member))
        .collect()
}

fn archive_member_path(path: &Path) -> Result<String> {
    let raw = path.to_string_lossy();
    let windows_drive_prefix = raw.as_bytes().get(1) == Some(&b':')
        && raw
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic());
    if path.is_absolute() || raw.starts_with('\\') || raw.contains('\\') || windows_drive_prefix {
        return Err(Error::Validation(
            "upgrade archive contains an absolute member path".to_string(),
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => {
                components.push(component.to_string_lossy().to_string())
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::Validation(
                    "upgrade archive contains an unsafe member path".to_string(),
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(Error::Validation(
            "upgrade archive contains an empty member path".to_string(),
        ));
    }
    Ok(components.join("/"))
}

#[cfg(unix)]
fn set_extracted_permissions(path: &Path, mode: u32, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if executable {
        mode | 0o111
    } else {
        mode & !0o111
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777)).map_err(|error| {
        Error::Repository(format!(
            "failed to set extracted upgrade permissions: {error}"
        ))
    })
}

#[cfg(not(unix))]
fn set_extracted_permissions(_path: &Path, _mode: u32, _executable: bool) -> Result<()> {
    Ok(())
}

/// Resolve the executable and backup locations a portable promotion will use.
///
/// This performs every check that must precede the durable journal: the
/// installation must be portable, the executable must be resolvable and live in
/// a directory, and no earlier backup may be overwritten.
#[cfg_attr(windows, allow(dead_code))]
pub fn portable_upgrade_paths(
    installation_kind: InstallationKind,
    executable_path: Option<&Path>,
    current_version: &str,
) -> Result<PortableUpgradePaths> {
    #[cfg(unix)]
    {
        if installation_kind != InstallationKind::Portable {
            return Err(Error::Validation(
                "portable replacement is only available for portable installations".to_string(),
            ));
        }
        let executable_path = executable_path
            .map(Path::to_path_buf)
            .or_else(|| std::env::current_exe().ok())
            .ok_or_else(|| {
                Error::Repository("failed to resolve the running executable path".to_string())
            })?;
        if executable_path.parent().is_none() {
            return Err(Error::Validation(
                "running executable has no parent directory".to_string(),
            ));
        }
        let backup_path = PathBuf::from(format!(
            "{}.pre-upgrade-{current_version}",
            executable_path.display()
        ));
        if backup_path.exists() {
            return Err(Error::Validation(format!(
                "refusing to overwrite existing application backup '{}'",
                backup_path.display()
            )));
        }
        Ok(PortableUpgradePaths {
            executable_path,
            backup_path,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (installation_kind, executable_path, current_version);
        Err(Error::Validation(
            "portable replacement is not available on this platform".to_string(),
        ))
    }
}

/// Promote the extracted executable over the installed one, retaining the
/// previous executable as a backup.
#[cfg_attr(windows, allow(dead_code))]
pub fn apply_portable_upgrade<S, R>(
    product: &ProductDescriptor,
    extracted_dir: &Path,
    artifact: &UpgradeArtifact,
    paths: &PortableUpgradePaths,
    expected_version: &str,
    ensure_available_space: S,
    rename: R,
) -> std::result::Result<(), PortablePromotionFailure>
where
    S: Fn(&Path, u64) -> Result<()>,
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    #[cfg(unix)]
    {
        let executable_dir = paths.executable_path.parent().ok_or_else(|| {
            Error::Validation("running executable has no parent directory".to_string())
        })?;
        let new_binary = find_upgraded_executable(extracted_dir, artifact, &paths.executable_path)?;
        let new_binary_size = fs::metadata(&new_binary)
            .map_err(|error| {
                Error::Repository(format!("failed to stat upgraded executable: {error}"))
            })?
            .len();
        ensure_available_space(
            executable_dir,
            new_binary_size.saturating_add(UPGRADE_STAGING_RESERVE_BYTES),
        )?;
        let new_path = executable_dir.join(format!(
            "{}{expected_version}",
            product.staged_replacement_prefix
        ));
        fs::copy(&new_binary, &new_path).map_err(|error| {
            Error::Repository(format!("failed to stage replacement executable: {error}"))
        })?;
        if let Err(error) = rename(&paths.executable_path, &paths.backup_path) {
            let _ = fs::remove_file(&new_path);
            return Err(Error::Repository(format!(
                "failed to retain current executable backup: {error}"
            ))
            .into());
        }
        if let Err(error) = rename(&new_path, &paths.executable_path) {
            return match rename(&paths.backup_path, &paths.executable_path) {
                Ok(()) => {
                    let _ = fs::remove_file(&new_path);
                    Err(Error::Repository(format!(
                        "failed to replace application executable: {error}; the previous executable was restored"
                    ))
                    .into())
                }
                Err(rollback_error) => Err(PortablePromotionFailure::RecoveryRequired(
                    Error::Repository(format!(
                        "failed to replace application executable: {error}; failed to restore the previous executable from '{}': {rollback_error}",
                        paths.backup_path.display()
                    )),
                )),
            };
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (
            product,
            extracted_dir,
            artifact,
            paths,
            expected_version,
            ensure_available_space,
            rename,
        );
        Err(
            Error::Validation("portable replacement is not available on this platform".to_string())
                .into(),
        )
    }
}

/// Undo a completed promotion after a later step failed.
///
/// The backup is moved back over the newly installed executable. The journal is
/// removed only after that restoration succeeds so an interrupted rollback
/// retains the paths needed for recovery.
#[cfg(not(windows))]
pub fn roll_back_portable_promotion<R>(
    paths: &PortableUpgradePaths,
    journal_path: &Path,
    rename: R,
    error: Error,
) -> Error
where
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    let outcome = match rename(&paths.backup_path, &paths.executable_path) {
        Ok(()) => {
            let mut outcome = "the previous executable was restored".to_string();
            if let Err(cleanup_error) = crate::journal::remove_file_if_exists(journal_path) {
                outcome.push_str(&format!(
                    "; the application upgrade journal could not be removed: {cleanup_error}"
                ));
            }
            outcome
        }
        Err(rollback_error) => format!(
            "the previous executable could not be restored from '{}': {rollback_error}; the recovery journal was retained",
            paths.backup_path.display()
        ),
    };
    Error::Repository(format!(
        "application upgrade failed after the executable was replaced: {error}; {outcome}"
    ))
}

#[cfg(unix)]
fn find_upgraded_executable(
    extracted_dir: &Path,
    artifact: &UpgradeArtifact,
    executable_path: &Path,
) -> Result<PathBuf> {
    let current_name = executable_path.file_name();
    let exact = artifact
        .members
        .iter()
        .find(|member| member.executable && Path::new(&member.path).file_name() == current_name);
    let candidates = artifact
        .members
        .iter()
        .filter(|member| member.executable)
        .collect::<Vec<_>>();
    let selected = exact
        .or_else(|| (candidates.len() == 1).then_some(candidates[0]))
        .ok_or_else(|| {
            Error::Validation(
                "upgrade archive does not identify a unique replacement executable".to_string(),
            )
        })?;
    Ok(extracted_dir.join(&selected.path))
}

/// Empty and recreate the staging directory, owner-only where the platform
/// supports it.
pub fn recreate_staging_dir(path: &Path) -> Result<()> {
    crate::journal::remove_dir_if_exists(path)?;
    fs::create_dir_all(path).map_err(|error| {
        Error::Repository(format!(
            "failed to create upgrade staging directory: {error}"
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Error::Repository(format!(
                "failed to protect upgrade staging directory: {error}"
            ))
        })?;
    }
    Ok(())
}

/// Bytes the staging filesystem must hold: the downloaded artifact, everything
/// it decompresses into, and the fixed working reserve.
///
/// MSI artifacts declare no members, so their admission is the artifact plus the
/// reserve exactly as before.
pub fn staging_space_requirement(artifact: &UpgradeArtifact) -> u64 {
    artifact
        .members
        .iter()
        .fold(artifact.size, |total, member| {
            total.saturating_add(member.size)
        })
        .saturating_add(UPGRADE_STAGING_RESERVE_BYTES)
}

/// Resolve a path through symlinks, falling back to the path as given.
///
/// Startup evidence canonicalizes the running executable, so every comparison
/// against it must resolve the same way or a symlinked install (Homebrew's
/// `/usr/local/opt`, `/home/linuxbrew`) never matches itself.
pub fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn archive_error(error: impl std::fmt::Display) -> Error {
    Error::Validation(format!("invalid upgrade archive: {error}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::product::test_product::EXAMPLEAPP;

    fn portable_tar_artifact(size: u64) -> UpgradeArtifact {
        UpgradeArtifact {
            platform: UpgradePlatform::Linux,
            arch: UpgradeArchitecture::X86_64,
            channel: UpgradeChannel::Portable,
            asset_name: "exampleapp.tar.gz".to_string(),
            url: format!(
                "{}exampleapp.tar.gz",
                EXAMPLEAPP.release_download_prefix("v0.18.22")
            ),
            size: 0,
            blake3: "0".repeat(64),
            archive: UpgradeArchive::TarGz,
            members: vec![UpgradeArtifactMember {
                path: "exampleapp".to_string(),
                size,
                executable: true,
            }],
        }
    }

    pub(crate) fn windows_portable_artifact(
        members: Vec<UpgradeArtifactMember>,
    ) -> UpgradeArtifact {
        UpgradeArtifact {
            platform: UpgradePlatform::Windows,
            arch: UpgradeArchitecture::X86_64,
            channel: UpgradeChannel::Portable,
            asset_name: "exampleapp-windows-x86_64-portable.tar.gz".to_string(),
            url: "https://example.invalid/exampleapp-windows-x86_64-portable.tar.gz".to_string(),
            size: 0,
            blake3: "0".repeat(64),
            archive: UpgradeArchive::TarGz,
            members,
        }
    }

    pub(crate) fn windows_member(path: &str, size: u64) -> UpgradeArtifactMember {
        UpgradeArtifactMember {
            path: path.to_string(),
            size,
            executable: true,
        }
    }

    pub(crate) fn tar_gz(members: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes, mode) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).expect("set archive path");
            header.set_size(bytes.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            archive
                .append(&header, *bytes)
                .expect("append archive member");
        }
        archive
            .into_inner()
            .expect("finish archive")
            .finish()
            .expect("finish gzip")
    }

    /// The Windows portable artifact travels the same `.tar.gz` container as
    /// every other platform, so it gets the same member validation.
    pub(crate) const WINDOWS_ARCHIVE_MEMBERS: [(&str, &[u8], u32); 4] = [
        ("exampleapp.exe", b"windows backend".as_slice(), 0o755),
        ("exampleapp-tray.exe", b"windows tray".as_slice(), 0o755),
        ("LICENSE", b"license text".as_slice(), 0o644),
        ("README.txt", b"readme text".as_slice(), 0o644),
    ];

    pub(crate) fn write_windows_archive(
        directory: &Path,
        members: &[(&str, &[u8], u32)],
    ) -> PathBuf {
        fs::create_dir_all(directory).expect("create archive directory");
        let archive_path = directory.join("exampleapp-windows-x86_64-portable.tar.gz");
        fs::write(&archive_path, tar_gz(members)).expect("write windows upgrade archive");
        archive_path
    }

    pub(crate) fn windows_manifest_members(
        members: &[(&str, &[u8], u32)],
    ) -> Vec<UpgradeArtifactMember> {
        let mut members = members
            .iter()
            .map(|(path, bytes, mode)| UpgradeArtifactMember {
                path: (*path).to_string(),
                size: bytes.len() as u64,
                executable: mode & 0o111 != 0,
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| left.path.cmp(&right.path));
        members
    }

    #[test]
    fn archive_member_paths_reject_parent_components() {
        let error = archive_member_path(Path::new("bin/../exampleapp")).expect_err("unsafe path");
        assert!(error.to_string().contains("unsafe member path"));
    }

    #[test]
    fn archive_member_paths_reject_windows_paths_on_all_platforms() {
        for path in ["C:\\exampleapp", "bin\\exampleapp"] {
            let error = archive_member_path(Path::new(path)).expect_err("unsafe path");
            assert!(error.to_string().contains("absolute member path"));
        }
    }

    #[test]
    fn tar_archive_members_must_match_the_signed_manifest_exactly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive_path = temp.path().join("upgrade.tar.gz");
        let output = fs::File::create(&archive_path).expect("create archive");
        let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let bytes = b"new executable";
        let mut header = tar::Header::new_gnu();
        header.set_path("exampleapp").expect("set path");
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive.append(&header, &bytes[..]).expect("append member");
        let encoder = archive.into_inner().expect("finish tar");
        encoder.finish().expect("finish gzip");

        let artifact = portable_tar_artifact(bytes.len() as u64);
        validate_archive_members(&archive_path, &artifact).expect("manifest member matches");

        let mismatch = portable_tar_artifact(bytes.len() as u64 + 1);
        let error = validate_archive_members(&archive_path, &mismatch)
            .expect_err("signed member size must match");
        assert!(error.to_string().contains("do not exactly match"));
    }

    #[test]
    fn windows_tar_archive_members_must_match_the_signed_manifest_exactly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive_path = write_windows_archive(temp.path(), &WINDOWS_ARCHIVE_MEMBERS);
        let artifact =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));
        validate_archive_members(&archive_path, &artifact).expect("archive matches the manifest");

        // A member the manifest never signed.
        let mut missing = artifact.clone();
        missing.members.retain(|member| member.path != "LICENSE");
        assert!(
            validate_archive_members(&archive_path, &missing)
                .expect_err("unsigned member is rejected")
                .to_string()
                .contains("do not exactly match")
        );

        // A signed member the archive does not carry.
        let mut extra = artifact.clone();
        extra
            .members
            .push(windows_member("exampleapp-extra.exe", 1));
        extra
            .members
            .sort_by(|left, right| left.path.cmp(&right.path));
        assert!(
            validate_archive_members(&archive_path, &extra)
                .expect_err("absent member is rejected")
                .to_string()
                .contains("do not exactly match")
        );

        // A member whose length differs from the signed length.
        let mut resized = artifact.clone();
        resized
            .members
            .iter_mut()
            .find(|member| member.path == "exampleapp.exe")
            .expect("backend member")
            .size += 1;
        assert!(
            validate_archive_members(&archive_path, &resized)
                .expect_err("resized member is rejected")
                .to_string()
                .contains("do not exactly match")
        );
    }

    #[test]
    fn windows_tar_archive_rejects_duplicate_and_non_regular_members() {
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));

        let mut duplicated = WINDOWS_ARCHIVE_MEMBERS.to_vec();
        duplicated.push(("exampleapp.exe", b"windows backend".as_slice(), 0o755));
        let duplicate_path = write_windows_archive(&temp.path().join("duplicate"), &duplicated);
        assert!(
            validate_archive_members(&duplicate_path, &artifact)
                .expect_err("duplicate member is rejected")
                .to_string()
                .contains("duplicate member")
        );

        let directory_path = temp.path().join("directory");
        fs::create_dir_all(&directory_path).expect("create archive directory");
        let archive_path = directory_path.join("exampleapp-windows-x86_64-portable.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            fs::File::create(&archive_path).expect("create archive"),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_path("bin").expect("set directory path");
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, &[][..]).expect("append directory");
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip");
        assert!(
            validate_archive_members(&archive_path, &artifact)
                .expect_err("directory entry is rejected")
                .to_string()
                .contains("is not a regular file")
        );
    }

    #[test]
    fn windows_tar_artifact_hash_must_match_the_signed_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive_path = write_windows_archive(temp.path(), &WINDOWS_ARCHIVE_MEMBERS);
        let bytes = fs::read(&archive_path).expect("read archive");

        let mut artifact =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));
        artifact.size = bytes.len() as u64;
        artifact.blake3 = blake3::hash(&bytes).to_hex().to_string();
        verify_artifact_hash(&archive_path, &artifact).expect("hash matches the manifest");

        artifact.blake3 = blake3::hash(b"other bytes").to_hex().to_string();
        assert!(
            verify_artifact_hash(&archive_path, &artifact)
                .expect_err("hash mismatch is rejected")
                .to_string()
                .contains("BLAKE3 hash does not match")
        );
    }

    #[test]
    fn windows_tar_extraction_rejects_members_the_manifest_never_signed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive_path = write_windows_archive(temp.path(), &WINDOWS_ARCHIVE_MEMBERS);
        let mut artifact =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));
        artifact
            .members
            .retain(|member| member.path != "README.txt");
        let error = extract_archive(&archive_path, &artifact, &temp.path().join("extracted"))
            .expect_err("unsigned member is rejected");
        assert!(
            error
                .to_string()
                .contains("unexpected upgrade archive member")
        );

        let mut resized =
            windows_portable_artifact(windows_manifest_members(&WINDOWS_ARCHIVE_MEMBERS));
        resized
            .members
            .iter_mut()
            .find(|member| member.path == "exampleapp-tray.exe")
            .expect("tray member")
            .size += 1;
        let error = extract_archive(&archive_path, &resized, &temp.path().join("resized"))
            .expect_err("resized member is rejected");
        assert!(error.to_string().contains("invalid upgrade archive member"));
    }

    #[test]
    fn staging_admission_includes_every_decompressed_member() {
        let mut artifact = portable_tar_artifact(10);
        artifact.size = 7;
        assert_eq!(
            staging_space_requirement(&artifact),
            7 + 10 + UPGRADE_STAGING_RESERVE_BYTES
        );

        artifact.members.push(UpgradeArtifactMember {
            path: "exampleapp-tray".to_string(),
            size: 5,
            executable: true,
        });
        assert_eq!(
            staging_space_requirement(&artifact),
            7 + 10 + 5 + UPGRADE_STAGING_RESERVE_BYTES
        );

        // MSI artifacts declare no members, so their admission is unchanged.
        artifact.members.clear();
        assert_eq!(
            staging_space_requirement(&artifact),
            7 + UPGRADE_STAGING_RESERVE_BYTES
        );

        let mut saturating = portable_tar_artifact(u64::MAX);
        saturating.size = u64::MAX;
        assert_eq!(staging_space_requirement(&saturating), u64::MAX);
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected_by_the_real_sigstore_verifier() {
        let error = verify_upgrade_manifest_signature(
            &EXAMPLEAPP,
            b"{\"schema\":\"exampleapp.upgrade.manifest.v1\"}".to_vec(),
            b"not a sigstore bundle".to_vec(),
            "exampleapp-v0.19.4",
        )
        .await
        .expect_err("garbage signature bundle must be rejected");
        assert!(
            error
                .to_string()
                .contains("upgrade manifest signature verification failed")
        );
    }
}
