//! Signed release-manifest validation for in-application upgrades.
//!
//! Two manifest generations are published side by side.
//!
//! **v1** ([`parse_and_validate_upgrade_manifest`]) is frozen. Its types use
//! `deny_unknown_fields` and closed enums, so every shipped client rejects the
//! whole document on any value it does not recognize. Nothing may ever be added
//! to it; the v1 parser additionally refuses any artifact naming a channel
//! introduced after v1, so a v1 manifest can never carry v2-only content.
//!
//! **v2** ([`parse_and_validate_upgrade_manifest_v2`]) exists so that never
//! happens again. Its compatibility contract, which the publisher may rely on:
//!
//! * Unknown JSON object fields are ignored everywhere in the document.
//! * Unknown `platform`, `arch`, `channel` and `archive` values deserialize
//!   into [`Tolerant::Unknown`], keeping the raw string. Such an artifact is
//!   retained in the parsed document, is never selectable, and is excluded from
//!   per-artifact validation beyond its JSON shape. It never invalidates the
//!   manifest.
//! * An artifact may differ in shape, not only in values. An entry that names
//!   at least one unknown `platform`, `arch`, `channel` or `archive` and cannot
//!   be read at all (missing or differently typed fields) is set aside as
//!   opaque. An entry naming only known values must have the known shape.
//! * Every artifact the client *does* understand is validated exactly as
//!   strictly as v1: https, URL prefix bound to the requested tag, asset-name
//!   suffix, BLAKE3 shape, channel/archive agreement, member-path safety, and
//!   member sorting and uniqueness. Strict ordering and duplicate rules apply
//!   among the understood artifacts, because a client cannot know where a
//!   platform it has never heard of sorts.
//! * The top-level `schema` must equal the product's v2 schema exactly, and the
//!   signature is still taken over the raw bytes. Tolerance never weakens the
//!   signature, tag binding, URL prefix, hash, size or member-path checks for an
//!   artifact that is actually selected.

use std::fmt;
use std::path::{Component, Path};

use semver::Version;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::{Error, ProductDescriptor, Result};

/// The maximum accepted signed upgrade-manifest size in bytes.
pub const UPGRADE_MANIFEST_MAX_BYTES: u64 = 262_144;

/// A signed release manifest describing installable application artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeManifest {
    /// The schema identifier for this manifest.
    pub schema: String,
    /// The release tag used in artifact URLs.
    pub tag: String,
    /// The released application version.
    pub version: String,
    /// The artifacts available from this release.
    pub artifacts: Vec<UpgradeArtifact>,
}

/// A release artifact that can be used for an application upgrade.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeArtifact {
    /// The operating system for this artifact.
    pub platform: UpgradePlatform,
    /// The CPU architecture for this artifact.
    pub arch: UpgradeArchitecture,
    /// The distribution channel encoded by the artifact.
    pub channel: UpgradeChannel,
    /// The release-asset filename.
    pub asset_name: String,
    /// The canonical GitHub Release download URL.
    pub url: String,
    /// The artifact's exact byte length.
    pub size: u64,
    /// The lowercase hexadecimal BLAKE3 hash of the complete artifact.
    pub blake3: String,
    /// The container format of the artifact.
    pub archive: UpgradeArchive,
    /// The regular files contained in a portable archive.
    pub members: Vec<UpgradeArtifactMember>,
}

/// The operating systems supported by an upgrade artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradePlatform {
    /// macOS.
    Darwin,
    /// Linux.
    Linux,
    /// Windows.
    Windows,
}

impl UpgradePlatform {
    /// The wire spelling of this platform.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Darwin => "darwin",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }
}

/// The CPU architectures supported by an upgrade artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum UpgradeArchitecture {
    /// 64-bit ARM.
    #[serde(rename = "arm64")]
    Arm64,
    /// 64-bit x86.
    #[serde(rename = "x86_64")]
    X86_64,
}

impl UpgradeArchitecture {
    /// The wire spelling of this architecture.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X86_64 => "x86_64",
        }
    }
}

/// The distribution channels supported by an upgrade artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeChannel {
    /// A portable archive.
    Portable,
    /// A Windows Installer package.
    Msi,
    /// A macOS `.app` bundle, upgraded in place inside its parent directory.
    ///
    /// Introduced with manifest v2. A v1 manifest must never name it, and
    /// [`parse_and_validate_upgrade_manifest`] rejects one that does.
    App,
}

impl UpgradeChannel {
    /// The wire spelling of this channel.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::Msi => "msi",
            Self::App => "app",
        }
    }

    /// Whether this channel was introduced after manifest v1.
    const fn is_post_v1(self) -> bool {
        matches!(self, Self::App)
    }
}

/// The container formats supported by an upgrade artifact.
///
/// Every portable artifact — Windows included — is a gzip-compressed tar
/// archive. ZIP is deliberately not a supported upgrade container: the
/// human-facing Windows `.zip` download is not part of the upgrade channel and
/// is never named by a signed manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UpgradeArchive {
    /// A gzip-compressed tar archive.
    #[serde(rename = "tar.gz")]
    TarGz,
    /// A Windows Installer package.
    #[serde(rename = "msi")]
    Msi,
}

impl UpgradeArchive {
    /// The wire spelling of this container format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Msi => "msi",
        }
    }
}

/// A regular file in a portable upgrade archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeArtifactMember {
    /// The slash-separated relative archive path.
    pub path: String,
    /// The member's uncompressed byte length.
    pub size: u64,
    /// Whether the member is executable after extraction.
    pub executable: bool,
}

/// Parses and validates a signed upgrade manifest payload.
pub fn parse_and_validate_upgrade_manifest(
    product: &ProductDescriptor,
    raw: &[u8],
) -> Result<UpgradeManifest> {
    if raw.len() as u64 > UPGRADE_MANIFEST_MAX_BYTES {
        return Err(Error::Validation(format!(
            "upgrade manifest exceeds the maximum size of {UPGRADE_MANIFEST_MAX_BYTES} bytes"
        )));
    }

    let manifest = serde_json::from_slice::<UpgradeManifest>(raw)
        .map_err(|error| Error::Validation(format!("invalid upgrade manifest JSON: {error}")))?;

    if manifest.schema != product.manifest_schema {
        return Err(Error::Validation(format!(
            "unsupported upgrade manifest schema '{}'; expected '{}'",
            manifest.schema, product.manifest_schema
        )));
    }
    validate_manifest_identity(&manifest.tag, &manifest.version)?;

    validate_artifact_order(&manifest.artifacts)?;
    for (artifact_index, artifact) in manifest.artifacts.iter().enumerate() {
        // v1 is frozen: a channel introduced after it must never appear in a
        // v1 document, or a v1 publisher could ship content the shipped v1
        // clients — which reject the whole manifest on an unknown enum — would
        // choke on. v2 is where new channels live.
        if artifact.channel.is_post_v1() {
            return Err(Error::Validation(format!(
                "upgrade manifest artifact {artifact_index} channel '{}' is not part of the v1 manifest schema",
                artifact.channel.as_str()
            )));
        }
        validate_artifact(product, artifact, artifact_index, &manifest.tag)?;
    }

    Ok(manifest)
}

/// A wire value that may name something this client has never heard of.
///
/// Manifest v2 keeps the raw string rather than failing, so a publisher can add
/// platforms, architectures, channels and container formats without breaking
/// clients that predate them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tolerant<T> {
    /// A value this client understands.
    Known(T),
    /// A value this client does not understand, kept verbatim.
    Unknown(String),
}

impl<T> Tolerant<T> {
    /// The understood value, if this client understands it.
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// Whether this client understands the value.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }
}

impl<T: WireValue> Tolerant<T> {
    /// The raw wire spelling, understood or not.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(value) => value.as_wire_str(),
            Self::Unknown(raw) => raw.as_str(),
        }
    }
}

/// A closed manifest enum whose variants have a stable wire spelling.
pub trait WireValue: Copy {
    /// The wire spelling of this value.
    fn as_wire_str(&self) -> &'static str;
}

impl WireValue for UpgradePlatform {
    fn as_wire_str(&self) -> &'static str {
        self.as_str()
    }
}

impl WireValue for UpgradeArchitecture {
    fn as_wire_str(&self) -> &'static str {
        self.as_str()
    }
}

impl WireValue for UpgradeChannel {
    fn as_wire_str(&self) -> &'static str {
        self.as_str()
    }
}

impl WireValue for UpgradeArchive {
    fn as_wire_str(&self) -> &'static str {
        self.as_str()
    }
}

impl<'de, T> Deserialize<'de> for Tolerant<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        // Every tolerated enum is a plain string-valued unit enum, so the value
        // itself is the deserializer for the known case.
        match T::deserialize(
            IntoDeserializer::<serde::de::value::Error>::into_deserializer(raw.as_str()),
        ) {
            Ok(value) => Ok(Self::Known(value)),
            Err(_) => Ok(Self::Unknown(raw)),
        }
    }
}

impl<T> Serialize for Tolerant<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Known(value) => value.serialize(serializer),
            Self::Unknown(raw) => serializer.serialize_str(raw),
        }
    }
}

impl<T: WireValue> fmt::Display for Tolerant<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A signed v2 release manifest, exactly as published.
///
/// Unknown fields are ignored and unknown enum values are retained, so this is
/// a faithful, lossless-enough view of a document a newer publisher wrote.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeManifestV2 {
    /// The schema identifier for this manifest.
    pub schema: String,
    /// The release tag used in artifact URLs.
    pub tag: String,
    /// The released application version.
    pub version: String,
    /// Every artifact in the release, understood or not.
    pub artifacts: Vec<UpgradeArtifactV2>,
}

/// A v2 release artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeArtifactV2 {
    /// The operating system for this artifact.
    pub platform: Tolerant<UpgradePlatform>,
    /// The CPU architecture for this artifact.
    pub arch: Tolerant<UpgradeArchitecture>,
    /// The distribution channel encoded by the artifact.
    pub channel: Tolerant<UpgradeChannel>,
    /// The release-asset filename.
    pub asset_name: String,
    /// The canonical GitHub Release download URL.
    pub url: String,
    /// The artifact's exact byte length.
    pub size: u64,
    /// The lowercase hexadecimal BLAKE3 hash of the complete artifact.
    pub blake3: String,
    /// The container format of the artifact.
    pub archive: Tolerant<UpgradeArchive>,
    /// The regular files contained in an archive.
    #[serde(default)]
    pub members: Vec<UpgradeArtifactMemberV2>,
}

/// A regular file in a v2 upgrade archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeArtifactMemberV2 {
    /// The slash-separated relative archive path.
    pub path: String,
    /// The member's uncompressed byte length.
    pub size: u64,
    /// Whether the member is executable after extraction.
    pub executable: bool,
}

impl UpgradeArtifactV2 {
    /// Whether every enum value in this artifact is one this client understands.
    pub fn is_understood(&self) -> bool {
        self.platform.is_known()
            && self.arch.is_known()
            && self.channel.is_known()
            && self.archive.is_known()
    }

    fn to_understood(&self) -> Option<UpgradeArtifact> {
        Some(UpgradeArtifact {
            platform: *self.platform.known()?,
            arch: *self.arch.known()?,
            channel: *self.channel.known()?,
            asset_name: self.asset_name.clone(),
            url: self.url.clone(),
            size: self.size,
            blake3: self.blake3.clone(),
            archive: *self.archive.known()?,
            members: self
                .members
                .iter()
                .map(|member| UpgradeArtifactMember {
                    path: member.path.clone(),
                    size: member.size,
                    executable: member.executable,
                })
                .collect(),
        })
    }
}

/// A validated v2 manifest: the document as published, plus the subset of it
/// this client understands in the shared internal representation the rest of
/// the upgrade pipeline runs on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedUpgradeManifestV2 {
    /// Everything this client understands, validated exactly as strictly as v1.
    pub understood: UpgradeManifest,
    /// The manifest as published, unknown values and all.
    pub published: UpgradeManifestV2,
    /// Artifacts whose shape this client could not read at all. They are of a
    /// kind it does not know, are never selectable, and are kept only so a
    /// caller can report that the release carries more than it understood.
    pub opaque_artifacts: Vec<serde_json::Value>,
}

/// Parses and validates a signed v2 upgrade manifest payload.
///
/// See the module docs for the compatibility contract this implements.
pub fn parse_and_validate_upgrade_manifest_v2(
    product: &ProductDescriptor,
    raw: &[u8],
) -> Result<ValidatedUpgradeManifestV2> {
    if raw.len() as u64 > UPGRADE_MANIFEST_MAX_BYTES {
        return Err(Error::Validation(format!(
            "upgrade manifest exceeds the maximum size of {UPGRADE_MANIFEST_MAX_BYTES} bytes"
        )));
    }

    let envelope = serde_json::from_slice::<UpgradeManifestV2Envelope>(raw)
        .map_err(|error| Error::Validation(format!("invalid upgrade manifest JSON: {error}")))?;

    // Artifacts are read one at a time so that a future kind of artifact may
    // differ in shape, not only in its enum values: an entry this client
    // cannot read is set aside as opaque unless it claims to be a kind this
    // client knows, in which case its shape is this client's business and a
    // mismatch is an error.
    let mut artifacts = Vec::with_capacity(envelope.artifacts.len());
    let mut opaque_artifacts = Vec::new();
    for (artifact_index, value) in envelope.artifacts.into_iter().enumerate() {
        match serde_json::from_value::<UpgradeArtifactV2>(value.clone()) {
            Ok(artifact) => artifacts.push(artifact),
            Err(error) if claims_a_known_kind(&value) => {
                return Err(Error::Validation(format!(
                    "invalid upgrade manifest artifact {artifact_index}: {error}"
                )));
            }
            Err(_) => opaque_artifacts.push(value),
        }
    }
    let published = UpgradeManifestV2 {
        schema: envelope.schema,
        tag: envelope.tag,
        version: envelope.version,
        artifacts,
    };

    if published.schema != product.manifest_v2_schema {
        return Err(Error::Validation(format!(
            "unsupported upgrade manifest schema '{}'; expected '{}'",
            published.schema, product.manifest_v2_schema
        )));
    }
    validate_manifest_identity(&published.tag, &published.version)?;

    // Only the artifacts this client understands are validated or ordered: a
    // client cannot judge the shape of a channel or container it has never
    // heard of, and cannot know where an unknown platform sorts.
    let understood_artifacts = published
        .artifacts
        .iter()
        .filter_map(UpgradeArtifactV2::to_understood)
        .collect::<Vec<_>>();
    validate_artifact_order(&understood_artifacts)?;
    for (artifact_index, artifact) in understood_artifacts.iter().enumerate() {
        validate_artifact(product, artifact, artifact_index, &published.tag)?;
    }

    Ok(ValidatedUpgradeManifestV2 {
        understood: UpgradeManifest {
            schema: published.schema.clone(),
            tag: published.tag.clone(),
            version: published.version.clone(),
            artifacts: understood_artifacts,
        },
        published,
        opaque_artifacts,
    })
}

/// The v2 document with its artifacts left unread.
#[derive(Deserialize)]
struct UpgradeManifestV2Envelope {
    schema: String,
    tag: String,
    version: String,
    artifacts: Vec<serde_json::Value>,
}

/// Whether an artifact names a platform, architecture, channel and archive
/// this client knows. Such an entry must also have the shape this client
/// expects; anything else is a kind of artifact from the future.
fn claims_a_known_kind(value: &serde_json::Value) -> bool {
    fn known<T: for<'de> Deserialize<'de>>(value: &serde_json::Value, field: &str) -> bool {
        value
            .get(field)
            .is_some_and(|raw| serde_json::from_value::<T>(raw.clone()).is_ok())
    }
    known::<UpgradePlatform>(value, "platform")
        && known::<UpgradeArchitecture>(value, "arch")
        && known::<UpgradeChannel>(value, "channel")
        && known::<UpgradeArchive>(value, "archive")
}

fn validate_manifest_identity(tag: &str, version: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(Error::Validation(
            "upgrade manifest tag must not be empty".to_string(),
        ));
    }
    if version.is_empty() {
        return Err(Error::Validation(
            "upgrade manifest version must not be empty".to_string(),
        ));
    }
    let parsed = Version::parse(version).map_err(|error| {
        Error::Validation(format!(
            "upgrade manifest version must be a major.minor.patch semver: {error}"
        ))
    })?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(Error::Validation(
            "upgrade manifest version must be a major.minor.patch semver without prerelease or build metadata"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_artifact_order(artifacts: &[UpgradeArtifact]) -> Result<()> {
    for pair in artifacts.windows(2) {
        let previous = artifact_sort_key(&pair[0]);
        let current = artifact_sort_key(&pair[1]);
        if current == previous {
            return Err(Error::Validation(format!(
                "duplicate upgrade manifest artifact for platform '{}', arch '{}', and channel '{}'",
                current.0, current.1, current.2
            )));
        }
        if current < previous {
            return Err(Error::Validation(
                "upgrade manifest artifacts must be strictly sorted by platform, arch, and channel"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn artifact_sort_key(artifact: &UpgradeArtifact) -> (&str, &str, &str) {
    (
        artifact.platform.as_str(),
        artifact.arch.as_str(),
        artifact.channel.as_str(),
    )
}

fn validate_artifact(
    product: &ProductDescriptor,
    artifact: &UpgradeArtifact,
    index: usize,
    tag: &str,
) -> Result<()> {
    if artifact.asset_name.is_empty() {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {index} asset_name must not be empty"
        )));
    }

    let url = Url::parse(&artifact.url).map_err(|error| {
        Error::Validation(format!(
            "upgrade manifest artifact {index} has an invalid URL: {error}"
        ))
    })?;
    if url.scheme() != "https" {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {index} URL must use https"
        )));
    }
    let expected_prefix = product.release_download_prefix(tag);
    if !artifact.url.starts_with(&expected_prefix) {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {index} URL must start with '{expected_prefix}'"
        )));
    }
    if !artifact.url.ends_with(&artifact.asset_name) {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {index} URL must end with its asset_name"
        )));
    }

    if !is_lowercase_blake3_hex(&artifact.blake3) {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {index} blake3 must be 64 lowercase hexadecimal characters"
        )));
    }

    match (artifact.channel, artifact.archive) {
        (UpgradeChannel::Msi, UpgradeArchive::Msi) => {
            if !artifact.members.is_empty() {
                return Err(Error::Validation(format!(
                    "upgrade manifest MSI artifact {index} must have no members"
                )));
            }
        }
        (UpgradeChannel::Msi, _)
        | (UpgradeChannel::Portable, UpgradeArchive::Msi)
        | (UpgradeChannel::App, UpgradeArchive::Msi) => {
            return Err(Error::Validation(format!(
                "upgrade manifest artifact {index} channel and archive must both be MSI or both be non-MSI"
            )));
        }
        (UpgradeChannel::Portable, UpgradeArchive::TarGz)
        | (UpgradeChannel::App, UpgradeArchive::TarGz) => {
            if artifact.members.is_empty() {
                return Err(Error::Validation(format!(
                    "upgrade manifest portable artifact {index} must have at least one member"
                )));
            }
            validate_members(&artifact.members, index)?;
        }
    }

    Ok(())
}

fn validate_members(members: &[UpgradeArtifactMember], artifact_index: usize) -> Result<()> {
    for pair in members.windows(2) {
        if pair[1].path == pair[0].path {
            return Err(Error::Validation(format!(
                "upgrade manifest artifact {artifact_index} has duplicate member path '{}'",
                pair[1].path
            )));
        }
        if pair[1].path < pair[0].path {
            return Err(Error::Validation(format!(
                "upgrade manifest artifact {artifact_index} members must be sorted by path"
            )));
        }
    }

    for member in members {
        validate_member_path(&member.path, artifact_index)?;
    }
    Ok(())
}

fn validate_member_path(path: &str, artifact_index: usize) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {artifact_index} member path must not be empty"
        )));
    }
    if path.starts_with('/') || Path::new(path).is_absolute() || has_windows_drive_prefix(path) {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {artifact_index} member path must be relative: '{path}'"
        )));
    }
    if path.contains('\\') {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {artifact_index} member path must not contain backslashes: '{path}'"
        )));
    }
    if Path::new(path)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(Error::Validation(format!(
            "upgrade manifest artifact {artifact_index} member path must not contain '..': '{path}'"
        )));
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
}

fn is_lowercase_blake3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product::test_product::EXAMPLEAPP;

    const BLAKE3: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn valid_manifest() -> UpgradeManifest {
        UpgradeManifest {
            schema: EXAMPLEAPP.manifest_schema.to_string(),
            tag: "v1.2.3".to_string(),
            version: "1.2.3".to_string(),
            artifacts: vec![
                portable_artifact(UpgradePlatform::Darwin, UpgradeArchitecture::Arm64),
                portable_artifact(UpgradePlatform::Linux, UpgradeArchitecture::X86_64),
                msi_artifact(UpgradeArchitecture::Arm64),
                portable_artifact(UpgradePlatform::Windows, UpgradeArchitecture::Arm64),
            ],
        }
    }

    fn portable_artifact(platform: UpgradePlatform, arch: UpgradeArchitecture) -> UpgradeArtifact {
        let asset_name = format!("exampleapp-{}-{}.tar.gz", platform.as_str(), arch.as_str());
        UpgradeArtifact {
            platform,
            arch,
            channel: UpgradeChannel::Portable,
            url: format!(
                "{}{asset_name}",
                EXAMPLEAPP.release_download_prefix("v1.2.3")
            ),
            asset_name,
            size: 42,
            blake3: BLAKE3.to_string(),
            archive: UpgradeArchive::TarGz,
            members: vec![UpgradeArtifactMember {
                path: "bin/exampleapp".to_string(),
                size: 42,
                executable: true,
            }],
        }
    }

    fn msi_artifact(arch: UpgradeArchitecture) -> UpgradeArtifact {
        let asset_name = format!("exampleapp-windows-{}.msi", arch.as_str());
        UpgradeArtifact {
            platform: UpgradePlatform::Windows,
            arch,
            channel: UpgradeChannel::Msi,
            url: format!(
                "{}{asset_name}",
                EXAMPLEAPP.release_download_prefix("v1.2.3")
            ),
            asset_name,
            size: 42,
            blake3: BLAKE3.to_string(),
            archive: UpgradeArchive::Msi,
            members: Vec::new(),
        }
    }

    fn assert_rejected(manifest: UpgradeManifest, expected: &str) {
        let raw = serde_json::to_vec(&manifest).expect("serialize manifest");
        let error = parse_and_validate_upgrade_manifest(&EXAMPLEAPP, &raw)
            .expect_err("manifest is rejected");
        assert!(
            error.to_string().contains(expected),
            "expected '{expected}' in '{error}'"
        );
    }

    #[test]
    fn accepts_valid_manifest() {
        let raw = serde_json::to_vec(&valid_manifest()).expect("serialize manifest");
        assert_eq!(
            parse_and_validate_upgrade_manifest(&EXAMPLEAPP, &raw).expect("valid manifest"),
            valid_manifest()
        );
    }

    #[test]
    fn rejects_oversized_manifest() {
        let raw = vec![b' '; UPGRADE_MANIFEST_MAX_BYTES as usize + 1];
        let error =
            parse_and_validate_upgrade_manifest(&EXAMPLEAPP, &raw).expect_err("oversized manifest");
        assert!(error.to_string().contains("exceeds the maximum size"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut value = serde_json::to_value(valid_manifest()).expect("serialize manifest");
        value["unexpected"] = serde_json::Value::Bool(true);
        let raw = serde_json::to_vec(&value).expect("serialize JSON");
        let error =
            parse_and_validate_upgrade_manifest(&EXAMPLEAPP, &raw).expect_err("unknown field");
        assert!(error.to_string().contains("invalid upgrade manifest JSON"));
    }

    #[test]
    fn rejects_schema_and_version_violations() {
        let mut manifest = valid_manifest();
        manifest.schema = "other".to_string();
        assert_rejected(manifest, "unsupported upgrade manifest schema");

        let mut manifest = valid_manifest();
        manifest.tag.clear();
        assert_rejected(manifest, "tag must not be empty");

        let mut manifest = valid_manifest();
        manifest.version.clear();
        assert_rejected(manifest, "version must not be empty");

        let mut manifest = valid_manifest();
        manifest.version = "1.2".to_string();
        assert_rejected(manifest, "major.minor.patch semver");

        let mut manifest = valid_manifest();
        manifest.version = "1.2.3-rc.1".to_string();
        assert_rejected(manifest, "without prerelease");
    }

    #[test]
    fn rejects_invalid_artifact_urls() {
        let mut manifest = valid_manifest();
        manifest.artifacts[0].url = "not a URL".to_string();
        assert_rejected(manifest, "invalid URL");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].url = manifest.artifacts[0].url.replacen("https", "http", 1);
        assert_rejected(manifest, "must use https");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].url = manifest.artifacts[0]
            .url
            .replace(EXAMPLEAPP.release_repository, "other/repository");
        assert_rejected(manifest, "must start with");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].asset_name = "other.tar.gz".to_string();
        assert_rejected(manifest, "must end with its asset_name");
    }

    #[test]
    fn rejects_unsorted_or_duplicate_artifacts() {
        let mut manifest = valid_manifest();
        manifest.artifacts.swap(0, 1);
        assert_rejected(manifest, "must be strictly sorted");

        let mut manifest = valid_manifest();
        manifest.artifacts.insert(
            1,
            portable_artifact(UpgradePlatform::Darwin, UpgradeArchitecture::Arm64),
        );
        assert_rejected(manifest, "duplicate upgrade manifest artifact");
    }

    #[test]
    fn rejects_inconsistent_archives_and_members() {
        let mut manifest = valid_manifest();
        manifest.artifacts[0].archive = UpgradeArchive::Msi;
        assert_rejected(manifest, "channel and archive");

        let mut manifest = valid_manifest();
        manifest.artifacts[2].archive = UpgradeArchive::TarGz;
        assert_rejected(manifest, "channel and archive");

        let mut manifest = valid_manifest();
        manifest.artifacts[2].members.push(UpgradeArtifactMember {
            path: "unexpected".to_string(),
            size: 1,
            executable: false,
        });
        assert_rejected(manifest, "MSI artifact");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].members.clear();
        assert_rejected(manifest, "at least one member");
    }

    #[test]
    fn rejects_unsafe_duplicate_or_unsorted_member_paths() {
        for (path, expected) in [
            ("/absolute", "must be relative"),
            ("C:/absolute", "must be relative"),
            ("../parent", "must not contain '..'"),
            ("bin\\exampleapp", "must not contain backslashes"),
            ("", "must not be empty"),
        ] {
            let mut manifest = valid_manifest();
            manifest.artifacts[0].members[0].path = path.to_string();
            assert_rejected(manifest, expected);
        }

        let mut manifest = valid_manifest();
        manifest.artifacts[0].members.push(UpgradeArtifactMember {
            path: "bin/exampleapp".to_string(),
            size: 1,
            executable: false,
        });
        assert_rejected(manifest, "duplicate member path");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].members.insert(
            0,
            UpgradeArtifactMember {
                path: "z-last".to_string(),
                size: 1,
                executable: false,
            },
        );
        assert_rejected(manifest, "members must be sorted");
    }

    #[test]
    fn rejects_zip_as_an_upgrade_container() {
        let mut value = serde_json::to_value(valid_manifest()).expect("serialize manifest");
        value["artifacts"][3]["archive"] = serde_json::Value::String("zip".to_string());
        let raw = serde_json::to_vec(&value).expect("serialize JSON");
        let error = parse_and_validate_upgrade_manifest(&EXAMPLEAPP, &raw)
            .expect_err("zip is not a container");
        assert!(
            error.to_string().contains("invalid upgrade manifest JSON"),
            "expected a JSON decode failure, got '{error}'"
        );
    }

    #[test]
    fn rejects_malformed_blake3_values() {
        let mut manifest = valid_manifest();
        manifest.artifacts[0].blake3 = "abc".to_string();
        assert_rejected(manifest, "64 lowercase hexadecimal");

        let mut manifest = valid_manifest();
        manifest.artifacts[0].blake3 =
            "A23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        assert_rejected(manifest, "64 lowercase hexadecimal");
    }

    /// v1 is frozen. A publisher that puts v2-only content in a v1 document has
    /// made a mistake; the shipped v1 clients reject the whole manifest for it,
    /// so this one must too.
    #[test]
    fn v1_refuses_a_channel_introduced_after_it() {
        let mut manifest = valid_manifest();
        manifest.artifacts[0].channel = UpgradeChannel::App;
        assert_rejected(manifest, "not part of the v1 manifest schema");
    }

    // -------------------------------------------------------------------
    // Manifest v2: forward tolerance.
    // -------------------------------------------------------------------

    fn v2_of(manifest: &UpgradeManifest) -> serde_json::Value {
        let mut value = serde_json::to_value(manifest).expect("serialize manifest");
        value["schema"] = serde_json::Value::String(EXAMPLEAPP.manifest_v2_schema.to_string());
        value
    }

    fn parse_v2(value: &serde_json::Value) -> Result<ValidatedUpgradeManifestV2> {
        let raw = serde_json::to_vec(value).expect("serialize JSON");
        parse_and_validate_upgrade_manifest_v2(&EXAMPLEAPP, &raw)
    }

    fn app_artifact() -> serde_json::Value {
        serde_json::json!({
            "platform": "darwin",
            "arch": "arm64",
            "channel": "app",
            "asset_name": "exampleapp-darwin-arm64.app.tar.gz",
            "url": format!(
                "{}exampleapp-darwin-arm64.app.tar.gz",
                EXAMPLEAPP.release_download_prefix("v1.2.3")
            ),
            "size": 512,
            "blake3": BLAKE3,
            "archive": "tar.gz",
            "members": [
                { "path": "ExampleApp.app/Contents/Info.plist", "size": 12, "executable": false },
                { "path": "ExampleApp.app/Contents/MacOS/exampleapp", "size": 7, "executable": true },
            ],
        })
    }

    #[test]
    fn v2_accepts_the_same_content_v1_does_and_the_new_app_channel() {
        let mut value = v2_of(&valid_manifest());
        // `app` sorts before `portable` for the same platform and arch.
        value["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .insert(0, app_artifact());
        let parsed = parse_v2(&value).expect("v2 manifest is valid");
        assert_eq!(parsed.understood.artifacts.len(), 5);
        assert_eq!(parsed.understood.artifacts[0].channel, UpgradeChannel::App);
        assert_eq!(parsed.published.artifacts.len(), 5);
    }

    #[test]
    fn v2_rejects_the_v1_schema_string() {
        let value = serde_json::to_value(valid_manifest()).expect("serialize manifest");
        let error = parse_v2(&value).expect_err("the v1 schema is not a v2 manifest");
        assert!(
            error
                .to_string()
                .contains("unsupported upgrade manifest schema")
        );
    }

    /// The whole point of v2: a document written by a newer publisher — with
    /// values and fields this client has never seen — still parses, and the
    /// artifact this client actually wants is still found and still validated.
    #[test]
    fn v2_tolerates_unknown_values_and_fields_and_still_selects_a_known_artifact() {
        let mut value = v2_of(&valid_manifest());
        value["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .insert(0, app_artifact());
        value["future_top_level_field"] = serde_json::json!({ "anything": [1, 2, 3] });
        value["artifacts"][0]["future_artifact_field"] = serde_json::json!("ignored");
        value["artifacts"][0]["members"][0]["future_member_field"] = serde_json::json!(true);
        let artifacts = value["artifacts"].as_array_mut().expect("artifacts");
        artifacts.push(serde_json::json!({
            "platform": "darwin", "arch": "arm64", "channel": "flatpak",
            "asset_name": "x", "url": "https://example.invalid/x",
            "size": 1, "blake3": "nope", "archive": "tar.gz", "members": [],
        }));
        artifacts.push(serde_json::json!({
            "platform": "darwin", "arch": "arm64", "channel": "portable",
            "asset_name": "y", "url": "https://example.invalid/y",
            "size": 1, "blake3": "nope", "archive": "squashfs", "members": [],
        }));
        artifacts.push(serde_json::json!({
            "platform": "haiku", "arch": "riscv64", "channel": "portable",
            "asset_name": "z", "url": "https://example.invalid/z",
            "size": 1, "blake3": "nope", "archive": "tar.gz", "members": [],
        }));

        let parsed = parse_v2(&value).expect("unknown values never invalidate a v2 manifest");

        // Everything is retained, understood or not.
        assert_eq!(parsed.published.artifacts.len(), 8);
        assert_eq!(parsed.published.artifacts[5].channel.as_str(), "flatpak");
        assert_eq!(parsed.published.artifacts[6].archive.as_str(), "squashfs");
        assert_eq!(parsed.published.artifacts[7].platform.as_str(), "haiku");
        assert_eq!(parsed.published.artifacts[7].arch.as_str(), "riscv64");
        for index in 5..8 {
            assert!(!parsed.published.artifacts[index].is_understood());
        }

        // Only the understood ones reach the pipeline's representation, and
        // an unknown-valued artifact is therefore never selectable — note the
        // three above carry a `blake3` that strict validation would reject.
        assert_eq!(parsed.understood.artifacts.len(), 5);
        assert!(
            parsed
                .understood
                .artifacts
                .iter()
                .all(|artifact| artifact.blake3 == BLAKE3)
        );
        let selected = parsed
            .understood
            .artifacts
            .iter()
            .find(|artifact| artifact.channel == UpgradeChannel::App)
            .expect("the app artifact is still selectable");
        assert_eq!(selected.asset_name, "exampleapp-darwin-arm64.app.tar.gz");
    }

    /// Tolerance stops at the artifacts the client understands: one of those is
    /// held to exactly the v1 rules.
    #[test]
    fn v2_validates_every_understood_artifact_as_strictly_as_v1() {
        for (mutate, expected) in [
            (
                Box::new(|value: &mut serde_json::Value| {
                    value["artifacts"][0]["blake3"] = serde_json::json!("abc");
                }) as Box<dyn Fn(&mut serde_json::Value)>,
                "64 lowercase hexadecimal",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    value["artifacts"][0]["url"] =
                        serde_json::json!("https://example.invalid/elsewhere.tar.gz");
                }),
                "must start with",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    value["artifacts"][0]["url"] = serde_json::json!(format!(
                        "{}other.tar.gz",
                        EXAMPLEAPP.release_download_prefix("v1.2.3")
                    ));
                }),
                "must end with its asset_name",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    value["artifacts"][0]["members"][0]["path"] = serde_json::json!("../escape");
                }),
                "must not contain '..'",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    let artifacts = value["artifacts"].as_array_mut().expect("artifacts");
                    artifacts.swap(0, 1);
                }),
                "must be strictly sorted",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    let duplicate = value["artifacts"][0].clone();
                    value["artifacts"]
                        .as_array_mut()
                        .expect("artifacts")
                        .insert(1, duplicate);
                }),
                "duplicate upgrade manifest artifact",
            ),
            (
                Box::new(|value: &mut serde_json::Value| {
                    value["version"] = serde_json::json!("1.2.3-rc.1");
                }),
                "without prerelease",
            ),
        ] {
            let mut value = v2_of(&valid_manifest());
            mutate(&mut value);
            let error = parse_v2(&value).expect_err("an understood artifact is validated strictly");
            assert!(
                error.to_string().contains(expected),
                "expected '{expected}' in '{error}'"
            );
        }
    }

    /// Unknown artifacts are skipped for ordering too: a client cannot know
    /// where a platform it has never heard of sorts, so its position must not
    /// be able to invalidate a manifest.
    #[test]
    fn v2_ordering_ignores_artifacts_it_does_not_understand() {
        let mut value = v2_of(&valid_manifest());
        value["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .insert(
                1,
                serde_json::json!({
                    "platform": "plan9", "arch": "arm64", "channel": "portable",
                    "asset_name": "p", "url": "https://example.invalid/p",
                    "size": 1, "blake3": BLAKE3, "archive": "tar.gz", "members": [],
                }),
            );
        let parsed = parse_v2(&value).expect("an unknown platform never breaks the ordering");
        assert_eq!(parsed.understood.artifacts.len(), 4);
        assert_eq!(parsed.published.artifacts.len(), 5);
    }

    #[test]
    fn v2_sets_aside_a_future_artifact_with_a_shape_it_cannot_read() {
        let mut value = v2_of(&valid_manifest());
        let known = value["artifacts"].as_array().expect("artifacts").len();
        // A kind from the future: a channel this client has never heard of,
        // no `blake3`, no `size`, and a differently typed `members`.
        value["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .push(serde_json::json!({
                "platform": "darwin",
                "arch": "arm64",
                "channel": "delta",
                "archive": "zst-patch",
                "asset_name": "exampleapp-darwin-arm64.delta",
                "sha256": "00",
                "members": "none",
            }));
        let parsed = parse_v2(&value).expect("a future-shaped artifact is tolerated");
        assert_eq!(parsed.understood.artifacts.len(), known);
        assert_eq!(parsed.published.artifacts.len(), known);
        assert_eq!(parsed.opaque_artifacts.len(), 1);
    }

    #[test]
    fn v2_refuses_a_known_kind_of_artifact_with_the_wrong_shape() {
        let mut value = v2_of(&valid_manifest());
        value["artifacts"][0]
            .as_object_mut()
            .expect("artifact")
            .remove("blake3");
        let error = parse_v2(&value).expect_err("a known kind must have the known shape");
        assert!(error.to_string().contains("artifact 0"), "{error}");
    }

    #[test]
    fn v2_still_refuses_an_oversized_document() {
        let raw = vec![b' '; UPGRADE_MANIFEST_MAX_BYTES as usize + 1];
        let error = parse_and_validate_upgrade_manifest_v2(&EXAMPLEAPP, &raw)
            .expect_err("oversized manifest");
        assert!(error.to_string().contains("exceeds the maximum size"));
    }

    #[test]
    fn tolerant_values_round_trip_through_json() {
        let known: Tolerant<UpgradeChannel> =
            serde_json::from_str("\"app\"").expect("known channel");
        assert_eq!(known, Tolerant::Known(UpgradeChannel::App));
        assert_eq!(known.as_str(), "app");
        assert_eq!(serde_json::to_string(&known).expect("serialize"), "\"app\"");

        let unknown: Tolerant<UpgradeChannel> =
            serde_json::from_str("\"flatpak\"").expect("unknown channel");
        assert_eq!(unknown, Tolerant::Unknown("flatpak".to_string()));
        assert_eq!(unknown.known(), None);
        assert_eq!(
            serde_json::to_string(&unknown).expect("serialize"),
            "\"flatpak\""
        );

        // A non-string where a wire enum belongs is a malformed document, not
        // an unknown value, and is still rejected.
        serde_json::from_str::<Tolerant<UpgradeChannel>>("7")
            .expect_err("a number is not a tolerated enum value");
    }
}
