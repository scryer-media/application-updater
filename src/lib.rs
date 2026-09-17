//! Signed in-application upgrade core.
//!
//! This crate owns everything an application needs to upgrade itself from a
//! signed release manifest: manifest validation, installation classification,
//! artifact download and verification, archive validation and extraction,
//! portable promotion and rollback, the durable journal, and the temporary
//! Windows upgrade helper.
//!
//! Everything product-specific — executable names, the release repository and
//! workflow, asset filenames, schema identifiers, environment markers — is
//! supplied by the host through [`ProductDescriptor`]. The host also keeps
//! ownership of its job records, progress reporting, restart control and
//! filesystem-space accounting; those arrive through the injected seams in
//! [`pipeline`].
//!
//! The serialized formats produced here (journal, helper plan, manifest) are
//! frozen: a helper written by one version of an application must be able to
//! read a plan or journal written by another.

pub mod evidence;
pub mod helper;
pub mod helper_plan;
pub mod installation;
pub mod journal;
pub mod macos_bundle;
pub mod manifest;
pub mod pipeline;
pub mod product;
pub mod windows_handoff;

pub use product::{ProductDescriptor, UpgradeDirectories};

/// Stable progress phase names consumed by the application-upgrade UI and
/// written into the durable journal. Frozen: a journal written by one release
/// is read by another.
pub mod phases {
    pub const CHECKING: &str = "checking";
    pub const DOWNLOADING: &str = "downloading";
    pub const VERIFYING: &str = "verifying";
    pub const STAGING: &str = "staging";
    pub const APPLYING: &str = "applying";
    pub const AWAITING_ELEVATION: &str = "awaiting_elevation";
    pub const RESTARTING: &str = "restarting";
    pub const REBOOT_REQUIRED: &str = "reboot_required";
}

/// Failure of an upgrade operation.
///
/// The variants and their `Display` shape deliberately mirror the application
/// error types these operations were extracted from, so a host that maps them
/// one-to-one reports exactly the messages it reported before.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation: {0}")]
    Validation(String),

    #[error("repository: {0}")]
    Repository(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// An error raised by a host-supplied seam (progress reporting, the space
    /// check, the restart handle), carried back to the host unchanged so its
    /// own error type survives the round trip. `Display` is transparent, so a
    /// message built around one of these reads exactly as the host's own error.
    #[error(transparent)]
    Host(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Error {
    /// Wrap a host error so it can travel through the core unchanged.
    pub fn host(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Host(Box::new(error))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
