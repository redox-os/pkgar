mod bin;
pub mod ext;
mod package;
mod transaction;

pub use bin::*;
pub use package::*;
pub use transaction::*;

use std::io;
use std::path::PathBuf;

use thiserror::Error;
use user_error::UFE;

// This ensures that all platforms use the same mode defines
pub(crate) const MODE_PERM: u32 = 0o007777;
pub(crate) const MODE_KIND: u32 = 0o170000;
pub(crate) const MODE_FILE: u32 = 0o100000;
pub(crate) const MODE_SYMLINK: u32 = 0o120000;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{reason}: {file}")]
    Io {
        reason: String,
        file: PathBuf,
        #[source]
        source: io::Error,
    },
    
    #[error(transparent)]
    Keys(#[from] pkgar_keys::Error),
   
    #[error("Failed to commit transaction. {changed} files changed, {remaining} files remaining")]
    FailedCommit {
        changed: usize,
        remaining: usize,
        #[source]
        source: io::Error,
    },
    
    #[error("Package: {0}")]
    Core(pkgar_core::Error),
    
    #[error("Invalid component in entry path '{entry}': {component}")]
    InvalidPath {
        entry: PathBuf,
        component: PathBuf,
    },
    
    #[error("Entry size mismatch for '{entry}', expected {expected}, got {actual}")]
    LengthMismatch {
        entry: PathBuf,
        actual: u64,
        expected: u64,
    },
    
    #[error("Unsupported mode for entry {entry}: {mode:#o}")]
    UnsupportedMode {
        entry: PathBuf,
        mode: u32,
    },
}

impl From<pkgar_core::Error> for Error {
    // Core::Error doesn't implement std::Error, so thiserror won't generate this impl
    fn from(err: pkgar_core::Error) -> Error {
        Error::Core(err)
    }
}

impl UFE for Error {}

