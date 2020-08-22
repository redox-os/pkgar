mod bin;
pub mod ext;
mod package;
mod transaction;

pub use bin::*;
pub use package::*;
pub use transaction::*;

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use user_error::UFE;

// This ensures that all platforms use the same mode defines
pub(crate) const MODE_PERM: u32 = 0o007777;
pub(crate) const MODE_KIND: u32 = 0o170000;
pub(crate) const MODE_FILE: u32 = 0o100000;
pub(crate) const MODE_SYMLINK: u32 = 0o120000;

/// This mimics the way std::io::Error works, to manage adding context in an
/// adequate manner, without too much boilderplate.
#[derive(Debug, Error)]
enum Repr {
    /// pkgar_keys::Error is very high level and already contains path context
    #[error(transparent)]
    Keys(#[from] pkgar_keys::Error),
    
    /// Ideally this should never make it all the way back to the user without
    /// being converted into a Complex error.
    #[error(transparent)]
    Kind(ErrorKind),
    
    #[error("{}", match (path, reason) {
        (Some(path), Some(reason)) => format!("{}: {}", reason, path.display()),
        (Some(path), None) => format!("File: {}", path.display()),
        (None, Some(reason)) => reason.clone(),
        (None, None) => String::new(),
    })]
    Complex {
        path: Option<PathBuf>,
        reason: Option<String>,
        src: ErrorKind,
    }
}

impl Repr {
    fn as_complex(self, new_path: Option<PathBuf>, new_reason: Option<String>) -> Repr {
        match self {
            Repr::Kind(src) => Repr::Complex {
                path: new_path,
                reason: new_reason,
                src,
            },
            Repr::Complex { path, reason, src } => Repr::Complex {
                path: new_path.or(path),
                reason: new_reason.or(reason),
                src,
            },
            _ => self,
        }
    }
}

/// Primary error type for pkgar. Provides optional path and reason context
/// for the underlying [`ErrorKind`](enum.ErrorKind.html).
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error {
    #[from]
    repr: Repr,
}

impl Error {
    /// Set the path associated with this error. Calling `path()` multiple
    /// times will only store the most recently added path.
    ///
    /// Most pkgar APIs will have already called `path()`; therefore, it's
    /// unlikely that consumers of the library will need to use this function.
    pub fn path(mut self, path: impl AsRef<Path>) -> Error {
        let path = Some(path.as_ref().to_path_buf());
        self.repr = self.repr.as_complex(path, None);
        self
    }
    
    /// Set the reason associated with this error. Calling `reason()` multiple
    /// times will only store the most recently added reason.
    ///
    /// Most pkgar APIs will have already called `reason()`; therefore, it's
    /// unlikely that consumers of the library will need to use this function.
    pub fn reason(mut self, reason: impl ToString) -> Error {
        let reason = Some(reason.to_string());
        self.repr = self.repr.as_complex(None, reason);
        self
    }
}

impl<K> From<K> for Error
    where K: Into<ErrorKind>
{
    fn from(e: K) -> Error {
        Error::from(Repr::Kind(e.into()))
    }
}

impl From<pkgar_keys::Error> for Error {
    fn from(e: pkgar_keys::Error) -> Error {
        Error::from(Repr::Keys(e))
    }
}

impl UFE for Error {}

/// Primary enumeration of error types producible by the pkgar crate. Most
/// interaction with this type will be via [`Error`](struct.Error.html).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    #[error("Io")]
    Io(#[from] io::Error),
    
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

impl From<pkgar_core::Error> for ErrorKind {
    // Core::Error doesn't implement std::Error, so thiserror won't generate this impl
    fn from(err: pkgar_core::Error) -> ErrorKind {
        ErrorKind::Core(err)
    }
}

