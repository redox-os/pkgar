mod bin;
pub mod ext;
mod package;
mod transaction;

pub use bin::*;
pub use package::*;
pub use transaction::*;

use std::io;
use std::path::{Path, PathBuf};

use error_chain::error_chain;
use pkgar_core::{Entry, Mode};
//use thiserror::Error;
use user_error::UFE;

const READ_WRITE_HASH_BUF_SIZE: usize = 4 * 1024 * 1024;

error_chain! {
    types {
        Error, ErrorKind, ResultExt;
    }
    
    links {
        Keys(pkgar_keys::Error, pkgar_keys::ErrorKind);
    }
    
    foreign_links {
        Io(io::Error);
    }
    
    errors {
        Core(src: pkgar_core::Error) {
            display("{}", src),
        }
        
        FailedCommit(changed: usize, remaining: usize) {
            display(
                "Failed to commit transaction. {} files changed, {} files remaining",
                changed,
                remaining,
            ),
        }
        
        InvalidPathComponent(path: PathBuf) {
            display("Invalid path component: {}", path.display()),
        }
        
        LengthMismatch(actual: u64, expected: u64) {
            display("Entry size mismatch: expected {}, got {}", expected, actual),
        }
        
        InvalidModeKind(mode: Mode) {
            display("Invalid Mode Kind: {:#o}", mode),
        }
        
        Path(path: PathBuf) {
            display("Path: {}", path.display()),
        }
        
        Entry(entry: Entry) {
            display("Entry: {:?}", entry),
        }
    }
}

impl UFE for Error {}

// Unfortunately error_chain does not handle types that don't implement
// std::error::Error very well.
impl From<pkgar_core::Error> for Error {
    fn from(err: pkgar_core::Error) -> Error {
        Error::from_kind(ErrorKind::Core(err))
    }
}

impl From<&Path> for ErrorKind {
    fn from(path: &Path) -> ErrorKind {
        ErrorKind::Path(path.to_path_buf())
    }
}
/*
// Apparently this conflicts with the first implementation; Just use map_err
// with Error::from for chaining errors to a pkgar_core Result.
impl<T> ResultExt<T> for Result<T, pkgar_core::Error> {
    fn chain_err<F, EK>(self, callback: F) -> Result<T, Error>
        where F: FnOnce() -> EK,
              EK: Into<ErrorKind>,
    {
        self.map_err(|e|
            Error::with_boxed_chain(Box::new(e), callback().into())
        )
    }
}*/

/*
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
        entry: Option<Entry>,
        src: ErrorKind,
    }
}

impl Repr {
    fn as_complex(
        self,
        new_path: Option<PathBuf>,
        new_reason: Option<String>,
        new_entry: Option<Entry>,
    ) -> Repr {
        match self {
            Repr::Kind(src) => Repr::Complex {
                path: new_path,
                reason: new_reason,
                entry: new_entry,
                src,
            },
            Repr::Complex { path, reason, entry, src } => Repr::Complex {
                path: new_path.or(path),
                reason: new_reason.or(reason),
                entry: new_entry.or(entry),
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
        self.repr = self.repr.as_complex(path, None, None);
        self
    }
    
    /// Set the reason associated with this error. Calling `reason()` multiple
    /// times will only store the most recently added reason.
    ///
    /// Most pkgar APIs will have already called `reason()`; therefore, it's
    /// unlikely that consumers of the library will need to use this function.
    pub fn reason(mut self, reason: impl ToString) -> Error {
        let reason = Some(reason.to_string());
        self.repr = self.repr.as_complex(None, reason, None);
        self
    }
    
    pub fn entry(mut self, entry: Entry) -> Error {
        self.repr = self.repr.as_complex(None, None, Some(entry));
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
    
    #[error("Invalid path component: {0}")]
    InvalidPathComponent(PathBuf),
    
    #[error("Entry size mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        actual: u64,
        expected: u64,
    },
    
    #[error("Invalid Mode Kind: {0:#o}")]
    InvalidModeKind(Mode),
}

impl ErrorKind {
    pub fn as_error(self) -> Error {
        Error::from(self)
    }
}

// Core::Error doesn't implement std::Error, so thiserror won't generate this impl
impl From<pkgar_core::Error> for ErrorKind {
    fn from(err: pkgar_core::Error) -> ErrorKind {
        ErrorKind::Core(err)
    }
}
*/
