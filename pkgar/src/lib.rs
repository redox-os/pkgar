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

// Allow .chain_err(|| path )
impl From<&Path> for ErrorKind {
    fn from(path: &Path) -> ErrorKind {
        ErrorKind::Path(path.to_path_buf())
    }
}

impl From<&PathBuf> for ErrorKind {
    fn from(path: &PathBuf) -> ErrorKind {
        ErrorKind::Path(path.clone())
    }
}

// Unfortunately error_chain does not handle types that don't implement
// std::error::Error very well.
impl From<pkgar_core::Error> for Error {
    fn from(err: pkgar_core::Error) -> Error {
        Error::from_kind(ErrorKind::Core(err))
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

