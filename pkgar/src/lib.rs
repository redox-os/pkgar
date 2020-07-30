pub mod bin;
mod package;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("key error: {0}")]
    Keys(#[from] pkgar_keys::Error),
    
    #[error("pkgar error: {0}")]
    Core(pkgar_core::Error),
}

impl From<pkgar_core::Error> for Error {
    // Core::Error doesn't implement std::Error, so thiserror won't generate this impl
    fn from(err: pkgar_core::Error) -> Error {
        Error::Core(err)
    }
}
