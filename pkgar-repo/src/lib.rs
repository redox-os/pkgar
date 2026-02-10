pub use self::package::*;

mod package;

use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Pkgar(Box<pkgar::Error>),
    Reqwest(reqwest::Error),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Pkgar(e) => Some(e),
            Self::Reqwest(e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pkgar(e) => write!(f, "{e}"),
            Self::Reqwest(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::Pkgar(Box::new(pkgar::Error::Io {
            source,
            path: None,
            context: "Generic Err",
        }))
    }
}

impl From<pkgar::Error> for Error {
    fn from(other: pkgar::Error) -> Self {
        Self::Pkgar(Box::new(other))
    }
}

impl From<pkgar_core::Error> for Error {
    fn from(other: pkgar_core::Error) -> Self {
        Self::Pkgar(Box::new(other.into()))
    }
}

impl From<reqwest::Error> for Error {
    fn from(other: reqwest::Error) -> Self {
        Self::Reqwest(other)
    }
}
