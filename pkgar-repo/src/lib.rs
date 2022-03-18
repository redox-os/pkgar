pub use self::package::*;

mod package;

#[derive(Debug)]
pub enum Error {
    Pkgar(pkgar::Error),
    Reqwest(reqwest::Error),
}

impl From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Self {
        Self::Pkgar(other.into())
    }
}

impl From<pkgar::Error> for Error {
    fn from(other: pkgar::Error) -> Self {
        Self::Pkgar(other)
    }
}

impl From<pkgar_core::Error> for Error {
    fn from(other: pkgar_core::Error) -> Self {
        Self::Pkgar(other.into())
    }
}

impl From<reqwest::Error> for Error {
    fn from(other: reqwest::Error) -> Self {
        Self::Reqwest(other)
    }
}
