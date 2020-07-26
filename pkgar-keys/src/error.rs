use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub struct FileError {
    kind: Error,
    src: PathBuf,
}

impl Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.src.display(), self.kind)
    }
}

impl StdError for FileError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.kind.source()
    }
}

#[derive(Debug)]
pub enum Error {
    Custom(String),
    Io(io::Error),
    KeyInvalid,
    KeyMismatch,
    MAlloc,
    NonceInvalid,
    PassphraseIncorrect,
    PassphraseMismatch,
    Ser(toml::ser::Error),
    Deser(toml::de::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Error {
        Error::Deser(err)
    }
}

impl From<toml::ser::Error> for Error {
    fn from(err: toml::ser::Error) -> Error {
        Error::Ser(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Error::Custom(e) => e.clone(),
            Error::KeyInvalid => "Key length invalid".to_string(),
            Error::KeyMismatch => "Public and private keys do not match".to_string(),
            Error::MAlloc => "Unable to allocate locked/zeroed memory".to_string(),
            Error::NonceInvalid => "Nonce length invalid".to_string(),
            Error::PassphraseIncorrect => "Incorrect passphrase".to_string(),
            Error::PassphraseMismatch => "Passphrases do not match".to_string(),
            Error::Io(err) => format!("{}", err),
            Error::Ser(err) => format!("{}", err),
            Error::Deser(err) => format!("{}", err),
        };
        
        write!(f, "Error: {}", msg)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Ser(err) => Some(err),
            Error::Deser(err) => Some(err),
            _ => None,
        }
    }
}

