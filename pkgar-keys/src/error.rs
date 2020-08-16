use std::io;
use std::path::PathBuf;

use user_error::UFE;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("File: {path}")]
pub struct Error {
    #[source]
    pub src: ErrorKind,
    pub path: PathBuf,
}

impl UFE for Error {}

#[derive(Debug, Error)]
pub enum ErrorKind {
    #[error("Io")]
    Io(#[from] io::Error),
    
    #[error("Key length invalid")]
    KeyInvalid,
    
    #[error("Public and secret keys do not match")]
    KeyMismatch,
    
    #[error("Unable to allocate locked/zeroed memory")]
    SecureMem,
    
    #[error("Invalid nonce length")]
    NonceInvalid,
    
    #[error("Incorrect passphrase")]
    PassphraseIncorrect,
    
    #[error("Passphrases did not match")]
    PassphraseMismatch,
    
    #[error("Serialization")]
    Ser(#[from] toml::ser::Error),
    
    #[error("Deserialization")]
    Deser(#[from] toml::de::Error),
}

