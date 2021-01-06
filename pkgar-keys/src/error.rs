use std::io;
use std::path::PathBuf;

use error_chain::error_chain;
use user_error::UFE;
//use thiserror::Error;

error_chain! {
    types {
        Error, ErrorKind, ResultExt;
    }
    
    foreign_links {
        Io(io::Error);
        Ser(toml::ser::Error);
        Deser(toml::de::Error);
    }
    
    errors {
        KeyInvalid {
            description("Key length invalid"),
        }
        
        KeyMismatch {
            description("Public and secret keys do not match"),
        }
        
        NonceInvalid {
            description("Invalid nonce length"),
        }
        
        PassphraseIncorrect {
            description("Incorrect passphrase"),
        }
        
        PassphraseMismatch {
            description("Passphrases did not match"),
        }
        
        Path(path: PathBuf) {
            display("{}: ", path.display()),
        }
    }
    
    skip_msg_variant
}

impl UFE for Error {}

/*
/// An error which includes path context and implements `UFE` for easy display.
#[derive(Debug, Error)]
#[error("File: {path}")]
pub struct Error {
    #[source]
    pub src: ErrorKind,
    pub path: PathBuf,
}

/// The main error type that is used by this library internally. For additional
/// contextual information, most public routines use [`Error`](struct.Error.html).
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ErrorKind {
    #[error("Io")]
    Io(#[from] io::Error),
    
    #[error("Key length invalid")]
    KeyInvalid,
    
    #[error("Public and secret keys do not match")]
    KeyMismatch,
    
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
*/

