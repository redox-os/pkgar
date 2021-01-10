use std::io;
use std::path::{Path, PathBuf};

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

