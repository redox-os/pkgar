use std::error::Error as StdError;
use std::fmt;
use std::io;

#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] pkgar_core::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ser(#[from] toml::ser::Error),
    #[error(transparent)]
    Deser(#[from] toml::de::Error),
    #[error("Invalid cypher key length (expected {expected}, got {actual})")]
    KeyInvalid { expected: usize, actual: usize },
    #[error("KeyMismatch")]
    KeyMismatch,
    #[error("Invalid nonce length")]
    NonceInvalid,
    #[error("Incorrect passphrase")]
    PassphraseIncorrect,
    #[error("Passphrases did not match")]
    PassphraseMismatch,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{self}")?;

        let mut source = self.source();
        while let Some(err) = source {
            writeln!(f, "\tCaused by: {err}")?;
            source = err.source();
        }

        // if let Some(backtrace) = self.backtrace() {
        //     write!(f, "{backtrace:?}")?;
        // }

        Ok(())
    }
}
