use alloc::format;
use alloc::string::ToString;
use core::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub enum Error {
    Dryoc(dryoc::Error),
    InvalidBlake3,
    InvalidData,
    InvalidKey,
    InvalidMode(u32),
    Plain(plain::Error),
    Overflow,
    TryFromInt(core::num::TryFromIntError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Error::*;

        let msg = match self {
            Dryoc(err) => format!("Dryoc: {:?}", err),
            InvalidBlake3 => "Invalid Blake3".to_string(),
            InvalidData => "Data Invalid".to_string(),
            InvalidKey => "Key Invalid".to_string(),
            InvalidMode(mode) => format!("Invalid Mode: {:o}", mode),
            Plain(err) => format!("Plain: {:?}", err),
            Overflow => "Overflow".to_string(),
            TryFromInt(err) => format!("TryFromInt: {}", err),
        };
        write!(f, "{}", msg)
    }
}

impl From<dryoc::Error> for Error {
    fn from(err: dryoc::Error) -> Error {
        Error::Dryoc(err)
    }
}

impl From<plain::Error> for Error {
    fn from(err: plain::Error) -> Error {
        Error::Plain(err)
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(err: core::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}
