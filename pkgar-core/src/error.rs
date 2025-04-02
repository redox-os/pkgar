use alloc::format;
use alloc::string::ToString;
use core::error;
use core::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub enum Error {
    Dryoc(dryoc::Error),
    InvalidBlake3,
    InvalidData,
    InvalidKey,
    InvalidMode(u32),
    Plain(PlainDelegate),
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
            Plain(err) => format!("Plain: {}", err),
            Overflow => "Overflow".to_string(),
            TryFromInt(err) => format!("TryFromInt: {}", err),
        };
        write!(f, "{}", msg)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Dryoc(e) => Some(e),
            Self::Plain(e) => Some(e),
            Self::TryFromInt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<dryoc::Error> for Error {
    fn from(err: dryoc::Error) -> Error {
        Error::Dryoc(err)
    }
}

impl From<plain::Error> for Error {
    fn from(err: plain::Error) -> Error {
        Error::Plain(err.into())
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(err: core::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

/// Delegate type for [`plain::Error`] because it doesn't implement [`error::Error`]
#[derive(Debug)]
pub enum PlainDelegate {
    TooShort,
    BadAlignment,
}

impl Display for PlainDelegate {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match *self {
            Self::TooShort => write!(f, "Slice too short to construct type"),
            Self::BadAlignment => write!(f, "Bytes incorrectly aligned for type"),
        }
    }
}

impl error::Error for PlainDelegate {}

// TODO: plain is deprecated; use bytemuck
impl From<plain::Error> for PlainDelegate {
    fn from(error: plain::Error) -> Self {
        match error {
            plain::Error::TooShort => Self::TooShort,
            plain::Error::BadAlignment => Self::BadAlignment,
        }
    }
}
