use alloc::format;
use alloc::string::ToString;
use core::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidBlake3,
    InvalidSignature,
    Plain(plain::Error),
    Overflow,
    TryFromInt(core::num::TryFromIntError),
}

//TODO: Improve Error messages
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Error::*;
        
        let msg = match self {
            InvalidData => "DataInvalid".to_string(),
            InvalidKey => "KeyInvalid".to_string(),
            InvalidBlake3 => "InvalidBlake3".to_string(),
            InvalidSignature => "InvalidSignature".to_string(),
            Plain(err) => format!("Plain: {:?}", err),
            Overflow => "Overflow".to_string(),
            TryFromInt(err) => format!("TryFromInt: {}", err),
        };
        write!(f, "{}", msg)
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

