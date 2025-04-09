use alloc::format;
use alloc::string::ToString;
use core::error;
use core::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub enum Error {
    Cast(bytemuck::PodCastError),
    Dryoc(dryoc::Error),
    InvalidBlake3,
    InvalidData,
    InvalidKey,
    InvalidMode(u32),
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
            Cast(err) => format!("Bytemuck: {}", err),
            Overflow => "Overflow".to_string(),
            TryFromInt(err) => format!("TryFromInt: {}", err),
        };
        write!(f, "{}", msg)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            // TODO: Bump bytemuck when new version has core Error patch 
            // Self::Cast(e) => Some(e),
            Self::Dryoc(e) => Some(e),
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

impl From<core::num::TryFromIntError> for Error {
    fn from(err: core::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

impl From<bytemuck::PodCastError> for Error {
    fn from(err: bytemuck::PodCastError) -> Self {
        Self::Cast(err)
    }
}
